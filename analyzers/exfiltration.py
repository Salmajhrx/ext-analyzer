"""
Analyzer 6: Exfiltration Chain Detection
Detects complete data-steal chains: collect → package → transmit.
Highest-confidence malicious indicator when full chain is present.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict, Set


@dataclass
class ExfilFinding:
    chain_type: str
    stage: str   # "collect", "package", "transmit", "full_chain"
    file: str
    line_number: int
    line_snippet: str
    risk_score: int
    reason: str


@dataclass
class ExfilResult:
    findings: List[ExfilFinding] = field(default_factory=list)
    total_score: int = 0
    chains_detected: List[str] = field(default_factory=list)


# Stage 1: Data Collection
COLLECT_PATTERNS = [
    (r"document\.querySelectorAll\(['\"]input", 6, "Scrapes all form inputs"),
    (r"input\[type=['\"]?password", 8, "Targets password input fields"),
    (r"input\[type=['\"]?email", 7, "Targets email input fields"),
    (r"\.value\b.*password|password.*\.value\b", 8, "Reads password field value"),
    (r"chrome\.cookies\.getAll", 9, "Dumps all browser cookies"),
    (r"chrome\.cookies\.get\b", 7, "Reads specific cookie"),
    (r"navigator\.clipboard\.readText", 8, "Reads clipboard content"),
    (r"chrome\.history\.search|chrome\.history\.getVisits", 7, "Reads browsing history"),
    (r"localStorage\.getItem|sessionStorage\.getItem", 5, "Reads local storage"),
    (r"document\.cookie\b", 7, "Reads document.cookie directly"),
    (r"window\.location\.href|document\.URL", 4, "Captures current page URL"),
    (r"document\.title\b", 3, "Captures page title"),
    (r"form.*addEventListener.*submit|addEventListener.*submit.*form", 7,
     "Hooks form submission events"),
    (r"keydown|keypress|keyup.*addEventListener|addEventListener.*key(down|press|up)", 8,
     "Installs keylogger via keyboard event listener"),
    (r"MutationObserver", 5, "Observes DOM changes — may capture dynamic content"),
    (r"getComputedStyle|getBoundingClientRect", 3, "Visual fingerprinting"),
    (r"navigator\.(userAgent|language|plugins|platform)", 4, "Browser fingerprinting"),
    (r"screen\.(width|height|colorDepth)", 3, "Screen fingerprinting"),
    (r"chrome\.identity\.getAuthToken", 9, "Steals OAuth auth token"),
    (r"requestHeaders.*Cookie|Cookie.*requestHeaders", 8, "Intercepts Cookie headers"),
]

# Stage 2: Data Packaging
PACKAGE_PATTERNS = [
    (r"JSON\.stringify\b", 3, "Serializes data to JSON for transmission"),
    (r"btoa\s*\(", 5, "Base64-encodes data — obfuscates exfiltrated content"),
    (r"encodeURIComponent|encodeURI\b", 3, "URL-encodes data for transmission"),
    (r"FormData\b", 4, "Packages data in FormData for POST"),
    (r"new\s+Blob\b", 4, "Packages data as Blob"),
    (r"\.join\s*\(\s*['\"][,|&]['\"]", 3, "Joins collected data with delimiter"),
    (r"Object\.assign.*\{.*url|url.*Object\.assign", 4, "Builds request payload with URL"),
    (r"data\s*\+?=\s*.*cookie|cookie.*data\s*\+?=", 7, "Appends cookie to data payload"),
]

# Stage 3: Data Transmission
TRANSMIT_PATTERNS = [
    (r"navigator\.sendBeacon\(", 8, "Sends data via sendBeacon — fires even on page unload"),
    (r"fetch\s*\(\s*['\"]https?://", 6, "Fetch POST to remote URL"),
    (r"XMLHttpRequest.*send\b", 6, "XHR data transmission"),
    (r"\.send\s*\(\s*(?:data|JSON|payload|body)", 7, "Sends payload via XHR"),
    (r"new\s+Image\s*\(\s*\).*src\s*=.*\?", 6, "Pixel tracking — sends data via image request"),
    (r"new\s+WebSocket\b", 7, "WebSocket data transmission"),
    (r"ws\.send\(|socket\.send\(", 8, "Sends data over WebSocket"),
    (r"chrome\.runtime\.sendMessage.*fetch|fetch.*chrome\.runtime\.sendMessage", 6,
     "Relays data between extension components before transmitting"),
    (r"EventSource\b", 5, "Server-Sent Events — persistent connection for data streaming"),
]

# Specific high-confidence exfil chains (regex against joined source)
KNOWN_CHAINS = [
    (
        "PASSWORD_HARVEST",
        r"password.*\.value|\.value.*password",
        r"JSON\.stringify|btoa",
        r"sendBeacon|fetch|XMLHttpRequest",
        10,
        "CONFIRMED PASSWORD HARVEST: collect password → package → transmit"
    ),
    (
        "COOKIE_THEFT",
        r"chrome\.cookies\.getAll|document\.cookie",
        r"JSON\.stringify",
        r"sendBeacon|fetch|XMLHttpRequest|\.send",
        10,
        "CONFIRMED COOKIE THEFT: dump cookies → serialize → exfil"
    ),
    (
        "KEYLOGGER",
        r"addEventListener.*key(down|press|up)",
        r"key(down|press|up).*key",
        r"sendBeacon|fetch|XMLHttpRequest",
        10,
        "KEYLOGGER: keyboard listener → capture keystrokes → transmit"
    ),
    (
        "FORM_JACKER",
        r"addEventListener.*submit",
        r"querySelectorAll.*input|input.*value",
        r"sendBeacon|fetch|XMLHttpRequest",
        10,
        "FORM JACKING: intercept form submit → steal field values → exfil"
    ),
    (
        "HISTORY_EXFIL",
        r"chrome\.history\.(search|getVisits)",
        r"JSON\.stringify",
        r"fetch|XMLHttpRequest",
        8,
        "HISTORY EXFIL: collect history → serialize → transmit"
    ),
    (
        "OAUTH_THEFT",
        r"chrome\.identity\.getAuthToken",
        r"token|access_token",
        r"fetch|XMLHttpRequest|sendBeacon",
        10,
        "OAUTH TOKEN THEFT: steal Google auth token → transmit"
    ),
]


def analyze(js_files: Dict[str, str]) -> ExfilResult:
    result = ExfilResult()
    seen_stages: Dict[str, int] = {}

    # Per-file stage detection
    for filename, source in js_files.items():
        lines = source.splitlines()

        collect_hits = []
        package_hits = []
        transmit_hits = []

        for line_num, line in enumerate(lines, 1):
            # Collect stage
            for pattern, score, reason in COLLECT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.findings.append(ExfilFinding(
                        chain_type="data_collection",
                        stage="collect",
                        file=filename,
                        line_number=line_num,
                        line_snippet=line.strip()[:120],
                        risk_score=score,
                        reason=reason
                    ))
                    collect_hits.append(score)
                    key = f"collect_{pattern[:30]}"
                    if key not in seen_stages or seen_stages[key] < score:
                        seen_stages[key] = score

            # Package stage
            for pattern, score, reason in PACKAGE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.findings.append(ExfilFinding(
                        chain_type="data_packaging",
                        stage="package",
                        file=filename,
                        line_number=line_num,
                        line_snippet=line.strip()[:120],
                        risk_score=score,
                        reason=reason
                    ))
                    package_hits.append(score)
                    key = f"package_{pattern[:30]}"
                    if key not in seen_stages or seen_stages[key] < score:
                        seen_stages[key] = score

            # Transmit stage
            for pattern, score, reason in TRANSMIT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.findings.append(ExfilFinding(
                        chain_type="data_transmission",
                        stage="transmit",
                        file=filename,
                        line_number=line_num,
                        line_snippet=line.strip()[:120],
                        risk_score=score,
                        reason=reason
                    ))
                    transmit_hits.append(score)
                    key = f"transmit_{pattern[:30]}"
                    if key not in seen_stages or seen_stages[key] < score:
                        seen_stages[key] = score

        # Check for complete chains in this file
        if collect_hits and package_hits and transmit_hits:
            chain_score = max(collect_hits) + 3  # bonus for complete chain
            result.chains_detected.append(f"Full 3-stage chain in {filename}")
            result.findings.append(ExfilFinding(
                chain_type="FULL_EXFIL_CHAIN",
                stage="full_chain",
                file=filename,
                line_number=0,
                line_snippet="",
                risk_score=min(10, chain_score),
                reason=f"Complete exfiltration chain detected: collect({len(collect_hits)} hits) → package({len(package_hits)} hits) → transmit({len(transmit_hits)} hits)"
            ))
            seen_stages["full_chain"] = 10

        # Check known chain patterns against full file source
        for chain_name, p1, p2, p3, score, reason in KNOWN_CHAINS:
            if re.search(p1, source, re.IGNORECASE) and \
               re.search(p3, source, re.IGNORECASE):
                result.chains_detected.append(chain_name)
                result.findings.append(ExfilFinding(
                    chain_type=chain_name,
                    stage="full_chain",
                    file=filename,
                    line_number=0,
                    line_snippet="",
                    risk_score=score,
                    reason=reason
                ))
                seen_stages[chain_name] = score

    result.total_score = sum(seen_stages.values())
    return result
