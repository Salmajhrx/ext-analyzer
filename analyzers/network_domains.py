"""
Analyzer 3: External Domain Communication
Extracts and risk-scores all external domains contacted by the extension.
"""
import re
from dataclasses import dataclass, field
from typing import List, Set, Dict
from urllib.parse import urlparse


@dataclass
class DomainFinding:
    domain: str
    url: str
    file: str
    line_number: int
    line_snippet: str
    risk_score: int
    reason: str
    category: str


@dataclass
class NetworkResult:
    findings: List[DomainFinding] = field(default_factory=list)
    unique_domains: Set[str] = field(default_factory=set)
    total_score: int = 0


# TLDs / patterns that are inherently suspicious
SUSPICIOUS_TLDS = [
    (".ru",  7, "Russian TLD — common in malware C2"),
    (".cn",  6, "Chinese TLD — elevated risk for exfil"),
    (".tk",  8, "Free TLD heavily abused by malware"),
    (".top", 6, "Free TLD abused for phishing/malware"),
    (".xyz", 5, "Cheap TLD common in malicious infra"),
    (".icu", 5, "Cheap TLD common in malicious infra"),
    (".cc",  5, "Often used in malware campaigns"),
    (".pw",  6, "Free TLD used in malicious infra"),
    (".gq",  7, "Free TLD, extremely high abuse rate"),
    (".ml",  6, "Free TLD, high abuse rate"),
    (".cf",  6, "Free TLD, high abuse rate"),
    (".ga",  6, "Free TLD, high abuse rate"),
]

# Known C2/tracking/analytics infrastructure (partial matches)
KNOWN_MALICIOUS_PATTERNS = [
    (r"track(er|ing)\.",    8, "Tracking subdomain pattern"),
    (r"collect\.",          8, "Data collection endpoint pattern"),
    (r"exfil\.",            10, "Explicit exfiltration subdomain"),
    (r"harvest\.",          9, "Data harvesting subdomain"),
    (r"c2\.",               10, "Command-and-control subdomain"),
    (r"cmd\.",              8, "Command subdomain pattern"),
    (r"steal\.",            10, "Data theft subdomain"),
    (r"log(ger|ging)?\.",   7, "Remote logging endpoint"),
    (r"analytics\.",        3, "Analytics endpoint (low risk alone)"),
    (r"stat(s)?\.",         2, "Stats endpoint"),
    (r"update\.",           5, "Update endpoint — may fetch new code"),
    (r"config\.",           6, "Remote config endpoint — medium risk"),
    (r"api\.",              3, "API endpoint (context-dependent)"),
    (r"data\.",             4, "Data endpoint"),
    (r"report\.",           5, "Reporting endpoint"),
]

# URL context patterns that indicate exfiltration intent
EXFIL_URL_PATTERNS = [
    (r"/collect",    8, "Data collection endpoint path"),
    (r"/steal",      10, "Explicit theft endpoint path"),
    (r"/log\b",      7, "Logging endpoint path"),
    (r"/report",     6, "Reporting endpoint path"),
    (r"/ping",       4, "Ping/beacon endpoint"),
    (r"/track",      7, "Tracking endpoint path"),
    (r"/exfil",      10, "Explicit exfiltration path"),
    (r"/harvest",    9, "Harvesting endpoint path"),
    (r"/data\b",     5, "Data submission path"),
    (r"/api/v\d",    3, "Versioned API (check combined with other signals)"),
]

# URL extraction patterns
URL_PATTERNS = [
    r'https?://[^\s\'"<>)\]]+',
    r'fetch\([\'"]([^\'"]+)[\'"]',
    r'XMLHttpRequest.*?open\([\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
    r'navigator\.sendBeacon\([\'"]([^\'"]+)[\'"]',
    r'\.src\s*=\s*[\'"]([^\'"]+)[\'"]',
    r'new\s+WebSocket\([\'"]([^\'"]+)[\'"]',
]

# Legitimate CDN / known-good domains (reduce noise)
KNOWN_GOOD_DOMAINS = {
    "googleapis.com", "gstatic.com", "google.com", "youtube.com",
    "cloudflare.com", "fastly.net", "jsdelivr.net", "unpkg.com",
    "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com",
    "chrome.google.com",
}


def analyze(js_files: Dict[str, str], manifest: dict) -> NetworkResult:
    result = NetworkResult()
    domain_scores: Dict[str, int] = {}

    for filename, source in js_files.items():
        lines = source.splitlines()
        for line_num, line in enumerate(lines, 1):
            urls = _extract_urls(line)
            for url in urls:
                parsed = _safe_parse(url)
                if not parsed:
                    continue

                domain = parsed.netloc.lower()
                if not domain or domain in KNOWN_GOOD_DOMAINS:
                    continue

                # Check if it's a CDN subdomain
                if any(domain.endswith("." + gd) for gd in KNOWN_GOOD_DOMAINS):
                    continue

                result.unique_domains.add(domain)
                risk, reason, category = _score_domain(domain, url)

                finding = DomainFinding(
                    domain=domain,
                    url=url[:150],
                    file=filename,
                    line_number=line_num,
                    line_snippet=line.strip()[:120],
                    risk_score=risk,
                    reason=reason,
                    category=category
                )
                result.findings.append(finding)

                if domain not in domain_scores or domain_scores[domain] < risk:
                    domain_scores[domain] = risk

    # Also check CSP / web accessible resources for domains
    csp = manifest.get("content_security_policy", "")
    if isinstance(csp, dict):
        csp = " ".join(csp.values())
    if csp:
        csp_domains = re.findall(r'https?://([^\s;\'\"]+)', csp)
        for d in csp_domains:
            domain = d.split("/")[0].lower()
            if domain and domain not in KNOWN_GOOD_DOMAINS:
                result.unique_domains.add(domain)

    result.total_score = sum(domain_scores.values())
    return result


def _extract_urls(line: str) -> List[str]:
    urls = []
    for pattern in URL_PATTERNS:
        matches = re.findall(pattern, line)
        for m in matches:
            m = m.strip().rstrip('",;)')
            if m.startswith("http") and len(m) > 10:
                urls.append(m)
    return list(set(urls))


def _safe_parse(url: str):
    try:
        p = urlparse(url)
        if p.netloc:
            return p
    except Exception:
        pass
    return None


def _score_domain(domain: str, url: str) -> tuple:
    max_score = 1
    best_reason = "External domain contact"
    category = "external_domain"

    # Check TLD
    for tld, score, reason in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            if score > max_score:
                max_score = score
                best_reason = reason
                category = "suspicious_tld"

    # Check subdomain patterns
    for pattern, score, reason in KNOWN_MALICIOUS_PATTERNS:
        if re.search(pattern, domain, re.IGNORECASE):
            if score > max_score:
                max_score = score
                best_reason = reason
                category = "suspicious_subdomain"

    # Check URL path
    for pattern, score, reason in EXFIL_URL_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            if score > max_score:
                max_score = score
                best_reason = reason
                category = "suspicious_endpoint"

    # Check for IP addresses (direct IP comms = suspicious)
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score = 7
        if score > max_score:
            max_score = score
            best_reason = "Direct IP address — bypasses DNS, common in C2"
            category = "direct_ip"

    return max_score, best_reason, category
