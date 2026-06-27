"""
Analyzer 2: Sensitive Chrome API Usage
Detects dangerous chrome.* API calls in JS source files.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class APIFinding:
    api: str
    file: str
    line_number: int
    line_snippet: str
    risk_score: int
    reason: str


@dataclass
class APIResult:
    findings: List[APIFinding] = field(default_factory=list)
    total_score: int = 0
    files_scanned: int = 0


# Format: api_pattern -> (risk_score, reason)
SENSITIVE_APIS = {
    # Credential & session theft
    r"chrome\.cookies\.getAll":        (9,  "Dumps ALL cookies across all sites — session hijacking"),
    r"chrome\.cookies\.get\b":         (7,  "Reads specific site cookie"),
    r"chrome\.cookies\.set\b":         (7,  "Sets/overwrites cookies — session fixation"),

    # Traffic interception
    r"chrome\.webRequest\.onBeforeSendHeaders": (8, "Intercepts outgoing request headers incl. auth tokens"),
    r"chrome\.webRequest\.onHeadersReceived":   (7, "Intercepts and can modify server response headers"),
    r"chrome\.webRequest\.onBeforeRequest":     (8, "Intercepts raw request body — can steal POST data"),
    r"chrome\.declarativeNetRequest\.updateDynamicRules": (6, "Dynamically adds traffic redirect rules"),

    # Tab/history surveillance
    r"chrome\.tabs\.captureVisibleTab":  (8, "Screenshots active tab — visual surveillance"),
    r"chrome\.history\.search":          (7, "Searches full browsing history"),
    r"chrome\.history\.getVisits":       (7, "Gets visit timestamps for URLs"),

    # Clipboard
    r"navigator\.clipboard\.readText":   (8, "Reads clipboard — captures copied passwords/2FA"),
    r"document\.execCommand\(['\"]paste": (7, "Legacy clipboard read via execCommand"),

    # Screen/media capture
    r"chrome\.desktopCapture\.chooseDesktopMedia": (9, "Initiates screen capture"),
    r"chrome\.tabCapture\.capture":      (8, "Captures tab audio/video stream"),

    # Extension manipulation
    r"chrome\.management\.setEnabled":   (8, "Enables/disables other extensions"),
    r"chrome\.management\.uninstall":    (8, "Uninstalls other extensions"),

    # Native communication
    r"chrome\.runtime\.connectNative":   (10, "Opens channel to native desktop app"),
    r"chrome\.runtime\.sendNativeMessage": (10, "Sends message to native desktop app"),

    # Identity/OAuth
    r"chrome\.identity\.getAuthToken":   (8, "Steals OAuth token for user's Google account"),
    r"chrome\.identity\.launchWebAuthFlow": (7, "Initiates OAuth flow — can phish credentials"),

    # Downloads (can drop files)
    r"chrome\.downloads\.download\b":   (6, "Silently downloads files to disk"),

    # Debugging API
    r"chrome\.debugger\.attach":         (10, "Attaches debugger to tab — full keylogging possible"),
    r"chrome\.debugger\.sendCommand":    (9,  "Sends debugger command — can exfil page content"),

    # Proxy manipulation
    r"chrome\.proxy\.settings\.set":     (9, "Redirects ALL browser traffic through attacker proxy"),

    # Storage exfil
    r"chrome\.storage\.sync\.get":       (4, "Reads synced storage — may contain sensitive config"),
    r"localStorage\.getItem":            (4, "Reads local storage — may contain tokens/session data"),
    r"sessionStorage\.getItem":          (4, "Reads session storage"),

    # Misc data access
    r"chrome\.bookmarks\.getTree":       (5, "Dumps entire bookmark tree"),
    r"chrome\.topSites\.get":            (4, "Gets most visited sites"),
    r"chrome\.pageCapture\.saveAsMHTML": (6, "Saves full page content incl. form data"),
}


def analyze(js_files: Dict[str, str]) -> APIResult:
    """
    js_files: dict of {filename: source_code}
    """
    result = APIResult()
    result.files_scanned = len(js_files)
    seen_apis = set()  # deduplicate per-api scoring

    for filename, source in js_files.items():
        lines = source.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern, (score, reason) in SENSITIVE_APIS.items():
                if re.search(pattern, line):
                    api_name = pattern.replace(r"\b", "").replace("\\.", ".").replace("\\(", "(")
                    # Clean up the regex pattern for display
                    clean_api = re.sub(r'[\\()\[\]^$]', '', pattern).replace(r"\.", ".").strip()

                    result.findings.append(APIFinding(
                        api=clean_api,
                        file=filename,
                        line_number=line_num,
                        line_snippet=line.strip()[:120],
                        risk_score=score,
                        reason=reason
                    ))

                    if clean_api not in seen_apis:
                        seen_apis.add(clean_api)

    # Score = sum of unique API risk scores (avoid inflating from repeated calls)
    unique_apis: Dict[str, int] = {}
    for f in result.findings:
        if f.api not in unique_apis or unique_apis[f.api] < f.risk_score:
            unique_apis[f.api] = f.risk_score

    result.total_score = sum(unique_apis.values())
    return result
