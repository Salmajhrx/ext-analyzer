"""
Analyzer 1: Permission Analysis
Scores and flags dangerous permission combinations.
"""
from dataclasses import dataclass, field
from typing import List, Tuple

# Risk levels: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
DANGEROUS_PERMISSIONS = {
    # Critical — direct exfil / takeover capability
    "debugger":             (10, "Full tab debugging, can intercept everything including passwords"),
    "nativeMessaging":      (10, "Communicates with native desktop apps, full OS access"),
    "management":           (9,  "Can disable/uninstall other extensions"),
    "proxy":                (9,  "Routes ALL browser traffic through attacker-controlled server"),

    # High — data access
    "cookies":              (8,  "Read/write cookies for any site, enables session hijacking"),
    "webRequestBlocking":   (8,  "Intercept and modify/block any HTTP request"),
    "history":              (7,  "Full browsing history access"),
    "bookmarks":            (5,  "Read all bookmarks"),
    "clipboardRead":        (7,  "Read clipboard contents — can steal copied passwords/2FA"),
    "geolocation":          (6,  "Access physical location"),
    "identity":             (6,  "Access Google account OAuth tokens"),

    # Medium — attack surface
    "webRequest":           (5,  "Observe all HTTP traffic metadata"),
    "tabs":                 (4,  "Read URLs and titles of all open tabs"),
    "downloads":            (4,  "Initiate downloads silently"),
    "storage":              (2,  "Local storage (low risk alone, high risk combined)"),
    "declarativeNetRequest":(3,  "Modify network rules — can redirect traffic"),
    "contentSettings":      (5,  "Change browser content settings (camera, mic, location)"),
    "privacy":              (4,  "Modify privacy settings"),
    "browsingData":         (5,  "Clear browsing data including passwords"),
    "desktopCapture":       (7,  "Capture screen / window contents"),
    "pageCapture":          (6,  "Save web pages as MHTML — captures all content"),
    "tabCapture":           (7,  "Capture tab audio/video stream"),
}

HIGH_RISK_HOST_PATTERNS = [
    ("<all_urls>",    10, "Detected <all_urls> : access to ALL websites"),
    ("*://*/*",       10, "Detected *://*/* : access to ALL websites"),
    ("http://*/*",    8,  "Detected http://*/* : Access to all HTTP sites"),
    ("https://*/*",   8,  "Detected https://*/* : Access to all HTTPS sites"),
    ("*://*.google.com/*", 6, "Detected Google domains : could target user related credentials."),
    ("*://*.paypal.com/*", 8, "Detected PayPal domain : high-value financial target"),
    ("*://*.*.com/*", 7, "Detected *://*.*.com/ : Broad multi-domain wildcard"),
]

DANGEROUS_COMBOS = [
    (
        ["cookies", "webRequest"],
        9,
        "COOKIE THEFT CHAIN: Can intercept requests AND steal cookies → session hijacking"
    ),
    (
        ["clipboardRead", "tabs"],
        8,
        "CLIPBOARD SPY: Reads clipboard while knowing which sites you're on"
    ),
    (
        ["history", "identity"],
        8,
        "PROFILE BUILDER: Combines OAuth identity with full browsing history"
    ),
    (
        ["debugger", "tabs"],
        10,
        "TOTAL SURVEILLANCE: Debugger + tab access = full keylogging capability"
    ),
    (
        ["webRequestBlocking", "cookies"],
        9,
        "MITM CAPABLE: Can intercept requests and modify cookie headers"
    ),
    (
        ["management", "storage"],
        7,
        "PERSISTENCE: Can survive extension cleanup by managing other extensions"
    ),
    (
        ["downloads", "nativeMessaging"],
        9,
        "DROPPER CHAIN: Can download files and pass to native executable"
    ),
]


@dataclass
class PermissionFinding:
    name: str
    risk_score: int
    reason: str
    category: str = "permission"


@dataclass
class PermissionResult:
    findings: List[PermissionFinding] = field(default_factory=list)
    combo_findings: List[PermissionFinding] = field(default_factory=list)
    host_findings: List[PermissionFinding] = field(default_factory=list)
    total_score: int = 0
    permissions: List[str] = field(default_factory=list)
    host_permissions: List[str] = field(default_factory=list)


def analyze(manifest: dict) -> PermissionResult:
    result = PermissionResult()

    perms = manifest.get("permissions", [])
    host_perms = manifest.get("host_permissions", [])
    # MV2 also embeds host patterns in permissions
    pure_perms = [p for p in perms if not p.startswith("http") and not p.startswith("*") and not p.startswith("<")]
    embedded_hosts = [p for p in perms if p.startswith("http") or p.startswith("*") or p.startswith("<")]

    all_hosts = host_perms + embedded_hosts
    result.permissions = pure_perms
    result.host_permissions = all_hosts

    # Score individual permissions
    for perm in pure_perms:
        if perm in DANGEROUS_PERMISSIONS:
            score, reason = DANGEROUS_PERMISSIONS[perm]
            result.findings.append(PermissionFinding(perm, score, reason))

    # Score host permissions
    for host in all_hosts:
        for pattern, score, reason in HIGH_RISK_HOST_PATTERNS:
            if host == pattern or _host_matches(host, pattern):
                result.host_findings.append(
                    PermissionFinding(host, score, reason, category="host_permission")
                )
                break
        else:
            # Any host permission is at least low-risk
            if host not in [f.name for f in result.host_findings]:
                result.host_findings.append(
                    PermissionFinding(host, 2, f"Site-specific access: {host}", category="host_permission")
                )

    # Check dangerous combos
    perm_set = set(pure_perms)
    for combo, score, reason in DANGEROUS_COMBOS:
        if all(p in perm_set for p in combo):
            result.combo_findings.append(
                PermissionFinding("+".join(combo), score, reason, category="combo")
            )

    # Total score: sum of individual + host max + combo max
    indiv_score = sum(f.risk_score for f in result.findings)
    host_score = max((f.risk_score for f in result.host_findings), default=0)
    combo_score = max((f.risk_score for f in result.combo_findings), default=0)
    result.total_score = indiv_score + host_score + combo_score

    return result


def _host_matches(host: str, pattern: str) -> bool:
    """Simple wildcard matching for host patterns."""
    if pattern == "<all_urls>" or pattern == "*://*/*":
        return True
    return False
