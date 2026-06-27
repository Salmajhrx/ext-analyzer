"""
CXT-SCAN Rules Engine
YARA-style conditional behavioural rules over combined analyzer output.

Design:
  - Each rule gets the full AnalysisContext (flat view of all analyzer results)
  - Rule fires only when ALL its conditions are satisfied (not just one signal)
  - Matched rules are listed by name in the final report
  - Rules score adds on top of the existing static + sandbox score

How to add a new rule:
  1. Define a function that receives (ctx: AnalysisContext) -> List[str]
     Return a list of evidence strings if the rule fires, [] if not.
  2. Decorate it with @rule(...) filling in name, description, severity, reference.
  3. That's it — it auto-registers in RULES and runs on every scan.

Severity → score contribution:
  CRITICAL = 40 pts   HIGH = 25 pts   MEDIUM = 12 pts   LOW = 5 pts
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Callable, Dict, Set, Optional


# ── Analysis Context ──────────────────────────────────────────────────────────

@dataclass
class AnalysisContext:
    """
    Flat, unified view built from all analyzer result objects.
    Rules only touch this object — never raw analyzer results directly.
    """

    # ── From manifest ─────────────────────────────────────────────────────────
    extension_name: str           = ""
    manifest_version: int         = 3
    permissions: List[str]        = field(default_factory=list)
    host_permissions: List[str]   = field(default_factory=list)
    has_content_scripts: bool     = False
    content_script_matches: List[str] = field(default_factory=list)
    has_background: bool          = False

    # ── From permissions analyzer ─────────────────────────────────────────────
    perm_score: int               = 0
    dangerous_perm_combos: List[str] = field(default_factory=list)  # e.g. "cookies+webRequest"

    # ── From sensitive_apis analyzer ──────────────────────────────────────────
    detected_apis: List[str]      = field(default_factory=list)   # unique API names found in source

    # ── From network_domains analyzer ─────────────────────────────────────────
    external_domains: List[str]   = field(default_factory=list)
    domain_categories: Dict[str, str] = field(default_factory=dict)  # domain → category string

    # ── From remote_config analyzer ───────────────────────────────────────────
    has_remote_fetch_on_install: bool = False
    has_eval_of_remote_payload: bool  = False
    has_websocket_c2: bool            = False
    has_polling_fetch: bool           = False
    remote_config_patterns: List[str] = field(default_factory=list)

    # ── From dynamic_execution analyzer ───────────────────────────────────────
    has_eval: bool                = False
    has_base64_exec: bool         = False   # eval(atob(...))
    has_obfuscation: bool         = False
    obfuscation_verdict: str      = "Clean"

    # ── From exfiltration analyzer ────────────────────────────────────────────
    confirmed_chains: List[str]   = field(default_factory=list)  # e.g. ["COOKIE_THEFT", "KEYLOGGER"]
    exfil_collect_hits: int       = 0
    exfil_transmit_hits: int      = 0

    # ── From sandbox — Malware Jail runtime ───────────────────────────────────
    runtime_urls: List[Dict]      = field(default_factory=list)
    runtime_eval_calls: List[Dict]= field(default_factory=list)
    runtime_chrome_apis: List[str]= field(default_factory=list)  # list of api names called
    runtime_dom_hooks: List[str]  = field(default_factory=list)  # event types hooked

    # ── From sandbox — JS-X-Ray SAST ─────────────────────────────────────────
    sast_kinds: Set[str]          = field(default_factory=set)   # warning kind strings

    # ── From sandbox — Box.js IOCs ────────────────────────────────────────────
    boxjs_ioc_types: List[str]    = field(default_factory=list)  # e.g. ["Run", "UrlFetch"]

    # ── Derived sets (built in __post_init__) ─────────────────────────────────
    _perm_set: Set[str]           = field(default_factory=set, init=False, repr=False)
    _api_set: Set[str]            = field(default_factory=set, init=False, repr=False)
    _domain_set: Set[str]         = field(default_factory=set, init=False, repr=False)
    _runtime_url_strings: Set[str]= field(default_factory=set, init=False, repr=False)

    def __post_init__(self):
        self._perm_set          = set(self.permissions)
        self._api_set           = set(self.detected_apis)
        self._domain_set        = set(self.external_domains)
        self._runtime_url_strings = {u.get("url", "") for u in self.runtime_urls}

    # ── Query helpers ─────────────────────────────────────────────────────────

    def has_perm(self, *perms: str) -> bool:
        """True if ANY of the listed permissions are declared."""
        return any(p in self._perm_set for p in perms)

    def has_all_perms(self, *perms: str) -> bool:
        """True if ALL of the listed permissions are declared."""
        return all(p in self._perm_set for p in perms)

    def has_api(self, *apis: str) -> bool:
        """True if ANY of the API patterns appear in source."""
        return any(a in self._api_set for a in apis)

    def host_is_wildcard(self) -> bool:
        """True if extension requests access to all URLs."""
        wildcards = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
        return bool(wildcards & set(self.host_permissions))

    def has_confirmed_chain(self, *chains: str) -> bool:
        return any(c in self.confirmed_chains for c in chains)

    def domains_match_tld(self, *tlds: str) -> List[str]:
        """Return domains matching any of the given TLDs."""
        return [d for d in self._domain_set if any(d.endswith(t) for t in tlds)]

    def domains_match_pattern(self, pattern: str) -> List[str]:
        """Return domains matching a regex pattern."""
        return [d for d in self._domain_set
                if re.search(pattern, d, re.IGNORECASE)]

    def runtime_contacted(self, *fragments: str) -> List[str]:
        """Return runtime URLs containing any of the given fragments."""
        return [u for u in self._runtime_url_strings
                if any(f in u for f in fragments)]

    def runtime_contacted_pattern(self, pattern: str) -> List[str]:
        """Return runtime URLs matching a regex pattern."""
        return [u for u in self._runtime_url_strings
                if re.search(pattern, u, re.IGNORECASE)]

    def runtime_api_called(self, *fragments: str) -> bool:
        """True if any runtime Chrome API call matches the fragments."""
        return any(
            any(f in api for f in fragments)
            for api in self.runtime_chrome_apis
        )

    def has_combo(self, *perms: str) -> bool:
        """True if this exact permission combination was flagged as dangerous."""
        combo = "+".join(sorted(perms))
        return any(combo in c for c in self.dangerous_perm_combos)


# ── Rule scaffold ─────────────────────────────────────────────────────────────

SEVERITY_SCORE = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5}

RULES: List["Rule"] = []   # auto-populated by @rule decorator


@dataclass
class RuleMatch:
    name: str
    severity: str
    score: int
    description: str
    evidence: List[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    description: str
    severity: str
    reference: str
    tags: List[str]
    _fn: Callable

    def evaluate(self, ctx: AnalysisContext) -> Optional[RuleMatch]:
        try:
            evidence = self._fn(ctx)
            if evidence:
                return RuleMatch(
                    name        = self.name,
                    severity    = self.severity,
                    score       = SEVERITY_SCORE.get(self.severity, 5),
                    description = self.description,
                    evidence    = evidence,
                )
        except Exception:
            pass
        return None


def rule(name: str, description: str, severity: str,
         reference: str = "", tags: List[str] = None):
    """Decorator — registers a function as a named detection rule."""
    def decorator(fn):
        RULES.append(Rule(
            name=name, description=description, severity=severity,
            reference=reference, tags=tags or [], _fn=fn,
        ))
        return fn
    return decorator


# ── Rules result ──────────────────────────────────────────────────────────────

@dataclass
class RulesResult:
    matches: List[RuleMatch] = field(default_factory=list)
    total_score: int         = 0
    highest_severity: str    = "NONE"

    def add(self, match: RuleMatch):
        self.matches.append(match)
        self.total_score += match.score
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
        if rank.get(match.severity, 0) > rank.get(self.highest_severity, 0):
            self.highest_severity = match.severity


# ════════════════════════════════════════════════════════════════════════════
# RULE DEFINITIONS
# Each function receives AnalysisContext and returns:
#   List[str]  — evidence lines if rule fires  (non-empty = MATCH)
#   []         — rule does not fire
# ════════════════════════════════════════════════════════════════════════════


@rule(
    name        = "CYBERHAVEN_BEHAVIOUR",
    description = (
        "Matches the supply-chain pattern used in the Dec 2024 Cyberhaven breach: "
        "extension silently fetches remote config/payload on install, holds session "
        "cookies, and exfiltrates them to an external C2 server."
    ),
    severity    = "CRITICAL",
    reference   = "https://cyberhaven.com/blog/cyberhavens-chrome-extension-security-incident",
    tags        = ["supply-chain", "cookie-theft", "remote-config", "c2"],
)
def _cyberhaven(ctx: AnalysisContext) -> List[str]:
    ev = []

    if ctx.host_is_wildcard():
        ev.append(f"host_permission: {ctx.host_permissions[0]} — unrestricted site access")

    if ctx.has_perm("cookies"):
        ev.append("permission: cookies — can read/write session cookies on any site")

    if ctx.has_remote_fetch_on_install:
        ev.append("remote_config: fetches external URL at install/startup time")

    if ctx.has_eval_of_remote_payload:
        ev.append("remote_config: fetched payload is executed via eval()")

    if ctx.has_confirmed_chain("COOKIE_THEFT"):
        ev.append("exfil_chain: COOKIE_THEFT confirmed — collect → serialize → transmit")

    sus = ctx.domains_match_tld(".ru", ".tk", ".xyz", ".top", ".pw")
    if sus:
        ev.append(f"network: external domain(s) on suspicious TLD: {', '.join(sus[:3])}")

    runtime_cookie = ctx.runtime_contacted("cookie", "session", "token")
    if runtime_cookie:
        ev.append(f"runtime: data containing 'cookie/session/token' sent to "
                  f"{runtime_cookie[0][:60]}")

    # Rule fires only when at least 4 distinct signals align
    return ev if len(ev) >= 4 else []


@rule(
    name        = "DOM_INJECTION_BEHAVIOUR",
    description = (
        "Extension injects scripts or overlays into web pages and hooks form/keyboard "
        "events — consistent with credential harvesting, phishing overlays, or "
        "form-jacking (stealing data before it's submitted)."
    ),
    severity    = "HIGH",
    reference   = "https://attack.mitre.org/techniques/T1185/",
    tags        = ["dom-injection", "form-jacking", "credential-theft", "keylogger"],
)
def _dom_injection(ctx: AnalysisContext) -> List[str]:
    ev = []

    form_hooks = [t for t in ctx.runtime_dom_hooks
                  if t in ("submit", "keydown", "keypress", "input", "change")]
    if form_hooks:
        ev.append(f"runtime: event listeners registered — {', '.join(set(form_hooks))}")

    if ctx.has_confirmed_chain("FORM_JACKER"):
        ev.append("exfil_chain: FORM_JACKER — intercepts form submit + steals field values")

    if ctx.has_confirmed_chain("KEYLOGGER"):
        ev.append("exfil_chain: KEYLOGGER — keystroke capture + remote transmit detected")

    if ctx.has_content_scripts and ctx.host_is_wildcard():
        ev.append("manifest: content_scripts injected into ALL websites")

    if ctx.has_api("chrome.tabs.captureVisibleTab"):
        ev.append("api: tabs.captureVisibleTab — takes screenshots of active tab")

    if ctx.exfil_transmit_hits > 0 and form_hooks:
        ev.append(f"combined: DOM hooks + {ctx.exfil_transmit_hits} transmit "
                  f"hit(s) = active data exfiltration")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "REALTIME_C2_BEHAVIOUR",
    description = (
        "Extension opens a persistent WebSocket connection to an external server "
        "and executes received messages via eval() — a live command-and-control "
        "channel that lets the attacker run arbitrary code in the browser at any time."
    ),
    severity    = "CRITICAL",
    reference   = "https://attack.mitre.org/techniques/T1095/",
    tags        = ["c2", "websocket", "remote-exec", "live-control"],
)
def _realtime_c2(ctx: AnalysisContext) -> List[str]:
    ev = []

    if ctx.has_websocket_c2:
        ev.append("source: WebSocket + eval() combination detected in JS source")

    ws_runtime = [u for u in ctx.runtime_urls if u.get("type") == "websocket"]
    for ws in ws_runtime[:3]:
        ev.append(f"runtime: WebSocket connected to {ws.get('url','?')[:80]}")

    if ctx.runtime_eval_calls:
        ev.append(f"runtime: {len(ctx.runtime_eval_calls)} eval() call(s) intercepted "
                  f"— '{ctx.runtime_eval_calls[0].get('code','')[:50]}'")

    sus_ws = [u for u in ws_runtime
              if ctx.domains_match_tld(".ru", ".tk", ".xyz", ".top")
              and any(d in u.get("url","") for d in ctx.domains_match_tld(".ru",".tk",".xyz",".top"))]
    if sus_ws:
        ev.append("combined: C2 WebSocket endpoint on suspicious TLD")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "PROXY_TRAFFIC_HIJACK",
    description = (
        "Extension declares the proxy permission and contacts external domains, "
        "suggesting it reroutes ALL browser traffic through an attacker-controlled "
        "server — enabling full traffic inspection, credential interception, and "
        "SSL stripping without the user knowing."
    ),
    severity    = "CRITICAL",
    reference   = "https://attack.mitre.org/techniques/T1090/",
    tags        = ["proxy", "mitm", "traffic-redirect"],
)
def _proxy_hijack(ctx: AnalysisContext) -> List[str]:
    ev = []

    if not ctx.has_perm("proxy"):
        return []

    ev.append("permission: proxy — can redirect ALL browser traffic externally")

    if ctx.external_domains:
        ev.append(f"network: {len(ctx.external_domains)} external domain(s) contacted "
                  f"— {', '.join(ctx.external_domains[:2])}")

    sus = ctx.domains_match_tld(".ru", ".cn", ".tk", ".xyz", ".top")
    if sus:
        ev.append(f"network: proxy target on suspicious TLD — {sus[0]}")

    if ctx.runtime_api_called("proxy"):
        ev.append("runtime: chrome.proxy.settings.set() called — proxy actively configured")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "OAUTH_TOKEN_THEFT",
    description = (
        "Extension calls chrome.identity.getAuthToken to obtain the user's "
        "Google OAuth token, then transmits it to an external server. "
        "Gives the attacker persistent access to Gmail, Drive, Calendar, "
        "and any other Google service the user is signed into."
    ),
    severity    = "CRITICAL",
    reference   = "https://attack.mitre.org/techniques/T1528/",
    tags        = ["oauth", "token-theft", "google-account"],
)
def _oauth_theft(ctx: AnalysisContext) -> List[str]:
    ev = []

    if not ctx.has_api("chrome.identity.getAuthToken",
                        "chrome.identity.launchWebAuthFlow"):
        return []

    ev.append("api: chrome.identity.getAuthToken — requests Google OAuth token")

    if ctx.runtime_api_called("identity"):
        ev.append("runtime: identity API actually called at runtime (not just defined)")

    if ctx.exfil_transmit_hits > 0:
        ev.append(f"exfil: {ctx.exfil_transmit_hits} outbound transmit hit(s) "
                  "— token likely sent externally")

    if ctx.external_domains:
        ev.append(f"network: token destination candidate — {ctx.external_domains[0]}")

    if ctx.has_confirmed_chain("OAUTH_THEFT"):
        ev.append("exfil_chain: OAUTH_THEFT confirmed end-to-end")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "SLEEPER_AGENT_BEHAVIOUR",
    description = (
        "Extension appears benign at install time but fetches and executes a "
        "remote payload after a delay — the classic 'sleeper agent' technique "
        "used to pass manual code review then activate malicious behavior later. "
        "Common in supply-chain attacks where an existing trusted extension is hijacked."
    ),
    severity    = "CRITICAL",
    reference   = "https://attack.mitre.org/techniques/T1027/",
    tags        = ["sleeper", "supply-chain", "remote-exec", "obfuscation"],
)
def _sleeper_agent(ctx: AnalysisContext) -> List[str]:
    ev = []

    if ctx.has_polling_fetch:
        ev.append("remote_config: periodic fetch detected (setInterval/setTimeout + fetch) "
                  "— polls for updated instructions")

    if ctx.has_eval_of_remote_payload:
        ev.append("remote_config: fetched remote data is executed via eval()")

    if ctx.has_base64_exec:
        ev.append("source: eval(atob(...)) — base64 payload decoded and executed at runtime")

    if ctx.has_obfuscation:
        ev.append(f"obfuscation: {ctx.obfuscation_verdict} — code hidden from static review")

    if "unsafe-stmt" in ctx.sast_kinds and "encoded-literal" in ctx.sast_kinds:
        ev.append("sast: JS-X-Ray flagged BOTH unsafe-stmt AND encoded-literal "
                  "— combined obfuscated execution signal")

    if ctx.runtime_eval_calls:
        decoded = ctx.runtime_eval_calls[0].get("code", "")
        ev.append(f"runtime: eval() fired — decoded payload: '{decoded[:60]}'")

    return ev if len(ev) >= 3 else []


@rule(
    name        = "MASS_DATA_HARVESTER",
    description = (
        "Extension combines multiple data-collection permissions (history, bookmarks, "
        "cookies, clipboard, identity) to build a comprehensive profile of the user. "
        "Consistent with commercial spyware, stalkerware, or nation-state collection."
    ),
    severity    = "HIGH",
    reference   = "https://attack.mitre.org/tactics/TA0009/",
    tags        = ["spyware", "surveillance", "data-collection"],
)
def _mass_harvester(ctx: AnalysisContext) -> List[str]:
    ev = []

    harvest_perms = [p for p in ctx.permissions
                     if p in ("history", "bookmarks", "cookies", "clipboardRead",
                               "tabs", "identity", "topSites", "browsingData")]
    if len(harvest_perms) >= 3:
        ev.append(f"permissions: {len(harvest_perms)} data-collection perms declared — "
                  f"{', '.join(harvest_perms)}")

    harvest_apis = [a for a in ctx.detected_apis
                    if any(x in a for x in ("history", "bookmarks", "cookies",
                                             "clipboard", "identity", "topSites"))]
    if len(harvest_apis) >= 2:
        ev.append(f"apis: {len(harvest_apis)} harvest APIs in source — "
                  f"{', '.join(harvest_apis[:3])}")

    if ctx.exfil_transmit_hits > 0 and len(harvest_perms) >= 3:
        ev.append(f"exfil: outbound transmit hit(s) present alongside harvest permissions")

    if ctx.external_domains:
        ev.append(f"network: collected data likely sent to {ctx.external_domains[0]}")

    return ev if len(ev) >= 3 else []


@rule(
    name        = "EXTENSION_MANAGEMENT_ABUSE",
    description = (
        "Extension uses the management API to disable or uninstall other extensions. "
        "Attackers use this to silence security tools, ad blockers, or competing "
        "extensions — and to ensure their own extension survives cleanup attempts."
    ),
    severity    = "HIGH",
    reference   = "https://attack.mitre.org/techniques/T1562/",
    tags        = ["defense-evasion", "persistence", "management"],
)
def _management_abuse(ctx: AnalysisContext) -> List[str]:
    ev = []

    if not ctx.has_perm("management"):
        return []

    ev.append("permission: management — can enable, disable, or uninstall other extensions")

    if ctx.has_api("chrome.management.setEnabled", "chrome.management.uninstall"):
        ev.append("api: management.setEnabled/uninstall found in source")

    if ctx.runtime_api_called("management.setEnabled", "management.uninstall"):
        ev.append("runtime: management API actually called at runtime")

    if ctx.has_perm("storage"):
        ev.append("combined: management + storage = can persist state and survive removal")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "NATIVE_MESSAGING_DROPPER",
    description = (
        "Extension communicates with a locally installed native binary via "
        "nativeMessaging, combined with downloads permission. This is a classic "
        "dropper pattern: extension fetches a payload from the internet, passes "
        "it to a native app, which executes it outside the browser sandbox."
    ),
    severity    = "CRITICAL",
    reference   = "https://attack.mitre.org/techniques/T1105/",
    tags        = ["dropper", "native-messaging", "persistence", "out-of-sandbox"],
)
def _native_dropper(ctx: AnalysisContext) -> List[str]:
    ev = []

    if not ctx.has_perm("nativeMessaging"):
        return []

    ev.append("permission: nativeMessaging — direct channel to native desktop binary")

    if ctx.has_perm("downloads"):
        ev.append("permission: downloads — can write arbitrary files to disk")

    if ctx.has_api("chrome.runtime.connectNative", "chrome.runtime.sendNativeMessage"):
        ev.append("api: connectNative/sendNativeMessage found in source")

    if ctx.external_domains:
        ev.append(f"network: fetches from {len(ctx.external_domains)} external domain(s) "
                  "— likely retrieves payload before passing to native app")

    if "Run" in ctx.boxjs_ioc_types:
        ev.append("boxjs: shell command execution detected via Box.js emulation")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "SUSPICIOUS_TLD_EXFIL",
    description = (
        "Extension contacts domains on TLDs commonly abused for malicious "
        "infrastructure (.ru, .tk, .xyz, .top, etc.) AND has data-collection "
        "or transmission signals. Elevated confidence when runtime contact is confirmed."
    ),
    severity    = "HIGH",
    reference   = "https://unit42.paloaltonetworks.com/top-level-domains-cybercrime/",
    tags        = ["c2", "exfil", "suspicious-infrastructure"],
)
def _suspicious_tld_exfil(ctx: AnalysisContext) -> List[str]:
    ev = []

    sus_tlds = (".ru", ".tk", ".xyz", ".top", ".pw", ".gq", ".ml", ".cf", ".ga", ".icu")
    sus_domains = ctx.domains_match_tld(*sus_tlds)
    if not sus_domains:
        return []

    ev.append(f"network: {len(sus_domains)} domain(s) on suspicious TLD — "
              f"{', '.join(sus_domains[:3])}")

    # Rule only fires when ALSO paired with data access or exfil signals
    if ctx.has_perm("cookies") or ctx.has_api("chrome.cookies.getAll"):
        ev.append("combined: cookie access + suspicious-TLD contact = high-confidence theft")

    runtime_sus = ctx.runtime_contacted_pattern(
        "|".join(re.escape(d) for d in sus_domains[:5])
    )
    if runtime_sus:
        ev.append(f"runtime: {len(runtime_sus)} actual connection(s) to suspicious TLD confirmed")

    if ctx.exfil_transmit_hits > 0:
        ev.append(f"exfil: {ctx.exfil_transmit_hits} outbound transmit hit(s) paired with sus TLD")

    return ev if len(ev) >= 2 else []


@rule(
    name        = "SCREEN_CAPTURE_SURVEILLANCE",
    description = (
        "Extension captures screenshots, tab streams, or full page content. "
        "When combined with external domain contact this indicates covert "
        "visual surveillance — consistent with stalkerware or corporate espionage."
    ),
    severity    = "HIGH",
    reference   = "https://attack.mitre.org/techniques/T1113/",
    tags        = ["surveillance", "screen-capture", "stalkerware"],
)
def _screen_capture(ctx: AnalysisContext) -> List[str]:
    ev = []

    cap_perms = [p for p in ("desktopCapture", "tabCapture", "pageCapture")
                 if ctx.has_perm(p)]
    if cap_perms:
        ev.append(f"permissions: {', '.join(cap_perms)} — visual capture capability")

    cap_apis = [a for a in ctx.detected_apis
                if any(x in a for x in ("captureVisibleTab", "desktopCapture",
                                         "tabCapture", "pageCapture"))]
    if cap_apis:
        ev.append(f"apis: {', '.join(cap_apis)} found in source")

    if ctx.runtime_api_called("captureVisibleTab", "desktopCapture", "tabCapture"):
        ev.append("runtime: capture API actually called during sandbox execution")

    if ctx.external_domains and (cap_perms or cap_apis):
        ev.append(f"network: captured data likely sent to {ctx.external_domains[0]}")

    return ev if len(ev) >= 2 else []


# ── Context builder ───────────────────────────────────────────────────────────

def build_context(
    manifest:       dict,
    perm_result,
    api_result,
    net_result,
    rc_result,
    dyn_result,
    exfil_result,
    sandbox_result,
) -> AnalysisContext:
    """Build a flat AnalysisContext from all analyzer result objects."""

    # Content scripts
    cs_matches = []
    for cs in manifest.get("content_scripts", []):
        cs_matches.extend(cs.get("matches", []))

    # Detected APIs (unique names)
    detected_apis = list({f.api for f in api_result.findings})

    # Remote config signals
    rc_reasons = [f.reason for f in rc_result.findings]
    has_remote_fetch  = any("install" in r.lower() or "startup" in r.lower()
                            for r in rc_reasons)
    has_eval_remote   = any("eval" in r.lower() and ("fetch" in r.lower() or
                             "remote" in r.lower()) for r in rc_reasons)
    has_ws_c2         = any("WebSocket" in r for r in rc_reasons)
    has_polling       = any("periodic" in r.lower() or "setInterval" in r.lower()
                            for r in rc_reasons)

    # Exfil chains
    named_chains = list({f.chain_type for f in exfil_result.findings
                         if f.stage == "full_chain"})
    collect_hits = sum(1 for f in exfil_result.findings if f.stage == "collect")
    transmit_hits= sum(1 for f in exfil_result.findings if f.stage == "transmit")

    # Dynamic exec signals
    has_eval    = any("eval" in f.technique.lower() for f in dyn_result.findings)
    has_b64_exec= any("atob" in f.technique.lower() for f in dyn_result.findings)
    has_obf     = dyn_result.obfuscation_verdict != "Clean"

    # Sandbox signals
    sast_kinds = set()
    dom_hooks  = []
    for fr in sandbox_result.file_results:
        for w in fr.jsxray.warnings:
            sast_kinds.add(w.get("kind", ""))
        for op in fr.mjail.dom_ops:
            if op.get("type"):
                dom_hooks.append(op["type"])

    runtime_apis = [c.get("api", "") for c in sandbox_result.all_chrome_api_calls]
    boxjs_types  = [ioc.get("type", "") for ioc in sandbox_result.all_iocs]

    return AnalysisContext(
        extension_name        = manifest.get("name", ""),
        manifest_version      = manifest.get("manifest_version", 3),
        permissions           = perm_result.permissions,
        host_permissions      = perm_result.host_permissions,
        has_content_scripts   = bool(manifest.get("content_scripts")),
        content_script_matches= cs_matches,
        has_background        = bool(manifest.get("background")),

        perm_score            = perm_result.total_score,
        dangerous_perm_combos = [f.name for f in perm_result.combo_findings],

        detected_apis         = detected_apis,

        external_domains      = [f.domain for f in net_result.findings],
        domain_categories     = {f.domain: f.category for f in net_result.findings},

        has_remote_fetch_on_install = has_remote_fetch,
        has_eval_of_remote_payload  = has_eval_remote,
        has_websocket_c2            = has_ws_c2,
        has_polling_fetch           = has_polling,
        remote_config_patterns      = rc_reasons,

        has_eval              = has_eval,
        has_base64_exec       = has_b64_exec,
        has_obfuscation       = has_obf,
        obfuscation_verdict   = dyn_result.obfuscation_verdict,

        confirmed_chains      = named_chains,
        exfil_collect_hits    = collect_hits,
        exfil_transmit_hits   = transmit_hits,

        runtime_urls          = sandbox_result.all_urls,
        runtime_eval_calls    = sandbox_result.all_eval_calls,
        runtime_chrome_apis   = runtime_apis,
        runtime_dom_hooks     = dom_hooks,

        sast_kinds            = sast_kinds,
        boxjs_ioc_types       = boxjs_types,
    )


# ── Engine entry point ────────────────────────────────────────────────────────

def evaluate(ctx: AnalysisContext) -> RulesResult:
    """Run all registered rules against the context. Returns matched results."""
    result = RulesResult()
    for r in RULES:
        match = r.evaluate(ctx)
        if match:
            result.add(match)
    return result
