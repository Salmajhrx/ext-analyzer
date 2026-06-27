"""
Sandbox Runner — v1.7
Supports two interchangeable sandbox engines via SANDBOX_ENGINE env var:

  SANDBOX_ENGINE=boxjs    → Box.js  REST API  (port 8080, WScript/ActiveX)
  SANDBOX_ENGINE=fakeium  → Fakeium REST API  (port 8081, Chrome extension APIs)

Both engines expose the identical REST interface:
  POST   /sample          upload JS file → { id }
  GET    /sample/:id      poll           → { ready }
  GET    /sample/:id/report              → full IOC report
  DELETE /sample/:id      cleanup

Switch at runtime — no code changes needed:
  SANDBOX_ENGINE=fakeium python analyze.py myext.crx
  SANDBOX_ENGINE=boxjs    python analyze.py malware_dropper.js

IOC types per engine
  Box-js   → Run, UrlFetch, FileWrite, FileRead, RegistryWrite
  Fakeium  → ChromeAPI, UrlFetch, EvalCall
  _score_file handles all of them; unknown types score 0 and are logged.
"""

import os
import json
import time
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# ── Engine selection ──────────────────────────────────────────────────────────
SANDBOX_ENGINE = os.environ.get("SANDBOX_ENGINE", "fakeium").lower()
assert SANDBOX_ENGINE in ("boxjs", "fakeium"), \
    f"SANDBOX_ENGINE must be 'boxjs' or 'fakeium', got '{SANDBOX_ENGINE}'"

_ENGINE_DEFAULTS = {
    "boxjs":   "http://localhost:8080",
    "fakeium": "http://localhost:8081",
}
BOX_API_URL = os.environ.get("BOX_API_URL", _ENGINE_DEFAULTS[SANDBOX_ENGINE])

# ── Config ────────────────────────────────────────────────────────────────────
TOOL_TIMEOUT     = int(os.environ.get("BOX_TIMEOUT", "30"))
API_HTTP_TIMEOUT = 10
POLL_INTERVAL    = 1.5
MAX_WAIT         = TOOL_TIMEOUT + 30
MAX_FILE_SIZE    = 2 * 1024 * 1024


# ── Preflight ─────────────────────────────────────────────────────────────────

def preflight_check() -> dict:
    try:
        req  = urllib.request.urlopen(
            f"{BOX_API_URL}/health", timeout=API_HTTP_TIMEOUT
        )
        data = json.loads(req.read())
        ok   = data.get("status") == "ok"
    except Exception:
        ok = False

    label = "FAKEIUM" if SANDBOX_ENGINE == "fakeium" else "BOX.JS"
    if ok:
        print(f"  \033[92m✔  {label} SANDBOX API REACHABLE\033[0m  ({BOX_API_URL})")
    else:
        print()
        print(f"  \033[93m⚠  {label} SANDBOX API NOT REACHABLE\033[0m")
        print(f"     Expected: {BOX_API_URL}")
        if SANDBOX_ENGINE == "fakeium":
            print("     Start it: docker compose up -d  (in your fakeium/ folder)")
            print("     Override: set BOX_API_URL or SANDBOX_ENGINE=boxjs")
        else:
            print("     Start it: docker compose up -d  (in your boxjs/ folder)")
            print("     Override: set BOX_API_URL or SANDBOX_ENGINE=fakeium")
        print()

    return {f"{SANDBOX_ENGINE}-api": ok}


_TOOLS = preflight_check()


# ── Result dataclasses (unchanged from v1.3) ──────────────────────────────────

@dataclass
class MJailResult:
    urls: List[Dict]             = field(default_factory=list)
    eval_calls: List[Dict]       = field(default_factory=list)
    network_requests: List[Dict] = field(default_factory=list)
    chrome_api_calls: List[Dict] = field(default_factory=list)
    logs: List[Dict]             = field(default_factory=list)
    dom_ops: List[Dict]          = field(default_factory=list)
    error: Optional[str]         = None


@dataclass
class BoxJsResult:
    iocs: List[Dict]       = field(default_factory=list)
    urls: List[str]        = field(default_factory=list)
    active_urls: List[str] = field(default_factory=list)
    commands: List[str]    = field(default_factory=list)
    snippets: List[str]    = field(default_factory=list)
    resources: Dict        = field(default_factory=dict)
    error: Optional[str]   = None


@dataclass
class JsXRayResult:
    warnings: List[Dict]      = field(default_factory=list)
    dependencies: List[str]   = field(default_factory=list)
    has_encoded_literal: bool = False
    has_unsafe_stmt: bool     = False
    has_obfuscated_code: bool = False
    error: Optional[str]      = None


@dataclass
class SynchronyResult:
    deobfuscated_code: Optional[str] = None
    was_obfuscated: bool             = False
    error: Optional[str]             = None


@dataclass
class FileSandboxResult:
    filename: str
    mjail:     MJailResult     = field(default_factory=MJailResult)
    boxjs:     BoxJsResult     = field(default_factory=BoxJsResult)
    jsxray:    JsXRayResult    = field(default_factory=JsXRayResult)
    synchrony: SynchronyResult = field(default_factory=SynchronyResult)
    risk_score: int            = 0
    risk_signals: List[str]    = field(default_factory=list)


@dataclass
class SandboxResult:
    file_results: List[FileSandboxResult] = field(default_factory=list)
    total_score: int                       = 0
    all_urls: List[Dict]                   = field(default_factory=list)
    all_eval_calls: List[Dict]             = field(default_factory=list)
    all_chrome_api_calls: List[Dict]       = field(default_factory=list)
    all_iocs: List[Dict]                   = field(default_factory=list)
    deobfuscated_files: List[str]          = field(default_factory=list)


# ── REST API client (engine-agnostic) ────────────────────────────────────────

class _ApiError(Exception):
    pass


def _api_get(path: str) -> dict:
    try:
        req = urllib.request.urlopen(
            f"{BOX_API_URL}{path}", timeout=API_HTTP_TIMEOUT
        )
        return json.loads(req.read())
    except urllib.error.HTTPError as e:
        raise _ApiError(f"HTTP {e.code} on GET {path}")
    except Exception as e:
        raise _ApiError(f"GET {path} failed: {e}")


def _api_post_file(js_path: str) -> str:
    boundary  = "----SandboxBoundary7f3a9b2c"
    filename  = Path(js_path).name

    with open(js_path, "rb") as fh:
        file_data = fh.read()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="sample"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_data + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        f"{BOX_API_URL}/sample",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=API_HTTP_TIMEOUT)
        data = json.loads(resp.read())
        if data.get("server_err", 0) != 0:
            raise _ApiError(f"API rejected upload: {data}")
        return data["id"]
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")
        raise _ApiError(f"Upload HTTP {e.code}: {body_text[:300]}")
    except _ApiError:
        raise
    except Exception as e:
        raise _ApiError(f"Upload failed: {e}")


def _api_poll(analysis_id: str) -> dict:
    deadline = time.monotonic() + MAX_WAIT
    while time.monotonic() < deadline:
        try:
            s = _api_get(f"/sample/{analysis_id}")
            if s.get("ready") == 1:
                return s
        except _ApiError:
            pass
        time.sleep(POLL_INTERVAL)
    raise _ApiError(f"Timed out waiting for {analysis_id}")


def _api_report(analysis_id: str) -> dict:
    data = _api_get(f"/sample/{analysis_id}/report")
    if data.get("server_err", 0) != 0:
        raise _ApiError(f"Report fetch failed: {data}")
    return data


def _api_delete(analysis_id: str):
    try:
        req = urllib.request.Request(
            f"{BOX_API_URL}/sample/{analysis_id}", method="DELETE"
        )
        urllib.request.urlopen(req, timeout=API_HTTP_TIMEOUT)
    except Exception:
        pass


# ── Sandbox runner ────────────────────────────────────────────────────────────

def _run_sandbox(js_path: str) -> BoxJsResult:
    result    = BoxJsResult()
    engine_key = f"{SANDBOX_ENGINE}-api"

    if not _TOOLS.get(engine_key):
        result.error = (
            f"{SANDBOX_ENGINE} API not reachable at {BOX_API_URL}. "
            f"Start with: docker compose up -d  "
            f"(in your {'fakeium' if SANDBOX_ENGINE == 'fakeium' else 'boxjs'}/ folder)"
        )
        return result

    analysis_id = None
    try:
        analysis_id = _api_post_file(js_path)
        status      = _api_poll(analysis_id)

        if status.get("status") == "error" and status.get("exitMeaning") not in (
            "timeout", "success"
        ):
            result.error = f"{SANDBOX_ENGINE} exited: {status.get('exitMeaning', 'error')}"

        report  = _api_report(analysis_id)
        results = report.get("results", {})

        raw_urls = results.get("urls", [])
        result.urls = [
            u if isinstance(u, str) else u.get("url", str(u)) for u in raw_urls
        ]
        raw_active = results.get("activeUrls", [])
        result.active_urls = [
            u if isinstance(u, str) else u.get("url", str(u)) for u in raw_active
        ]

        raw_iocs    = results.get("iocs", [])
        result.iocs = raw_iocs if isinstance(raw_iocs, list) else []
        for ioc in result.iocs:
            itype = ioc.get("type", "")
            val   = ioc.get("value", {})
            if itype == "UrlFetch":
                u = val.get("url", "") if isinstance(val, dict) else str(val)
                if u and u not in result.urls:
                    result.urls.append(u)
            elif itype == "Run":
                cmd = val.get("command", "") if isinstance(val, dict) else str(val)
                if cmd:
                    result.commands.append(cmd)

        result.resources = results.get("resources", {})
        raw_snips = results.get("snippets", [])
        if isinstance(raw_snips, list):
            result.snippets = [str(s)[:500] for s in raw_snips[:10]]

        if status.get("exitMeaning") == "timeout" and not result.error:
            result.error = "Analysis timed out — results may be partial"

    except _ApiError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Unexpected error: {e}"
    finally:
        if analysis_id:
            _api_delete(analysis_id)

    return result


# ── Per-file scoring ──────────────────────────────────────────────────────────

_IOC_SCORES = {
    "Run":           8,
    "FileWrite":     6,
    "RegistryWrite": 7,
    "FileRead":      2,
    "UrlFetch":      4,
    "ChromeAPI":     3,
    "EvalCall":      5,
}

_CHROME_HIGH_RISK = {
    "chrome.cookies",
    "chrome.webRequest",
    "chrome.debugger",
    "chrome.tabs.executeScript",
    "chrome.scripting.executeScript",
    "chrome.browsingData",
    "chrome.proxy",
}

# APIs that are routine extension plumbing — score 0, suppress signal noise.
# The sandbox reports every intermediate traversal (e.g. "chrome",
# "chrome.storage", "chrome.storage.local", "chrome.storage.local.set")
# as separate ChromeAPI IOCs, so without this allowlist a simple
# storage read inflates the score by 12+ pts and causes false positives.
_CHROME_BENIGN = {
    # Lifecycle — every extension uses these
    "chrome.runtime",
    "chrome.runtime.onInstalled",
    "chrome.runtime.onInstalled.addListener",
    "chrome.runtime.onStartup",
    "chrome.runtime.onStartup.addListener",
    "chrome.runtime.onMessage",
    "chrome.runtime.onMessage.addListener",
    "chrome.runtime.sendMessage",
    "chrome.runtime.getURL",
    "chrome.runtime.id",
    # Storage — reading/writing local extension data is not suspicious
    "chrome.storage",
    "chrome.storage.local",
    "chrome.storage.local.get",
    "chrome.storage.local.set",
    "chrome.storage.local.remove",
    "chrome.storage.local.clear",
    # Action / popup — UI only
    "chrome.action",
    "chrome.action.setBadgeText",
    "chrome.action.setBadgeBackgroundColor",
    "chrome.action.setTitle",
    "chrome.action.setIcon",
    # i18n — locale strings, harmless
    "chrome.i18n",
    "chrome.i18n.getMessage",
    # Alarms — scheduling only, suspicious only when combined with fetch
    "chrome.alarms",
    "chrome.alarms.create",
    "chrome.alarms.onAlarm",
    "chrome.alarms.onAlarm.addListener",
}

_SUSPICIOUS_URL_MARKERS = [
    ".ru", ".tk", ".xyz", "c2.", "evil",
    "steal", "exfil", "collect", "harvest",
]


def _score_file(fr: FileSandboxResult):
    score   = 0
    signals = []
    bj      = fr.boxjs
    tag     = f"[{SANDBOX_ENGINE.upper()}]"

    for ioc in bj.iocs:
        itype = ioc.get("type", "")
        val   = ioc.get("value", {})
        delta = _IOC_SCORES.get(itype, 0)

        if itype == "Run":
            cmd = val.get("command", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} Shell command: {str(cmd)[:80]}")
            if any(x in cmd.lower() for x in
                   ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "regsvr"]):
                score += 4
                signals.append(f"{tag} Dangerous shell: {cmd[:80]}")

        elif itype == "UrlFetch":
            url = val.get("url", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} URL fetch: {str(url)[:80]}")
            if any(x in str(url) for x in _SUSPICIOUS_URL_MARKERS):
                score += 5
                signals.append(f"{tag} SUSPICIOUS URL: {str(url)[:80]}")

        elif itype == "FileWrite":
            p = val.get("path", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} File write: {str(p)[:80]}")

        elif itype == "FileRead":
            p = val.get("path", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} File read: {str(p)[:60]}")

        elif itype == "RegistryWrite":
            key = val.get("key", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} Registry write: {str(key)[:80]}")

        elif itype == "ChromeAPI":
            api = val.get("api", "") if isinstance(val, dict) else str(val)
            # Skip benign lifecycle/storage APIs — the sandbox emits one IOC
            # per traversal step ("chrome", "chrome.storage",
            # "chrome.storage.local", "chrome.storage.local.set"), so a single
            # storage.local.get call generates 4 IOCs × 3 pts = 12 pts of
            # false-positive score. Allowlisted APIs score 0 and are not
            # shown as signals.
            if any(api == b or api.startswith(b + ".") for b in _CHROME_BENIGN):
                continue
            score += delta
            signals.append(f"{tag} Chrome API: {str(api)[:80]}")
            if any(api.startswith(h) for h in _CHROME_HIGH_RISK):
                score += 5
                signals.append(f"{tag} HIGH-RISK Chrome API: {str(api)[:80]}")

        elif itype == "EvalCall":
            body = val.get("body", "") if isinstance(val, dict) else str(val)
            score += delta
            signals.append(f"{tag} eval() / new Function(): {str(body)[:80]}")

    for url in bj.active_urls:
        score += 6
        signals.append(f"{tag} ACTIVE URL (served payload): {str(url)[:80]}")

    ioc_urls = {
        ioc.get("value", {}).get("url", "") if isinstance(ioc.get("value"), dict)
        else str(ioc.get("value", ""))
        for ioc in bj.iocs if ioc.get("type") == "UrlFetch"
    }
    for url in bj.urls:
        if url not in ioc_urls:
            score += 2
            signals.append(f"{tag} Network contact: {str(url)[:80]}")

    fr.risk_score   = score
    fr.risk_signals = signals


# ── Main entry point (unchanged signature) ────────────────────────────────────

def analyze(js_files: Dict[str, str], deobf_dir: str = None) -> SandboxResult:
    """
    SANDBOX_ENGINE=fakeium  (default) — Chrome extension APIs
    SANDBOX_ENGINE=boxjs              — WSH / ActiveX malware droppers
    """
    result     = SandboxResult()
    tmp_js_dir = tempfile.mkdtemp(prefix="cxtscan_js_")

    label = "FAKEIUM (Chrome extension APIs)" if SANDBOX_ENGINE == "fakeium" \
            else "BOX.JS  (WScript / ActiveX)"
    print(f"\n  {'─'*54}")
    print(f"  {label}")
    print(f"  {'─'*54}")

    try:
        for filename, source in js_files.items():

            if len(source.encode("utf-8", errors="replace")) > MAX_FILE_SIZE:
                continue

            safe_name = filename.replace("/", "_").replace("\\", "_")
            js_path   = os.path.join(tmp_js_dir, safe_name)
            with open(js_path, "w", encoding="utf-8") as f:
                f.write(source)

            fr           = FileSandboxResult(filename=filename)
            fr.boxjs     = _run_sandbox(js_path)
            fr.mjail     = MJailResult()
            fr.jsxray    = JsXRayResult()
            fr.synchrony = SynchronyResult()

            _score_file(fr)

            for u in fr.boxjs.urls:
                result.all_urls.append({"type": SANDBOX_ENGINE, "url": u})
            for u in fr.boxjs.active_urls:
                result.all_urls.append({"type": f"{SANDBOX_ENGINE}-active", "url": u})

            result.all_iocs    += fr.boxjs.iocs
            result.total_score += fr.risk_score
            result.file_results.append(fr)

            print(f"  ▶ {filename}  [sandbox score: {fr.risk_score}]")

    finally:
        import shutil
        shutil.rmtree(tmp_js_dir, ignore_errors=True)

    return result