"""
Terminal Reporter
Renders analysis results with color-coded risk output.
"""
import json
import os
from datetime import datetime
from typing import Optional


# Try colorama for cross-platform color support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _NoColor:
        def __getattr__(self, name):
            return ""

    Fore = _NoColor()
    Back = _NoColor()
    Style = _NoColor()


def _risk_color(score: int) -> str:
    if score >= 8:
        return Fore.RED + Style.BRIGHT
    elif score >= 6:
        return Fore.RED
    elif score >= 4:
        return Fore.YELLOW
    elif score >= 2:
        return Fore.CYAN
    return Fore.GREEN


def _verdict_color(verdict: str) -> str:
    colors = {
        "MALICIOUS":    Fore.RED + Style.BRIGHT,
        "HIGH RISK":    Fore.RED,
        "SUSPICIOUS":   Fore.YELLOW + Style.BRIGHT,
        "LOW RISK":     Fore.CYAN,
        "SAFE":         Fore.GREEN,
    }
    for key, color in colors.items():
        if key in verdict.upper():
            return color
    return Fore.WHITE


def _score_bar(score: int, max_score: int = 100, width: int = 30) -> str:
    filled = int((score / max_score) * width)
    filled = min(filled, width)
    bar = "█" * filled + "░" * (width - filled)
    color = _risk_color(score // 10 if max_score >= 100 else score)
    return f"{color}[{bar}]{Style.RESET_ALL} {score}"


def _section_header(title: str, icon: str = ""):
    width = 68
    line = "─" * width
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{line}")
    print(f"  {icon}  {title}")
    print(f"{line}{Style.RESET_ALL}")


def _risk_badge(score: int) -> str:
    color = _risk_color(score)
    return f"{color}[{score:2d}/10]{Style.RESET_ALL}"


def print_banner():
    banner = r"""
  ██████╗ ██╗  ██╗████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
 ██╔════╝ ╚██╗██╔╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
 ██║       ╚███╔╝    ██║       ███████╗██║     ███████║██╔██╗██║
 ██║       ██╔██╗    ██║       ╚════██║██║     ██╔══██║██║╚████║
 ╚██████╗ ██╔╝╚██╗   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
    """
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(f"  {Fore.WHITE}Chrome Extension Security Analyzer  {Fore.CYAN}v1.0  {Fore.YELLOW}Mode 1: Pre-Install")
    print(f"  {Fore.WHITE}{'─' * 60}{Style.RESET_ALL}\n")


def print_extension_info(manifest: dict, source: str, js_count: int):
    _section_header("EXTENSION OVERVIEW", "📦")
    name = manifest.get("name", "Unknown")
    version = manifest.get("version", "?")
    mv = manifest.get("manifest_version", "?")
    desc = manifest.get("description", "")[:80]

    print(f"  {Fore.WHITE}Name:{Style.RESET_ALL}              {Fore.YELLOW}{name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Version:{Style.RESET_ALL}           {version}")
    print(f"  {Fore.WHITE}Manifest Version:{Style.RESET_ALL}  MV{mv}")
    if desc:
        print(f"  {Fore.WHITE}Description:{Style.RESET_ALL}       {desc}")
    print(f"  {Fore.WHITE}Source:{Style.RESET_ALL}            {source}")
    print(f"  {Fore.WHITE}JS Files Scanned:{Style.RESET_ALL}  {js_count}")
    if mv == 2:
        print(f"  {Fore.YELLOW}⚠  MV2 extension — older format with broader permissions model{Style.RESET_ALL}")


def print_permission_results(result):
    from analyzers.permissions import PermissionResult
    _section_header("PERMISSION ANALYSIS", "🔐")

    if result.permissions:
        print(f"  {Fore.WHITE}Declared permissions:{Style.RESET_ALL} {', '.join(result.permissions)}")
    if result.host_permissions:
        print(f"  {Fore.WHITE}Host permissions:{Style.RESET_ALL}     {', '.join(result.host_permissions[:5])}")
        if len(result.host_permissions) > 5:
            print(f"                        ... and {len(result.host_permissions) - 5} more")

    print()
    if result.findings:
        print(f"  {Fore.WHITE}Dangerous permissions:{Style.RESET_ALL}")
        for f in sorted(result.findings, key=lambda x: -x.risk_score):
            print(f"    {_risk_badge(f.risk_score)}  {Fore.YELLOW}{f.name:<30}{Style.RESET_ALL} {f.reason}")

    if result.host_findings:
        print(f"\n  {Fore.WHITE}Host permission risks:{Style.RESET_ALL}")
        for f in sorted(result.host_findings, key=lambda x: -x.risk_score)[:5]:
            print(f"    {_risk_badge(f.risk_score)}  {Fore.YELLOW}{f.name:<40}{Style.RESET_ALL}")
            print(f"            {Fore.WHITE}{f.reason}{Style.RESET_ALL}")

    if result.combo_findings:
        print(f"\n  {Fore.RED + Style.BRIGHT}⚡ DANGEROUS PERMISSION COMBINATIONS:{Style.RESET_ALL}")
        for f in sorted(result.combo_findings, key=lambda x: -x.risk_score):
            print(f"    {_risk_badge(f.risk_score)}  {Fore.RED}{f.name}{Style.RESET_ALL}")
            print(f"            {f.reason}")

    print(f"\n  Permission Risk Score: {_score_bar(result.total_score, 100)}")


def print_api_results(result):
    _section_header("SENSITIVE API USAGE", "🔌")
    if not result.findings:
        print(f"  {Fore.GREEN}✓ No sensitive API calls detected{Style.RESET_ALL}")
        return

    print(f"  Found {len(result.findings)} sensitive API calls across {result.files_scanned} file(s)\n")

    # Group by API
    by_api = {}
    for f in result.findings:
        if f.api not in by_api:
            by_api[f.api] = f
    
    for api, finding in sorted(by_api.items(), key=lambda x: -x[1].risk_score)[:15]:
        print(f"    {_risk_badge(finding.risk_score)}  {Fore.YELLOW}{finding.api:<45}{Style.RESET_ALL}")
        print(f"            {finding.reason}")
        print(f"            {Fore.WHITE}→ {finding.file}:{finding.line_number}{Style.RESET_ALL}")
        print(f"            {Fore.CYAN}{finding.line_snippet[:100]}{Style.RESET_ALL}\n")

    print(f"  API Risk Score: {_score_bar(result.total_score, 100)}")


def print_network_results(result):
    _section_header("EXTERNAL DOMAIN COMMUNICATION", "🌐")
    if not result.findings:
        print(f"  {Fore.GREEN}✓ No suspicious external domains detected{Style.RESET_ALL}")
        return

    print(f"  Unique external domains: {len(result.unique_domains)}\n")

    seen_domains = set()
    for f in sorted(result.findings, key=lambda x: -x.risk_score):
        if f.domain in seen_domains:
            continue
        seen_domains.add(f.domain)
        print(f"    {_risk_badge(f.risk_score)}  {Fore.YELLOW}{f.domain:<45}{Style.RESET_ALL} [{f.category}]")
        print(f"            {f.reason}")
        print(f"            {Fore.CYAN}{f.url[:90]}{Style.RESET_ALL}")
        print(f"            {Fore.WHITE}→ {f.file}:{f.line_number}{Style.RESET_ALL}\n")

    print(f"  Network Risk Score: {_score_bar(result.total_score, 100)}")


def print_remote_config_results(result):
    _section_header("REMOTE CONFIGURATION DETECTION", "☁️")
    if not result.findings:
        print(f"  {Fore.GREEN}✓ No remote configuration patterns detected{Style.RESET_ALL}")
        return

    seen = set()
    for f in sorted(result.findings, key=lambda x: -x.risk_score):
        key = f.pattern_name
        if key in seen:
            continue
        seen.add(key)
        print(f"    {_risk_badge(f.risk_score)}  {Fore.YELLOW}{f.reason}{Style.RESET_ALL}")
        print(f"            {Fore.WHITE}→ {f.file}:{f.line_number}{Style.RESET_ALL}")
        print(f"            {Fore.CYAN}{f.line_snippet[:100]}{Style.RESET_ALL}\n")

    print(f"  Remote Config Risk Score: {_score_bar(result.total_score, 100)}")


def print_dynexec_results(result):
    _section_header("DYNAMIC EXECUTION & OBFUSCATION", "🎭")

    # Obfuscation verdict
    obf_colors = {
        "HEAVILY OBFUSCATED": Fore.RED + Style.BRIGHT,
        "Likely Obfuscated": Fore.RED,
        "Possibly Obfuscated": Fore.YELLOW,
        "Clean": Fore.GREEN,
    }
    color = obf_colors.get(result.obfuscation_verdict, Fore.WHITE)
    print(f"  Obfuscation Analysis: {color}{result.obfuscation_verdict}{Style.RESET_ALL} "
          f"(entropy score: {result.obfuscation_score:.1f})")

    if not result.findings:
        print(f"  {Fore.GREEN}✓ No dynamic execution patterns detected{Style.RESET_ALL}")
        return

    print()
    seen = set()
    for f in sorted(result.findings, key=lambda x: -x.risk_score):
        if f.technique in seen:
            continue
        seen.add(f.technique)
        print(f"    {_risk_badge(f.risk_score)}  {Fore.YELLOW}{f.technique:<35}{Style.RESET_ALL}")
        print(f"            {f.reason}")
        print(f"            {Fore.WHITE}→ {f.file}:{f.line_number}{Style.RESET_ALL}")
        print(f"            {Fore.CYAN}{f.line_snippet[:100]}{Style.RESET_ALL}\n")

    print(f"  Dynamic Execution Risk Score: {_score_bar(result.total_score, 100)}")


def print_exfil_results(result):
    _section_header("EXFILTRATION CHAIN DETECTION", "💀")
    if not result.findings:
        print(f"  {Fore.GREEN}✓ No exfiltration patterns detected{Style.RESET_ALL}")
        return

    if result.chains_detected:
        print(f"  {Fore.RED + Style.BRIGHT}⚠  CONFIRMED EXFILTRATION CHAINS DETECTED:{Style.RESET_ALL}")
        for chain in result.chains_detected:
            print(f"      {Fore.RED}▶ {chain}{Style.RESET_ALL}")
        print()

    # Show full chain findings first
    full_chains = [f for f in result.findings if f.stage == "full_chain"]
    stage_findings = [f for f in result.findings if f.stage != "full_chain"]

    for f in full_chains:
        print(f"    {_risk_badge(f.risk_score)}  {Fore.RED + Style.BRIGHT}{f.chain_type}{Style.RESET_ALL}")
        print(f"            {f.reason}")
        print(f"            {Fore.WHITE}→ {f.file}{Style.RESET_ALL}\n")

    # Count by stage
    collect = [f for f in stage_findings if f.stage == "collect"]
    package = [f for f in stage_findings if f.stage == "package"]
    transmit = [f for f in stage_findings if f.stage == "transmit"]

    if collect or package or transmit:
        print(f"  {Fore.WHITE}Stage breakdown:{Style.RESET_ALL}")
        print(f"    Collect  (stage 1): {len(collect):3d} hits")
        print(f"    Package  (stage 2): {len(package):3d} hits")
        print(f"    Transmit (stage 3): {len(transmit):3d} hits")

    print(f"\n  Exfiltration Risk Score: {_score_bar(result.total_score, 100)}")


def print_final_verdict(total_score: int, max_score: int, breakdown: dict, extension_name: str):
    _section_header("FINAL VERDICT", "⚖️")

    # Normalize to 0-100
    normalized = min(100, int((total_score / max(max_score, 1)) * 100)) if max_score > 0 else min(100, total_score)
    # Use raw total with a cap for verdict
    raw = total_score

    if raw >= 60:
        verdict = "MALICIOUS"
        color = Fore.RED + Style.BRIGHT
        icon = "🚨"
        advice = "DO NOT INSTALL. This extension exhibits multiple confirmed malicious behaviors."
    elif raw >= 35:
        verdict = "HIGH RISK"
        color = Fore.RED
        icon = "🔴"
        advice = "Strong indicators of malicious intent. Avoid unless from a highly trusted source."
    elif raw >= 20:
        verdict = "SUSPICIOUS"
        color = Fore.YELLOW + Style.BRIGHT
        icon = "🟡"
        advice = "Multiple risk factors present. Exercise caution and investigate further."
    elif raw >= 8:
        verdict = "LOW RISK"
        color = Fore.CYAN
        icon = "🔵"
        advice = "Minor risk signals. Review specific findings before installing."
    else:
        verdict = "LIKELY SAFE"
        color = Fore.GREEN
        icon = "✅"
        advice = "No significant threats detected. Standard caution still advised."

    print(f"\n  Extension: {Fore.YELLOW}{extension_name}{Style.RESET_ALL}")
    print(f"\n  {icon}  Risk Verdict: {color}{verdict}{Style.RESET_ALL}")
    print(f"\n  Overall Risk Score: {_score_bar(raw, 100)}")
    print(f"\n  {Fore.WHITE}Score Breakdown:{Style.RESET_ALL}")

    labels = {
        "permissions":    ("🔐", "Permissions"),
        "apis":           ("🔌", "Sensitive APIs"),
        "network":        ("🌐", "External Domains"),
        "remote_config":  ("☁️ ", "Remote Config"),
        "dynamic_exec":   ("🎭", "Dynamic Execution"),
        "exfiltration":   ("💀", "Exfil Chains"),
        "sandbox":        ("🔬", "Sandbox (4-tool)"),
        "rules":          ("📋", "Rules Engine"),
    }
    for key, (icon_lbl, label) in labels.items():
        score = breakdown.get(key, 0)
        bar = "█" * min(20, score // 3) + "░" * max(0, 20 - score // 3)
        color_bar = _risk_color(score // 10 if score > 10 else score)
        print(f"    {icon_lbl} {label:<20} {color_bar}{bar}{Style.RESET_ALL} {score}")

    print(f"\n  {Fore.WHITE}Recommendation:{Style.RESET_ALL}")
    print(f"  {color}{advice}{Style.RESET_ALL}")
    print()


def save_json_report(output: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  {Fore.CYAN}📄 JSON report saved: {path}{Style.RESET_ALL}")
