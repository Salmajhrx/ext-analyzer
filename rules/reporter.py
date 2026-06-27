"""
Rules section reporter — prints RULES engine match results to terminal.
"""
try:
    from colorama import Fore, Style
except ImportError:
    class _C:
        def __getattr__(self, n): return ""
    Fore = Style = _C()

_SEV_COLOR = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW + Style.BRIGHT,
    "LOW":      Fore.CYAN,
}
_SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


def print_rules_results(rules_result):
    width = 68
    matched = rules_result.matches

    print(f"\n{Fore.RED + Style.BRIGHT}{'═' * width}")
    print(f"  📋  RULES ENGINE  —  {len(matched)} rule(s) matched")
    print(f"{'═' * width}{Style.RESET_ALL}")

    if not matched:
        print(f"\n  {Fore.GREEN}✓ No behavioural rules matched{Style.RESET_ALL}")
        return

    # Sort CRITICAL first
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for m in sorted(matched, key=lambda x: rank.get(x.severity, 0), reverse=True):
        color = _SEV_COLOR.get(m.severity, Fore.WHITE)
        icon  = _SEV_ICON.get(m.severity, "•")

        print(f"\n  {icon}  {color}{m.name}{Style.RESET_ALL}  "
              f"[{m.severity} · +{m.score} pts]")
        print(f"     {Fore.WHITE}{m.description[:105]}{Style.RESET_ALL}")
        print(f"     {Fore.WHITE}Evidence:{Style.RESET_ALL}")
        for ev in m.evidence:
            print(f"       {Fore.YELLOW}→ {ev}{Style.RESET_ALL}")

    print(f"\n  {'─' * 60}")
    hs_color = _SEV_COLOR.get(rules_result.highest_severity, Fore.WHITE)
    print(f"  Rules score:           "
          f"{Fore.RED + Style.BRIGHT}{rules_result.total_score} pts{Style.RESET_ALL}")
    print(f"  Highest severity hit:  "
          f"{hs_color}{rules_result.highest_severity}{Style.RESET_ALL}")
