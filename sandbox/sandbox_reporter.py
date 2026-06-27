"""
Sandbox Reporter — v1.4
Prints Box.js REST API results per JS file.
(Malware Jail, JS-X-Ray and Synchrony sections removed in v1.4)
"""
try:
    from colorama import Fore, Style
except ImportError:
    class _C:
        def __getattr__(self, n): return ""
    Fore = Style = _C()


def _hdr(title):
    print(f"\n  {Fore.MAGENTA}{'─'*58}")
    print(f"  {title}")
    print(f"  {'─'*58}{Style.RESET_ALL}")


def print_sandbox_results(result):
    width = 68
    print(f"\n{Fore.MAGENTA + Style.BRIGHT}{'═'*width}")
    print(f"  🔬  SANDBOX ANALYSIS  (Box.js — WScript/ActiveX/IOC engine)")
    print(f"{'═'*width}{Style.RESET_ALL}")

    if not result.file_results:
        print(f"  {Fore.YELLOW}No JS files sandboxed.{Style.RESET_ALL}")
        return

    for fr in result.file_results:
        score_color = (Fore.RED + Style.BRIGHT if fr.risk_score >= 15
                       else Fore.YELLOW if fr.risk_score >= 6 else Fore.GREEN)
        print(f"\n  {score_color}▶ {fr.filename}  "
              f"[sandbox score: {fr.risk_score}]{Style.RESET_ALL}")

        # ── Box.js ────────────────────────────────────────────────────────
        _hdr("BOX.JS — WScript / ActiveX emulation + IOC extraction")
        bj = fr.boxjs

        if bj.error and not (bj.iocs or bj.urls or bj.active_urls):
            print(f"    {Fore.YELLOW}⚠  {bj.error}{Style.RESET_ALL}")

        else:
            # Surface soft error (e.g. timeout) without hiding results
            if bj.error:
                print(f"    {Fore.YELLOW}⚠  Note: {bj.error}{Style.RESET_ALL}")

            # IOCs
            if bj.iocs:
                print(f"    {Fore.RED}IOCs detected: {len(bj.iocs)}{Style.RESET_ALL}")
                for ioc in bj.iocs[:8]:
                    itype = ioc.get("type", "?")
                    val   = ioc.get("value", {})
                    if isinstance(val, dict):
                        detail = (val.get("url") or val.get("command") or
                                  val.get("path") or val.get("key") or str(val))
                    else:
                        detail = str(val)
                    print(f"      {Fore.YELLOW}[{itype}]{Style.RESET_ALL} "
                          f"{str(detail)[:90]}")

            # Active URLs (payload-dropping)
            if bj.active_urls:
                print(f"    {Fore.RED}⚡ Active URLs (served payload): "
                      f"{len(bj.active_urls)}{Style.RESET_ALL}")
                for u in bj.active_urls[:6]:
                    print(f"      {Fore.RED}🔴 {str(u)[:90]}{Style.RESET_ALL}")

            # All contacted URLs (not already covered by IOCs)
            other_urls = [u for u in bj.urls if u not in bj.active_urls]
            if other_urls:
                print(f"    {Fore.YELLOW}Network contacts: "
                      f"{len(other_urls)}{Style.RESET_ALL}")
                for u in other_urls[:6]:
                    print(f"      {Fore.CYAN}{str(u)[:90]}{Style.RESET_ALL}")

            # Shell commands
            if bj.commands:
                print(f"    {Fore.RED}Shell commands: "
                      f"{len(bj.commands)}{Style.RESET_ALL}")
                for cmd in bj.commands[:4]:
                    print(f"      {Fore.RED}{str(cmd)[:90]}{Style.RESET_ALL}")

            # Resources (files written to disk)
            #if bj.resources:
                #print(f"    {Fore.YELLOW}Files written to disk: "
                      #f"{len(bj.resources)}{Style.RESET_ALL}")
                #for uid, res in list(bj.resources.items())[:4]:
                    #rtype = res.get("type", "?") if isinstance(res, dict) else "?"
                    #rmd5  = res.get("md5",  "?") if isinstance(res, dict) else "?"
                    #print(f"      {Fore.WHITE}{uid[:8]}…  "
                          #f"type={rtype}  md5={rmd5}{Style.RESET_ALL}")

            # Snippets
            if bj.snippets:
                print(f"    {Fore.RED}Extracted code snippets: "
                      f"{len(bj.snippets)}{Style.RESET_ALL}")
                for s in bj.snippets[:2]:
                    print(f"      {Fore.CYAN}{str(s)[:120]}{Style.RESET_ALL}")

            if not (bj.iocs or bj.urls or bj.active_urls or bj.commands):
                print(f"    {Fore.GREEN}✓ No IOCs or suspicious activity detected"
                      f"{Style.RESET_ALL}")

        # ── Risk signals ─────────────────────────────────────────────────
        if fr.risk_signals:
            print(f"\n  {Fore.RED + Style.BRIGHT}⚡ SANDBOX SIGNALS "
                  f"[{fr.risk_score} pts]{Style.RESET_ALL}")
            for sig in fr.risk_signals[:10]:
                print(f"    {Fore.YELLOW}• {sig}{Style.RESET_ALL}")

    # ── Aggregate totals ──────────────────────────────────────────────────
    width = 68
    print(f"\n{Fore.MAGENTA + Style.BRIGHT}{'─'*width}")
    print(f"  SANDBOX TOTALS  (Box.js){Style.RESET_ALL}")

    all_boxjs_urls    = [u for u in result.all_urls if u.get("type") == "boxjs"]
    all_active_urls   = [u for u in result.all_urls if u.get("type") == "boxjs-active"]
    shell_iocs        = [i for i in result.all_iocs if i.get("type") == "Run"]
    file_iocs         = [i for i in result.all_iocs if i.get("type") == "FileWrite"]

    print(f"  URLs contacted:      {Fore.YELLOW}{len(all_boxjs_urls)}{Style.RESET_ALL}")
    print(f"  Active URLs:         "
          f"{Fore.RED if all_active_urls else Fore.YELLOW}"
          f"{len(all_active_urls)}{Style.RESET_ALL}")
    print(f"  Total IOCs:          {Fore.YELLOW}{len(result.all_iocs)}{Style.RESET_ALL}")
    print(f"  Shell commands:      "
          f"{Fore.RED if shell_iocs else Fore.YELLOW}"
          f"{len(shell_iocs)}{Style.RESET_ALL}")
    print(f"  Files written:       {Fore.YELLOW}{len(file_iocs)}{Style.RESET_ALL}")
    print(f"  Sandbox score:       "
          f"{Fore.RED + Style.BRIGHT}{result.total_score}{Style.RESET_ALL}")

    # Unique URLs summary
    all_url_strs = list({u.get("url", "") for u in result.all_urls if u.get("url")})
    if all_url_strs:
        print(f"\n  {Fore.WHITE}All contacted URLs:{Style.RESET_ALL}")
        for url in all_url_strs[:15]:
            utype = next(
                (u.get("type","?") for u in result.all_urls if u.get("url") == url),
                "?"
            )
            color = Fore.RED if "active" in utype else Fore.CYAN
            print(f"    {color}{utype.upper():<14}{Style.RESET_ALL} {url[:80]}")