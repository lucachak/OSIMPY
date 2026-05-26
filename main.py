#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║           OSINPY — OSINT & Dorking Multifunctional Suite      ║
║           github.com/lucachak  |  For authorized use only     ║
╚═══════════════════════════════════════════════════════════════╝

USAGE:
  python main.py <command> [target] [options]

COMMANDS:
  dork        Google Dorking (original engine)
  whois       WHOIS + DNS + CDN/WAF detection
  subdomains  Passive + active subdomain enumeration
  ip          IP geolocation, ASN, open ports (Shodan InternetDB)
  username    Username check across 60+ platforms
  email       Email OSINT — breaches, accounts, domain emails
  portscan    TCP port scan + banner grabbing
  tech        Technology fingerprinting + security header audit
  leaks       Leaked data search (BreachDirectory, IntelX, DeHashed)
  person      Identity/People OSINT (aggregates username, email, phone)
  recon       Full Infra OSINT pipeline — runs all modules automatically
  config      Show current API key configuration + generate .env template

EXAMPLES:
  python main.py whois google.com
  python main.py subdomains github.com --brute
  python main.py ip 8.8.8.8
  python main.py username torvalds
  python main.py email user@example.com
  python main.py portscan 192.168.1.1 --top100
  python main.py tech https://example.com
  python main.py leaks user@example.com
  python main.py recon example.com
  python main.py dork auto findFiles pdfs --filter example.com
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

# ── Rich console (optional but highly recommended) ───────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    console = Console()
    HAS_RICH = True
except ImportError:
    console = None
    HAS_RICH = False


def _print(msg: str, style: str = "") -> None:
    if HAS_RICH and console:
        console.print(msg)
    else:
        # Strip rich tags for plain output
        import re
        plain = re.sub(r"\[/?[^\]]+\]", "", msg)
        print(plain)


def _banner() -> None:
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║       ██████╗ ███████╗██╗███╗  ██╗██████╗ ██╗   ██╗         ║
║      ██╔═══██╗██╔════╝██║████╗ ██║██╔══██╗╚██╗ ██╔╝         ║
║      ██║   ██║███████╗██║██╔██╗██║██████╔╝ ╚████╔╝          ║
║      ██║   ██║╚════██║██║██║╚████║██╔═══╝   ╚██╔╝           ║
║      ╚██████╔╝███████║██║██║ ╚███║██║        ██║            ║
║       ╚═════╝ ╚══════╝╚═╝╚═╝  ╚══╝╚═╝        ╚═╝            ║
║                   OSINT Suite v2.0                            ║
║      For authorized security research only                    ║
╚═══════════════════════════════════════════════════════════════╝"""
    if HAS_RICH:
        console.print(f"[bold cyan]{banner}[/bold cyan]")
    else:
        print(banner)


# ═══════════════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osinpy",
        description="OSINPY — OSINT & Dorking Multifunctional Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    subparsers.required = True

    # ── Global flags (shared by all subcommands) ─────────────────────────
    def _add_globals(p: argparse.ArgumentParser) -> None:
        p.add_argument("-o", "--output", default="./output",
                       help="Output directory (default: ./output)")
        p.add_argument("--no-report", action="store_true",
                       help="Skip saving report files")
        p.add_argument("--json", action="store_true",
                       help="Print raw JSON output instead of rich tables")

    # ── dork ─────────────────────────────────────────────────────────────
    p_dork = subparsers.add_parser("dork", help="Google Dorking (original engine)")
    p_dork.add_argument("search_engine",
                        choices=["auto", "google", "duckduckgo", "nodriver"],
                        help="Search engine")
    p_dork.add_argument("dorks_option", help="Dork category (e.g. findFiles)")
    p_dork.add_argument("file_type", help="Sub-category (e.g. pdfs)")
    p_dork.add_argument("--filter", help="Domain/TLD filter")
    p_dork.add_argument("--query", default="", help="Extra search keywords")
    p_dork.add_argument("--headless", action="store_true", help="Headless browser mode")
    p_dork.add_argument("--max-results", type=int, default=30, help="Max results")
    p_dork.add_argument("--download", action="store_true", help="Auto-download found files")
    p_dork.add_argument("--download-dir", default="./downloads", help="Download directory")
    p_dork.add_argument("--summary-only", action="store_true", help="Only show summary")
    _add_globals(p_dork)

    # ── whois ─────────────────────────────────────────────────────────────
    p_whois = subparsers.add_parser("whois", help="WHOIS + DNS + CDN/WAF detection")
    p_whois.add_argument("target", help="Domain name (e.g. google.com)")
    p_whois.add_argument("--timeout", type=int, default=10, help="Request timeout")
    _add_globals(p_whois)

    # ── subdomains ────────────────────────────────────────────────────────
    p_subs = subparsers.add_parser("subdomains", help="Subdomain enumeration")
    p_subs.add_argument("target", help="Domain name")
    p_subs.add_argument("--brute", action="store_true",
                        help="Enable DNS brute force with wordlist")
    p_subs.add_argument("--wordlist", default=None,
                        help="Custom wordlist file for brute force")
    p_subs.add_argument("--timeout", type=int, default=10, help="Timeout")
    p_subs.add_argument("--threads", type=int, default=30, help="Thread count")
    _add_globals(p_subs)

    # ── ip ────────────────────────────────────────────────────────────────
    p_ip = subparsers.add_parser("ip", help="IP intelligence (geo, ASN, ports, CVEs)")
    p_ip.add_argument("target", help="IP address or hostname")
    p_ip.add_argument("--timeout", type=int, default=10, help="Timeout")
    _add_globals(p_ip)

    # ── username ──────────────────────────────────────────────────────────
    p_user = subparsers.add_parser("username", help="Username check across 60+ platforms")
    p_user.add_argument("target", help="Username to check")
    p_user.add_argument("--timeout", type=int, default=8, help="Per-platform timeout")
    p_user.add_argument("--threads", type=int, default=30, help="Thread count")
    _add_globals(p_user)

    # ── email ─────────────────────────────────────────────────────────────
    p_email = subparsers.add_parser("email", help="Email OSINT — breaches, accounts")
    p_email.add_argument("target", help="Email address")
    p_email.add_argument("--timeout", type=int, default=10, help="Timeout")
    _add_globals(p_email)

    # ── portscan ──────────────────────────────────────────────────────────
    p_port = subparsers.add_parser("portscan", help="TCP port scan + banner grabbing")
    p_port.add_argument("target", help="IP address or hostname")
    p_port.add_argument("--top100", action="store_true",
                        help="Scan top 100 common ports (default)")
    p_port.add_argument("--ports", default=None,
                        help="Custom port list: 22,80,443 or 1-1024")
    p_port.add_argument("--passive-only", action="store_true",
                        help="Only use Shodan InternetDB (no active scan)")
    p_port.add_argument("--no-banner", action="store_true",
                        help="Skip banner grabbing")
    p_port.add_argument("--timeout", type=float, default=1.5,
                        help="Per-port timeout seconds")
    p_port.add_argument("--threads", type=int, default=100, help="Thread count")
    _add_globals(p_port)

    # ── tech ──────────────────────────────────────────────────────────────
    p_tech = subparsers.add_parser("tech", help="Technology fingerprinting")
    p_tech.add_argument("target", help="URL or hostname")
    p_tech.add_argument("--no-probe", action="store_true",
                        help="Skip interesting file probing")
    p_tech.add_argument("--timeout", type=int, default=10, help="Timeout")
    _add_globals(p_tech)

    # ── leaks ─────────────────────────────────────────────────────────────
    p_leaks = subparsers.add_parser("leaks", help="Leaked data search")
    p_leaks.add_argument("target", help="Email, domain, username, or IP")
    p_leaks.add_argument("--type", dest="query_type",
                         choices=["email", "domain", "username", "ip", "phone"],
                         default="email", help="Type of query")
    p_leaks.add_argument("--timeout", type=int, default=15, help="Timeout")
    _add_globals(p_leaks)

    # ── person ────────────────────────────────────────────────────────────
    p_person = subparsers.add_parser("person", help="Identity OSINT aggregator")
    p_person.add_argument("--name", default="", help="Full Name")
    p_person.add_argument("--username", default="", help="Username")
    p_person.add_argument("--email", default="", help="Email address")
    p_person.add_argument("--phone", default="", help="Phone number (with +cc)")
    p_person.add_argument("--timeout", type=int, default=10, help="Timeout")
    _add_globals(p_person)

    # ── recon ─────────────────────────────────────────────────────────────
    p_recon = subparsers.add_parser("recon",
                                     help="Full OSINT pipeline — runs all modules")
    p_recon.add_argument("target", help="Domain, IP, or hostname")
    p_recon.add_argument("--skip", nargs="*", default=[],
                         choices=["whois", "subdomains", "ip", "tech", "portscan", "leaks"],
                         help="Modules to skip")
    p_recon.add_argument("--brute", action="store_true",
                         help="Enable subdomain brute force")
    p_recon.add_argument("--passive-only", action="store_true",
                         help="No active scanning (DNS/HTTP only)")
    p_recon.add_argument("--timeout", type=int, default=10, help="Timeout")
    _add_globals(p_recon)

    # ── config ────────────────────────────────────────────────────────────
    p_cfg = subparsers.add_parser("config", help="Show API key status + generate .env template")
    p_cfg.add_argument("--init", action="store_true",
                       help="Write .env template to current directory")

    return parser


# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_ports(port_arg: str | None) -> list[int]:
    """Parse '22,80,443' or '1-1024' or None (→ top 100)."""
    from helpers.osint.port_scan import TOP_100_PORTS
    if not port_arg:
        return TOP_100_PORTS
    ports: list[int] = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def _save_json(data: dict, output_dir: str, filename: str) -> Path:
    """Save a dict as JSON to the output directory."""
    p = Path(output_dir)
    p.mkdir(parents=True, exist_ok=True)
    fp = p / filename
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    _print(f"[dim][💾] Saved: {fp}[/dim]")
    return fp


def _load_config():
    """Load config (API keys etc.)."""
    try:
        from helpers.config import Config
        return Config
    except ImportError:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

# ── dork ─────────────────────────────────────────────────────────────────────

async def cmd_dork(args) -> None:
    from helpers.Crawler import Crawler
    from helpers.Executor import Executor

    BASE_DIR = Path(__file__).parent.resolve()
    PROFILE_DIR = BASE_DIR / "chrome_profile"

    _print(f"""
[bold cyan]╔══ DORKING ══╗[/bold cyan]
  Engine:    {args.search_engine}
  Category:  {args.dorks_option} → {args.file_type}
  Filter:    {getattr(args, 'filter', None) or 'None'}
  Query:     {args.query or 'None'}
  Headless:  {args.headless}
""")

    executor = Executor(
        search_engine=args.search_engine,
        dorks_option=args.dorks_option,
        file_type=args.file_type,
        search_filter=getattr(args, "filter", None),
        search_query=args.query,
        headless=args.headless,
        max_results=args.max_results,
        output_dir=args.output,
        user_data_dir=PROFILE_DIR,
    )

    _print("[*] Building dork and initiating search...")
    result = await executor.execute()

    if result is None:
        _print("[bold red][!] Execution failed or returned no data.[/bold red]")
        sys.exit(1)

    _print(executor.summary())

    if not args.summary_only and result.links:
        _print(f"\n[bold green][+] Links Discovered ({len(result.links)}):[/bold green]")
        for i, link in enumerate(result.links, 1):
            _print(f"  {i:3d}. {link}")

    should_download = args.download or args.download_dir != "./downloads"
    if should_download and result.links:
        _print("\n[*] Initializing downloader...")
        download_crawler = Crawler(
            query=result.dork,
            engine=args.search_engine,
            headless=args.headless,
            download_dir=args.download_dir,
            user_data_dir=PROFILE_DIR,
        )
        download_crawler.links = result.links
        downloaded = await asyncio.to_thread(download_crawler.download_all)
        _print(f"[📥] Downloaded {len(downloaded)} files to '{args.download_dir}'.")

    stats = Crawler.stats()
    _print(f"""
[bold]SESSION STATS[/bold]
  Searches:   {stats.total_searches}
  nodriver:   {stats.nodriver_success}
  DuckDuckGo: {stats.duckduckgo_success}
  Google:     {stats.google_success}
  Links:      {stats.total_links_found}
""")
    await Crawler.close_driver()


# ── whois ─────────────────────────────────────────────────────────────────────

def cmd_whois(args) -> None:
    from helpers.osint.whois_lookup import WhoisLookup
    from helpers.osint.report import ReportBuilder

    wl = WhoisLookup(domain=args.target, timeout=args.timeout)
    data = wl.run()

    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        WhoisLookup.print_result(data)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_whois(data)
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── subdomains ────────────────────────────────────────────────────────────────

def cmd_subdomains(args) -> None:
    from helpers.osint.subdomain_enum import SubdomainEnum
    from helpers.osint.report import ReportBuilder

    se = SubdomainEnum(
        domain=args.target,
        brute=args.brute,
        wordlist_path=args.wordlist,
        timeout=args.timeout,
        max_workers=args.threads,
    )
    result = se.run()

    if args.json:
        print(json.dumps(SubdomainEnum.to_dict(result), indent=2, default=str))
    else:
        SubdomainEnum.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_subdomains(SubdomainEnum.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── ip ────────────────────────────────────────────────────────────────────────

def cmd_ip(args) -> None:
    from helpers.osint.ip_intel import IPIntel
    from helpers.osint.report import ReportBuilder

    intel = IPIntel(target=args.target, timeout=args.timeout)
    result = intel.run()

    if args.json:
        print(json.dumps(IPIntel.to_dict(result), indent=2, default=str))
    else:
        IPIntel.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_ip_intel(IPIntel.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── username ──────────────────────────────────────────────────────────────────

def cmd_username(args) -> None:
    from helpers.osint.username_osint import UsernameOSINT
    from helpers.osint.report import ReportBuilder

    checker = UsernameOSINT(
        username=args.target,
        timeout=args.timeout,
        max_workers=args.threads,
    )
    result = checker.run()

    if args.json:
        print(json.dumps(UsernameOSINT.to_dict(result), indent=2, default=str))
    else:
        UsernameOSINT.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_username(UsernameOSINT.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── email ─────────────────────────────────────────────────────────────────────

def cmd_email(args) -> None:
    from helpers.osint.email_osint import EmailOSINT
    from helpers.osint.report import ReportBuilder

    cfg = _load_config()
    checker = EmailOSINT(
        email=args.target,
        hibp_key=cfg.HIBP_API_KEY if cfg else None,
        hunter_key=cfg.HUNTER_API_KEY if cfg else None,
        timeout=args.timeout,
    )
    result = checker.run()

    if args.json:
        print(json.dumps(EmailOSINT.to_dict(result), indent=2, default=str))
    else:
        EmailOSINT.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_email(EmailOSINT.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── portscan ──────────────────────────────────────────────────────────────────

def cmd_portscan(args) -> None:
    from helpers.osint.port_scan import PortScan
    from helpers.osint.report import ReportBuilder

    ports = _parse_ports(args.ports)
    scanner = PortScan(
        target=args.target,
        ports=ports,
        active=not args.passive_only,
        banner_grab=not args.no_banner,
        timeout=args.timeout,
        max_workers=args.threads,
    )
    result = scanner.run()

    if args.json:
        print(json.dumps(PortScan.to_dict(result), indent=2, default=str))
    else:
        PortScan.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_ports(PortScan.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── tech ──────────────────────────────────────────────────────────────────────

def cmd_tech(args) -> None:
    from helpers.osint.tech_fingerprint import TechFingerprint
    from helpers.osint.report import ReportBuilder

    fp = TechFingerprint(
        target=args.target,
        probe_files=not args.no_probe,
        timeout=args.timeout,
    )
    result = fp.run()

    if args.json:
        print(json.dumps(TechFingerprint.to_dict(result), indent=2, default=str))
    else:
        TechFingerprint.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_tech(TechFingerprint.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── leaks ─────────────────────────────────────────────────────────────────────

def cmd_leaks(args) -> None:
    from helpers.osint.leak_search import LeakSearch
    from helpers.osint.report import ReportBuilder

    cfg = _load_config()
    searcher = LeakSearch(
        query=args.target,
        query_type=args.query_type,
        dehashed_email=cfg.DEHASHED_EMAIL if cfg else None,
        dehashed_api_key=cfg.DEHASHED_API_KEY if cfg else None,
        intelx_api_key=cfg.INTELX_API_KEY if cfg else None,
        timeout=args.timeout,
    )
    result = searcher.run()

    if args.json:
        print(json.dumps(LeakSearch.to_dict(result), indent=2, default=str))
    else:
        LeakSearch.print_result(result)

    if not args.no_report:
        rb = ReportBuilder(target=args.target, output_dir=args.output)
        rb.add_leaks(LeakSearch.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── person ────────────────────────────────────────────────────────────────────

def cmd_person(args) -> None:
    from helpers.osint.person_recon import PersonRecon
    from helpers.osint.report import ReportBuilder

    cfg = _load_config()
    
    if not (args.name or args.username or args.email or args.phone):
        _print("[red]Error: You must provide at least one of: --name, --username, --email, --phone[/red]")
        sys.exit(1)

    recon = PersonRecon(
        name=args.name,
        username=args.username,
        email=args.email,
        phone=args.phone,
        config=cfg,
        timeout=args.timeout,
    )
    result = recon.run()

    if args.json:
        print(json.dumps(PersonRecon.to_dict(result), indent=2, default=str))
    else:
        PersonRecon.print_result(result)

    if not args.no_report:
        tgt_name = args.name or args.username or args.email or args.phone
        rb = ReportBuilder(target=f"person_{tgt_name}", output_dir=args.output)
        rb.add_person_recon(PersonRecon.to_dict(result))
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)


# ── recon ─────────────────────────────────────────────────────────────────────

def cmd_recon(args) -> None:
    """Full OSINT pipeline — runs all applicable modules sequentially."""
    from helpers.osint.report import ReportBuilder
    import socket

    target = args.target
    skip = set(args.skip or [])
    timeout = args.timeout
    cfg = _load_config()

    _print(f"\n[bold cyan]╔══════════════════════════════════════╗[/bold cyan]")
    _print(f"[bold cyan]║   RECON — {target:<28}║[/bold cyan]")
    _print(f"[bold cyan]╚══════════════════════════════════════╝[/bold cyan]\n")
    _print(f"Skipping: {skip or 'none'} | Active scan: {not args.passive_only}\n")

    rb = ReportBuilder(target=target, output_dir=args.output)

    # Resolve IP for target
    ip_target = target
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            ip_target = socket.gethostbyname(target)
        except Exception:
            ip_target = target

    # ── 1. WHOIS ──────────────────────────────────────────────────────────
    if "whois" not in skip:
        _print("\n[bold yellow]━━━ [1/6] WHOIS & DNS ━━━[/bold yellow]")
        try:
            from helpers.osint.whois_lookup import WhoisLookup
            wl = WhoisLookup(domain=target, timeout=timeout)
            data = wl.run()
            WhoisLookup.print_result(data)
            rb.add_whois(data)
        except Exception as e:
            _print(f"[red][whois] Error: {e}[/red]")

    # ── 2. SUBDOMAINS ─────────────────────────────────────────────────────
    if "subdomains" not in skip:
        _print("\n[bold yellow]━━━ [2/6] SUBDOMAIN ENUMERATION ━━━[/bold yellow]")
        try:
            from helpers.osint.subdomain_enum import SubdomainEnum
            se = SubdomainEnum(domain=target, brute=args.brute, timeout=timeout)
            result = se.run()
            SubdomainEnum.print_result(result)
            rb.add_subdomains(SubdomainEnum.to_dict(result))
        except Exception as e:
            _print(f"[red][subdomains] Error: {e}[/red]")

    # ── 3. IP INTEL ───────────────────────────────────────────────────────
    if "ip" not in skip:
        _print("\n[bold yellow]━━━ [3/6] IP INTELLIGENCE ━━━[/bold yellow]")
        try:
            from helpers.osint.ip_intel import IPIntel
            intel = IPIntel(target=ip_target, timeout=timeout)
            result = intel.run()
            IPIntel.print_result(result)
            rb.add_ip_intel(IPIntel.to_dict(result))
        except Exception as e:
            _print(f"[red][ip] Error: {e}[/red]")

    # ── 4. TECH FINGERPRINT ───────────────────────────────────────────────
    if "tech" not in skip:
        _print("\n[bold yellow]━━━ [4/6] TECHNOLOGY FINGERPRINT ━━━[/bold yellow]")
        try:
            from helpers.osint.tech_fingerprint import TechFingerprint
            fp = TechFingerprint(target=target, timeout=timeout)
            result = fp.run()
            TechFingerprint.print_result(result)
            rb.add_tech(TechFingerprint.to_dict(result))
        except Exception as e:
            _print(f"[red][tech] Error: {e}[/red]")

    # ── 5. PORT SCAN ─────────────────────────────────────────────────────
    if "portscan" not in skip:
        _print("\n[bold yellow]━━━ [5/6] PORT SCAN ━━━[/bold yellow]")
        try:
            from helpers.osint.port_scan import PortScan, TOP_100_PORTS
            scanner = PortScan(
                target=ip_target,
                ports=TOP_100_PORTS,
                active=not args.passive_only,
                timeout=1.5,
            )
            result = scanner.run()
            PortScan.print_result(result)
            rb.add_ports(PortScan.to_dict(result))
        except Exception as e:
            _print(f"[red][portscan] Error: {e}[/red]")

    # ── 6. LEAK SEARCH ───────────────────────────────────────────────────
    if "leaks" not in skip:
        _print("\n[bold yellow]━━━ [6/6] LEAK SEARCH ━━━[/bold yellow]")
        try:
            from helpers.osint.leak_search import LeakSearch
            searcher = LeakSearch(
                query=target,
                query_type="domain",
                dehashed_email=cfg.DEHASHED_EMAIL if cfg else None,
                dehashed_api_key=cfg.DEHASHED_API_KEY if cfg else None,
                intelx_api_key=cfg.INTELX_API_KEY if cfg else None,
                timeout=timeout,
            )
            result = searcher.run()
            LeakSearch.print_result(result)
            rb.add_leaks(LeakSearch.to_dict(result))
        except Exception as e:
            _print(f"[red][leaks] Error: {e}[/red]")

    # ── Save final report ─────────────────────────────────────────────────
    if not args.no_report:
        _print("\n[bold cyan]━━━ SAVING REPORT ━━━[/bold cyan]")
        report_dir = rb.build()
        ReportBuilder.print_summary(report_dir)

    _print("\n[bold green]✅ Recon complete![/bold green]\n")


# ── config ────────────────────────────────────────────────────────────────────

def cmd_config(args) -> None:
    from helpers.config import Config

    Config.show()

    if args.init:
        env_path = Path(".env")
        if env_path.exists():
            _print("[yellow].env already exists. Not overwriting.[/yellow]")
        else:
            env_path.write_text(Config.env_template())
            _print(f"[green]✅ Created .env template at {env_path.resolve()}[/green]")
            _print("[dim]Edit it with your API keys and re-run.[/dim]")


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════════════════

def interactive_menu() -> None:
    """A rich-based interactive menu when run without args."""
    if not HAS_RICH:
        print("Interactive menu requires 'rich'. Please 'pip install rich'.")
        sys.exit(1)
        
    from rich.prompt import Prompt, Confirm
    
    _banner()
    console.print("\n[bold cyan]1.[/bold cyan] Identity OSINT (People Recon)")
    console.print("[bold cyan]2.[/bold cyan] Infrastructure OSINT (Domain/IP Recon)")
    console.print("[bold cyan]3.[/bold cyan] Configure API Keys (.env)")
    console.print("[bold cyan]0.[/bold cyan] Exit")
    
    choice = Prompt.ask("\n[?] Select an option", choices=["1", "2", "3", "0"], default="1")
    
    class ArgsMock:
        def __init__(self):
            self.json = False
            self.no_report = False
            self.output = "./output"
            self.timeout = 10
            
    if choice == "0":
        sys.exit(0)
    elif choice == "3":
        args = ArgsMock()
        args.init = True
        cmd_config(args)
    elif choice == "1":
        # Identity OSINT
        console.print("\n[bold magenta]═══ Identity Recon ═══[/bold magenta]")
        console.print("Fill in whatever you know about the target (leave blank to skip):")
        args = ArgsMock()
        args.name = Prompt.ask("Full Name")
        args.username = Prompt.ask("Username")
        args.email = Prompt.ask("Email")
        args.phone = Prompt.ask("Phone (e.g. +5511999999999)")
        
        if not (args.name or args.username or args.email or args.phone):
            console.print("[red]You must provide at least one piece of information.[/red]")
            sys.exit(1)
            
        cmd_person(args)
        
    elif choice == "2":
        # Infra OSINT
        console.print("\n[bold yellow]═══ Infrastructure Recon ═══[/bold yellow]")
        args = ArgsMock()
        args.target = Prompt.ask("Domain or IP (e.g. example.com)")
        
        args.brute = Confirm.ask("Enable Subdomain Brute Force?", default=False)
        args.passive_only = Confirm.ask("Use passive-only mode? (No active port scans)", default=False)
        args.skip = []
        
        cmd_recon(args)

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRYPOINT
# ═══════════════════════════════════════════════════════════════════════════════

async def main() -> None:
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = build_parser()
    args = parser.parse_args()

    _banner()

    dispatch = {
        "dork":       lambda: cmd_dork(args),
        "whois":      lambda: cmd_whois(args),
        "subdomains": lambda: cmd_subdomains(args),
        "ip":         lambda: cmd_ip(args),
        "username":   lambda: cmd_username(args),
        "email":      lambda: cmd_email(args),
        "portscan":   lambda: cmd_portscan(args),
        "tech":       lambda: cmd_tech(args),
        "leaks":      lambda: cmd_leaks(args),
        "person":     lambda: cmd_person(args),
        "recon":      lambda: cmd_recon(args),
        "config":     lambda: cmd_config(args),
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    # Async commands run in event loop; sync commands run directly
    if args.command == "dork":
        await handler()
    else:
        # Run sync handler (blocking I/O, threads used internally)
        handler()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        _print("\n[yellow][!] Interrupted by user (Ctrl+C). Exiting safely.[/yellow]")
        sys.exit(1)
