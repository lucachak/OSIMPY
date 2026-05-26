"""
OSINPY — Subdomain Enumeration Module
Passive: crt.sh, HackerTarget, AlienVault OTX
Active: DNS brute force with wordlist
No API key required.
"""

from __future__ import annotations
import socket
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ── Default brute-force wordlist ─────────────────────────────────────────────

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "dev", "staging", "test", "qa", "uat", "prod", "production", "demo",
    "api", "app", "admin", "portal", "dashboard", "panel", "console",
    "blog", "shop", "store", "cdn", "static", "assets", "media", "img",
    "images", "files", "upload", "uploads", "download", "downloads",
    "secure", "login", "auth", "sso", "oauth", "vpn", "remote", "rdp",
    "ssh", "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "jira", "confluence", "wiki", "docs", "help", "support", "ticket",
    "monitor", "status", "health", "metrics", "grafana", "kibana",
    "elastic", "redis", "mysql", "db", "database", "sql", "mongo",
    "backup", "bak", "old", "new", "beta", "alpha", "v1", "v2", "v3",
    "api2", "api3", "mobile", "m", "wap", "internal", "intranet",
    "corp", "office", "hr", "finance", "accounting", "legal", "crm",
    "erp", "exchange", "webmail", "owa", "autodiscover", "cpanel",
    "whm", "webdisk", "cpcalendars", "cpcontacts", "webmin", "plesk",
    "directadmin", "pma", "phpmyadmin", "myadmin", "billing", "pay",
    "payment", "checkout", "cart", "catalog", "search", "news", "forum",
    "community", "social", "chat", "messaging", "ws", "socket", "stream",
]


@dataclass
class Subdomain:
    name: str
    ip: str = ""
    source: str = ""
    alive: bool = False


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[Subdomain] = field(default_factory=list)
    total: int = 0
    alive: int = 0
    sources_used: list[str] = field(default_factory=list)


class SubdomainEnum:
    """
    Multi-source passive subdomain enumeration with optional DNS brute force.
    Sources: crt.sh, HackerTarget, AlienVault OTX
    """

    def __init__(self, domain: str, brute: bool = False, wordlist_path: str | None = None,
                 timeout: int = 10, max_workers: int = 30):
        self.domain = domain.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]
        self.brute = brute
        self.timeout = timeout
        self.max_workers = max_workers
        self._found: dict[str, Subdomain] = {}  # name -> Subdomain
        self.wordlist: list[str] = DEFAULT_WORDLIST

        if wordlist_path:
            p = Path(wordlist_path)
            if p.exists():
                self.wordlist = p.read_text().splitlines()
                print(f"[subdomains] Loaded {len(self.wordlist)} words from {p}")

    # ── Public API ──────────────────────────────────────────────────────────

    def run(self) -> SubdomainResult:
        print(f"\n[subdomains] 🔍 Enumerating subdomains for {self.domain}...")
        result = SubdomainResult(domain=self.domain)

        # Passive sources (run in parallel)
        sources = [
            ("crt.sh", self._crtsh),
            ("HackerTarget", self._hackertarget),
            ("AlienVault OTX", self._alienvault),
        ]

        for name, fn in sources:
            try:
                subs = fn()
                if subs:
                    result.sources_used.append(name)
                    for s in subs:
                        if s not in self._found:
                            self._found[s] = Subdomain(name=s, source=name)
                    print(f"[subdomains] {name}: +{len(subs)} subdomains")
            except Exception as e:
                print(f"[subdomains] {name} error: {e}")

        # Active brute force
        if self.brute:
            brute_found = self._brute_force()
            if brute_found:
                result.sources_used.append("brute-force")
                print(f"[subdomains] Brute force: +{len(brute_found)} subdomains")

        # Resolve IPs and check liveness
        print(f"[subdomains] Resolving {len(self._found)} unique subdomains...")
        self._resolve_all()

        result.subdomains = sorted(self._found.values(), key=lambda x: x.name)
        result.total = len(result.subdomains)
        result.alive = sum(1 for s in result.subdomains if s.alive)

        print(f"[subdomains] ✅ Found {result.total} subdomains ({result.alive} alive)")
        return result

    # ── Sources ─────────────────────────────────────────────────────────────

    def _crtsh(self) -> list[str]:
        """Certificate Transparency Log search via crt.sh."""
        if not HAS_REQUESTS:
            return []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        resp = _requests.get(url, timeout=self.timeout,
                              headers={"User-Agent": "Mozilla/5.0"})
        data = resp.json()
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{self.domain}") or name == self.domain:
                    subs.add(name)
        return list(subs)

    def _hackertarget(self) -> list[str]:
        """HackerTarget subdomain search (free, no key)."""
        if not HAS_REQUESTS:
            return []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        resp = _requests.get(url, timeout=self.timeout,
                              headers={"User-Agent": "Mozilla/5.0"})
        subs = []
        for line in resp.text.splitlines():
            if "," in line:
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(self.domain):
                    subs.append(sub)
        return subs

    def _alienvault(self) -> list[str]:
        """AlienVault OTX passive DNS (free, no key for basic)."""
        if not HAS_REQUESTS:
            return []
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        resp = _requests.get(url, timeout=self.timeout,
                              headers={"User-Agent": "Mozilla/5.0"})
        data = resp.json()
        subs = []
        for entry in data.get("passive_dns", []):
            h = entry.get("hostname", "").lower()
            if h.endswith(self.domain) and h != self.domain:
                subs.append(h)
        return list(set(subs))

    # ── Brute Force ─────────────────────────────────────────────────────────

    def _brute_force(self) -> list[str]:
        """DNS brute force using the wordlist."""
        found = []
        candidates = [f"{w}.{self.domain}" for w in self.wordlist]
        print(f"[subdomains] Brute forcing {len(candidates)} candidates...")

        def resolve(fqdn: str) -> str | None:
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(fqdn)
                return fqdn
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(resolve, c): c for c in candidates}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found.append(result)
                    if result not in self._found:
                        self._found[result] = Subdomain(name=result, source="brute-force")

        return found

    # ── Resolution ──────────────────────────────────────────────────────────

    def _resolve_one(self, sub: Subdomain) -> None:
        try:
            socket.setdefaulttimeout(3)
            ip = socket.gethostbyname(sub.name)
            sub.ip = ip
            sub.alive = True
        except Exception:
            sub.alive = False

    def _resolve_all(self) -> None:
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            list(ex.map(self._resolve_one, self._found.values()))

    # ── Pretty print ────────────────────────────────────────────────────────

    @staticmethod
    def print_result(result: SubdomainResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Subdomains — {result.domain} ═══[/bold cyan]")
            console.print(f"Sources: {', '.join(result.sources_used)} | "
                          f"Total: [bold]{result.total}[/bold] | "
                          f"Alive: [bold green]{result.alive}[/bold green]\n")

            t = Table(box=box.SIMPLE, show_header=True)
            t.add_column("Subdomain", style="cyan", width=45)
            t.add_column("IP", style="yellow", width=18)
            t.add_column("Source", style="dim", width=15)
            t.add_column("Status", width=8)

            for s in result.subdomains:
                status = "[green]alive[/green]" if s.alive else "[red]dead[/red]"
                t.add_row(s.name, s.ip or "—", s.source, status)

            console.print(t)
        except ImportError:
            print(f"\nSubdomains for {result.domain} ({result.total} total, {result.alive} alive):")
            for s in result.subdomains:
                mark = "✅" if s.alive else "❌"
                print(f"  {mark} {s.name:<45} {s.ip or '—':<18} [{s.source}]")

    @staticmethod
    def to_dict(result: SubdomainResult) -> dict:
        return {
            "domain": result.domain,
            "total": result.total,
            "alive": result.alive,
            "sources_used": result.sources_used,
            "subdomains": [
                {"name": s.name, "ip": s.ip, "source": s.source, "alive": s.alive}
                for s in result.subdomains
            ],
        }
