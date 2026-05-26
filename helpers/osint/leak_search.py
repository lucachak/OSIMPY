"""
OSINPY — Leak Search Module
Searches for leaked data across public sources:
- BreachDirectory (public API)
- IntelX.io (free tier)
- DeHashed (requires paid API key)
- Reuses Crawler for Pastebin/GitHub dork searches
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class LeakEntry:
    source: str
    email: str = ""
    username: str = ""
    password: str = ""
    hash_value: str = ""
    database: str = ""
    phone: str = ""
    address: str = ""
    ip_address: str = ""
    raw: str = ""


@dataclass
class LeakSearchResult:
    query: str
    query_type: str = "email"   # email | domain | username | ip | phone
    total_found: int = 0
    leaks: list[LeakEntry] = field(default_factory=list)
    sources_checked: list[str] = field(default_factory=list)
    dork_urls: list[str] = field(default_factory=list)


class LeakSearch:
    """
    Aggregates breach/leak data from multiple sources.
    Gracefully degrades when API keys are missing.
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; OSINPY/2.0)",
        "Accept": "application/json",
    }

    def __init__(self, query: str, query_type: str = "email",
                 dehashed_email: str | None = None,
                 dehashed_api_key: str | None = None,
                 intelx_api_key: str | None = None,
                 timeout: int = 15):
        self.query = query.strip()
        self.query_type = query_type
        self.dehashed_email = dehashed_email
        self.dehashed_api_key = dehashed_api_key
        self.intelx_api_key = intelx_api_key
        self.timeout = timeout

    def run(self) -> LeakSearchResult:
        print(f"\n[leaks] 🔍 Searching for leaks: '{self.query}' (type: {self.query_type})...")
        result = LeakSearchResult(query=self.query, query_type=self.query_type)

        if not HAS_REQUESTS:
            print("[leaks] ⚠️  requests not installed.")
            return result

        # BreachDirectory — public, no key
        self._breachdirectory(result)

        # IntelX — free tier with key
        if self.intelx_api_key:
            self._intelx(result)
        else:
            print("[leaks] IntelX: skipped (no INTELX_API_KEY)")

        # DeHashed — requires paid key
        if self.dehashed_email and self.dehashed_api_key:
            self._dehashed(result)
        else:
            print("[leaks] DeHashed: skipped (no DEHASHED credentials)")

        # Dork-based search on Pastebin/GitHub
        self._dork_search(result)

        result.total_found = len(result.leaks)
        print(f"[leaks] ✅ Found {result.total_found} leak entries across {len(result.sources_checked)} sources.")
        return result

    def _breachdirectory(self, result: LeakSearchResult) -> None:
        """BreachDirectory public API — no key required for basic lookup."""
        try:
            result.sources_checked.append("BreachDirectory")
            # Public search endpoint
            url = "https://breachdirectory.org/api"
            params = {"func": "auto", "term": self.query}
            resp = _requests.get(url, params=params, headers=self.HEADERS,
                                  timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                found = data.get("found", 0)
                if found:
                    print(f"[leaks] BreachDirectory: {found} records")
                    # If the API returns actual entries (may vary by tier)
                    for entry in data.get("result", [])[:20]:
                        result.leaks.append(LeakEntry(
                            source="BreachDirectory",
                            email=entry.get("email", ""),
                            password=entry.get("password", ""),
                            hash_value=entry.get("sha1", ""),
                            raw=str(entry),
                        ))
                    if not data.get("result") and found:
                        # Just a count, create a summary entry
                        result.leaks.append(LeakEntry(
                            source="BreachDirectory",
                            email=self.query if "@" in self.query else "",
                            raw=f"{found} records found (upgrade API tier for details)",
                        ))
            elif resp.status_code == 429:
                print("[leaks] BreachDirectory: rate limited")
            elif resp.status_code == 404:
                print("[leaks] BreachDirectory: not found (clean)")
        except Exception as e:
            print(f"[leaks] BreachDirectory error: {e}")

    def _intelx(self, result: LeakSearchResult) -> None:
        """IntelX.io search — requires free API key."""
        try:
            result.sources_checked.append("IntelX")
            # Phase 1: initiate search
            search_url = "https://2.intelx.io/intelligent/search"
            payload = {
                "term": self.query,
                "buckets": [],
                "lookuplevel": 0,
                "maxresults": 20,
                "timeout": 5,
                "datefrom": "",
                "dateto": "",
                "sort": 4,
                "media": 0,
                "terminate": [],
            }
            headers = dict(self.HEADERS)
            headers["x-key"] = self.intelx_api_key

            resp = _requests.post(search_url, json=payload, headers=headers,
                                   timeout=self.timeout)
            if resp.status_code != 200:
                print(f"[leaks] IntelX: HTTP {resp.status_code}")
                return

            search_id = resp.json().get("id")
            if not search_id:
                return

            import time
            time.sleep(2)

            # Phase 2: fetch results
            results_url = f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=20&offset=0"
            resp2 = _requests.get(results_url, headers=headers, timeout=self.timeout)
            if resp2.status_code == 200:
                records = resp2.json().get("records", [])
                print(f"[leaks] IntelX: {len(records)} records")
                for rec in records:
                    result.leaks.append(LeakEntry(
                        source="IntelX",
                        database=rec.get("bucket", ""),
                        raw=rec.get("name", ""),
                    ))
        except Exception as e:
            print(f"[leaks] IntelX error: {e}")

    def _dehashed(self, result: LeakSearchResult) -> None:
        """DeHashed — requires paid subscription."""
        try:
            result.sources_checked.append("DeHashed")
            url = "https://api.dehashed.com/search"
            params = {"query": self.query, "size": 20}
            resp = _requests.get(
                url,
                params=params,
                auth=(self.dehashed_email, self.dehashed_api_key),
                headers={"Accept": "application/json"},
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("entries", []) or []
                print(f"[leaks] DeHashed: {data.get('total', len(entries))} records")
                for entry in entries[:20]:
                    result.leaks.append(LeakEntry(
                        source="DeHashed",
                        email=entry.get("email", ""),
                        username=entry.get("username", ""),
                        password=entry.get("password", ""),
                        hash_value=entry.get("hashed_password", ""),
                        database=entry.get("database_name", ""),
                        ip_address=entry.get("ip_address", ""),
                        phone=entry.get("phone", ""),
                        address=entry.get("address", ""),
                    ))
            elif resp.status_code == 401:
                print("[leaks] DeHashed: Invalid credentials")
            elif resp.status_code == 429:
                print("[leaks] DeHashed: Rate limited")
        except Exception as e:
            print(f"[leaks] DeHashed error: {e}")

    def _dork_search(self, result: LeakSearchResult) -> None:
        """Generate useful dorks for manual Pastebin/GitHub search."""
        result.sources_checked.append("Dork URLs (manual)")
        import urllib.parse

        q = urllib.parse.quote(self.query)
        dork_urls = [
            f"https://www.google.com/search?q=site:pastebin.com+{q}",
            f"https://www.google.com/search?q=site:github.com+{q}",
            f"https://www.google.com/search?q=site:rentry.co+{q}",
            f"https://www.google.com/search?q=site:controlc.com+{q}",
            f"https://www.google.com/search?q=site:justpaste.it+{q}",
        ]

        if "@" in self.query:
            dork_urls.append(
                f"https://www.google.com/search?q=%22{q}%22+%22password%22"
            )

        result.dork_urls = dork_urls
        print(f"[leaks] Generated {len(dork_urls)} dork URLs for manual investigation")

    @staticmethod
    def print_result(result: LeakSearchResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Leak Search — '{result.query}' ═══[/bold cyan]")
            console.print(f"Sources checked: {', '.join(result.sources_checked)}")
            console.print(f"Total entries: [bold red]{result.total_found}[/bold red]\n")

            if result.leaks:
                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("Source", style="yellow", width=18)
                t.add_column("Email", style="cyan", width=28)
                t.add_column("Username", width=18)
                t.add_column("Database", style="dim", width=20)
                t.add_column("Has Hash/PW", width=12)
                for leak in result.leaks[:30]:
                    has_cred = "✅" if (leak.password or leak.hash_value) else "—"
                    t.add_row(
                        leak.source,
                        leak.email[:28] or "—",
                        leak.username[:18] or "—",
                        leak.database[:20] or leak.raw[:20] or "—",
                        has_cred,
                    )
                console.print(t)

            if result.dork_urls:
                console.print("\n[bold]🔗 Manual investigation dork URLs:[/bold]")
                for url in result.dork_urls:
                    console.print(f"  {url}")
        except ImportError:
            print(f"\nLeaks for '{result.query}': {result.total_found} found")
            for leak in result.leaks:
                print(f"  [{leak.source}] {leak.email} {leak.database}")

    @staticmethod
    def to_dict(result: LeakSearchResult) -> dict:
        return {
            "query": result.query,
            "query_type": result.query_type,
            "total_found": result.total_found,
            "sources_checked": result.sources_checked,
            "leaks": [
                {
                    "source": l.source,
                    "email": l.email,
                    "username": l.username,
                    "database": l.database,
                    "has_password": bool(l.password),
                    "has_hash": bool(l.hash_value),
                    "raw": l.raw[:200],
                }
                for l in result.leaks
            ],
            "dork_urls": result.dork_urls,
        }
