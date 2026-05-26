"""
OSINPY — Email OSINT Module
- Account existence check across major platforms (holehe-style)
- HaveIBeenPwned breach check (optional API key)
- Hunter.io email finder for domain (optional API key)
- BreachDirectory public lookup
"""

from __future__ import annotations
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Email validators ─────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email.strip()))


# ── Platform checks (holehe-style, no key) ──────────────────────────────────
# Each entry: name -> {method, url, data/params, check}

_PLATFORM_CHECKS: list[dict] = [
    {
        "name": "Adobe",
        "url": "https://auth.services.adobe.com/en_US/index.html",
        "method": "GET",
        "check_type": "url_contains",
        "payload": {},
    },
    {
        "name": "Amazon",
        "url": "https://www.amazon.com/ap/signin",
        "method": "GET",
        "check_type": "skip",
        "payload": {},
    },
    {
        "name": "GitHub",
        "url": "https://github.com/password_reset",
        "method": "POST",
        "data": {"authenticity_token": "", "email": "{email}"},
        "check_type": "text_absent",
        "text": "We'll send you an email",
    },
    {
        "name": "Twitter/X",
        "url": "https://api.twitter.com/i/users/email_available.json",
        "method": "GET",
        "params": {"email": "{email}"},
        "check_type": "json_field",
        "field": "valid",
        "negate": True,   # valid=false means email is taken
    },
    {
        "name": "Firefox Accounts",
        "url": "https://api.accounts.firefox.com/v1/account/status",
        "method": "POST",
        "json": {"email": "{email}"},
        "check_type": "json_field",
        "field": "exists",
    },
    {
        "name": "Spotify",
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account",
        "method": "GET",
        "params": {"validate": "1", "email": "{email}"},
        "check_type": "json_field",
        "field": "status",
        "value": 20,
        "negate": True,  # status!=20 means it exists
    },
    {
        "name": "Lastpass",
        "url": "https://lastpass.com/create_account.php",
        "method": "POST",
        "data": {"skipemail": "1", "email": "{email}"},
        "check_type": "text_absent",
        "text": "created",
    },
    {
        "name": "Duolingo",
        "url": "https://www.duolingo.com/2017-06-30/users",
        "method": "GET",
        "params": {"email": "{email}"},
        "check_type": "json_list_nonempty",
        "field": "users",
    },
    {
        "name": "Proton Mail",
        "url": "https://api.proton.me/core/v4/users",
        "method": "GET",
        "params": {"Email": "{email}"},
        "check_type": "json_field",
        "field": "Code",
        "value": 1000,
        "negate": True,
    },
]


@dataclass
class EmailPlatformResult:
    platform: str
    exists: bool
    method: str = ""
    error: str = ""


@dataclass
class BreachEntry:
    name: str
    breach_date: str = ""
    data_classes: list[str] = field(default_factory=list)
    description: str = ""
    is_verified: bool = False


@dataclass
class EmailOSINTResult:
    email: str
    domain: str = ""
    is_valid: bool = True
    # Platform checks
    platform_results: list[EmailPlatformResult] = field(default_factory=list)
    found_on: list[str] = field(default_factory=list)
    # Breach data
    breaches: list[BreachEntry] = field(default_factory=list)
    paste_count: int = 0
    breach_count: int = 0
    # Hunter.io domain email discovery
    domain_emails: list[str] = field(default_factory=list)
    domain_email_pattern: str = ""


class EmailOSINT:
    """
    Multi-source email OSINT:
    - Holehe-style account existence checks across major platforms
    - HaveIBeenPwned breach lookup (API key optional)
    - Hunter.io domain email discovery (API key optional)
    - BreachDirectory.org public lookup
    """

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Accept": "application/json, text/html",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self, email: str, hibp_key: str | None = None,
                 hunter_key: str | None = None, timeout: int = 10):
        self.email = email.strip().lower()
        self.domain = self.email.split("@")[-1] if "@" in self.email else ""
        self.hibp_key = hibp_key
        self.hunter_key = hunter_key
        self.timeout = timeout

    def run(self) -> EmailOSINTResult:
        result = EmailOSINTResult(
            email=self.email,
            domain=self.domain,
            is_valid=is_valid_email(self.email),
        )

        if not result.is_valid:
            print(f"[email] ❌ Invalid email format: {self.email}")
            return result

        if not HAS_REQUESTS:
            print("[email] ⚠️  requests not installed.")
            return result

        print(f"\n[email] 🔍 Investigating {self.email}...")

        # Run platform checks
        self._platform_checks(result)

        # HIBP breach check
        self._hibp_check(result)

        # BreachDirectory public check
        self._breachdirectory_check(result)

        # Hunter.io domain email discovery
        if self.hunter_key and self.domain:
            self._hunter_domain_search(result)

        print(f"[email] ✅ Done. Found on {len(result.found_on)} platforms, "
              f"{result.breach_count} breaches.")
        return result

    def _platform_checks(self, result: EmailOSINTResult) -> None:
        """Run holehe-style checks across defined platforms."""
        def check_one(cfg: dict) -> EmailPlatformResult:
            name = cfg["name"]
            if cfg.get("check_type") == "skip":
                return EmailPlatformResult(platform=name, exists=False)
            try:
                url = cfg["url"]
                method = cfg.get("method", "GET").upper()
                params = {k: v.replace("{email}", self.email)
                          for k, v in cfg.get("params", {}).items()}
                data = {k: v.replace("{email}", self.email)
                        for k, v in cfg.get("data", {}).items()}
                json_body = None
                if cfg.get("json"):
                    json_body = {k: (v.replace("{email}", self.email) if isinstance(v, str) else v)
                                 for k, v in cfg["json"].items()}

                if method == "GET":
                    resp = _requests.get(url, params=params, headers=self.HEADERS,
                                          timeout=self.timeout, allow_redirects=True)
                else:
                    resp = _requests.post(url, params=params, data=data or None,
                                           json=json_body, headers=self.HEADERS,
                                           timeout=self.timeout, allow_redirects=True)

                ctype = cfg.get("check_type", "status_200")
                exists = False

                if ctype == "json_field":
                    try:
                        d = resp.json()
                        val = d.get(cfg["field"])
                        if "value" in cfg:
                            exists = (val == cfg["value"])
                        else:
                            exists = bool(val)
                        if cfg.get("negate"):
                            exists = not exists
                    except Exception:
                        exists = False
                elif ctype == "json_list_nonempty":
                    try:
                        d = resp.json()
                        exists = len(d.get(cfg["field"], [])) > 0
                    except Exception:
                        exists = False
                elif ctype == "text_absent":
                    exists = cfg.get("text", "") not in resp.text
                elif ctype == "text_present":
                    exists = cfg.get("text", "") in resp.text
                elif ctype == "status_200":
                    exists = resp.status_code == 200

                return EmailPlatformResult(platform=name, exists=exists)
            except Exception as e:
                return EmailPlatformResult(platform=name, exists=False, error=str(e)[:60])

        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(check_one, cfg): cfg["name"] for cfg in _PLATFORM_CHECKS}
            for fut in as_completed(futures):
                pr = fut.result()
                result.platform_results.append(pr)
                if pr.exists:
                    result.found_on.append(pr.platform)

    def _hibp_check(self, result: EmailOSINTResult) -> None:
        """HaveIBeenPwned breach check. Free tier available without API key for v2."""
        try:
            headers = dict(self.HEADERS)
            headers["hibp-api-key"] = self.hibp_key or ""
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}?truncateResponse=false"
            resp = _requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 200:
                for b in resp.json():
                    result.breaches.append(BreachEntry(
                        name=b.get("Name", ""),
                        breach_date=b.get("BreachDate", ""),
                        data_classes=b.get("DataClasses", []),
                        description=b.get("Description", "")[:200],
                        is_verified=b.get("IsVerified", False),
                    ))
                result.breach_count = len(result.breaches)
            elif resp.status_code == 404:
                print("[email] HIBP: No breaches found ✅")
            elif resp.status_code == 401:
                print("[email] HIBP: API key required for v3. Set HIBP_API_KEY in .env")
            elif resp.status_code == 429:
                print("[email] HIBP: Rate limited, try again later")
        except Exception as e:
            print(f"[email] HIBP error: {e}")

    def _breachdirectory_check(self, result: EmailOSINTResult) -> None:
        """BreachDirectory public search (no key, limited results)."""
        try:
            url = f"https://breachdirectory.org/api?func=auto&term={self.email}"
            resp = _requests.get(url, headers=self.HEADERS, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("found") and not result.breach_count:
                    result.breach_count = data.get("found", 0)
                    print(f"[email] BreachDirectory: {result.breach_count} records found")
        except Exception as e:
            print(f"[email] BreachDirectory error: {e}")

    def _hunter_domain_search(self, result: EmailOSINTResult) -> None:
        """Hunter.io domain email discovery (requires free API key)."""
        try:
            url = "https://api.hunter.io/v2/domain-search"
            params = {"domain": self.domain, "api_key": self.hunter_key, "limit": 20}
            resp = _requests.get(url, params=params, timeout=self.timeout)
            data = resp.json().get("data", {})
            result.domain_email_pattern = data.get("pattern", "")
            for email_obj in data.get("emails", []):
                result.domain_emails.append(email_obj.get("value", ""))
            print(f"[email] Hunter.io: {len(result.domain_emails)} emails found for {self.domain}")
        except Exception as e:
            print(f"[email] Hunter.io error: {e}")

    @staticmethod
    def print_result(result: EmailOSINTResult) -> None:
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Email OSINT — {result.email} ═══[/bold cyan]\n")

            if result.found_on:
                console.print(f"[bold green]✅ Accounts found on:[/bold green] {', '.join(result.found_on)}\n")
            else:
                console.print("[dim]No platform accounts detected.\n[/dim]")

            if result.breaches:
                console.print(f"[bold red]⚠️  Found in {result.breach_count} breach(es):[/bold red]")
                t = Table(box=box.SIMPLE, show_header=True)
                t.add_column("Breach", style="red", width=25)
                t.add_column("Date", width=12)
                t.add_column("Data Types", style="dim")
                for b in result.breaches[:15]:
                    t.add_row(b.name, b.breach_date, ", ".join(b.data_classes[:5]))
                console.print(t)
            elif result.breach_count:
                console.print(f"[bold red]⚠️  Found in {result.breach_count} breach records[/bold red]")
            else:
                console.print("[green]✅ No breaches found[/green]")

            if result.domain_emails:
                console.print(f"\n[bold]📧 Emails on {result.domain} (Hunter.io):[/bold]")
                for e in result.domain_emails:
                    console.print(f"  • {e}")
        except ImportError:
            print(f"\nEmail: {result.email}")
            print(f"Found on: {', '.join(result.found_on) or 'none'}")
            print(f"Breaches: {result.breach_count}")

    @staticmethod
    def to_dict(result: EmailOSINTResult) -> dict:
        return {
            "email": result.email,
            "domain": result.domain,
            "found_on": result.found_on,
            "breach_count": result.breach_count,
            "breaches": [
                {"name": b.name, "date": b.breach_date, "data_classes": b.data_classes}
                for b in result.breaches
            ],
            "domain_emails": result.domain_emails,
            "domain_email_pattern": result.domain_email_pattern,
        }
