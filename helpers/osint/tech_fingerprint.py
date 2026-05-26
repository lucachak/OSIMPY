"""
OSINPY — Tech Fingerprinting Module
Identifies technologies, CMS, frameworks, security posture.
Wappalyzer-style detection via HTTP headers + HTML patterns.
No API key required.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Fingerprint signatures ────────────────────────────────────────────────────
# Format: category -> list of (name, detection_dict)
# detection: header:<header_name>:<pattern> | html:<pattern> | url:<pattern>

SIGNATURES: list[dict] = [
    # ── CMS ──────────────────────────────────────────────────────────────────
    {"name": "WordPress",       "cat": "CMS",       "html": [r"wp-content", r"wp-includes", r"/wp-json/"], "header": []},
    {"name": "Joomla",          "cat": "CMS",       "html": [r"/media/jui/", r"Joomla!"], "header": []},
    {"name": "Drupal",          "cat": "CMS",       "html": [r"Drupal\.settings", r"/sites/default/files/"], "header": [("x-generator", r"Drupal")]},
    {"name": "Magento",         "cat": "CMS",       "html": [r"Mage\.Cookies", r"/skin/frontend/"], "header": []},
    {"name": "Shopify",         "cat": "CMS",       "html": [r"cdn\.shopify\.com", r"Shopify\.theme"], "header": [("x-shopify-stage", r".")]},
    {"name": "Ghost",           "cat": "CMS",       "html": [r"ghost\.io", r"/ghost/"], "header": []},
    {"name": "Wix",             "cat": "CMS",       "html": [r"static\.wixstatic\.com", r"wixsite\.com"], "header": []},
    {"name": "Squarespace",     "cat": "CMS",       "html": [r"squarespace\.com", r"static1\.squarespace"], "header": []},
    {"name": "Webflow",         "cat": "CMS",       "html": [r"webflow\.com"], "header": []},
    {"name": "Contentful",      "cat": "CMS",       "html": [r"ctfassets\.net"], "header": []},
    {"name": "Hugo",            "cat": "CMS",       "html": [r"Hugo"], "header": [("x-generator", r"Hugo")]},
    {"name": "Jekyll",          "cat": "CMS",       "html": [r"jekyll"], "header": [("x-generator", r"Jekyll")]},

    # ── Web Frameworks ─────────────────────────────────────────────────────
    {"name": "Laravel",         "cat": "Framework", "html": [r"laravel_session", r"laravel"], "cookie": ["laravel_session"], "header": []},
    {"name": "Django",          "cat": "Framework", "html": [], "cookie": ["csrftoken", "sessionid"], "header": []},
    {"name": "Ruby on Rails",   "cat": "Framework", "html": [r"csrf-token"], "header": [("x-runtime", r"\d+\.\d+"), ("x-powered-by", r"Phusion Passenger")]},
    {"name": "ASP.NET",         "cat": "Framework", "html": [r"__VIEWSTATE", r"__EVENTVALIDATION"], "cookie": ["ASP.NET_SessionId", ".ASPXAUTH"], "header": [("x-aspnet-version", r"."), ("x-powered-by", r"ASP\.NET")]},
    {"name": "Express.js",      "cat": "Framework", "html": [], "header": [("x-powered-by", r"Express")]},
    {"name": "Next.js",         "cat": "Framework", "html": [r"__NEXT_DATA__", r"_next/static"], "header": [("x-powered-by", r"Next\.js")]},
    {"name": "Nuxt.js",         "cat": "Framework", "html": [r"__nuxt", r"_nuxt/"], "header": []},
    {"name": "Angular",         "cat": "Framework", "html": [r"ng-version=", r"angular\.js"], "header": []},
    {"name": "React",           "cat": "Framework", "html": [r"react\.development\.js", r"react-root", r"__react"], "header": []},
    {"name": "Vue.js",          "cat": "Framework", "html": [r"vue\.js", r"__vue__", r"v-app"], "header": []},
    {"name": "Svelte",          "cat": "Framework", "html": [r"svelte-", r"__svelte"], "header": []},

    # ── Server / Runtime ───────────────────────────────────────────────────
    {"name": "Apache",          "cat": "Web Server","html": [], "header": [("server", r"Apache")]},
    {"name": "Nginx",           "cat": "Web Server","html": [], "header": [("server", r"nginx")]},
    {"name": "IIS",             "cat": "Web Server","html": [], "header": [("server", r"Microsoft-IIS"), ("x-powered-by", r"ASP\.NET")]},
    {"name": "LiteSpeed",       "cat": "Web Server","html": [], "header": [("server", r"LiteSpeed")]},
    {"name": "Caddy",           "cat": "Web Server","html": [], "header": [("server", r"Caddy")]},
    {"name": "Cloudflare",      "cat": "CDN/Proxy", "html": [], "header": [("server", r"cloudflare"), ("cf-ray", r".")]},
    {"name": "Vercel",          "cat": "Hosting",   "html": [], "header": [("x-vercel-id", r".")]},
    {"name": "Netlify",         "cat": "Hosting",   "html": [], "header": [("server", r"Netlify"), ("x-nf-request-id", r".")]},
    {"name": "GitHub Pages",    "cat": "Hosting",   "html": [], "header": [("server", r"GitHub\.com")]},
    {"name": "AWS S3",          "cat": "Hosting",   "html": [], "header": [("server", r"AmazonS3"), ("x-amz-bucket-region", r".")]},
    {"name": "Heroku",          "cat": "Hosting",   "html": [], "header": [("via", r"1\.1 vegur")]},

    # ── Language indicators ────────────────────────────────────────────────
    {"name": "PHP",             "cat": "Language",  "html": [], "header": [("x-powered-by", r"PHP"), ("set-cookie", r"PHPSESSID")]},
    {"name": "Python",          "cat": "Language",  "html": [], "header": [("x-powered-by", r"Python")]},
    {"name": "Java",            "cat": "Language",  "html": [], "cookie": ["JSESSIONID"], "header": [("x-powered-by", r"JSP")]},
    {"name": "Node.js",         "cat": "Language",  "html": [], "header": [("x-powered-by", r"Express|Node")]},

    # ── Analytics / Marketing ─────────────────────────────────────────────
    {"name": "Google Analytics","cat": "Analytics", "html": [r"google-analytics\.com/analytics\.js", r"gtag\(", r"UA-\d{6,}-\d"]},
    {"name": "Google Tag Mgr",  "cat": "Analytics", "html": [r"googletagmanager\.com/gtm\.js", r"GTM-"]},
    {"name": "Hotjar",          "cat": "Analytics", "html": [r"hotjar\.com"]},
    {"name": "Matomo",          "cat": "Analytics", "html": [r"matomo\.js", r"piwik\.js"]},
    {"name": "Segment",         "cat": "Analytics", "html": [r"cdn\.segment\.com", r"analytics\.js"]},
    {"name": "Intercom",        "cat": "Support",   "html": [r"intercom\.io", r"widget\.intercom"]},
    {"name": "Zendesk",         "cat": "Support",   "html": [r"zendesk\.com", r"zdassets\.com"]},
    {"name": "HubSpot",         "cat": "Marketing", "html": [r"js\.hs-scripts\.com", r"hubspot\.com"]},

    # ── JS Libraries ──────────────────────────────────────────────────────
    {"name": "jQuery",          "cat": "JS Lib",    "html": [r"jquery\.min\.js", r"jquery-\d"]},
    {"name": "Bootstrap",       "cat": "CSS Lib",   "html": [r"bootstrap\.min\.css", r"bootstrap\.bundle"]},
    {"name": "Tailwind CSS",    "cat": "CSS Lib",   "html": [r"tailwindcss", r"cdn\.tailwindcss"]},
    {"name": "Lodash",          "cat": "JS Lib",    "html": [r"lodash\.min\.js"]},
    {"name": "Axios",           "cat": "JS Lib",    "html": [r"axios\.min\.js"]},

    # ── Payment / E-commerce ──────────────────────────────────────────────
    {"name": "Stripe",          "cat": "Payment",   "html": [r"js\.stripe\.com"]},
    {"name": "PayPal",          "cat": "Payment",   "html": [r"paypalobjects\.com", r"paypal\.com/sdk"]},
    {"name": "Braintree",       "cat": "Payment",   "html": [r"braintreepayments\.com"]},
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

_INTERESTING_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/humans.txt",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/favicon.ico",
    "/.git/HEAD",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/.env",
    "/wp-config.php",
    "/web.config",
]


@dataclass
class TechDetection:
    name: str
    category: str
    version: str = ""
    confidence: str = "medium"  # low | medium | high


@dataclass
class TechFingerprintResult:
    target: str
    url: str = ""
    status_code: int = 0
    server: str = ""
    technologies: list[TechDetection] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    security_score: int = 0   # 0-100
    cookies: list[str] = field(default_factory=list)
    interesting_files: list[str] = field(default_factory=list)
    raw_headers: dict[str, str] = field(default_factory=dict)
    title: str = ""
    cms: str = ""


class TechFingerprint:
    """
    Detects technologies, frameworks, CMS, analytics, CDN and security posture
    from a single HTTP request + optional file probing.
    """

    def __init__(self, target: str, probe_files: bool = True, timeout: int = 10):
        self.target = target.strip()
        self.probe_files = probe_files
        self.timeout = timeout
        # Normalise URL
        if not self.target.startswith(("http://", "https://")):
            self.base_url = f"https://{self.target}"
        else:
            self.base_url = self.target

    def run(self) -> TechFingerprintResult:
        if not HAS_REQUESTS:
            print("[tech] ⚠️  requests not installed.")
            return TechFingerprintResult(target=self.target)

        print(f"\n[tech] 🔍 Fingerprinting {self.base_url}...")
        result = TechFingerprintResult(target=self.target, url=self.base_url)

        # Main page fetch
        html, headers, cookies = self._fetch(self.base_url)
        if html is None:
            # Try HTTP fallback
            http_url = self.base_url.replace("https://", "http://")
            html, headers, cookies = self._fetch(http_url)

        if html is None:
            print("[tech] ❌ Target unreachable.")
            return result

        result.raw_headers = dict(headers)
        result.server = headers.get("server", headers.get("Server", ""))
        result.cookies = cookies

        # Extract page title
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        result.title = m.group(1).strip()[:120] if m else ""

        # Detect technologies
        self._detect(html, headers, cookies, result)

        # Security headers audit
        self._audit_security(headers, result)

        # Probe interesting files
        if self.probe_files:
            self._probe_files(result)

        # Determine primary CMS
        cms_techs = [t for t in result.technologies if t.category == "CMS"]
        if cms_techs:
            result.cms = cms_techs[0].name

        print(f"[tech] ✅ Detected {len(result.technologies)} technologies. "
              f"Security score: {result.security_score}/100")
        return result

    def _fetch(self, url: str) -> tuple[str | None, dict, list[str]]:
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
        try:
            resp = _requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )
            cookies = [f"{c.name}={c.value[:30]}" for c in resp.cookies]
            return resp.text, dict(resp.headers), cookies
        except Exception as e:
            print(f"[tech] Fetch error for {url}: {e}")
            return None, {}, []

    def _detect(self, html: str, headers: dict, cookies: list[str],
                result: TechFingerprintResult) -> None:
        # Normalise headers to lowercase keys
        h_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies_str = " ".join(cookies).lower()

        seen = set()
        for sig in SIGNATURES:
            name = sig["name"]
            if name in seen:
                continue

            matched = False
            confidence = "low"

            # HTML patterns
            for pattern in sig.get("html", []):
                if re.search(pattern, html, re.IGNORECASE):
                    matched = True
                    confidence = "high"
                    break

            # Header patterns
            if not matched:
                for hname, pattern in sig.get("header", []):
                    val = h_lower.get(hname.lower(), "")
                    if val and re.search(pattern, val, re.IGNORECASE):
                        matched = True
                        confidence = "medium"
                        break

            # Cookie patterns
            if not matched:
                for cookie_name in sig.get("cookie", []):
                    if cookie_name.lower() in cookies_str:
                        matched = True
                        confidence = "medium"
                        break

            if matched:
                seen.add(name)
                # Try to extract version
                version = self._extract_version(name, html, h_lower)
                result.technologies.append(TechDetection(
                    name=name,
                    category=sig.get("cat", "Unknown"),
                    version=version,
                    confidence=confidence,
                ))

    def _extract_version(self, tech: str, html: str, headers: dict) -> str:
        """Try to extract version number for common technologies."""
        patterns = {
            "WordPress": [r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)",
                          r'content="WordPress ([\d.]+)"'],
            "jQuery":    [r"jquery-([\d.]+)\.min\.js", r"jQuery v([\d.]+)"],
            "Bootstrap": [r"bootstrap/([\d.]+)/css", r"Bootstrap v([\d.]+)"],
            "PHP":       [r"PHP/([\d.]+)"],
            "Apache":    [r"Apache/([\d.]+)"],
            "Nginx":     [r"nginx/([\d.]+)"],
            "IIS":       [r"Microsoft-IIS/([\d.]+)"],
        }
        server_header = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        search_in = html + " " + server_header + " " + x_powered

        for pattern in patterns.get(tech, []):
            m = re.search(pattern, search_in, re.IGNORECASE)
            if m:
                return m.group(1)
        return ""

    def _audit_security(self, headers: dict, result: TechFingerprintResult) -> None:
        """Audit security headers and compute a score."""
        h_lower = {k.lower(): v for k, v in headers.items()}
        score = 0
        per_header = 100 // len(_SECURITY_HEADERS)

        for sh in _SECURITY_HEADERS:
            val = h_lower.get(sh, "")
            result.security_headers[sh] = val if val else "MISSING"
            if val:
                score += per_header

        result.security_score = min(score, 100)

    def _probe_files(self, result: TechFingerprintResult) -> None:
        """Check for the presence of interesting/sensitive files."""
        import urllib3
        try:
            urllib3.disable_warnings()
        except Exception:
            pass

        base = self.base_url.rstrip("/")
        for path in _INTERESTING_FILES:
            try:
                resp = _requests.get(
                    base + path,
                    timeout=4,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if resp.status_code in (200, 301, 302):
                    result.interesting_files.append(
                        f"{path} [{resp.status_code}]"
                    )
            except Exception:
                pass

    @staticmethod
    def print_result(result: TechFingerprintResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Tech Fingerprint — {result.target} ═══[/bold cyan]")
            if result.title:
                console.print(f"[dim]Title: {result.title}[/dim]")
            if result.server:
                console.print(f"[dim]Server: {result.server}[/dim]")
            console.print()

            # Technologies by category
            cats: dict[str, list] = {}
            for t in result.technologies:
                cats.setdefault(t.category, []).append(t)

            if cats:
                t_table = Table(box=box.SIMPLE, show_header=True)
                t_table.add_column("Category", style="bold yellow", width=15)
                t_table.add_column("Technology", style="green", width=22)
                t_table.add_column("Version", style="cyan", width=12)
                t_table.add_column("Confidence", style="dim", width=10)
                for cat, techs in sorted(cats.items()):
                    for tech in techs:
                        t_table.add_row(cat, tech.name, tech.version or "—", tech.confidence)
                console.print("[bold]🔬 Technologies Detected:[/bold]")
                console.print(t_table)
            else:
                console.print("[dim]No technologies detected.[/dim]")

            # Security score
            score = result.security_score
            color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
            console.print(f"\n[bold]🔒 Security Header Score:[/bold] [{color}]{score}/100[/{color}]")
            for sh, val in result.security_headers.items():
                if val == "MISSING":
                    console.print(f"  [red]✗ {sh}[/red]")
                else:
                    console.print(f"  [green]✓ {sh}[/green]: {val[:60]}")

            # Interesting files
            if result.interesting_files:
                console.print(f"\n[bold red]⚠️  Interesting files found:[/bold red]")
                for f in result.interesting_files:
                    console.print(f"  • {result.url.rstrip('/')}{f}")

            # Cookies
            if result.cookies:
                console.print(f"\n[bold]🍪 Cookies:[/bold] {', '.join(result.cookies[:8])}")

        except ImportError:
            print(f"\nTarget: {result.target}")
            print(f"Technologies: {[t.name for t in result.technologies]}")
            print(f"Security score: {result.security_score}/100")
            print(f"Interesting files: {result.interesting_files}")

    @staticmethod
    def to_dict(result: TechFingerprintResult) -> dict:
        return {
            "target": result.target,
            "url": result.url,
            "title": result.title,
            "server": result.server,
            "cms": result.cms,
            "technologies": [
                {"name": t.name, "category": t.category, "version": t.version,
                 "confidence": t.confidence}
                for t in result.technologies
            ],
            "security_score": result.security_score,
            "security_headers": result.security_headers,
            "interesting_files": result.interesting_files,
            "cookies": result.cookies,
        }
