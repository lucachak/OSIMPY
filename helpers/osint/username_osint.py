"""
OSINPY — Username OSINT Module
Checks username existence across 60+ platforms concurrently.
No API key required. Pure HTTP.
"""

from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Platform definitions ──────────────────────────────────────────────────────
# Format: name -> (url_template, claim_type, expected_status OR error_text)
# claim_type: "status_200" | "status_not_404" | "text_present" | "text_absent"

PLATFORMS: dict[str, dict] = {
    # Code / Dev
    "GitHub":          {"url": "https://github.com/{}", "check": "status_200"},
    "GitLab":          {"url": "https://gitlab.com/{}", "check": "status_200"},
    "Bitbucket":       {"url": "https://bitbucket.org/{}", "check": "status_200"},
    "Replit":          {"url": "https://replit.com/@{}", "check": "status_200"},
    "Codepen":         {"url": "https://codepen.io/{}", "check": "status_200"},
    "HackerRank":      {"url": "https://www.hackerrank.com/{}", "check": "status_200"},
    "LeetCode":        {"url": "https://leetcode.com/{}", "check": "status_200"},
    "SourceForge":     {"url": "https://sourceforge.net/u/{}", "check": "status_200"},
    "npm":             {"url": "https://www.npmjs.com/~{}", "check": "status_200"},
    "PyPI":            {"url": "https://pypi.org/user/{}", "check": "status_200"},

    # Social
    "Twitter/X":       {"url": "https://twitter.com/{}", "check": "status_200"},
    "Instagram":       {"url": "https://www.instagram.com/{}/", "check": "status_200"},
    "Facebook":        {"url": "https://www.facebook.com/{}", "check": "status_200"},
    "TikTok":          {"url": "https://www.tiktok.com/@{}", "check": "status_200"},
    "Reddit":          {"url": "https://www.reddit.com/user/{}", "check": "status_200"},
    "LinkedIn":        {"url": "https://www.linkedin.com/in/{}", "check": "status_200"},
    "Pinterest":       {"url": "https://www.pinterest.com/{}/", "check": "status_200"},
    "Tumblr":          {"url": "https://{}.tumblr.com", "check": "status_200"},
    "Flickr":          {"url": "https://www.flickr.com/people/{}", "check": "status_200"},
    "VK":              {"url": "https://vk.com/{}", "check": "status_200"},
    "Twitch":          {"url": "https://www.twitch.tv/{}", "check": "status_200"},
    "YouTube":         {"url": "https://www.youtube.com/@{}", "check": "status_200"},
    "Snapchat":        {"url": "https://www.snapchat.com/add/{}", "check": "status_200"},
    "Telegram":        {"url": "https://t.me/{}", "check": "status_200"},
    "Discord":         {"url": "https://discord.com/users/{}", "check": "status_200"},

    # Tech / Community
    "HackerNews":      {"url": "https://news.ycombinator.com/user?id={}", "check": "status_200"},
    "StackOverflow":   {"url": "https://stackoverflow.com/users/{}", "check": "status_not_404"},
    "Dev.to":          {"url": "https://dev.to/{}", "check": "status_200"},
    "Medium":          {"url": "https://medium.com/@{}", "check": "status_200"},
    "Hashnode":        {"url": "https://hashnode.com/@{}", "check": "status_200"},
    "Substack":        {"url": "https://{}.substack.com", "check": "status_200"},
    "Quora":           {"url": "https://www.quora.com/profile/{}", "check": "status_200"},

    # Creative / Portfolio
    "Behance":         {"url": "https://www.behance.net/{}", "check": "status_200"},
    "Dribbble":        {"url": "https://dribbble.com/{}", "check": "status_200"},
    "DeviantArt":      {"url": "https://www.deviantart.com/{}", "check": "status_200"},
    "ArtStation":      {"url": "https://www.artstation.com/{}", "check": "status_200"},
    "500px":           {"url": "https://500px.com/p/{}", "check": "status_200"},
    "SoundCloud":      {"url": "https://soundcloud.com/{}", "check": "status_200"},
    "Bandcamp":        {"url": "https://{}.bandcamp.com", "check": "status_200"},
    "Spotify":         {"url": "https://open.spotify.com/user/{}", "check": "status_200"},
    "Mixcloud":        {"url": "https://www.mixcloud.com/{}/", "check": "status_200"},

    # Gaming
    "Steam":           {"url": "https://steamcommunity.com/id/{}", "check": "status_200"},
    "Chess.com":       {"url": "https://www.chess.com/member/{}", "check": "status_200"},
    "Lichess":         {"url": "https://lichess.org/@/{}", "check": "status_200"},
    "Roblox":          {"url": "https://www.roblox.com/user.aspx?username={}", "check": "status_200"},
    "Minecraft":       {"url": "https://namemc.com/profile/{}", "check": "status_200"},

    # Professional / Education
    "Academia.edu":    {"url": "https://independent.academia.edu/{}", "check": "status_200"},
    "ResearchGate":    {"url": "https://www.researchgate.net/profile/{}", "check": "status_200"},
    "ORCID":           {"url": "https://orcid.org/{}", "check": "status_200"},
    "Lattes CNPq":     {"url": "https://lattes.cnpq.br/{}", "check": "status_not_404"},

    # Misc
    "About.me":        {"url": "https://about.me/{}", "check": "status_200"},
    "Gravatar":        {"url": "https://en.gravatar.com/{}", "check": "status_200"},
    "Keybase":         {"url": "https://keybase.io/{}", "check": "status_200"},
    "Patreon":         {"url": "https://www.patreon.com/{}", "check": "status_200"},
    "Ko-fi":           {"url": "https://ko-fi.com/{}", "check": "status_200"},
    "Buy Me a Coffee": {"url": "https://www.buymeacoffee.com/{}", "check": "status_200"},
    "Product Hunt":    {"url": "https://www.producthunt.com/@{}", "check": "status_200"},
    "Angellist":       {"url": "https://angel.co/u/{}", "check": "status_200"},
    "Trello":          {"url": "https://trello.com/{}", "check": "status_not_404"},
    "DockerHub":       {"url": "https://hub.docker.com/u/{}", "check": "status_200"},
}


@dataclass
class PlatformResult:
    platform: str
    url: str
    found: bool
    status_code: int = 0
    error: str = ""


@dataclass
class UsernameResult:
    username: str
    found: list[PlatformResult] = field(default_factory=list)
    not_found: list[PlatformResult] = field(default_factory=list)
    errors: list[PlatformResult] = field(default_factory=list)
    total_checked: int = 0


class UsernameOSINT:
    """
    Checks a username across 60+ platforms using parallel HTTP requests.
    No API keys required.
    """

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    def __init__(self, username: str, timeout: int = 8, max_workers: int = 30,
                 platforms: list[str] | None = None):
        self.username = username.strip()
        self.timeout = timeout
        self.max_workers = max_workers
        # Optionally filter to specific platforms
        self.platforms = {k: v for k, v in PLATFORMS.items()
                          if platforms is None or k in platforms}

    def run(self) -> UsernameResult:
        if not HAS_REQUESTS:
            print("[username] ⚠️  requests not installed.")
            return UsernameResult(username=self.username)

        print(f"\n[username] 🔍 Checking '{self.username}' across {len(self.platforms)} platforms...")
        result = UsernameResult(username=self.username, total_checked=len(self.platforms))

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {
                ex.submit(self._check, name, cfg): name
                for name, cfg in self.platforms.items()
            }
            for fut in as_completed(futures):
                pres = fut.result()
                if pres.found:
                    result.found.append(pres)
                    print(f"  [bold green]✅ {pres.platform}[/bold green]: {pres.url}" if False
                          else f"  ✅ {pres.platform}: {pres.url}")
                elif pres.error:
                    result.errors.append(pres)
                else:
                    result.not_found.append(pres)

        # Sort alphabetically
        result.found.sort(key=lambda x: x.platform)
        result.not_found.sort(key=lambda x: x.platform)

        print(f"\n[username] Found on {len(result.found)}/{result.total_checked} platforms.")
        return result

    def _check(self, platform: str, cfg: dict) -> PlatformResult:
        url = cfg["url"].format(self.username)
        check = cfg.get("check", "status_200")
        try:
            session = _requests.Session()
            resp = session.get(
                url,
                headers=self.HEADERS,
                timeout=self.timeout,
                allow_redirects=True,
            )
            found = False
            if check == "status_200":
                found = resp.status_code == 200
            elif check == "status_not_404":
                found = resp.status_code not in (404, 410)
            elif check == "text_present":
                found = cfg.get("text", "") in resp.text
            elif check == "text_absent":
                found = cfg.get("text", "") not in resp.text

            return PlatformResult(
                platform=platform,
                url=url,
                found=found,
                status_code=resp.status_code,
            )
        except Exception as e:
            return PlatformResult(
                platform=platform,
                url=url,
                found=False,
                error=str(e)[:60],
            )

    @staticmethod
    def print_result(result: UsernameResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Username OSINT — '{result.username}' ═══[/bold cyan]")
            console.print(f"Checked: {result.total_checked} | "
                          f"[bold green]Found: {len(result.found)}[/bold green] | "
                          f"Not found: {len(result.not_found)} | "
                          f"Errors: {len(result.errors)}\n")

            if result.found:
                console.print("[bold green]✅ FOUND ON:[/bold green]")
                t = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
                t.add_column("Platform", style="bold green", width=20)
                t.add_column("URL", style="cyan")
                for r in result.found:
                    t.add_row(r.platform, r.url)
                console.print(t)

            if result.not_found:
                nf_names = ", ".join(r.platform for r in result.not_found)
                console.print(f"\n[dim]❌ Not found on: {nf_names}[/dim]")
        except ImportError:
            print(f"\nUsername '{result.username}' found on {len(result.found)} platforms:")
            for r in result.found:
                print(f"  ✅ {r.platform:<25} {r.url}")

    @staticmethod
    def to_dict(result: UsernameResult) -> dict:
        return {
            "username": result.username,
            "total_checked": result.total_checked,
            "found_count": len(result.found),
            "found": [{"platform": r.platform, "url": r.url, "status": r.status_code}
                      for r in result.found],
            "not_found": [r.platform for r in result.not_found],
        }
