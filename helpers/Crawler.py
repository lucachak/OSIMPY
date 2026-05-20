import http.cookiejar
import re
import asyncio
import time
import random
from pathlib import Path
from urllib import error, parse, request
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    # pyrefly: ignore [missing-import]
    import nodriver as uc
    HAS_NODRIVER = True
except ImportError:
    HAS_NODRIVER = False


@dataclass
class SearchResult:
    url: str
    title: str = ""
    snippet: str = ""
    file_type: str = ""
    source_engine: str = ""


@dataclass
class CrawlerStats:
    total_searches: int = 0
    google_success: int = 0
    duckduckgo_success: int = 0
    nodriver_success: int = 0
    total_links_found: int = 0
    total_time: float = 0.0


class Crawler:
    """
    Advanced web crawler for Google Dorks with multiple engines and fallback.

    Engines:
        - nodriver: Real browser via Chrome (bypasses anti-bot)
        - duckduckgo: DuckDuckGo HTML (bot-friendly)
        - urllib: Raw HTTP (fastest, often blocked)
    """

    _nodriver_driver = None
    _nodriver_lock = asyncio.Lock()
    _stats = CrawlerStats()

    def __init__(
        self,
        query: str | None = None,
        engine: str = "auto",
        headless: bool = True,
        max_results: int = 30,
        timeout: int = 20,
        download_dir: str = "./downloads",
        stealth_mode: bool = True,
    ):
        self.query = query
        self.engine = engine
        self.headless = headless
        self.max_results = max_results
        self.timeout = timeout
        self.download_dir = Path(download_dir)
        self.stealth_mode = stealth_mode
        self.results: list[str] = []
        self.links: list[str] = []
        self.structured_results: list[SearchResult] = []
        self._session_start = time.time()
        self._searched = False

        self.download_dir.mkdir(parents=True, exist_ok=True)

    # ============================================================
    # 🔥 NODRIVER ENGINE
    # ============================================================

    async def _get_nodriver_driver(self):
        """Get or create shared nodriver driver (singleton)."""
        async with self._nodriver_lock:
            if self._nodriver_driver is None:
                browser_args = [
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-infobars",
                    "--disable-notifications",
                ]
                if self.stealth_mode:
                    browser_args.extend([
                        "--disable-features=IsolateOrigins,site-per-process",
                        f"--window-size={random.randint(1280,1920)},{random.randint(720,1080)}",
                    ])

                self._nodriver_driver = await uc.start(
                    headless=self.headless,
                    browser_args=browser_args,
                )
        return self._nodriver_driver

    async def nodriver_search(self) -> str | None:
        """Search Google using a real browser via nodriver."""
        if not HAS_NODRIVER:
            print("[nodriver] Not installed. Skipping.")
            return None

        try:
            driver = await self._get_nodriver_driver()
            encoded_query = parse.quote(self.query)
            url = f"https://www.google.com/search?q={encoded_query}&num={self.max_results}"

            print(f"[nodriver] 🔍 Searching: {self.query[:80]}...")
            page = await driver.get(url, new_tab=True)
            await page.wait(random.uniform(1.5, 3.0))

            # Human-like scroll
            await page.evaluate(f"window.scrollBy(0, {random.randint(200, 600)})")
            await page.wait(random.uniform(0.5, 1.5))

            html = await page.get_content()

            # Extract structured results via JavaScript
            structured_json = await page.evaluate("""
                JSON.stringify((() => {
                    const results = [];
                    document.querySelectorAll('.g, [data-sokoban-container]').forEach(el => {
                        const link = el.querySelector('a[href]');
                        const title = el.querySelector('h3');
                        const snippet = el.querySelector('.VwiC3b, .st');
                        if (link) {
                            results.push({
                                url: link.href,
                                title: title?.innerText || '',
                                snippet: snippet?.innerText || ''
                            });
                        }
                    });
                    return results;
                })())
            """)
            import json
            structured = json.loads(structured_json or "[]")

            for item in structured[:self.max_results]:
                url = item.get("url", "")
                if url and not url.startswith(("https://www.google", "https://support.google")):
                    if "/url?q=" in url:
                        url = url.split("/url?q=")[1].split("&")[0]
                    self.structured_results.append(SearchResult(
                        url=url,
                        title=item.get("title", ""),
                        snippet=item.get("snippet", ""),
                        source_engine="nodriver",
                    ))

            self.results.append(html)
            self._stats.nodriver_success += 1
            await page.close()
            print(f"[nodriver] ✅ Found {len(self.structured_results)} results")
            return html

        except Exception as e:
            print(f"[nodriver] ❌ Error: {e}")
            return None

    # ============================================================
    # 🦆 DUCKDUCKGO ENGINE
    # ============================================================

    def duckduckgo_search(self) -> str | None:
        """Search DuckDuckGo (fallback)."""
        url = "https://html.duckduckgo.com/html/"
        data = parse.urlencode({"q": self.query}).encode()

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }

        url_request = request.Request(url, data=data, headers=headers)

        try:
            with request.urlopen(url_request, timeout=self.timeout) as response:
                html = response.read().decode("utf-8", errors="ignore")
            self.results.append(html)
            self._stats.duckduckgo_success += 1
            return html
        except Exception as e:
            print(f"[DuckDuckGo] Error: {e}")
            return None

    # ============================================================
    # 🔗 GOOGLE URLIB ENGINE
    # ============================================================

    def google_search(self) -> str | None:
        """Search Google via urllib (often blocked)."""
        encoded_query = parse.quote(self.query)
        url = f"https://www.google.com/search?q={encoded_query}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        }

        cookie_jar = http.cookiejar.CookieJar()
        opener = request.build_opener(request.HTTPCookieProcessor(cookie_jar))

        try:
            req_home = request.Request("https://www.google.com", headers=headers)
            opener.open(req_home, timeout=5)

            req_search = request.Request(url, headers=headers)
            with opener.open(req_search, timeout=self.timeout) as response:
                html = response.read().decode("utf-8", errors="ignore")

            if "retry/enablejs" in html or "nossl" in html:
                raise Exception("Blocked by Google (JS challenge)")

            self.results.append(html)
            self._stats.google_success += 1
            return html
        except Exception as e:
            print(f"[Google/urllib] Error: {e}")
            return None

    def yahoo_search(self) -> str | None:
        """Search Yahoo via urllib and extract target URLs from redirects."""
        try:
            import re
            encoded_query = parse.quote(self.query)
            url = f"https://search.yahoo.com/search?p={encoded_query}"
            req = request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            with request.urlopen(req, timeout=10) as response:
                html = response.read().decode("utf-8")
                
                # Extract all r.search.yahoo.com links
                raw_redirects = re.findall(r'href="(https://r\.search\.yahoo\.com/[^"]+)"', html)
                
                extracted_urls = []
                for redirect in raw_redirects:
                    if "/RU=" in redirect:
                        try:
                            ru_part = redirect.split("/RU=")[1].split("/RK=")[0]
                            real_url = parse.unquote(ru_part)
                            # Basic validation: ensure it's a real target URL
                            if real_url.startswith("http") and "yahoo.com" not in real_url:
                                extracted_urls.append(real_url)
                        except Exception:
                            continue
                
                # Store structured results if we got them
                if extracted_urls:
                    for target_url in extracted_urls:
                        self.structured_results.append(SearchResult(
                            url=target_url,
                            title="Yahoo Result",
                            snippet="Organic result from Yahoo Search",
                            source_engine="yahoo",
                        ))
                    self._stats.google_success += 1  # Track success using existing stat slot
                    print(f"[yahoo] ✅ Found {len(extracted_urls)} results")
                    return html
                else:
                    return None
        except Exception as e:
            print(f"[yahoo] Error: {e}")
            return None

    # ============================================================
    # 🎯 SMART SEARCH
    # ============================================================

    async def search(self) -> list[str]:
        """Smart search with automatic engine selection and fallback."""
        self._searched = True
        self._session_start = time.time()
        self._stats.total_searches += 1

        if self.query is None:
            print("[!] No query provided.")
            return []

        html = None
        engines_to_try = []

        if self.engine in ("auto", "nodriver"):
            engines_to_try.append(("nodriver", self.nodriver_search))
        if self.engine in ("auto", "duckduckgo"):
            engines_to_try.append(("duckduckgo", lambda: asyncio.to_thread(self.duckduckgo_search)))
        if self.engine in ("auto", "google"):
            engines_to_try.append(("google", lambda: asyncio.to_thread(self.google_search)))
        if self.engine in ("auto", "yahoo"):
            engines_to_try.append(("yahoo", lambda: asyncio.to_thread(self.yahoo_search)))

        for engine_name, engine_func in engines_to_try:
            print(f"[*] Trying {engine_name}...")
            try:
                if engine_name == "nodriver":
                    html = await engine_func()
                else:
                    html = await engine_func()
                
                # Extract links immediately to check if we got valid organic results
                current_links = []
                if html:
                    current_links = self.extract_links(html)
                if self.structured_results:
                    current_links.extend([r.url for r in self.structured_results])
                
                # Filter unique links
                current_links = list(dict.fromkeys(current_links))
                # Remove common Google search/login redirect URLs
                current_links = [
                    l for l in current_links 
                    if not any(x in l for x in ["google.com/search", "google.com/ServiceLogin", "duckduckgo.com", "accounts.google.com"])
                ]
                
                if current_links:
                    self.links = current_links
                    print(f"[*] ✅ {engine_name} succeeded (found {len(current_links)} organic links)")
                    break
                else:
                    print(f"[*] ⚠️ {engine_name} returned 0 organic links. Trying fallback...")
            except Exception as e:
                print(f"[*] ❌ {engine_name} failed: {e}")

        if not self.links:
            print("[!] All engines failed to find organic links.")
            self.links = []

        self.links = list(dict.fromkeys(self.links))[:self.max_results]
        self._stats.total_links_found += len(self.links)

        elapsed = time.time() - self._session_start
        self._stats.total_time += elapsed
        print(f"\n[+] Found {len(self.links)} links in {elapsed:.1f}s")

        return self.links

    # ============================================================
    # 🔗 LINK EXTRACTION
    # ============================================================

    # Pre-compiled regular expressions for performance
    _GOOGLE_PATTERN_1 = re.compile(r'href="(/url\?q=)?(https?://[^&"]+)')
    _GOOGLE_PATTERN_2 = re.compile(r'<a[^>]+href="(https?://[^"]+)"')
    _DDG_PATTERN = re.compile(r'<a[^>]+class="result__a"[^>]+href="(https?://[^"]+)"')

    def extract_links(self, html: str) -> list[str]:
        """Extract links from search results HTML using pre-compiled regex."""
        links = []

        # Google patterns
        for match in self._GOOGLE_PATTERN_1.findall(html):
            url = match[1] if isinstance(match, tuple) else match
            if not url.startswith(("https://www.google", "https://support.google")):
                links.append(url)

        for match in self._GOOGLE_PATTERN_2.findall(html):
            url = match if isinstance(match, str) else match[0]
            if not url.startswith(("https://www.google", "https://support.google")):
                links.append(url)

        # DuckDuckGo pattern
        for url in self._DDG_PATTERN.findall(html):
            if url not in links:
                links.append(url)

        return list(dict.fromkeys(links))

    def extract_files(self, extensions: list[str] = None) -> list[str]:
        """Filter links by file extension."""
        if extensions is None:
            return self.links
        return [
            link for link in self.links
            if any(f".{ext}" in link.lower() for ext in extensions)
        ]

    # ============================================================
    # 📥 FILE DOWNLOAD
    # ============================================================

    def download_file(self, url: str, filename: str = None) -> Path | None:
        """Download a file from URL."""
        if filename is None:
            filename = url.split("/")[-1].split("?")[0] or "download"
        filepath = self.download_dir / filename

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            req = request.Request(url, headers=headers)
            with request.urlopen(req, timeout=30) as response:
                data = response.read()
                filepath.write_bytes(data)
                print(f"[📥] Downloaded: {filepath} ({len(data)} bytes)")
                return filepath
        except Exception as e:
            print(f"[!] Download failed for {url}: {e}")
            return None

    def download_all(self, extensions: list[str] = None) -> list[Path]:
        """Download all found files concurrently using a ThreadPoolExecutor."""
        links = self.extract_files(extensions) if extensions else self.links
        downloaded = []

        print(f"\n[📥] Downloading {len(links)} files in parallel...")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.download_file, link): link for link in links}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        downloaded.append(result)
                except Exception as e:
                    print(f"[!] Thread error for {url}: {e}")

        print(f"[📥] Concurrently downloaded {len(downloaded)}/{len(links)} files.")
        return downloaded

    # ============================================================
    # 📊 STATS & UTILS
    # ============================================================

    @classmethod
    def stats(cls) -> CrawlerStats:
        return cls._stats

    @classmethod
    def reset_stats(cls):
        cls._stats = CrawlerStats()

    async def Normalized(self) -> list[str]:
        """Return normalized links (alias for compatibility)."""
        if not self._searched:
            await self.search()
        return self.links

    @classmethod
    async def close_driver(cls):
        """Close shared nodriver driver."""
        async with cls._nodriver_lock:
            if cls._nodriver_driver is not None:
                await cls._nodriver_driver.aclose()
                cls._nodriver_driver = None

    def __str__(self) -> str:
        return f"Crawler(query='{self.query}', engine={self.engine}, links={len(self.links)})"

    def __repr__(self) -> str:
        return f"Crawler(query={self.query!r}, engine={self.engine!r}, links={len(self.links)})"