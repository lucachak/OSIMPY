"""
OSINPY — WHOIS + DNS Lookup Module
Fetches domain registration data and full DNS record set.
No API key required.
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import whois as _whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Known CDN / Hosting signatures ─────────────────────────────────────────

_CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":    ["cloudflare", "1.1.1.1", "104.16.", "104.17.", "104.18.", "104.19.", "104.21."],
    "Fastly":        ["fastly", "151.101."],
    "Akamai":        ["akamai", "akamaitechnologies", "edgekey.net", "edgesuite.net"],
    "AWS CloudFront":["cloudfront.net", "amazonaws.com"],
    "Google":        ["google.com", "googleusercontent.com", "1e100.net"],
    "Azure CDN":     ["azureedge.net", "azurefd.net", "msecnd.net"],
    "Vercel":        ["vercel.app", "vercel-dns.com"],
    "Netlify":       ["netlify.app", "netlify.com"],
    "GitHub Pages":  ["github.io", "githubusercontent.com"],
}

_WAF_HEADERS: dict[str, list[str]] = {
    "Cloudflare":   ["cf-ray", "cf-cache-status", "cf-request-id"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":      ["x-iinfo", "x-cdn"],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "Akamai":       ["x-akamai-transformed", "x-check-cacheable"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id"],
    "F5 BigIP":     ["x-waf-event-info", "bigipserver"],
}


@dataclass
class WhoisResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    dnssec: str = ""
    raw: str = ""


@dataclass
class DNSResult:
    domain: str
    A: list[str] = field(default_factory=list)
    AAAA: list[str] = field(default_factory=list)
    MX: list[str] = field(default_factory=list)
    NS: list[str] = field(default_factory=list)
    TXT: list[str] = field(default_factory=list)
    CNAME: list[str] = field(default_factory=list)
    SOA: str = ""
    cdn_detected: list[str] = field(default_factory=list)
    waf_detected: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)


class WhoisLookup:
    """
    Performs WHOIS lookup + full DNS enumeration on a domain.
    Falls back gracefully if dependencies are missing.
    """

    def __init__(self, domain: str, timeout: int = 10):
        self.domain = domain.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]
        self.timeout = timeout

    # ── Public API ──────────────────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """Run WHOIS + DNS and return combined result dict."""
        print(f"\n[whois] 🔍 Querying {self.domain}...")
        result: dict[str, Any] = {
            "domain": self.domain,
            "whois": {},
            "dns": {},
            "http_headers": {},
            "security_headers": {},
            "cdn": [],
            "waf": [],
        }

        whois_data = self._whois()
        dns_data = self._dns()
        http_data = self._http_probe()

        if whois_data:
            result["whois"] = self._serialize_whois(whois_data)
        if dns_data:
            result["dns"] = self._serialize_dns(dns_data)
        if http_data:
            result["http_headers"] = http_data.get("headers", {})
            result["security_headers"] = http_data.get("security", {})
            result["cdn"] = http_data.get("cdn", [])
            result["waf"] = http_data.get("waf", [])

        # Merge CDN detected from DNS too
        if dns_data and dns_data.cdn_detected:
            for c in dns_data.cdn_detected:
                if c not in result["cdn"]:
                    result["cdn"].append(c)

        return result

    # ── WHOIS ───────────────────────────────────────────────────────────────

    def _whois(self) -> WhoisResult | None:
        if not HAS_WHOIS:
            print("[whois] ⚠️  python-whois not installed. Run: pip install python-whois")
            return None
        try:
            w = _whois.whois(self.domain)
            return WhoisResult(
                domain=self.domain,
                registrar=str(w.registrar or ""),
                creation_date=self._fmt_date(w.creation_date),
                expiration_date=self._fmt_date(w.expiration_date),
                updated_date=self._fmt_date(w.updated_date),
                name_servers=self._listify(w.name_servers),
                status=self._listify(w.status),
                emails=self._listify(w.emails),
                org=str(w.org or ""),
                country=str(w.country or ""),
                dnssec=str(w.dnssec or ""),
                raw=str(w.text or "")[:2000],
            )
        except Exception as e:
            print(f"[whois] Error: {e}")
            return None

    # ── DNS ─────────────────────────────────────────────────────────────────

    def _dns(self) -> DNSResult | None:
        if not HAS_DNSPYTHON:
            # Fallback: resolve via socket
            print("[dns] ⚠️  dnspython not installed. Using socket fallback.")
            return self._dns_socket_fallback()

        result = DNSResult(domain=self.domain)
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
            try:
                answers = resolver.resolve(self.domain, rtype, raise_on_no_answer=False)
                records = []
                for rdata in answers:
                    val = str(rdata)
                    records.append(val)
                    if rtype == "A":
                        result.ip_addresses.append(val)

                if rtype == "A":
                    result.A = records
                elif rtype == "AAAA":
                    result.AAAA = records
                elif rtype == "MX":
                    result.MX = [r.split()[-1] if " " in r else r for r in records]
                elif rtype == "NS":
                    result.NS = records
                elif rtype == "TXT":
                    result.TXT = records
                elif rtype == "CNAME":
                    result.CNAME = records
                elif rtype == "SOA":
                    result.SOA = records[0] if records else ""
            except Exception:
                pass

        # CDN detection
        all_ns = " ".join(result.NS + result.CNAME + result.A).lower()
        for cdn_name, sigs in _CDN_SIGNATURES.items():
            if any(s.lower() in all_ns for s in sigs):
                result.cdn_detected.append(cdn_name)

        return result

    def _dns_socket_fallback(self) -> DNSResult | None:
        result = DNSResult(domain=self.domain)
        try:
            info = socket.getaddrinfo(self.domain, None)
            result.A = list({r[4][0] for r in info if r[0] == socket.AF_INET})
            result.AAAA = list({r[4][0] for r in info if r[0] == socket.AF_INET6})
            result.ip_addresses = result.A + result.AAAA
        except Exception as e:
            print(f"[dns] Socket fallback error: {e}")
        return result

    # ── HTTP Probe ──────────────────────────────────────────────────────────

    def _http_probe(self) -> dict | None:
        if not HAS_REQUESTS:
            return None
        headers_out: dict[str, str] = {}
        security: dict[str, str] = {}
        cdn: list[str] = []
        waf: list[str] = []

        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{self.domain}"
                resp = _requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; OSINPY/2.0)"},
                    verify=False,
                )
                h = {k.lower(): v for k, v in resp.headers.items()}
                headers_out = dict(h)

                # Security headers audit
                sec_headers = [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                    "x-xss-protection",
                ]
                for sh in sec_headers:
                    security[sh] = h.get(sh, "MISSING")

                # WAF detection
                for waf_name, sigs in _WAF_HEADERS.items():
                    if any(s in h for s in sigs):
                        waf.append(waf_name)

                # CDN via headers
                server = h.get("server", "").lower()
                via = h.get("via", "").lower()
                for cdn_name, sigs in _CDN_SIGNATURES.items():
                    if any(s.lower() in server or s.lower() in via for s in sigs):
                        if cdn_name not in cdn:
                            cdn.append(cdn_name)

                break  # success, stop trying
            except Exception:
                continue

        return {"headers": headers_out, "security": security, "cdn": cdn, "waf": waf}

    # ── Helpers ─────────────────────────────────────────────────────────────

    @staticmethod
    def _fmt_date(val: Any) -> str:
        if val is None:
            return ""
        if isinstance(val, list):
            val = val[0]
        try:
            return val.isoformat()
        except Exception:
            return str(val)

    @staticmethod
    def _listify(val: Any) -> list[str]:
        if val is None:
            return []
        if isinstance(val, (list, tuple)):
            return [str(v).lower().strip() for v in val if v]
        return [str(val).lower().strip()]

    @staticmethod
    def _serialize_whois(w: WhoisResult) -> dict:
        return {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
            "dnssec": w.dnssec,
        }

    @staticmethod
    def _serialize_dns(d: DNSResult) -> dict:
        return {
            "A": d.A,
            "AAAA": d.AAAA,
            "MX": d.MX,
            "NS": d.NS,
            "TXT": d.TXT,
            "CNAME": d.CNAME,
            "SOA": d.SOA,
            "ip_addresses": d.ip_addresses,
        }

    # ── Pretty print ────────────────────────────────────────────────────────

    @staticmethod
    def print_result(data: dict) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ WHOIS / DNS — {data['domain']} ═══[/bold cyan]\n")

            # WHOIS
            w = data.get("whois", {})
            if w:
                t = Table(box=box.SIMPLE, show_header=False)
                t.add_column("Field", style="bold green", width=22)
                t.add_column("Value", style="white")
                for k, v in w.items():
                    if v:
                        val = ", ".join(v) if isinstance(v, list) else str(v)
                        t.add_row(k, val[:120])
                console.print("[bold]📋 WHOIS[/bold]")
                console.print(t)

            # DNS
            dns = data.get("dns", {})
            if dns:
                t2 = Table(box=box.SIMPLE, show_header=False)
                t2.add_column("Type", style="bold yellow", width=8)
                t2.add_column("Records", style="white")
                for rtype, records in dns.items():
                    if records and rtype != "ip_addresses":
                        val = ", ".join(records) if isinstance(records, list) else str(records)
                        t2.add_row(rtype, val[:200])
                console.print("[bold]🌐 DNS Records[/bold]")
                console.print(t2)

            # CDN / WAF
            if data.get("cdn"):
                console.print(f"[bold]☁️  CDN Detected:[/bold] {', '.join(data['cdn'])}")
            if data.get("waf"):
                console.print(f"[bold]🛡️  WAF Detected:[/bold] {', '.join(data['waf'])}")

            # Security headers
            sec = data.get("security_headers", {})
            if sec:
                console.print("\n[bold]🔒 Security Headers:[/bold]")
                for h, v in sec.items():
                    color = "red" if v == "MISSING" else "green"
                    console.print(f"  [{color}]{h}[/{color}]: {v[:80]}")

        except ImportError:
            # Fallback plain print
            import json
            print(json.dumps(data, indent=2, default=str))
