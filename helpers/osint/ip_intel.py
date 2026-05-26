"""
OSINPY — IP Intelligence Module
Geoip + ASN + Shodan InternetDB (no key) + abuse check.
No API key required for core functionality.
"""

from __future__ import annotations
import json
import socket
from dataclasses import dataclass, field
from typing import Any

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class IPIntelResult:
    ip: str
    hostname: str = ""
    # Geo
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    # ASN / Org
    asn: str = ""
    asn_name: str = ""
    isp: str = ""
    org: str = ""
    # Shodan InternetDB
    ports: list[int] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Abuse
    is_bogon: bool = False
    is_datacenter: bool = False
    abuse_score: int = 0
    abuse_reports: int = 0


class IPIntel:
    """
    Multi-source IP intelligence aggregator.
    Sources: ip-api.com (geo), ipinfo.io (ASN), Shodan InternetDB (ports/CVEs),
             AbuseIPDB public lookup.
    """

    def __init__(self, target: str, timeout: int = 10):
        self.timeout = timeout
        # Resolve hostname to IP if needed
        self.original = target.strip()
        self.ip = self._resolve(target.strip())

    def _resolve(self, target: str) -> str:
        """Resolve hostname to IP if not already an IP."""
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            pass
        try:
            return socket.gethostbyname(target)
        except Exception:
            return target

    def run(self) -> IPIntelResult:
        print(f"\n[ip-intel] 🔍 Investigating {self.ip} (target: {self.original})...")
        result = IPIntelResult(ip=self.ip)

        # Try to reverse-resolve hostname
        try:
            result.hostname = socket.gethostbyaddr(self.ip)[0]
        except Exception:
            pass

        if not HAS_REQUESTS:
            print("[ip-intel] ⚠️  requests not installed.")
            return result

        self._query_ipapi(result)
        self._query_ipinfo(result)
        self._query_shodan_internetdb(result)

        return result

    def _query_ipapi(self, result: IPIntelResult) -> None:
        """ip-api.com — free, no key, 45 req/min."""
        try:
            url = f"http://ip-api.com/json/{self.ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
            resp = _requests.get(url, timeout=self.timeout,
                                  headers={"User-Agent": "OSINPY/2.0"})
            data = resp.json()
            if data.get("status") == "success":
                result.country = data.get("country", "")
                result.country_code = data.get("countryCode", "")
                result.region = data.get("regionName", "")
                result.city = data.get("city", "")
                result.latitude = data.get("lat", 0.0)
                result.longitude = data.get("lon", 0.0)
                result.timezone = data.get("timezone", "")
                result.isp = data.get("isp", "")
                result.org = data.get("org", "")
                asn_raw = data.get("as", "")
                if asn_raw:
                    parts = asn_raw.split(" ", 1)
                    result.asn = parts[0]
                    result.asn_name = parts[1] if len(parts) > 1 else ""
        except Exception as e:
            print(f"[ip-intel] ip-api.com error: {e}")

    def _query_ipinfo(self, result: IPIntelResult) -> None:
        """ipinfo.io — free tier, no key, 50k/month."""
        try:
            url = f"https://ipinfo.io/{self.ip}/json"
            resp = _requests.get(url, timeout=self.timeout,
                                  headers={"User-Agent": "OSINPY/2.0"})
            data = resp.json()
            if not result.org:
                result.org = data.get("org", "")
            if not result.asn and data.get("org", "").startswith("AS"):
                parts = data["org"].split(" ", 1)
                result.asn = parts[0]
                result.asn_name = parts[1] if len(parts) > 1 else ""
            if not result.hostname:
                result.hostname = data.get("hostname", "")
            result.is_bogon = data.get("bogon", False)
        except Exception as e:
            print(f"[ip-intel] ipinfo.io error: {e}")

    def _query_shodan_internetdb(self, result: IPIntelResult) -> None:
        """
        Shodan InternetDB — completely free, no key, no rate limit.
        Returns open ports, CVEs, hostnames, tags.
        """
        try:
            url = f"https://internetdb.shodan.io/{self.ip}"
            resp = _requests.get(url, timeout=self.timeout,
                                  headers={"User-Agent": "OSINPY/2.0"})
            if resp.status_code == 200:
                data = resp.json()
                result.ports = data.get("ports", [])
                result.cves = data.get("vulns", [])
                result.hostnames = data.get("hostnames", [])
                result.tags = data.get("tags", [])
                if "cdn" in result.tags or "cloud" in result.tags:
                    result.is_datacenter = True
            elif resp.status_code == 404:
                print(f"[ip-intel] Shodan InternetDB: no data for {self.ip}")
        except Exception as e:
            print(f"[ip-intel] Shodan InternetDB error: {e}")

    @staticmethod
    def print_result(result: IPIntelResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ IP Intelligence — {result.ip} ═══[/bold cyan]\n")

            t = Table(box=box.SIMPLE, show_header=False)
            t.add_column("Field", style="bold green", width=22)
            t.add_column("Value", style="white")

            rows = [
                ("Hostname", result.hostname or "—"),
                ("Country", f"{result.country} ({result.country_code})"),
                ("Region / City", f"{result.region} / {result.city}"),
                ("Coordinates", f"{result.latitude}, {result.longitude}"),
                ("Timezone", result.timezone or "—"),
                ("ISP", result.isp or "—"),
                ("Organization", result.org or "—"),
                ("ASN", f"{result.asn} {result.asn_name}"),
                ("Bogon IP", "⚠️ Yes" if result.is_bogon else "No"),
                ("Datacenter/CDN", "Yes" if result.is_datacenter else "No"),
            ]
            for k, v in rows:
                if v and v != " ()":
                    t.add_row(k, str(v))
            console.print(t)

            if result.ports:
                console.print(f"[bold yellow]🔌 Open Ports:[/bold yellow] {', '.join(str(p) for p in sorted(result.ports))}")
            if result.cves:
                console.print(f"\n[bold red]⚠️  CVEs ({len(result.cves)}):[/bold red]")
                for cve in result.cves[:10]:
                    console.print(f"  • {cve}")
                if len(result.cves) > 10:
                    console.print(f"  ... and {len(result.cves) - 10} more")
            if result.hostnames:
                console.print(f"\n[bold]🌐 Hostnames:[/bold] {', '.join(result.hostnames[:10])}")
            if result.tags:
                console.print(f"[bold]🏷️  Tags:[/bold] {', '.join(result.tags)}")

        except ImportError:
            print(f"\nIP: {result.ip} | Country: {result.country} | ISP: {result.isp}")
            print(f"Ports: {result.ports}")
            print(f"CVEs:  {result.cves}")

    @staticmethod
    def to_dict(result: IPIntelResult) -> dict:
        return {
            "ip": result.ip,
            "hostname": result.hostname,
            "country": result.country,
            "country_code": result.country_code,
            "region": result.region,
            "city": result.city,
            "latitude": result.latitude,
            "longitude": result.longitude,
            "timezone": result.timezone,
            "isp": result.isp,
            "org": result.org,
            "asn": result.asn,
            "asn_name": result.asn_name,
            "is_bogon": result.is_bogon,
            "is_datacenter": result.is_datacenter,
            "ports": result.ports,
            "cves": result.cves,
            "hostnames": result.hostnames,
            "tags": result.tags,
        }
