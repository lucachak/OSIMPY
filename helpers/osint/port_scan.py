"""
OSINPY — Port Scanner Module
Passive: Shodan InternetDB (no key)
Active: TCP connect scan + banner grabbing
No external API key required.
"""

from __future__ import annotations
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Well-known port service map ───────────────────────────────────────────────

SERVICE_MAP: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP/TLS", 631: "IPP (Printer)",
    993: "IMAP/TLS", 995: "POP3/TLS", 1433: "MSSQL", 1521: "Oracle DB",
    2181: "Zookeeper", 2375: "Docker (unauth)", 2376: "Docker TLS",
    3000: "Dev Server / Grafana", 3306: "MySQL", 3389: "RDP",
    3690: "SVN", 4200: "Angular Dev", 4369: "Erlang Port Mapper",
    5000: "Flask / UPnP", 5432: "PostgreSQL", 5601: "Kibana",
    5672: "RabbitMQ", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes API",
    7000: "Cassandra", 7001: "WebLogic", 7474: "Neo4j",
    8000: "HTTP Alt", 8008: "HTTP Alt", 8009: "AJP (Tomcat)", 8080: "HTTP Alt / Jenkins",
    8081: "HTTP Alt", 8086: "InfluxDB", 8161: "ActiveMQ Console",
    8443: "HTTPS Alt", 8888: "Jupyter Notebook", 9000: "SonarQube / PHP-FPM",
    9042: "Cassandra", 9090: "Prometheus / Cockpit", 9092: "Kafka",
    9200: "Elasticsearch HTTP", 9300: "Elasticsearch Transport",
    10250: "Kubernetes Kubelet", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50000: "IBM DB2",
}

# Top 100 common ports
TOP_100_PORTS: list[int] = sorted(SERVICE_MAP.keys())


@dataclass
class PortResult:
    port: int
    service: str = ""
    banner: str = ""
    open: bool = False
    tls: bool = False


@dataclass
class PortScanResult:
    target: str
    ip: str = ""
    # Passive (Shodan InternetDB)
    passive_ports: list[int] = field(default_factory=list)
    passive_cves: list[str] = field(default_factory=list)
    passive_tags: list[str] = field(default_factory=list)
    # Active
    active_results: list[PortResult] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    scan_time: float = 0.0


class PortScan:
    """
    Two-phase port scanner:
    1. Passive: Shodan InternetDB (no key, immediate, no intrusion)
    2. Active: TCP connect scan with optional banner grabbing
    """

    def __init__(self, target: str, ports: list[int] | None = None,
                 active: bool = True, banner_grab: bool = True,
                 timeout: float = 1.5, max_workers: int = 100):
        self.target = target.strip()
        self.ports = ports or TOP_100_PORTS
        self.active = active
        self.banner_grab = banner_grab
        self.timeout = timeout
        self.max_workers = max_workers
        self.ip = self._resolve(self.target)

    def _resolve(self, target: str) -> str:
        try:
            socket.inet_aton(target)
            return target
        except socket.error:
            pass
        try:
            return socket.gethostbyname(target)
        except Exception:
            return target

    def run(self) -> PortScanResult:
        print(f"\n[portscan] 🔍 Scanning {self.target} ({self.ip})...")
        result = PortScanResult(target=self.target, ip=self.ip)
        start = time.time()

        # Phase 1: Passive
        self._passive_scan(result)

        # Phase 2: Active
        if self.active:
            print(f"[portscan] 🔌 Active TCP scan on {len(self.ports)} ports...")
            self._active_scan(result)

        result.scan_time = round(time.time() - start, 2)
        print(f"[portscan] ✅ Done in {result.scan_time}s. "
              f"Open: {len(result.open_ports)} ports.")
        return result

    def _passive_scan(self, result: PortScanResult) -> None:
        """Shodan InternetDB — no key required."""
        if not HAS_REQUESTS:
            return
        try:
            url = f"https://internetdb.shodan.io/{self.ip}"
            resp = _requests.get(url, timeout=10,
                                  headers={"User-Agent": "OSINPY/2.0"})
            if resp.status_code == 200:
                data = resp.json()
                result.passive_ports = data.get("ports", [])
                result.passive_cves = data.get("vulns", [])
                result.passive_tags = data.get("tags", [])
                print(f"[portscan] Shodan InternetDB: {len(result.passive_ports)} ports, "
                      f"{len(result.passive_cves)} CVEs")
            elif resp.status_code == 404:
                print("[portscan] Shodan InternetDB: no data for this IP")
        except Exception as e:
            print(f"[portscan] Shodan InternetDB error: {e}")

    def _active_scan(self, result: PortScanResult) -> None:
        """TCP connect scan with optional banner grabbing."""
        def probe(port: int) -> PortResult:
            pr = PortResult(port=port, service=SERVICE_MAP.get(port, "unknown"))
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                conn = sock.connect_ex((self.ip, port))
                if conn == 0:
                    pr.open = True
                    if self.banner_grab:
                        pr.banner = self._grab_banner(sock, port)
                sock.close()
            except Exception:
                pass
            return pr

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(probe, p): p for p in self.ports}
            for fut in as_completed(futures):
                pr = fut.result()
                result.active_results.append(pr)
                if pr.open:
                    result.open_ports.append(pr.port)
                    svc = pr.service or "unknown"
                    banner = f" — {pr.banner[:60]}" if pr.banner else ""
                    print(f"  [OPEN] {pr.port:<6} {svc}{banner}")

        result.open_ports.sort()
        result.active_results.sort(key=lambda x: x.port)

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Try to grab a service banner."""
        try:
            # Send probe depending on port
            if port in (80, 8080, 8000, 8008, 8081, 3000):
                sock.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port in (22,):
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.sendall(b"EHLO osinpy\r\n")
            else:
                sock.sendall(b"\r\n")

            sock.settimeout(1.0)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200]
        except Exception:
            return ""

    @staticmethod
    def print_result(result: PortScanResult) -> None:
        try:
            from rich.table import Table
            from rich.console import Console
            from rich import box
            console = Console()
            console.print(f"\n[bold cyan]═══ Port Scan — {result.target} ({result.ip}) ═══[/bold cyan]\n")

            if result.passive_ports:
                console.print(f"[bold]☁️  Shodan InternetDB (passive):[/bold]")
                console.print(f"  Ports: {', '.join(str(p) for p in sorted(result.passive_ports))}")
                if result.passive_cves:
                    console.print(f"  [red]CVEs: {', '.join(result.passive_cves[:5])}[/red]")
                if result.passive_tags:
                    console.print(f"  Tags: {', '.join(result.passive_tags)}")

            if result.active_results:
                open_results = [r for r in result.active_results if r.open]
                if open_results:
                    console.print(f"\n[bold]🔌 Active Scan — {len(open_results)} open port(s):[/bold]")
                    t = Table(box=box.SIMPLE, show_header=True)
                    t.add_column("Port", style="bold yellow", width=8)
                    t.add_column("Service", style="green", width=20)
                    t.add_column("Banner", style="dim")
                    for r in open_results:
                        t.add_row(str(r.port), r.service, r.banner[:80] or "—")
                    console.print(t)
                else:
                    console.print("\n[dim]No open ports found in active scan.[/dim]")

            console.print(f"\n[dim]Scan time: {result.scan_time}s[/dim]")
        except ImportError:
            print(f"\nTarget: {result.target} ({result.ip})")
            print(f"Passive ports (Shodan): {result.passive_ports}")
            print(f"Active open ports: {result.open_ports}")

    @staticmethod
    def to_dict(result: PortScanResult) -> dict:
        return {
            "target": result.target,
            "ip": result.ip,
            "passive_ports": result.passive_ports,
            "passive_cves": result.passive_cves,
            "passive_tags": result.passive_tags,
            "open_ports": result.open_ports,
            "active_details": [
                {"port": r.port, "service": r.service, "banner": r.banner, "open": r.open}
                for r in result.active_results if r.open
            ],
            "scan_time_seconds": result.scan_time,
        }
