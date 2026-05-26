"""
OSINPY — Unified Report Builder
Consolidates results from all OSINT modules into a JSON + Markdown report.
"""

from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class ReportSection:
    title: str
    data: dict
    module: str


@dataclass
class Report:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sections: list[ReportSection] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class ReportBuilder:
    """
    Collects OSINT module results and writes a structured report
    as both JSON and Markdown.
    """

    def __init__(self, target: str, output_dir: str = "./output"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.report = Report(target=target)
        self._summary_lines: list[str] = []

    # ── Add sections ─────────────────────────────────────────────────────────

    def add_whois(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="WHOIS & DNS", data=data, module="whois_lookup"
        ))
        # Summary bullets
        w = data.get("whois", {})
        if w.get("registrar"):
            self._summary_lines.append(f"- **Registrar:** {w['registrar']}")
        if w.get("creation_date"):
            self._summary_lines.append(f"- **Created:** {w['creation_date'][:10]}")
        if w.get("expiration_date"):
            self._summary_lines.append(f"- **Expires:** {w['expiration_date'][:10]}")
        if data.get("cdn"):
            self._summary_lines.append(f"- **CDN:** {', '.join(data['cdn'])}")
        if data.get("waf"):
            self._summary_lines.append(f"- **WAF:** {', '.join(data['waf'])}")
        return self

    def add_subdomains(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Subdomain Enumeration", data=data, module="subdomain_enum"
        ))
        total = data.get("total", 0)
        alive = data.get("alive", 0)
        self._summary_lines.append(f"- **Subdomains:** {total} found, {alive} alive")
        return self

    def add_ip_intel(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="IP Intelligence", data=data, module="ip_intel"
        ))
        self._summary_lines.append(
            f"- **IP:** {data.get('ip')} — {data.get('city')}, {data.get('country')} ({data.get('isp')})"
        )
        if data.get("ports"):
            self._summary_lines.append(f"- **Open Ports (Shodan):** {data['ports']}")
        if data.get("cves"):
            self._summary_lines.append(f"- **⚠️ CVEs:** {len(data['cves'])} vulnerabilities")
        return self

    def add_username(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Username OSINT", data=data, module="username_osint"
        ))
        found = [p["platform"] for p in data.get("found", [])]
        if found:
            self._summary_lines.append(f"- **Username found on:** {', '.join(found[:8])}")
        return self

    def add_email(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Email OSINT", data=data, module="email_osint"
        ))
        if data.get("breach_count"):
            self._summary_lines.append(f"- **⚠️ Breaches:** {data['breach_count']} breach(es) found")
        if data.get("found_on"):
            self._summary_lines.append(f"- **Email accounts:** {', '.join(data['found_on'])}")
        return self

    def add_ports(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Port Scan", data=data, module="port_scan"
        ))
        if data.get("open_ports"):
            self._summary_lines.append(f"- **Open Ports (active):** {data['open_ports']}")
        if data.get("passive_cves"):
            self._summary_lines.append(f"- **CVEs:** {', '.join(data['passive_cves'][:5])}")
        return self

    def add_tech(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Technology Fingerprint", data=data, module="tech_fingerprint"
        ))
        techs = [t["name"] for t in data.get("technologies", [])]
        if techs:
            self._summary_lines.append(f"- **Technologies:** {', '.join(techs[:10])}")
        score = data.get("security_score", 0)
        self._summary_lines.append(f"- **Security Header Score:** {score}/100")
        if data.get("interesting_files"):
            self._summary_lines.append(
                f"- **⚠️ Interesting files:** {', '.join(data['interesting_files'][:5])}"
            )
        return self

    def add_leaks(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Leak Search", data=data, module="leak_search"
        ))
        if data.get("total_found"):
            self._summary_lines.append(f"- **Leak records found:** {data['total_found']}")
        return self

    def add_phone(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Phone OSINT", data=data, module="phone_osint"
        ))
        if data.get("is_valid"):
            self._summary_lines.append(f"- **Phone:** {data.get('international_format')} ({data.get('location')}) - {data.get('carrier')}")
        return self

    def add_person_recon(self, data: dict) -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Identity OSINT Dossier", data=data, module="person_recon"
        ))
        tgt = data.get("target", {})
        parts = []
        if tgt.get("name"): parts.append(tgt["name"])
        if tgt.get("username"): parts.append(tgt["username"])
        if tgt.get("email"): parts.append(tgt["email"])
        self._summary_lines.append(f"- **Identity Target:** {' / '.join(parts)}")
        return self

    def add_dorks(self, links: list[str], dork: str = "") -> "ReportBuilder":
        self.report.sections.append(ReportSection(
            title="Dorking Results",
            data={"dork": dork, "links": links, "count": len(links)},
            module="dorking",
        ))
        self._summary_lines.append(f"- **Dork results:** {len(links)} URLs found")
        return self

    # ── Build & Save ─────────────────────────────────────────────────────────

    def build(self) -> Path:
        """Write JSON + Markdown reports to output/<target>_<ts>/."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace("/", "_").replace(":", "_")
        report_dir = self.output_dir / f"{safe_target}_{ts}"
        report_dir.mkdir(parents=True, exist_ok=True)

        # Build JSON
        report_data = {
            "meta": {
                "target": self.target,
                "timestamp": self.report.timestamp,
                "modules_run": [s.module for s in self.report.sections],
            },
            "summary": self._summary_lines,
            "sections": [
                {"title": s.title, "module": s.module, "data": s.data}
                for s in self.report.sections
            ],
        }

        json_path = report_dir / "report.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        # Build Markdown
        md_path = report_dir / "report.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self._render_markdown(report_data))

        print(f"\n[report] 📄 JSON  → {json_path}")
        print(f"[report] 📝 Markdown → {md_path}")
        return report_dir

    def _render_markdown(self, data: dict) -> str:
        meta = data["meta"]
        lines = [
            f"# OSINPY OSINT Report — `{meta['target']}`",
            f"",
            f"> **Generated:** {meta['timestamp']}  ",
            f"> **Modules:** {', '.join(meta['modules_run'])}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
        ]

        for line in data.get("summary", []):
            lines.append(line)

        lines += ["", "---", ""]

        for section in data.get("sections", []):
            lines.append(f"## {section['title']}")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(section["data"], indent=2, ensure_ascii=False,
                                    default=str)[:8000])
            lines.append("```")
            lines.append("")

        lines += [
            "---",
            "",
            "*Generated by [OSINPY](https://github.com/lucachak) — for authorized use only.*",
        ]
        return "\n".join(lines)

    @staticmethod
    def print_summary(report_dir: Path) -> None:
        """Print a short summary after saving."""
        try:
            from rich.console import Console
            console = Console()
            console.print(f"\n[bold green]✅ Report saved to:[/bold green] {report_dir}")
            md = report_dir / "report.md"
            json_f = report_dir / "report.json"
            console.print(f"  📝 {md}")
            console.print(f"  📄 {json_f}")
        except ImportError:
            print(f"\n✅ Report saved to: {report_dir}")
