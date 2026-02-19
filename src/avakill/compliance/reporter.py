"""Compliance report formatters (Rich table, JSON, Markdown)."""

from __future__ import annotations

import json
from typing import Any

from rich.table import Table

from avakill.compliance.frameworks import ComplianceReport

_STATUS_STYLES: dict[str, tuple[str, str]] = {
    "pass": ("[bold green]", "PASS"),
    "fail": ("[bold red]", "FAIL"),
    "partial": ("[bold yellow]", "PARTIAL"),
    "not_applicable": ("[dim]", "N/A"),
}


class ComplianceReporter:
    """Format a ComplianceReport for different output targets."""

    def to_rich_table(self, report: ComplianceReport) -> Table:
        """Render the report as a Rich Table for terminal display."""
        table = Table(
            title=f"Compliance Report: {report.framework}",
            show_lines=True,
        )
        table.add_column("Control", style="bold")
        table.add_column("Title")
        table.add_column("Status", justify="center")
        table.add_column("Evidence")
        table.add_column("Recommendations")

        for ctrl in report.controls:
            style_prefix, status_text = _STATUS_STYLES.get(ctrl.status, ("", ctrl.status.upper()))
            styled_status = f"{style_prefix}{status_text}[/]" if style_prefix else status_text
            table.add_row(
                ctrl.control_id,
                ctrl.title,
                styled_status,
                "\n".join(ctrl.evidence) if ctrl.evidence else "-",
                "\n".join(ctrl.recommendations) if ctrl.recommendations else "-",
            )

        return table

    def to_json(self, report: ComplianceReport) -> str:
        """Serialize the report to a JSON string."""
        data: dict[str, Any] = {
            "framework": report.framework,
            "generated_at": report.generated_at.isoformat(),
            "overall_status": report.overall_status,
            "summary": report.summary,
            "controls": [
                {
                    "control_id": c.control_id,
                    "framework": c.framework,
                    "title": c.title,
                    "description": c.description,
                    "status": c.status,
                    "evidence": c.evidence,
                    "recommendations": c.recommendations,
                }
                for c in report.controls
            ],
        }
        return json.dumps(data, indent=2)

    def to_markdown(self, report: ComplianceReport) -> str:
        """Render the report as a Markdown document."""
        lines: list[str] = []
        lines.append(f"# Compliance Report: {report.framework}")
        lines.append("")
        lines.append(f"**Overall Status:** {report.overall_status}")
        lines.append(f"**Generated:** {report.generated_at.isoformat()}")
        lines.append("")
        lines.append(report.summary)
        lines.append("")
        lines.append("| Control | Title | Status | Evidence | Recommendations |")
        lines.append("|---------|-------|--------|----------|-----------------|")
        for ctrl in report.controls:
            evidence = "; ".join(ctrl.evidence) if ctrl.evidence else "-"
            recs = "; ".join(ctrl.recommendations) if ctrl.recommendations else "-"
            lines.append(
                f"| {ctrl.control_id} | {ctrl.title} | {ctrl.status.upper()} "
                f"| {evidence} | {recs} |"
            )
        lines.append("")
        return "\n".join(lines)
