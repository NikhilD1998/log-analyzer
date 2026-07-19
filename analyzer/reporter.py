"""Reporting utilities for console and file outputs."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from pathlib import Path
import csv
import json

import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from analyzer.mitre import summarize_mitre
from analyzer.utils import DetectionResult, IOCMatch, NormalizedLog, collect_top_values, ensure_directory, timestamp_slug


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "green",
}


def print_console_dashboard(
    console: Console,
    events: list[NormalizedLog],
    findings: list[DetectionResult],
    ioc_matches: list[IOCMatch],
) -> None:
    """Render the CLI summary dashboard."""

    summary = Counter(result.severity.lower() for result in findings)
    top_ips = collect_top_values([event.source_ip for event in events])
    top_users = collect_top_values([event.username for event in events])
    mitre_summary = summarize_mitre(findings)[:5]

    table = Table(title="SOC Log Analyzer Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Total Logs", str(len(events)))
    table.add_row("Alerts", str(len(findings)))
    table.add_row("IOC Matches", str(len(ioc_matches)))
    for severity in ("critical", "high", "medium", "low", "informational"):
        table.add_row(f"{severity.title()} Findings", f"[{SEVERITY_STYLES[severity]}]{summary.get(severity, 0)}[/]")

    console.print(table)

    if top_ips:
        ip_table = Table(title="Top Source IPs")
        ip_table.add_column("IP")
        ip_table.add_column("Count")
        for ip, count in top_ips:
            ip_table.add_row(ip, str(count))
        console.print(ip_table)

    if top_users:
        user_table = Table(title="Top Users")
        user_table.add_column("User")
        user_table.add_column("Count")
        for user, count in top_users:
            user_table.add_row(user, str(count))
        console.print(user_table)

    if mitre_summary:
        mitre_table = Table(title="Top MITRE Techniques")
        mitre_table.add_column("Technique")
        mitre_table.add_column("Name")
        mitre_table.add_column("Count")
        for item in mitre_summary:
            mitre_table.add_row(str(item["technique"]), str(item["name"]), str(item["count"]))
        console.print(mitre_table)

    if findings:
        console.print(
            Panel(
                "\n".join(
                    f"[{SEVERITY_STYLES[result.severity.lower()]}]{result.severity.upper()}[/] {result.rule_name}: {result.description}"
                    for result in findings[:8]
                ),
                title="Critical Findings Preview",
            )
        )


def build_report_payload(
    events: list[NormalizedLog],
    findings: list[DetectionResult],
    ioc_matches: list[IOCMatch],
) -> dict[str, object]:
    """Build a structured report payload."""

    findings_by_severity: dict[str, list[dict[str, object]]] = {
        severity: [asdict(item) for item in findings if item.severity.lower() == severity]
        for severity in ("critical", "high", "medium", "low", "informational")
    }
    timeline = [
        {
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "source_type": event.source_type,
            "message": event.message,
            "source_ip": event.source_ip,
            "username": event.username,
        }
        for event in sorted(events, key=lambda item: item.timestamp or pd.Timestamp.min.to_pydatetime())
    ]
    return {
        "executive_summary": {
            "total_logs": len(events),
            "alerts": len(findings),
            "ioc_matches": len(ioc_matches),
        },
        "critical_findings": findings_by_severity["critical"],
        "high_findings": findings_by_severity["high"],
        "medium_findings": findings_by_severity["medium"],
        "low_findings": findings_by_severity["low"],
        "informational_findings": findings_by_severity["informational"],
        "timeline": timeline,
        "source_ips": [value for value, _ in collect_top_values([event.source_ip for event in events], limit=20)],
        "destination_ips": [value for value, _ in collect_top_values([event.destination_ip for event in events], limit=20)],
        "users": [value for value, _ in collect_top_values([event.username for event in events], limit=20)],
        "mitre_mapping": summarize_mitre(findings),
        "ioc_matches": [asdict(match) for match in ioc_matches],
        "recommendations": _build_recommendations(findings, ioc_matches),
    }


def write_reports(
    reports_dir: Path,
    payload: dict[str, object],
    findings: list[DetectionResult],
) -> dict[str, Path]:
    """Persist JSON, CSV, and Markdown reports."""

    ensure_directory(reports_dir)
    stamp = timestamp_slug()
    json_path = reports_dir / f"incident_report_{stamp}.json"
    csv_path = reports_dir / f"incident_report_{stamp}.csv"
    md_path = reports_dir / f"incident_report_{stamp}.md"

    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "timestamp",
                "rule_name",
                "severity",
                "description",
                "mitre_technique",
                "source_type",
                "source_ip",
                "destination_ip",
                "username",
            ],
        )
        writer.writeheader()
        for item in findings:
            writer.writerow(
                {
                    "timestamp": item.timestamp.isoformat() if item.timestamp else "",
                    "rule_name": item.rule_name,
                    "severity": item.severity,
                    "description": item.description,
                    "mitre_technique": item.mitre_technique,
                    "source_type": item.source_type,
                    "source_ip": item.source_ip or "",
                    "destination_ip": item.destination_ip or "",
                    "username": item.username or "",
                }
            )

    md_path.write_text(_markdown_report(payload), encoding="utf-8")
    return {"json": json_path, "csv": csv_path, "markdown": md_path}


def _markdown_report(payload: dict[str, object]) -> str:
    summary = payload["executive_summary"]
    mitre_mapping = payload["mitre_mapping"]
    recommendations = payload["recommendations"]
    lines = [
        "# Incident Report",
        "",
        "## Executive Summary",
        f"- Total Logs: {summary['total_logs']}",
        f"- Alerts: {summary['alerts']}",
        f"- IOC Matches: {summary['ioc_matches']}",
        "",
        "## MITRE Mapping",
    ]
    for item in mitre_mapping:
        lines.append(f"- {item['technique']} ({item['name']}): {item['count']}")
    lines.append("")
    lines.append("## Recommendations")
    for recommendation in recommendations:
        lines.append(f"- {recommendation}")
    return "\n".join(lines)


def _build_recommendations(findings: list[DetectionResult], ioc_matches: list[IOCMatch]) -> list[str]:
    recommendations = [
        "Review authentication controls for accounts and IPs with repeated failures.",
        "Investigate suspicious process execution chains and PowerShell activity.",
        "Block or monitor infrastructure associated with identified IOCs.",
    ]
    if any(item.rule_name.lower().startswith("new administrator") for item in findings):
        recommendations.append("Audit privileged account creation and validate change approval.")
    if ioc_matches:
        recommendations.append("Pivot on matched IOCs across endpoint, proxy, and DNS telemetry.")
    return recommendations