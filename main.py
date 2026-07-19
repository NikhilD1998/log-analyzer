"""Command-line entry point for the SOC log analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from analyzer.config import DEFAULT_CONFIG
from analyzer.detector import load_rules, run_detections
from analyzer.ioc import load_iocs, match_iocs
from analyzer.parser import parse_logs_from_path
from analyzer.reporter import build_report_payload, print_console_dashboard, write_reports
from analyzer.utils import severity_rank, setup_logging


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Analyze security logs and generate incident reports.")
    parser.add_argument("--file", type=Path, help="Path to a single log file.")
    parser.add_argument("--folder", type=Path, help="Path to a folder of log files.")
    parser.add_argument("--format", choices=["console", "json", "csv", "markdown", "all"], default="console")
    parser.add_argument("--report", action="store_true", help="Write report files to the reports directory.")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "informational"])
    parser.add_argument("--ioc-ips", type=Path, help="Optional IOC IP list.")
    parser.add_argument("--ioc-domains", type=Path, help="Optional IOC domain list.")
    parser.add_argument("--ioc-urls", type=Path, help="Optional IOC URL list.")
    parser.add_argument("--ioc-hashes", type=Path, help="Optional IOC hash list.")
    return parser


def main() -> int:
    """Run the analyzer CLI."""

    setup_logging()
    args = build_argument_parser().parse_args()
    target = args.file or args.folder
    if target is None:
        raise SystemExit("Provide either --file or --folder.")

    config = DEFAULT_CONFIG
    config.ioc.ips = args.ioc_ips
    config.ioc.domains = args.ioc_domains
    config.ioc.urls = args.ioc_urls
    config.ioc.hashes = args.ioc_hashes

    console = Console()
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task(description="Parsing logs", total=None)
        events = parse_logs_from_path(target)
        progress.add_task(description="Loading rules", total=None)
        rules = load_rules(config.rules_dir)
        progress.add_task(description="Running detections", total=None)
        findings = run_detections(events, rules)
        progress.add_task(description="Matching IOCs", total=None)
        ioc_matches = match_iocs(events, load_iocs(config.ioc))

    if args.severity:
        minimum = severity_rank(args.severity)
        findings = [item for item in findings if severity_rank(item.severity) >= minimum]

    print_console_dashboard(console, events, findings, ioc_matches)
    payload = build_report_payload(events, findings, ioc_matches)

    if args.report or args.format in {"json", "csv", "markdown", "all"}:
        written = write_reports(config.reports_dir, payload, findings)
        console.print(f"Saved reports: {', '.join(str(path) for path in written.values())}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())