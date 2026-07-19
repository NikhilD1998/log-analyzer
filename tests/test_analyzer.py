"""Focused tests for parser and detector behavior."""

from pathlib import Path

from detector import load_rules, run_detections
from parser import parse_logs_from_path


def test_folder_parsing_produces_events() -> None:
    events = parse_logs_from_path(Path("samples"))
    assert len(events) >= 10


def test_detection_engine_finds_bruteforce_and_powershell() -> None:
    events = parse_logs_from_path(Path("samples"))
    findings = run_detections(events, load_rules(Path("rules")))
    names = {item.rule_name for item in findings}
    assert "Brute Force" in names
    assert "Encoded PowerShell" in names