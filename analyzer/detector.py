"""Dynamic detection engine driven by YAML rules."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
import logging

import yaml

from analyzer.utils import DetectionResult, NormalizedLog, matches_patterns


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DetectionRule:
    """A detection rule loaded from YAML."""

    name: str
    severity: str
    description: str
    mitre_technique: str
    source_types: list[str] = field(default_factory=list)
    rule_type: str = "match"
    fields: list[str] = field(default_factory=lambda: ["message"])
    patterns: list[str] = field(default_factory=list)
    threshold: int | None = None
    window: int | None = None
    group_by: list[str] = field(default_factory=list)
    sequence: list[dict[str, str | list[str]]] = field(default_factory=list)


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    """Load all detection rules from YAML files."""

    rules: list[DetectionRule] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        except (OSError, yaml.YAMLError) as error:
            LOGGER.error("Failed loading rules from %s: %s", path, error)
            continue
        if isinstance(payload, dict):
            payload = [payload]
        for item in payload:
            if not isinstance(item, dict):
                continue
            rules.append(
                DetectionRule(
                    name=item["name"],
                    severity=item["severity"],
                    description=item["description"],
                    mitre_technique=item["mitre_technique"],
                    source_types=item.get("source_types", []),
                    rule_type=item.get("rule_type", "match"),
                    fields=item.get("fields", ["message"]),
                    patterns=item.get("pattern", item.get("patterns", [])),
                    threshold=item.get("threshold"),
                    window=item.get("window"),
                    group_by=item.get("group_by", []),
                    sequence=item.get("sequence", []),
                )
            )
    return rules


def run_detections(events: list[NormalizedLog], rules: list[DetectionRule]) -> list[DetectionResult]:
    """Evaluate all dynamic detection rules."""

    findings: list[DetectionResult] = []
    for rule in rules:
        scoped = [event for event in events if not rule.source_types or event.source_type in rule.source_types]
        if rule.rule_type == "match":
            findings.extend(_run_match_rule(scoped, rule))
        elif rule.rule_type == "threshold":
            findings.extend(_run_threshold_rule(scoped, rule))
        elif rule.rule_type == "sequence":
            findings.extend(_run_sequence_rule(scoped, rule))
    findings.sort(key=lambda item: (item.timestamp or 0, item.severity), reverse=False)
    return findings


def _run_match_rule(events: list[NormalizedLog], rule: DetectionRule) -> list[DetectionResult]:
    findings: list[DetectionResult] = []
    for event in events:
        haystacks = [_field_text(event, field) for field in rule.fields]
        if any(matches_patterns(text, rule.patterns) for text in haystacks if text):
            findings.append(_build_result(rule, [event]))
    return findings


def _run_threshold_rule(events: list[NormalizedLog], rule: DetectionRule) -> list[DetectionResult]:
    grouped: dict[tuple[str, ...], list[NormalizedLog]] = defaultdict(list)
    for event in events:
        haystacks = [_field_text(event, field) for field in rule.fields]
        if not any(matches_patterns(text, rule.patterns) for text in haystacks if text):
            continue
        key = tuple(_field_text(event, field) or "unknown" for field in rule.group_by) or ("all",)
        grouped[key].append(event)

    findings: list[DetectionResult] = []
    for bucket in grouped.values():
        bucket.sort(key=lambda item: item.timestamp or item.raw_line)
        if rule.threshold is None:
            continue
        window = timedelta(minutes=rule.window or 60)
        start_index = 0
        for end_index, event in enumerate(bucket):
            if event.timestamp:
                while start_index < end_index and bucket[start_index].timestamp and event.timestamp - bucket[start_index].timestamp > window:
                    start_index += 1
            current = bucket[start_index : end_index + 1]
            if len(current) >= rule.threshold:
                findings.append(_build_result(rule, current))
                break
    return findings


def _run_sequence_rule(events: list[NormalizedLog], rule: DetectionRule) -> list[DetectionResult]:
    if len(rule.sequence) < 2:
        return []

    grouped: dict[tuple[str, ...], list[NormalizedLog]] = defaultdict(list)
    for event in events:
        key = tuple(_field_text(event, field) or "unknown" for field in rule.group_by) or ("all",)
        grouped[key].append(event)

    findings: list[DetectionResult] = []
    for bucket in grouped.values():
        bucket.sort(key=lambda item: item.timestamp or item.raw_line)
        first_stage, second_stage = rule.sequence[0], rule.sequence[1]
        first_hits = [
            event
            for event in bucket
            if any(matches_patterns(_field_text(event, field), first_stage.get("patterns", [])) for field in first_stage.get("fields", ["message"]))
        ]
        second_hits = [
            event
            for event in bucket
            if any(matches_patterns(_field_text(event, field), second_stage.get("patterns", [])) for field in second_stage.get("fields", ["message"]))
        ]
        if first_hits and second_hits and second_hits[-1].timestamp and first_hits[0].timestamp and second_hits[-1].timestamp >= first_hits[0].timestamp:
            evidence = first_hits[-3:] + second_hits[-1:]
            findings.append(_build_result(rule, evidence))
    return findings


def _field_text(event: NormalizedLog, field: str) -> str:
    value = getattr(event, field, None)
    if value is None and field in event.metadata:
        value = event.metadata[field]
    return str(value or "")


def _build_result(rule: DetectionRule, events: list[NormalizedLog]) -> DetectionResult:
    event = events[-1]
    evidence = [item.raw_line for item in events[-5:]]
    return DetectionResult(
        rule_name=rule.name,
        severity=rule.severity,
        description=rule.description,
        mitre_technique=rule.mitre_technique,
        evidence=evidence,
        source_type=event.source_type,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        username=event.username,
    )