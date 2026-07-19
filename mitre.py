"""MITRE ATT&CK helpers."""

from __future__ import annotations

from collections import Counter

from utils import DetectionResult


MITRE_DESCRIPTIONS = {
    "T1110": "Brute Force",
    "T1059": "Command and Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1543": "Create or Modify System Process",
    "T1112": "Modify Registry",
    "T1053": "Scheduled Task/Job",
    "T1136": "Create Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1105": "Ingress Tool Transfer",
    "T1055": "Process Injection",
}


def describe_technique(technique_id: str) -> str:
    """Return a human-readable description for a MITRE technique."""

    return MITRE_DESCRIPTIONS.get(technique_id, "Unknown Technique")


def summarize_mitre(findings: list[DetectionResult]) -> list[dict[str, str | int]]:
    """Aggregate ATT&CK coverage across findings."""

    counter = Counter(result.mitre_technique for result in findings)
    return [
        {
            "technique": technique,
            "name": describe_technique(technique),
            "count": count,
        }
        for technique, count in counter.most_common()
    ]