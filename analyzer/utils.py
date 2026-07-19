"""Shared models and utility functions."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import logging
import re


LOGGER = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


@dataclass(slots=True)
class NormalizedLog:
    """Normalized security log event."""

    source_type: str
    timestamp: datetime | None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    event_id: str | None = None
    status: str | None = None
    process: str | None = None
    command: str | None = None
    log_level: str | None = None
    message: str = ""
    raw_line: str = ""
    file_path: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DetectionResult:
    """Detection engine output."""

    rule_name: str
    severity: str
    description: str
    mitre_technique: str
    evidence: list[str]
    source_type: str
    timestamp: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None


@dataclass(slots=True)
class IOCMatch:
    """An IOC hit extracted from a normalized event."""

    ioc_type: str
    value: str
    source_type: str
    timestamp: datetime | None
    context: str




def parse_datetime(value: str) -> datetime | None:
    """Parse common log timestamp formats."""

    formats = (
        "%b %d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S,%f",
    )

    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)

            # Linux logs don't include the year
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)

            # If timezone is missing, assume UTC
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            else:
                parsed = parsed.astimezone(timezone.utc)

            return parsed

        except ValueError:
            continue

    return None


def severity_rank(severity: str) -> int:
    """Return a sortable severity rank."""

    return SEVERITY_ORDER.get(severity.lower(), 0)


def matches_patterns(text: str, patterns: list[str]) -> bool:
    """Return whether any case-insensitive regex matches the text."""

    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def ensure_directory(path: Path) -> None:
    """Create a directory if it does not exist."""

    path.mkdir(parents=True, exist_ok=True)


def collect_top_values(values: list[str | None], limit: int = 5) -> list[tuple[str, int]]:
    """Return the most common non-empty values."""

    counter = Counter(value for value in values if value)
    return counter.most_common(limit)


def timestamp_slug(value: datetime | None = None) -> str:
    """Generate a filesystem-safe timestamp."""

    current = value or datetime.now()
    return current.strftime("%Y%m%d_%H%M%S")


def setup_logging() -> None:
    """Initialize module-safe logging."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def safe_read_lines(path: Path) -> list[str]:
    """Read a text file without failing on encoding issues."""

    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as error:
        LOGGER.error("Failed reading %s: %s", path, error)
        return []