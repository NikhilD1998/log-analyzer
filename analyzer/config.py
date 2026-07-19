"""Configuration models and helpers for the SOC log analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class IOCConfig:
    """Paths to optional IOC files."""

    ips: Path | None = None
    domains: Path | None = None
    urls: Path | None = None
    hashes: Path | None = None


@dataclass(slots=True)
class AnalyzerConfig:
    """Top-level runtime configuration."""

    rules_dir: Path = Path("rules")
    reports_dir: Path = Path("reports")
    ioc: IOCConfig = field(default_factory=IOCConfig)


DEFAULT_CONFIG = AnalyzerConfig()