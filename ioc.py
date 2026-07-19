"""IOC loading and matching."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import json
import logging
import re

import yaml

from config import IOCConfig
from utils import IOCMatch, NormalizedLog


LOGGER = logging.getLogger(__name__)

URL_PATTERN = re.compile(r"https?://[^\s\"]+", flags=re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", flags=re.IGNORECASE)
HASH_PATTERN = re.compile(r"\b[a-f0-9]{32,64}\b", flags=re.IGNORECASE)


@dataclass(slots=True)
class IOCStore:
    """In-memory IOC collections."""

    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


def _load_entries(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            if isinstance(data, dict):
                return {str(value).strip() for value in data.values() if str(value).strip()}
            return {str(value).strip() for value in data if str(value).strip()}
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                values: list[str] = []
                for item in data.values():
                    if isinstance(item, list):
                        values.extend(str(value).strip() for value in item)
                    else:
                        values.append(str(item).strip())
                return {value for value in values if value}
            return {str(value).strip() for value in data if str(value).strip()}
        return {
            line.strip()
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        }
    except (OSError, ValueError, yaml.YAMLError) as error:
        LOGGER.error("Failed loading IOC file %s: %s", path, error)
        return set()


def load_iocs(config: IOCConfig) -> IOCStore:
    """Load IOC sources from configured files."""

    return IOCStore(
        ips=_load_entries(config.ips),
        domains=_load_entries(config.domains),
        urls=_load_entries(config.urls),
        hashes=_load_entries(config.hashes),
    )


def match_iocs(events: list[NormalizedLog], store: IOCStore) -> list[IOCMatch]:
    """Scan normalized events for IOC hits."""

    matches: list[IOCMatch] = []
    for event in events:
        if event.source_ip and event.source_ip in store.ips:
            matches.append(
                IOCMatch("ip", event.source_ip, event.source_type, event.timestamp, event.raw_line)
            )
        if event.destination_ip and event.destination_ip in store.ips:
            matches.append(
                IOCMatch("ip", event.destination_ip, event.source_type, event.timestamp, event.raw_line)
            )
        for url in URL_PATTERN.findall(event.raw_line):
            if url in store.urls:
                matches.append(IOCMatch("url", url, event.source_type, event.timestamp, event.raw_line))
        for domain in DOMAIN_PATTERN.findall(event.raw_line):
            if domain in store.domains:
                matches.append(IOCMatch("domain", domain, event.source_type, event.timestamp, event.raw_line))
        for file_hash in HASH_PATTERN.findall(event.raw_line.lower()):
            if file_hash in {value.lower() for value in store.hashes}:
                matches.append(IOCMatch("hash", file_hash, event.source_type, event.timestamp, event.raw_line))
    return matches