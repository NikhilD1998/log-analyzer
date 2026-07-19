"""Log parsers for multiple security log formats."""

from __future__ import annotations

from pathlib import Path
import logging
import re

from utils import LOGGER, NormalizedLog, parse_datetime, safe_read_lines


LINUX_AUTH_PATTERN = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.*)$"
)
LINUX_IP_PATTERN = re.compile(r"from (?P<ip>\d+\.\d+\.\d+\.\d+)")
LINUX_USER_PATTERN = re.compile(r"for (?:invalid user )?(?P<user>[\w.$-]+)")

WINDOWS_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"EventID=(?P<event_id>\d+)\s+Level=(?P<level>\w+)\s+Message=(?P<message>.+)$"
)
KV_PATTERN = re.compile(r"(?P<key>[A-Za-z]+)=(?P<value>[^\s]+)")

APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?$'
)

NGINX_PATTERN = APACHE_PATTERN


def parse_log_file(path: Path) -> list[NormalizedLog]:
    """Parse a single log file into normalized events."""

    lines = safe_read_lines(path)
    lower_name = path.name.lower()
    if "auth" in lower_name:
        return _parse_linux_auth(lines, path)
    if "windows" in lower_name or lower_name.endswith(".evtx.txt"):
        return _parse_windows(lines, path)
    if "apache" in lower_name:
        return _parse_web_access(lines, path, source_type="apache")
    if "nginx" in lower_name:
        return _parse_web_access(lines, path, source_type="nginx")

    parsed = _parse_linux_auth(lines, path)
    if parsed:
        return parsed
    parsed = _parse_windows(lines, path)
    if parsed:
        return parsed
    parsed = _parse_web_access(lines, path, source_type="apache")
    if parsed:
        return parsed
    return _parse_web_access(lines, path, source_type="nginx")


def parse_logs_from_path(path: Path) -> list[NormalizedLog]:
    """Parse either a single file or every file in a folder."""

    if path.is_file():
        return parse_log_file(path)

    events: list[NormalizedLog] = []
    for file_path in sorted(candidate for candidate in path.iterdir() if candidate.is_file()):
        events.extend(parse_log_file(file_path))
    return events


def _parse_linux_auth(lines: list[str], path: Path) -> list[NormalizedLog]:
    events: list[NormalizedLog] = []
    for line in lines:
        match = LINUX_AUTH_PATTERN.match(line)
        if not match:
            continue
        message = match.group("message")
        username_match = LINUX_USER_PATTERN.search(message)
        ip_match = LINUX_IP_PATTERN.search(message)
        events.append(
            NormalizedLog(
                source_type="linux",
                timestamp=parse_datetime(match.group("ts")),
                username=username_match.group("user") if username_match else None,
                source_ip=ip_match.group("ip") if ip_match else None,
                status="failed" if "failed" in message.lower() else "success" if "accepted" in message.lower() else None,
                process=match.group("process"),
                message=message,
                raw_line=line,
                file_path=str(path),
            )
        )
    return events


def _parse_windows(lines: list[str], path: Path) -> list[NormalizedLog]:
    events: list[NormalizedLog] = []
    for line in lines:
        match = WINDOWS_PATTERN.match(line)
        if not match:
            continue
        metadata = {item.group("key").lower(): item.group("value") for item in KV_PATTERN.finditer(match.group("message"))}
        events.append(
            NormalizedLog(
                source_type="windows",
                timestamp=parse_datetime(match.group("ts")),
                username=metadata.get("user"),
                source_ip=metadata.get("srcip"),
                destination_ip=metadata.get("dstip"),
                event_id=match.group("event_id"),
                status=metadata.get("status") or match.group("level").lower(),
                process=metadata.get("process"),
                command=metadata.get("command"),
                log_level=match.group("level"),
                message=match.group("message"),
                raw_line=line,
                file_path=str(path),
                metadata=metadata,
            )
        )
    return events


def _parse_web_access(lines: list[str], path: Path, source_type: str) -> list[NormalizedLog]:
    events: list[NormalizedLog] = []
    pattern = APACHE_PATTERN if source_type == "apache" else NGINX_PATTERN
    for line in lines:
        match = pattern.match(line)
        if not match:
            continue
        request = match.group("request")
        events.append(
            NormalizedLog(
                source_type=source_type,
                timestamp=parse_datetime(match.group("ts")),
                source_ip=match.group("ip"),
                status=match.group("status"),
                command=request,
                message=request,
                raw_line=line,
                file_path=str(path),
            )
        )
    return events