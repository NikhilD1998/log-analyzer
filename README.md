# SOC Log Analyzer

SOC Log Analyzer is a Python CLI for parsing heterogeneous security logs, applying dynamic YAML-backed detections, matching IOCs, mapping findings to MITRE ATT&CK, and generating incident reports.

## Features

- Normalizes Linux auth, Windows event text exports, Apache, and Nginx logs.
- Loads detection content dynamically from YAML rule files.
- Supports threshold and sequence detections for brute-force and post-compromise behavior.
- Matches IOC lists for IPs, domains, URLs, and hashes.
- Generates console, JSON, CSV, and Markdown reports.
- Uses Rich for a SOC-style command-line dashboard.

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python analyzer.py --file samples/auth.log
python analyzer.py --folder samples --report
python analyzer.py --folder samples --format all --severity high
python analyzer.py --folder samples --ioc-domains iocs/domains.txt --ioc-ips iocs/ips.txt --report
```

## Rule Format

```yaml
- name: Brute Force
  severity: Critical
  description: Concentrated failed logins indicate brute-force behavior.
  mitre_technique: T1110
  source_types: [linux]
  rule_type: threshold
  fields: [message]
  pattern:
    - Failed password
  threshold: 5
  window: 60
  group_by: [source_ip]
```

## Reports

Generated reports are written to the reports directory with timestamped filenames.

## Testing

```bash
pytest
```
