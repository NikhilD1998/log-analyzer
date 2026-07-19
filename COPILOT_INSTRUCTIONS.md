# GitHub Copilot Instructions

## Project

**Name:** SOC Log Analyzer

**Goal:**

Build a production-quality Python CLI application that analyzes security logs from multiple sources, detects suspicious activity, maps findings to the MITRE ATT&CK framework, and generates an incident report.

The project should resemble a real SOC analyst tool rather than a coding exercise.

---

# Tech Stack

- Python 3.12+
- Rich (CLI)
- Pandas
- PyYAML
- Regex
- Dataclasses
- pathlib
- argparse
- logging
- json
- csv

---

# Project Structure

```text
soc-log-analyzer/
│
├── analyzer.py
├── parser.py
├── detector.py
├── reporter.py
├── ioc.py
├── mitre.py
├── utils.py
├── config.py
│
├── rules/
│   ├── windows.yaml
│   ├── linux.yaml
│   ├── apache.yaml
│   └── nginx.yaml
│
├── samples/
│   ├── windows.log
│   ├── auth.log
│   ├── apache.log
│   └── nginx.log
│
├── reports/
│
├── tests/
│
├── requirements.txt
├── README.md
└── .gitignore
```

---

# Development Rules

- Use Python type hints everywhere.
- Follow PEP8.
- Keep functions small and single-purpose.
- Avoid duplicated code.
- Prefer dataclasses for structured objects.
- Add docstrings for every public function.
- Add error handling for invalid log lines.
- Never crash on malformed logs.
- Log internal errors using Python logging.
- Make code modular and reusable.
- Avoid global variables.

---

# CLI Requirements

Support commands like:

```bash
python analyzer.py --file samples/auth.log

python analyzer.py --folder samples/

python analyzer.py --format json

python analyzer.py --report

python analyzer.py --severity high
```

---

# Phase 1 — Log Parsing

Implement parsers for:

- Linux auth.log
- Windows Event Logs (text export)
- Apache access.log
- Nginx access.log

Extract:

- Timestamp
- Username
- Source IP
- Destination IP (if present)
- Event ID
- Status
- Process
- Command
- Log Level
- Message

Return normalized log objects regardless of source.

---

# Phase 2 — Detection Engine

Create a modular detection engine.

Each detection should be an independent rule.

Detect:

- Failed login
- Multiple failed logins
- Brute-force attack
- Successful login after brute force
- Privilege escalation
- New administrator account
- Suspicious PowerShell
- Encoded PowerShell
- Suspicious cmd.exe usage
- Reverse shell indicators
- wget downloads
- curl downloads
- Service installation
- Scheduled task creation
- Registry modification
- Suspicious parent-child process relationships

Each detection should return:

- Rule name
- Severity
- Description
- MITRE Technique
- Evidence

---

# Phase 3 — IOC Detection

Support IOC lists:

- Malicious IPs
- Domains
- File hashes
- URLs

Implement IOC matching.

Highlight every IOC found.

---

# Phase 4 — YAML Detection Rules

Store detection rules inside:

```
rules/
```

Example:

```yaml
name: Brute Force

severity: High

pattern:
  - Failed password

threshold: 5

window: 60
```

Load rules dynamically.

Do not hardcode rules.

---

# Phase 5 — MITRE ATT&CK Mapping

Each detection must include ATT&CK mappings.

Examples:

| Detection             | MITRE |
| --------------------- | ----- |
| Brute Force           | T1110 |
| PowerShell            | T1059 |
| Valid Accounts        | T1078 |
| Remote Services       | T1021 |
| Service Installation  | T1543 |
| Registry Modification | T1112 |

Generate MITRE summaries in reports.

---

# Phase 6 — Incident Report

Generate reports in:

- Console
- JSON
- CSV
- Markdown

Report should contain:

- Executive Summary
- Critical Findings
- High Findings
- Medium Findings
- Low Findings
- Timeline
- Source IPs
- Destination IPs
- Users
- MITRE Mapping
- IOC Matches
- Recommendations

---

# CLI Dashboard

Use Rich to display:

- Progress bars
- Colored severity
- Tables
- Panels
- Summary statistics

Example sections:

- Total Logs
- Alerts
- Top IPs
- Top Users
- Top MITRE Techniques
- IOC Matches

---

# Severity Levels

Support:

- Critical
- High
- Medium
- Low
- Informational

---

# Reporting

Save reports inside:

```
reports/
```

Support:

- JSON
- CSV
- Markdown

File names should include timestamps.

---

# Unit Tests

Create tests for:

- Parsers
- Detection engine
- IOC matching
- Report generation
- Rule loading

Aim for high code coverage.

---

# README

Include:

- Features
- Installation
- Screenshots
- Sample logs
- CLI examples
- Detection examples
- MITRE mapping
- Future improvements

---

# Nice-to-Have Features

- Interactive dashboard
- Live log monitoring
- Watch mode
- Rule hot reload
- IP reputation integration
- GeoIP lookup
- VirusTotal integration (optional)
- Sigma rule support
- Export HTML reports
- Timeline visualization
- Search and filtering
- Configuration file
- Docker support
- GitHub Actions CI

---

# Coding Expectations

- Production-quality code.
- Clear module separation.
- Reusable architecture.
- Maintainable codebase.
- Consistent naming.
- Comprehensive comments where needed.
- Focus on readability over clever implementations.

---

# Final Deliverable

The finished project should:

- Parse multiple log formats.
- Detect common SOC security events.
- Support rule-based detection.
- Match Indicators of Compromise.
- Map findings to MITRE ATT&CK.
- Generate professional incident reports.
- Provide a polished CLI experience.
- Be suitable as a portfolio project for SOC Analyst and Blue Team roles.
