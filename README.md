# 🛡️ SOC Log Analyzer

> A Python-based Security Operations Center (SOC) Log Analyzer that parses logs from multiple sources, detects common attack techniques, maps detections to the MITRE ATT&CK framework, performs IOC matching, and generates professional incident reports.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

---

# ✨ Features

- Parse multiple log formats
  - Windows Event Logs
  - Linux Authentication Logs
  - Apache Access Logs
  - Nginx Access Logs

- Normalize all logs into a common schema

- Detect common security threats
  - Brute Force
  - Multiple Failed Logins
  - Successful Login After Brute Force
  - Encoded PowerShell
  - Suspicious PowerShell
  - Reverse Shell
  - Suspicious CMD
  - Service Installation
  - Scheduled Task Creation
  - Registry Modification
  - New Administrator Account
  - Suspicious Parent-Child Process Chain
  - Command Injection
  - Malicious Downloads

- MITRE ATT&CK Mapping

- IOC Matching
  - IP Addresses
  - Domains

- Timeline Generation

- Incident Summary Dashboard

- Professional Reports
  - JSON
  - CSV
  - Markdown

- Rich CLI Dashboard

---

# 📂 Project Structure

```
SOC-Log-Analyzer/
│
├── analyzer/
│   ├── config.py
│   ├── detector.py
│   ├── ioc.py
│   ├── mitre.py
│   ├── parser.py
│   ├── reporter.py
│   ├── rules.py
│   └── utils.py
│
├── samples/
│   ├── windows.log
│   ├── linux.log
│   ├── apache.log
│   └── nginx.log
│
├── iocs/
│   ├── ips.txt
│   └── domains.txt
│
├── reports/
│
├── requirements.txt
├── main.py
└── README.md
```

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/yourusername/soc-log-analyzer.git

cd soc-log-analyzer
```

Create virtual environment

```bash
python -m venv .venv
```

Activate

### Windows

```bash
.venv\Scripts\activate
```

### Linux

```bash
source .venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# 📦 Requirements

- Python 3.10+
- pandas
- rich

Install

```bash
pip install -r requirements.txt
```

---

# ⚡ Usage

## Analyze a Single Log

```bash
python main.py --file samples/windows.log
```

---

## Analyze an Entire Folder

```bash
python main.py --folder samples
```

---

## IOC Matching

```bash
python main.py \
    --folder samples \
    --ioc-ips iocs/ips.txt \
    --ioc-domains iocs/domains.txt
```

---

## Generate Reports

```bash
python main.py \
    --folder samples \
    --report
```

---

## IOC Matching + Reports

```bash
python main.py \
    --folder samples \
    --ioc-ips iocs/ips.txt \
    --ioc-domains iocs/domains.txt \
    --report
```

---

# 📝 Sample Console Output

```
SOC Log Analyzer Summary

Total Logs               24
Alerts                   31
IOC Matches              25

Critical Findings         5
High Findings             8
Medium Findings          18

Top Source IPs
198.51.100.20      11
203.0.113.10        6

Top MITRE Techniques
T1110    Brute Force
T1059    Command Interpreter
T1105    Ingress Tool Transfer

Incident Summary

CRITICAL Brute Force
IP               : 198.51.100.20
User             : jsmith
Evidence Events  : 5

HIGH Successful Login After Brute Force
IP               : 198.51.100.20
User             : jsmith
Evidence Events  : 4
```

---

# 🔍 Detection Rules

| Rule                               | Severity | MITRE |
| ---------------------------------- | -------- | ----- |
| Failed Login                       | Medium   | T1110 |
| Multiple Failed Logins             | High     | T1110 |
| Brute Force                        | Critical | T1110 |
| Successful Login After Brute Force | High     | T1078 |
| Encoded PowerShell                 | Critical | T1059 |
| Suspicious PowerShell              | High     | T1059 |
| Reverse Shell                      | Critical | T1059 |
| Service Installation               | High     | T1543 |
| Scheduled Task Creation            | High     | T1053 |
| Registry Modification              | Medium   | T1112 |
| Suspicious CMD                     | Medium   | T1059 |
| New Administrator Account          | Critical | T1136 |
| Suspicious Parent Child Process    | High     | T1059 |
| Apache Command Injection           | Medium   | T1190 |
| Nginx Download Activity            | Medium   | T1105 |

---

# 🛡️ MITRE ATT&CK Coverage

| Technique | Description                       |
| --------- | --------------------------------- |
| T1110     | Brute Force                       |
| T1078     | Valid Accounts                    |
| T1059     | Command and Scripting Interpreter |
| T1053     | Scheduled Task                    |
| T1112     | Modify Registry                   |
| T1543     | Create or Modify System Process   |
| T1136     | Create Account                    |
| T1105     | Ingress Tool Transfer             |
| T1190     | Exploit Public-Facing Application |

---

# 📄 Generated Reports

Running with the `--report` flag generates:

```
reports/

incident_report_TIMESTAMP.json

incident_report_TIMESTAMP.csv

incident_report_TIMESTAMP.md
```

### JSON

- Executive Summary
- Findings
- Timeline
- IOC Matches
- MITRE Mapping
- Recommendations

### CSV

- Detection Summary
- Timestamps
- Severity
- Source IP
- Destination IP
- Username

### Markdown

- Executive Summary
- MITRE Mapping
- Recommendations

---

# 🎯 Example Detection Workflow

```
Raw Logs
      │
      ▼
Log Parser
      │
      ▼
Normalization
      │
      ▼
Detection Engine
      │
      ├─────────────┐
      ▼             ▼
MITRE          IOC Matching
      │             │
      └──────┬──────┘
             ▼
Incident Report
             ▼
Console Dashboard
```

---

# 🔥 Example Attack Scenario

The sample logs simulate a realistic attack chain:

1. Repeated failed authentication attempts
2. Brute force attack
3. Successful login
4. Encoded PowerShell execution
5. Malware download
6. Scheduled task persistence
7. Service installation
8. Privilege escalation
9. Administrator account creation

The analyzer correlates these events into high-confidence security incidents and maps them to the MITRE ATT&CK framework.

---

# 📊 Supported Log Sources

| Source             | Status |
| ------------------ | ------ |
| Windows Event Logs | ✅     |
| Linux Auth Logs    | ✅     |
| Apache Access Logs | ✅     |
| Nginx Access Logs  | ✅     |

---

# 💡 Future Improvements

- HTML Report Dashboard
- Sigma Rule Support
- YARA Integration
- VirusTotal API Integration
- GeoIP Enrichment
- Threat Intelligence Feeds
- Email Alerting
- PDF Reports
- Splunk Export
- Elastic Export

---

# 🧪 Technologies Used

- Python
- Rich
- Pandas
- Regular Expressions
- Dataclasses
- JSON
- CSV
- MITRE ATT&CK

---

# 🎓 Learning Objectives

This project demonstrates:

- Security Log Parsing
- Log Normalization
- Detection Engineering
- IOC Matching
- Threat Hunting Concepts
- MITRE ATT&CK Mapping
- Incident Reporting
- Security Automation
- Python Software Design
- CLI Application Development

---

# 📜 License

This project is licensed under the MIT License.

---
