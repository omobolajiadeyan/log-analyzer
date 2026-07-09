# Log Analyzer

A lightweight threat detection engine that scans system and application log files for indicators of attack, suspicious behavior, and policy violations — mapped to the MITRE ATT&CK framework.

## Why This Matters

Logs are the first place a security analyst looks during an incident. This tool automates the tedious process of manually reviewing thousands of log lines, surfacing only what matters — with context.

## Features

- 13 built-in detection rules across 6 threat categories
- MITRE ATT&CK technique mapping for every alert
- Analyzes SSH, auth, web access, system, and application logs
- Identifies top offending IP addresses automatically
- Color-coded severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- JSON export for SIEM integration or reporting
- Scans entire directories of log files in one command
- Zero third-party dependencies — pure Python standard library

## Detection Categories & Rules

| ID | Rule | Category | Severity | MITRE |
|---|---|---|---|---|
| AUTH-001 | Failed Login Attempt | Authentication | MEDIUM | T1110 |
| AUTH-002 | Multiple Failed Logins (Brute Force) | Authentication | HIGH | T1110 |
| AUTH-003 | Root Login | Authentication | HIGH | T1078 |
| NET-001 | Port Scan Detected | Network | HIGH | T1046 |
| NET-002 | SQL Injection Attempt | Web Attack | CRITICAL | T1190 |
| NET-003 | XSS Attempt | Web Attack | HIGH | T1059.007 |
| NET-004 | Directory Traversal | Web Attack | HIGH | T1083 |
| SYS-001 | Privilege Escalation | Privilege Escalation | HIGH | T1548 |
| SYS-002 | Suspicious Command Execution | Execution | CRITICAL | T1059 |
| SYS-003 | File Deletion | Defense Evasion | HIGH | T1070.004 |
| SYS-004 | Cron Job Modified | Persistence | MEDIUM | T1053.003 |
| MAL-001 | Reverse Shell Indicator | Malware | CRITICAL | T1059.004 |
| MAL-002 | Tor/I2P Connection | Malware | HIGH | T1090.003 |

## Installation

```bash
git clone https://github.com/omobolajiadeyan/log-analyzer.git
cd log-analyzer
python --version  # Requires Python 3.10+
```

## Usage

```bash
# Analyze a single log file
python analyzer.py sample_logs/auth.log

# Analyze all logs in a directory
python analyzer.py sample_logs/

# Show full log lines for each alert
python analyzer.py sample_logs/ --verbose

# Only show HIGH and CRITICAL alerts
python analyzer.py sample_logs/ --severity HIGH

# Export report to JSON
python analyzer.py sample_logs/ --output report.json

# Analyze real system logs (Linux)
python analyzer.py /var/log/auth.log
python analyzer.py /var/log/
```

## Example Output

```
  LOG ANALYZER
  Threat detection engine for system & application logs

Analyzing 2 file(s) with 13 detection rules...

=================================================================
  LOG ANALYZER REPORT
=================================================================
  Files analyzed : 2
  Total lines    : 21
  Total alerts   : 9
  Critical       : 2
  High           : 6
=================================================================

  [Authentication]  —  5 alert(s)

  [CRITICAL] Multiple Failed Logins (Brute Force)  (AUTH-002)
    Category : Authentication
    MITRE    : T1110 - Brute Force
    File     : sample_logs/auth.log:6
    Detail   : Account locked or too many failed attempts — possible brute-force.

  Top Offending IPs:
    192.168.1.105  —  6 alert(s)
    203.0.113.99   —  2 alert(s)
    10.0.0.50      —  2 alert(s)
```

## Project Structure

```
log-analyzer/
├── analyzer.py        # Main CLI entrypoint
├── rules.py           # Detection rules with MITRE mappings
├── requirements.txt   # No dependencies needed
├── sample_logs/
│   ├── auth.log       # Sample SSH/auth log with threats
│   └── web_access.log # Sample web log with injection attempts
└── README.md
```

## Author

**Omobolaji Adeyan** — Cybersecurity Portfolio Project  
[GitHub](https://github.com/omobolajiadeyan)
