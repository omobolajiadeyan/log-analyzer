#!/usr/bin/env python3
"""
Log Analyzer - Detect threats and suspicious activity in system/application logs.
Author: Omobolaji Adeyan
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from rules import RULES, SEVERITY_ORDER

# ANSI colours
RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
}


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    mitre: str
    file: str
    line_number: int
    line_content: str
    description: str


@dataclass
class AnalysisResult:
    files_analyzed: list = field(default_factory=list)
    total_lines: int = 0
    alerts: list = field(default_factory=list)

    @property
    def total_alerts(self):
        return len(self.alerts)

    @property
    def critical_count(self):
        return sum(1 for a in self.alerts if a.severity == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for a in self.alerts if a.severity == "HIGH")


def analyze_file(filepath: str) -> tuple[list[Alert], int]:
    alerts = []
    compiled_rules = [(r, re.compile(r["regex"])) for r in RULES]

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{YELLOW}Warning: Could not read {filepath}: {e}{RESET}")
        return [], 0

    for line_num, line in enumerate(lines, start=1):
        for rule, regex in compiled_rules:
            if regex.search(line):
                alerts.append(Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    category=rule["category"],
                    mitre=rule["mitre"],
                    file=filepath,
                    line_number=line_num,
                    line_content=line.strip()[:200],
                    description=rule["description"],
                ))

    return alerts, len(lines)


def print_banner():
    print(f"""
{CYAN}{BOLD}
  ██╗      ██████╗  ██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
  ██║     ██╔═══██╗██╔════╝     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚════██║██╔════╝██╔══██╗
  ██║     ██║   ██║██║  ███╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝     ██╔╝█████╗  ██████╔╝
  ██║     ██║   ██║██║   ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝     ██╔╝ ██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝╚██████╔╝    ██║  ██║██║ ╚████║██║  ██║███████╗██║      ██║  ███████╗██║  ██║
  ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═╝  ╚══════╝╚═╝  ╚═╝
{RESET}{GRAY}  Threat detection engine for system & application logs | github.com/omobolajiadeyan{RESET}
""")


def print_alert(alert: Alert, verbose: bool = False):
    color = SEVERITY_COLOR.get(alert.severity, GRAY)
    print(f"\n  {color}{BOLD}[{alert.severity}]{RESET} {BOLD}{alert.rule_name}{RESET}  {GRAY}({alert.rule_id}){RESET}")
    print(f"    Category : {alert.category}")
    print(f"    MITRE    : {GRAY}{alert.mitre}{RESET}")
    print(f"    File     : {alert.file}:{alert.line_number}")
    if verbose:
        print(f"    Log line : {GRAY}{alert.line_content}{RESET}")
    print(f"    Detail   : {alert.description}")


def print_results(result: AnalysisResult, verbose: bool = False):
    # Group by category
    by_category = defaultdict(list)
    for alert in sorted(result.alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 99)):
        by_category[alert.category].append(alert)

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  LOG ANALYZER REPORT{RESET}")
    print(f"{'='*65}")
    print(f"  Files analyzed : {len(result.files_analyzed)}")
    print(f"  Total lines    : {result.total_lines:,}")
    print(f"  Total alerts   : {result.total_alerts}")
    print(f"  Critical       : {RED}{result.critical_count}{RESET}")
    print(f"  High           : {ORANGE}{result.high_count}{RESET}")
    print(f"{'='*65}")

    if not result.alerts:
        print(f"\n{GREEN}  No threats detected. Logs look clean.{RESET}\n")
        return

    for category, alerts in by_category.items():
        print(f"\n{BOLD}{CYAN}  [{category}]{RESET}  —  {len(alerts)} alert(s)")
        for alert in alerts:
            print_alert(alert, verbose=verbose)

    # Top offending IPs if present
    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    ip_counts = defaultdict(int)
    for alert in result.alerts:
        for ip in ip_pattern.findall(alert.line_content):
            ip_counts[ip] += 1

    if ip_counts:
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"\n{BOLD}  Top Offending IPs:{RESET}")
        for ip, count in top_ips:
            print(f"    {RED}{ip}{RESET}  —  {count} alert(s)")

    print()


def export_json(result: AnalysisResult, output_file: str):
    data = {
        "files_analyzed": result.files_analyzed,
        "total_lines": result.total_lines,
        "total_alerts": result.total_alerts,
        "alerts": [asdict(a) for a in result.alerts],
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{GREEN}Report exported to {output_file}{RESET}")


def collect_log_files(target: str) -> list[str]:
    """Collect all readable log files from a path."""
    target_path = Path(target)
    if target_path.is_file():
        return [str(target_path)]

    log_files = []
    log_extensions = {".log", ".txt", ".out", ".err", ".syslog", ".access", ".error"}
    for root, _, files in os.walk(target_path):
        for filename in files:
            fp = Path(root) / filename
            if fp.suffix in log_extensions or "log" in fp.name.lower():
                log_files.append(str(fp))
    return log_files


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer — Threat detection for system and application logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyzer.py /var/log/auth.log              # Analyze a single log file
  python analyzer.py /var/log/                      # Analyze all logs in a directory
  python analyzer.py sample_logs/                   # Analyze sample logs
  python analyzer.py sample_logs/ --verbose         # Show full log lines
  python analyzer.py sample_logs/ --severity HIGH   # Only HIGH and CRITICAL alerts
  python analyzer.py sample_logs/ --output report.json
        """,
    )
    parser.add_argument("target", help="Log file or directory to analyze")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full log line for each alert")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum severity to report (default: LOW = show all)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"{RED}Error: Path '{args.target}' does not exist.{RESET}")
        sys.exit(1)

    print_banner()

    log_files = collect_log_files(args.target)
    if not log_files:
        print(f"{YELLOW}No log files found in '{args.target}'.{RESET}")
        sys.exit(0)

    print(f"{CYAN}Analyzing {len(log_files)} file(s) with {len(RULES)} detection rules...{RESET}")

    result = AnalysisResult()
    for log_file in log_files:
        alerts, line_count = analyze_file(log_file)
        result.files_analyzed.append(log_file)
        result.total_lines += line_count
        result.alerts.extend(alerts)

    # Apply severity filter
    min_order = SEVERITY_ORDER.get(args.severity, 3)
    result.alerts = [a for a in result.alerts if SEVERITY_ORDER.get(a.severity, 99) <= min_order]

    print_results(result, verbose=args.verbose)

    if args.output:
        export_json(result, args.output)

    if result.critical_count > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
