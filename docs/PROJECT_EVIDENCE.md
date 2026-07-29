# Project Evidence

This page records reproducible evidence for Log Analyzer. The sample logs are
public-safe synthetic inputs designed for demonstration and regression testing,
not production telemetry.

## Technical Evidence

Snapshot verified on July 29, 2026:

- Detection rules: 13 built-in rules across authentication, web attack,
  network, privilege escalation, persistence, execution, and malware signals.
- MITRE ATT&CK mapping: every alert includes a technique reference.
- Automation output: JSON and SARIF 2.1.0.
- GitHub Action: reusable composite action that emits SARIF for Code Scanning.
- Browser review path: `web/` report viewer for exported JSON reports.
- Test coverage: analyzer, collection, summary, SARIF, and rule behavior tests.
- Runtime dependency posture: Python standard library only.

## Reproducible Demo

Run the sample analysis:

```bash
python analyzer.py sample_logs/ --verbose
```

Generate JSON evidence for the browser viewer:

```bash
python analyzer.py sample_logs/ --output web/sample-report.json
```

Generate SARIF evidence for code-scanning workflows:

```bash
python analyzer.py sample_logs/ --format sarif --output log-analyzer.sarif
```

Expected sample-report summary:

| Metric | Value |
| --- | ---: |
| Files analyzed | 2 |
| Total log lines | 21 |
| Total alerts | 19 |
| Critical alerts | 3 |
| High alerts | 9 |
| Top source IP | 192.168.1.105 |

The command exits with status `2` when critical alerts are present. That is
intentional so CI workflows can fail on critical log evidence.

## Report Viewer Evidence

Open `web/index.html` from a static server and inspect `web/sample-report.json`.
The viewer shows:

- risk level and alert totals;
- severity counts;
- top offending IPs;
- MITRE-mapped alert detail;
- upload support for a fresh JSON report.

## Boundaries

Log Analyzer is a lightweight detection aid. It does not replace a SIEM, EDR,
incident-response process, tuned detections, or environment-specific baselines.
Use alerts as investigation leads and validate them against local context.
