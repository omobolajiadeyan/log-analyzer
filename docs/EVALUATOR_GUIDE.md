# Evaluator Guide

This guide gives reviewers a quick path to judge Log Analyzer without reading
the entire repository.

## Five-Minute Review

1. Run the tests:

   ```bash
   python -m unittest discover -s tests -v
   ```

2. Run the sample analyzer:

   ```bash
   python analyzer.py sample_logs/ --verbose
   ```

3. Export JSON:

   ```bash
   python analyzer.py sample_logs/ --output web/sample-report.json
   ```

4. Open the browser viewer:

   ```bash
   cd web
   python3 -m http.server 8080
   ```

   Then open `http://127.0.0.1:8080/`.

5. Export SARIF:

   ```bash
   python analyzer.py sample_logs/ --format sarif --output log-analyzer.sarif
   ```

## What To Inspect

- `rules.py`: rule IDs, regex patterns, severity, categories, and MITRE
  mappings.
- `analyzer.py`: file collection, alert construction, summary output, JSON,
  SARIF, and critical-alert exit behavior.
- `web/`: reviewer-friendly report viewer for exported JSON.
- `tests/test_analyzer.py`: regression coverage for detections, file
  collection, summary, and SARIF.

## Reviewer Notes

- The sample logs are synthetic public-safe evidence.
- Critical alerts intentionally return exit code `2`.
- JSON contains summary fields for review and dashboard usage.
- SARIF is intended for GitHub Code Scanning workflows.
