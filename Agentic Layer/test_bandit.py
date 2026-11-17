from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

import bandit_scanner  # noqa: E402
from bandit_report import flagged_line, parse_bandit_findings  # noqa: E402

PID = "proj-1"


def _item(test_id, severity, confidence, line, text="Issue text", cwe=None, filename=None, code=None):
    return {
        "test_id": test_id,
        "test_name": test_id.lower(),
        "issue_severity": severity,
        "issue_confidence": confidence,
        "issue_text": text,
        "issue_cwe": {"id": cwe, "link": "https://cwe.mitre.org"} if cwe else {},
        "filename": filename or f"/tmp/scan/{PID}/app/app.py",
        "line_number": line,
        "code": code if code is not None else f"{line - 1} before()\n{line} flagged_call(secret)\n{line + 1} after()\n",
        "line_range": [line - 1, line, line + 1] if test_id == "B501" else [line],
        "more_info": f"https://bandit.readthedocs.io/{test_id}",
    }


SAMPLE = json.dumps({
    "results": [
        _item("B105", "LOW", "MEDIUM", 26, "Possible hardcoded password: 'secret'", cwe=259),
        _item("B324", "HIGH", "HIGH", 141, "Use of weak MD5 hash", cwe=327),
        _item("B608", "MEDIUM", "LOW", 261, "Possible SQL injection", cwe=89),
        _item("B999", "LOW", "LOW", 5, "Pure noise"),                      # LOW/LOW is dropped
        _item("B324", "HIGH", "HIGH", 141, "Use of weak MD5 hash", cwe=327),  # exact duplicate
        _item("B501", "HIGH", "HIGH", 18, "verify=False", cwe=295, filename=f"/tmp/scan/{PID}/tests/e2e.py"),
        _item("B777", "MEDIUM", "MEDIUM", 7, "No cwe given"),
    ]
})


class ParseBanditTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_bandit_findings(SAMPLE, PID)

    def test_low_severity_low_confidence_noise_and_duplicates_are_dropped(self):
        self.assertEqual(len(self.findings), 5)
        self.assertNotIn("B999", [x["rule_id"] for x in self.findings])
        self.assertEqual([x["rule_id"] for x in self.findings].count("B324"), 1)

    def test_severity_cwe_and_paths(self):
        by_rule = {x["rule_id"]: x for x in self.findings}
        self.assertEqual(by_rule["B324"]["severity"], "high")
        self.assertEqual(by_rule["B608"]["severity"], "medium")
        self.assertEqual(by_rule["B105"]["severity"], "low")
        self.assertEqual(by_rule["B324"]["cwe_id"], "327")
        self.assertEqual(by_rule["B777"]["cwe_id"], "unknown")
        self.assertEqual(by_rule["B324"]["filename"], "app/app.py")
        self.assertEqual(by_rule["B501"]["filename"], "tests/e2e.py")

    def test_only_the_flagged_line_is_returned_as_the_snippet(self):
        by_rule = {x["rule_id"]: x for x in self.findings}
        self.assertEqual(by_rule["B324"]["code_extract"], "flagged_call(secret)")

    def test_multiline_statement_range_is_kept(self):
        by_rule = {x["rule_id"]: x for x in self.findings}
        self.assertEqual((by_rule["B501"]["start_line"], by_rule["B501"]["end_line"]), (17, 19))
        self.assertEqual((by_rule["B324"]["start_line"], by_rule["B324"]["end_line"]), (141, 141))

    def test_audit_style_checks_are_reported_as_low(self):
        report = json.dumps({"results": [
            _item("B108", "MEDIUM", "MEDIUM", 5, "Probable insecure usage of temp file/directory."),
            _item("B310", "MEDIUM", "HIGH", 6, "Audit url open for permitted schemes."),
            _item("B608", "MEDIUM", "MEDIUM", 7, "Possible SQL injection", cwe=89),
        ]})
        severities = {x["rule_id"]: x["severity"] for x in parse_bandit_findings(report, PID)}
        self.assertEqual(severities, {"B108": "low", "B310": "low", "B608": "medium"})

    def test_empty_literal_passwords_are_not_findings_but_real_ones_are(self):
        report = json.dumps({"results": [
            _item("B107", "LOW", "MEDIUM", 3, "Possible hardcoded password: ''"),
            _item("B105", "LOW", "MEDIUM", 4, 'Possible hardcoded password: ""'),
            _item("B106", "LOW", "MEDIUM", 5, "Possible hardcoded password: 'hunter2'"),
        ]})
        self.assertEqual([x["rule_id"] for x in parse_bandit_findings(report, PID)], ["B106"])

    def test_template_placeholders_are_not_hardcoded_passwords(self):
        report = json.dumps({"results": [
            _item("B105", "LOW", "MEDIUM", 3, "Possible hardcoded password: '${random_password.db_master[0].result}'"),
            _item("B105", "LOW", "MEDIUM", 4, "Possible hardcoded password: '{{ db_password }}'"),
            _item("B105", "LOW", "MEDIUM", 5, "Possible hardcoded password: '<password>'"),
            _item("B105", "LOW", "MEDIUM", 6, "Possible hardcoded password: '$DB_PASSWORD'"),
            _item("B105", "LOW", "MEDIUM", 7, "Possible hardcoded password: 'p@ss$word'"),   # a real password that merely contains $
            _item("B105", "LOW", "MEDIUM", 8, "Possible hardcoded password: 'admin123'"),
        ]})
        self.assertEqual([x["line_number"] for x in parse_bandit_findings(report, PID)], [7, 8])

    def test_engine_and_docs_link(self):
        first = self.findings[0]
        self.assertEqual(first["engine"], "bandit")
        self.assertTrue(first["documentation_url"].startswith("https://bandit.readthedocs.io/"))

    def test_empty_or_invalid_reports(self):
        self.assertEqual(parse_bandit_findings("", PID), [])
        self.assertEqual(parse_bandit_findings("not json", PID), [])
        self.assertEqual(parse_bandit_findings('{"results": []}', PID), [])

    def test_flagged_line_helper(self):
        code = "10 a = 1\n11 b = md5(x)\n12 c = 3\n"
        self.assertEqual(flagged_line(code, 11), "b = md5(x)")
        self.assertEqual(flagged_line(code, 99), "")
        self.assertEqual(flagged_line("", 1), "")


class CommandTests(unittest.TestCase):
    def test_default_command(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BANDIT_SKIP", None)
            command = bandit_scanner.build_bandit_command(PID, "out.json")
        self.assertEqual(command[command.index("-r") + 1], f"/tmp/scan/{PID}")
        self.assertEqual(command[command.index("-f") + 1], "json")
        self.assertEqual(command[command.index("-o") + 1], "/output/out.json")
        self.assertIn("*/node_modules/*", command[command.index("-x") + 1])
        self.assertEqual(command[command.index("-s") + 1], "B101")
        self.assertIn("-q", command)

    def test_skip_list_is_configurable_and_validated(self):
        with mock.patch.dict(os.environ, {"BANDIT_SKIP": "b101, B404 ; rm -rf, notatest"}):
            self.assertEqual(bandit_scanner.bandit_skips(), ["B101", "B404"])
        with mock.patch.dict(os.environ, {"BANDIT_SKIP": ""}):
            self.assertEqual(bandit_scanner.bandit_skips(), [])
            self.assertNotIn("-s", bandit_scanner.build_bandit_command(PID, "o.json"))

    def test_enabled_flag_and_filename(self):
        with mock.patch.dict(os.environ, {"BANDIT_ENABLED": "false"}):
            self.assertFalse(bandit_scanner.bandit_enabled())
        with mock.patch.dict(os.environ, {"BANDIT_ENABLED": "true"}):
            self.assertTrue(bandit_scanner.bandit_enabled())
        self.assertEqual(bandit_scanner.bandit_report_filename("my app!", PID), f"my_app__{PID}_Bandit.json")


class RunBanditTests(unittest.TestCase):
    def _client(self, exit_code=0, logs=b""):
        container = mock.Mock()
        container.wait.return_value = {"StatusCode": exit_code}
        container.logs.return_value = logs
        client = mock.Mock()
        client.containers.run.return_value = container
        return client, container

    def test_exit_codes_0_and_1_are_success_and_the_container_is_isolated(self):
        for code in (0, 1):
            client, container = self._client(code)
            with mock.patch.object(bandit_scanner, "get_docker_client", return_value=client):
                ok, message = bandit_scanner.run_bandit_scan("demo", PID)
            self.assertTrue(ok, code)
            self.assertEqual(message, "")
            kwargs = client.containers.run.call_args.kwargs
            self.assertEqual(kwargs["network_mode"], "none")
            self.assertEqual(kwargs["volumes"][bandit_scanner.CODEBASE_VOLUME]["mode"], "ro")
            container.remove.assert_called_once_with(force=True)

    def test_failure_reports_exit_code_and_log_tail(self):
        client, container = self._client(2, b"syntax error in config\n")
        with mock.patch.object(bandit_scanner, "get_docker_client", return_value=client):
            ok, message = bandit_scanner.run_bandit_scan("demo", PID)
        self.assertFalse(ok)
        self.assertIn("code 2", message)
        self.assertIn("syntax error in config", message)
        container.remove.assert_called_once_with(force=True)

    def test_docker_errors_are_returned_not_raised(self):
        client = mock.Mock()
        client.containers.run.side_effect = RuntimeError("daemon down")
        with mock.patch.object(bandit_scanner, "get_docker_client", return_value=client):
            ok, message = bandit_scanner.run_bandit_scan("demo", PID)
        self.assertFalse(ok)
        self.assertIn("daemon down", message)


if __name__ == "__main__":
    unittest.main()
