from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

import result_parser  # noqa: E402
import semgrep  # noqa: E402
from semgrep_report import parse_semgrep_findings  # noqa: E402
from utils import sast_scans_ok  # noqa: E402

PID = "proj-1"


def _result(rule, path, line, severity="ERROR", cwe=None, message="Something is wrong. More detail follows."):
    return {
        "check_id": f"python.flask.security.{rule}",
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": {"cwe": cwe or [], "shortlink": f"https://sg.run/{rule}"},
        },
    }


SAMPLE = json.dumps({
    "results": [
        _result("tainted-sql-string", f"/tmp/scan/{PID}/app/app.py", 261, "ERROR",
                ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
                "Detected user input used to manually construct a SQL string. Use parameterized queries."),
        _result("tainted-sql-string", f"/tmp/scan/{PID}/app/app.py", 261, "ERROR", ["CWE-89: SQL"]),  # exact duplicate
        _result("insecure-hash-algorithm-md5", f"/tmp/scan/{PID}/app/app.py", 141, "WARNING", ["CWE-327: Broken crypto"]),
        _result("some-info-rule", f"/tmp/scan/{PID}/tests/t.py", 3, "INFO"),
        _result("odd-severity", "/elsewhere/x.py", 1, "SOMETHING"),
    ]
})


class ParseSemgrepFindingsTests(unittest.TestCase):
    def setUp(self):
        self.findings = parse_semgrep_findings(SAMPLE, PID)

    def test_duplicates_on_rule_file_line_are_removed(self):
        self.assertEqual(len(self.findings), 4)

    def test_paths_are_made_relative_to_the_project(self):
        self.assertEqual(self.findings[0]["filename"], "app/app.py")
        self.assertEqual(self.findings[3]["filename"], "elsewhere/x.py")

    def test_severity_mapping(self):
        self.assertEqual([f["severity"] for f in self.findings], ["high", "medium", "low", "medium"])

    def test_cwe_number_extracted_or_unknown(self):
        self.assertEqual(self.findings[0]["cwe_id"], "89")
        self.assertEqual(self.findings[2]["cwe_id"], "unknown")

    def test_title_is_first_sentence_of_message(self):
        self.assertEqual(
            self.findings[0]["title"],
            "Detected user input used to manually construct a SQL string.",
        )

    def test_rule_id_is_last_segment_and_link_is_kept(self):
        self.assertEqual(self.findings[0]["rule_id"], "tainted-sql-string")
        self.assertEqual(self.findings[0]["documentation_url"], "https://sg.run/tainted-sql-string")

    def test_empty_or_non_json_reports_yield_nothing(self):
        self.assertEqual(parse_semgrep_findings("", PID), [])
        self.assertEqual(parse_semgrep_findings("not json", PID), [])
        self.assertEqual(parse_semgrep_findings('{"results": []}', PID), [])


BEARER_SAMPLE = json.dumps({
    "medium": [{
        "id": "python_lang_weak_hash_md5",
        "title": "Usage of weak hashing library (MDx)",
        "cwe_ids": ["328"],
        "filename": "app/app.py",
        "line_number": 141,
        "code_extract": "hash_pass = hashlib.md5(password).hexdigest()",
        "documentation_url": "https://docs.bearer.com/x",
    }]
})


class BuildCodeSecurityTests(unittest.TestCase):
    def test_semgrep_and_bearer_reporting_the_same_md5_line_are_merged_once(self):
        groups = result_parser.build_code_security(PID, bearer_raw=BEARER_SAMPLE, semgrep_raw=SAMPLE)
        md5_hits = [o for g in groups for o in g["occurrences"] if o["line_number"] == 141]
        self.assertEqual(len(md5_hits), 1)
        self.assertEqual(md5_hits[0]["engines"], ["bearer", "semgrep"])
        self.assertTrue(md5_hits[0]["corroborated"])
        # the SQL injection only Semgrep found is still there
        pairs = {(o["filename"], o["line_number"]) for g in groups for o in g["occurrences"]}
        self.assertIn(("app/app.py", 261), pairs)

    def test_groups_are_sorted_by_severity_and_counted(self):
        groups = result_parser.build_code_security(PID, semgrep_raw=SAMPLE)
        order = ["critical", "high", "medium", "low"]
        self.assertEqual([order.index(g["severity"]) for g in groups], sorted(order.index(g["severity"]) for g in groups))
        self.assertTrue(all(g["count"] == len(g["occurrences"]) for g in groups))

    def test_groups_keep_the_shape_the_dashboard_renders(self):
        group = result_parser.build_code_security(PID, semgrep_raw=SAMPLE)[0]
        for key in ("cwe_id", "title", "severity", "count", "occurrences", "engines"):
            self.assertIn(key, group)
        for key in ("filename", "line_number", "code_extract", "documentation_url", "engines", "corroborated"):
            self.assertIn(key, group["occurrences"][0])

    def test_an_unreadable_optional_report_is_skipped_not_fatal(self):
        groups = result_parser.build_code_security(PID, bearer_raw=BEARER_SAMPLE, semgrep_raw="{broken", bandit_raw="[]")
        self.assertEqual(len(groups), 1)

    def test_an_unreadable_bearer_report_still_raises(self):
        with self.assertRaises(Exception):
            result_parser.build_code_security(PID, bearer_raw='{"medium": [')


class BuildCommandTests(unittest.TestCase):
    def test_default_command(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("SEMGREP_CONFIGS", "SEMGREP_INCLUDE_TESTS"):
                os.environ.pop(k, None)
            command = semgrep.build_semgrep_command(PID, "out.json")
        self.assertEqual(command[:2], ["semgrep", "scan"])
        self.assertIn("p/security-audit", command)
        self.assertEqual(command[command.index("--metrics") + 1], "off")
        self.assertEqual(command[command.index("--output") + 1], "/output/out.json")
        self.assertIn("--x-ignore-semgrepignore-files", command)
        self.assertEqual(command[-1], f"/tmp/scan/{PID}")

    def test_configs_and_test_scanning_are_configurable(self):
        with mock.patch.dict(os.environ, {"SEMGREP_CONFIGS": "p/python, p/flask  ./rules.yml -x", "SEMGREP_INCLUDE_TESTS": "false"}):
            command = semgrep.build_semgrep_command(PID, "out.json")
        configs = [command[i + 1] for i, c in enumerate(command) if c == "--config"]
        self.assertEqual(configs, ["p/python", "p/flask", "./rules.yml"])  # '-x' (an option) is rejected
        self.assertNotIn("--x-ignore-semgrepignore-files", command)

    def test_enabled_flag(self):
        with mock.patch.dict(os.environ, {"SEMGREP_ENABLED": "false"}):
            self.assertFalse(semgrep.semgrep_enabled())
        with mock.patch.dict(os.environ, {"SEMGREP_ENABLED": "true"}):
            self.assertTrue(semgrep.semgrep_enabled())

    def test_report_filename_is_sanitized(self):
        self.assertEqual(semgrep.semgrep_report_filename("my app!", PID), f"my_app__{PID}_Semgrep.json")


class SastOutcomeTests(unittest.TestCase):
    def test_one_sast_engine_may_fail_if_the_other_succeeds(self):
        self.assertTrue(sast_scans_ok([(True, "", "Bearer"), (False, "x", "Semgrep"), (True, "", "Syft+Grype")]))
        self.assertTrue(sast_scans_ok([(False, "x", "Bearer"), (True, "", "Semgrep")]))

    def test_all_sast_engines_failing_fails_the_scan(self):
        self.assertFalse(sast_scans_ok([(False, "x", "Bearer"), (False, "y", "Semgrep")]))

    def test_sca_failure_always_fails_the_scan(self):
        self.assertFalse(sast_scans_ok([(True, "", "Bearer"), (True, "", "Semgrep"), (False, "z", "Syft+Grype")]))

    def test_sca_only_and_sast_only_scans(self):
        self.assertTrue(sast_scans_ok([(True, "", "Syft+Grype")]))
        self.assertFalse(sast_scans_ok([(False, "", "Syft")]))
        self.assertTrue(sast_scans_ok([(True, "", "Bearer")]))


class RunSemgrepScanTests(unittest.TestCase):
    def _client(self, exit_code=0, logs=b""):
        container = mock.Mock()
        container.wait.return_value = {"StatusCode": exit_code}
        container.logs.return_value = logs
        client = mock.Mock()
        client.containers.run.return_value = container
        return client, container

    def test_success_runs_readonly_codebase_and_removes_container(self):
        client, container = self._client(0)
        with mock.patch.object(semgrep, "get_docker_client", return_value=client):
            ok, message = semgrep.run_semgrep_scan("demo", PID)
        self.assertTrue(ok)
        self.assertEqual(message, "")
        kwargs = client.containers.run.call_args.kwargs
        self.assertEqual(client.containers.run.call_args.args[0], semgrep.SEMGREP_IMAGE)
        self.assertEqual(kwargs["volumes"][semgrep.CODEBASE_VOLUME]["mode"], "ro")
        self.assertEqual(kwargs["environment"]["SEMGREP_SEND_METRICS"], "off")
        container.remove.assert_called_once_with(force=True)

    def test_failure_reports_exit_code_and_log_tail(self):
        client, container = self._client(2, b"Failed to download rules\n")
        with mock.patch.object(semgrep, "get_docker_client", return_value=client):
            ok, message = semgrep.run_semgrep_scan("demo", PID)
        self.assertFalse(ok)
        self.assertIn("code 2", message)
        self.assertIn("Failed to download rules", message)
        container.remove.assert_called_once_with(force=True)

    def test_docker_error_is_returned_not_raised(self):
        client = mock.Mock()
        client.containers.run.side_effect = RuntimeError("daemon down")
        with mock.patch.object(semgrep, "get_docker_client", return_value=client):
            ok, message = semgrep.run_semgrep_scan("demo", PID)
        self.assertFalse(ok)
        self.assertIn("daemon down", message)


if __name__ == "__main__":
    unittest.main()
