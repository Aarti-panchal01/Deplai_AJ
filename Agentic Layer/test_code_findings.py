from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from code_findings import (  # noqa: E402
    adjust_severity,
    consensus_severity,
    family_of,
    group_findings,
    is_test_path,
    merge_findings,
)


def f(engine, rule_id, title, severity="medium", cwe="unknown", filename="app/app.py", line=10, code=""):
    return {
        "engine": engine, "rule_id": rule_id, "title": title, "severity": severity, "cwe_id": cwe,
        "filename": filename, "line_number": line, "code_extract": code, "documentation_url": "",
    }


class FamilyTests(unittest.TestCase):
    def test_md5_lands_in_one_family_whatever_the_engine_calls_the_cwe(self):
        self.assertEqual(family_of(f("bearer", "python_lang_weak_hash_md5", "Usage of weak hashing library (MDx)", cwe="328")), "weak-hash")
        self.assertEqual(family_of(f("semgrep", "insecure-hash-algorithm-md5", "Detected MD5 hash algorithm which is considered insecure.", cwe="327")), "weak-hash")
        self.assertEqual(family_of(f("bandit", "B324", "Use of weak MD5 hash for security. Consider usedforsecurity=False", cwe="327")), "weak-hash")

    def test_weak_prng_is_not_confused_with_weak_hash_despite_sharing_cwe_327(self):
        self.assertEqual(family_of(f("bearer", "python_lang_weak_random", "Usage of weak Pseudo-Random Number Generator (PRNG)", cwe="327")), "weak-random")
        self.assertEqual(family_of(f("bandit", "B311", "Standard pseudo-random generators are not suitable for security/cryptographic purposes.", cwe="330")), "weak-random")

    def test_sql_injection_across_engines(self):
        self.assertEqual(family_of(f("semgrep", "tainted-sql-string", "Detected user input used to manually construct a SQL string.", cwe="704")), "sql-injection")
        self.assertEqual(family_of(f("bandit", "B608", "Possible SQL injection vector through string-based query construction.", cwe="89")), "sql-injection")
        self.assertEqual(family_of(f("bearer", "python_lang_sql_injection", "Unsanitized user input in SQL query", cwe="89")), "sql-injection")

    def test_a_password_that_merely_contains_sql_is_still_a_hardcoded_secret(self):
        finding = f("bandit", "B105", "Possible hardcoded password: 'sqlpass'", cwe="259")
        self.assertEqual(family_of(finding), "hardcoded-secret")

    def test_template_and_xss_findings_share_a_family(self):
        self.assertEqual(family_of(f("semgrep", "dangerous-template-string", "Found a template created with string formatting.", cwe="96")), "web-injection")
        self.assertEqual(family_of(f("semgrep", "raw-html-format", "Detected user input flowing into a manually constructed HTML string.", cwe="79")), "web-injection")

    def test_other_families(self):
        self.assertEqual(family_of(f("bandit", "B506", "Use of unsafe yaml load.", cwe="20")), "deserialization")
        self.assertEqual(family_of(f("semgrep", "disabled-cert-validation", "Certificate verification has been explicitly disabled.", cwe="295")), "tls-verification")
        self.assertEqual(family_of(f("bandit", "B501", "Call to requests with verify=False disabling SSL certificate checks", cwe="295")), "tls-verification")

    def test_unknown_cwe_falls_back_without_collapsing_everything(self):
        self.assertEqual(family_of(f("x", "some-rule", "Something odd", cwe="1234")), "cwe-1234")
        self.assertEqual(family_of(f("x", "some-rule", "Something odd", cwe="unknown")), "rule-some-rule")


class SeverityTests(unittest.TestCase):
    def test_prng_for_a_filename_prefix_is_demoted_to_low(self):
        finding = f("bearer", "python_lang_weak_random", "Usage of weak PRNG", severity="high", cwe="327", code="rand = random.randint(1, 100)")
        self.assertEqual(adjust_severity(finding), "low")

    def test_prng_protecting_something_keeps_its_severity(self):
        for line in ("session_token = random.randint(0, 99999)", "otp = str(random.random())", "reset_key = random.choice(chars)"):
            finding = f("bearer", "python_lang_weak_random", "Usage of weak PRNG", severity="high", cwe="327", code=line)
            self.assertEqual(adjust_severity(finding), "high", line)

    def test_prng_without_source_line_is_left_alone(self):
        finding = f("semgrep", "insecure-random", "weak PRNG", severity="high", code="")
        self.assertEqual(adjust_severity(finding), "high")

    def test_non_prng_findings_are_never_demoted(self):
        finding = f("bearer", "python_lang_weak_hash_md5", "weak hash", severity="medium", code="rand = hashlib.md5(x)")
        self.assertEqual(adjust_severity(finding), "medium")

    def test_unknown_severity_defaults_to_medium(self):
        self.assertEqual(adjust_severity(f("x", "r", "t", severity="weird")), "medium")

    def test_consensus(self):
        self.assertEqual(consensus_severity(["high"]), "high")
        self.assertEqual(consensus_severity(["medium", "high"]), "high")           # two engines: conservative
        self.assertEqual(consensus_severity(["medium", "medium", "high"]), "medium")  # three: median, no single inflator
        self.assertEqual(consensus_severity(["low", "high", "critical"]), "high")
        self.assertEqual(consensus_severity([]), "medium")


class SeverityRuleTests(unittest.TestCase):
    def test_hardcoded_credentials_are_at_least_medium(self):
        low = f("bandit", "B105", "Possible hardcoded password: 'secret'", severity="low", cwe="259")
        self.assertEqual(adjust_severity(low), "medium")
        high = f("bandit", "B105", "Possible hardcoded password: 'x'", severity="high", cwe="259")
        self.assertEqual(adjust_severity(high), "high")  # never lowered by the floor

    def test_test_code_is_one_level_lower(self):
        prod = f("bandit", "B501", "verify=False", severity="high", cwe="295", filename="app/client.py")
        test = f("bandit", "B501", "verify=False", severity="high", cwe="295", filename="tests/e2e_zap.py")
        self.assertEqual(adjust_severity(prod), "high")
        self.assertEqual(adjust_severity(test), "medium")
        self.assertEqual(adjust_severity(f("x", "r", "t", severity="low", filename="tests/a.py")), "low")  # floor at low

    def test_hardcoded_secret_in_test_code_is_floored_then_lowered(self):
        finding = f("bandit", "B105", "Possible hardcoded password: 'admin123'", severity="low", cwe="259", filename="tests/e2e_zap.py")
        self.assertEqual(adjust_severity(finding), "low")  # low -> floor medium -> test one level down

    def test_test_path_detection(self):
        for path in ("tests/a.py", "src/__tests__/x.ts", "app/test_models.py", "pkg/models_test.go", "web/button.test.tsx", "e2e/login.js", "a/b/fixtures/data.py"):
            self.assertTrue(is_test_path(path), path)
        for path in ("app/app.py", "src/latest.py", "contest/main.py", "app/protest.py", "Dockerfile"):
            self.assertFalse(is_test_path(path), path)


class CanonicalCweTests(unittest.TestCase):
    def test_wrong_engine_cwe_is_replaced_for_known_families(self):
        sql = merge_findings([f("semgrep", "tainted-sql-string", "SQL string", cwe="704")])[0]
        self.assertEqual(sql["cwe_id"], "89")
        prng = merge_findings([f("bearer", "python_lang_weak_random", "weak PRNG", cwe="327", code="x = random.random()")])[0]
        self.assertEqual(prng["cwe_id"], "338")

    def test_families_without_a_canonical_cwe_keep_the_lead_engines(self):
        item = merge_findings([f("semgrep", "dangerous-template-string", "Template", cwe="96")])[0]
        self.assertEqual(item["cwe_id"], "96")
        secret = merge_findings([f("bandit", "B105", "Possible hardcoded password", cwe="259")])[0]
        self.assertEqual(secret["cwe_id"], "259")


class MergeTests(unittest.TestCase):
    def _md5_trio(self):
        return [
            f("bandit", "B324", "Use of weak MD5 hash", severity="high", cwe="327", line=141, code="hash_pass = hashlib.md5(password).hexdigest()"),
            f("semgrep", "insecure-hash-algorithm-md5", "Detected MD5 hash algorithm.", severity="medium", cwe="327", line=141),
            f("bearer", "python_lang_weak_hash_md5", "Usage of weak hashing library (MDx)", severity="medium", cwe="328", line=141, code="hashlib.md5(password)"),
        ]

    def test_three_engines_on_one_line_collapse_to_one_corroborated_finding(self):
        merged = merge_findings(self._md5_trio())
        self.assertEqual(len(merged), 1)
        item = merged[0]
        self.assertEqual(item["engines"], ["bearer", "semgrep", "bandit"])
        self.assertTrue(item["corroborated"])
        self.assertEqual(item["severity"], "medium")  # median, not Bandit's HIGH
        self.assertEqual(item["title"], "Usage of weak hashing library (MDx)")  # Bearer leads the wording
        self.assertEqual(item["cwe_id"], "328")
        self.assertIn("hashlib.md5", item["code_extract"])

    def test_code_comes_from_any_engine_that_has_it(self):
        trio = self._md5_trio()
        trio[2]["code_extract"] = ""  # Bearer has none; Bandit does
        self.assertEqual(merge_findings(trio)[0]["code_extract"], "hash_pass = hashlib.md5(password).hexdigest()")

    def test_different_lines_or_families_stay_separate(self):
        merged = merge_findings([
            f("bandit", "B324", "Use of weak MD5 hash", line=10, cwe="327"),
            f("bandit", "B324", "Use of weak MD5 hash", line=11, cwe="327"),
            f("semgrep", "tainted-sql-string", "SQL string", line=10, cwe="704"),
        ])
        self.assertEqual(len(merged), 3)
        self.assertFalse(any(m["corroborated"] for m in merged))

    def test_same_engine_twice_is_not_corroboration(self):
        merged = merge_findings([
            f("semgrep", "dangerous-template-string", "Template", cwe="96", line=103),
            f("semgrep", "raw-html-format", "HTML", cwe="79", line=103),
        ])
        self.assertEqual(len(merged), 1)
        self.assertFalse(merged[0]["corroborated"])
        self.assertEqual(merged[0]["engines"], ["semgrep"])

    def test_input_is_not_mutated(self):
        trio = self._md5_trio()
        before = [dict(x) for x in trio]
        merge_findings(trio)
        self.assertEqual(trio, before)

    def test_prng_demotion_applies_before_consensus(self):
        merged = merge_findings([
            f("bearer", "python_lang_weak_random", "Usage of weak PRNG", severity="high", cwe="327", line=295, code="rand = random.randint(1, 100)"),
            f("bandit", "B311", "Standard pseudo-random generators are not suitable", severity="low", cwe="330", line=295, code="rand = random.randint(1, 100)"),
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["severity"], "low")


class OverlapMergeTests(unittest.TestCase):
    def test_engines_reporting_different_lines_of_one_call_are_merged(self):
        # a requests.post(...) call spread over lines 17-19: Semgrep flags the call, Bandit the verify= line
        merged = merge_findings([
            {**f("semgrep", "disabled-cert-validation", "Certificate verification disabled", severity="high", cwe="295", line=17), "start_line": 17, "end_line": 19},
            {**f("bandit", "B501", "verify=False", severity="high", cwe="295", line=18), "start_line": 17, "end_line": 19},
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["engines"], ["semgrep", "bandit"])
        self.assertTrue(merged[0]["corroborated"])
        self.assertEqual(merged[0]["line_number"], 17)  # the lead engine's line

    def test_non_overlapping_ranges_stay_separate(self):
        merged = merge_findings([
            {**f("semgrep", "disabled-cert-validation", "x", cwe="295", line=17), "start_line": 17, "end_line": 19},
            {**f("bandit", "B501", "x", cwe="295", line=28), "start_line": 28, "end_line": 29},
        ])
        self.assertEqual(len(merged), 2)

    def test_a_huge_range_cannot_swallow_distant_findings(self):
        merged = merge_findings([
            {**f("semgrep", "tainted-sql-string", "x", cwe="89", line=10), "start_line": 10, "end_line": 400},
            f("bandit", "B608", "y", cwe="89", line=300),
        ])
        self.assertEqual(len(merged), 2)

    def test_adjacent_single_line_findings_are_not_merged(self):
        merged = merge_findings([f("bandit", "B324", "md5", cwe="327", line=10), f("bandit", "B324", "md5", cwe="327", line=11)])
        self.assertEqual(len(merged), 2)


class GroupTests(unittest.TestCase):
    def test_groups_by_cwe_severity_title_sorted_and_counted(self):
        merged = merge_findings([
            f("bandit", "B324", "Use of weak MD5 hash", severity="high", cwe="327", line=1),
            f("bandit", "B324", "Use of weak MD5 hash", severity="high", cwe="327", line=2),
            f("semgrep", "tainted-sql-string", "SQL string", severity="medium", cwe="704", line=3),
            f("bandit", "B105", "Possible hardcoded password", severity="low", cwe="259", line=4),
        ])
        groups = group_findings(merged)
        # the hardcoded password is floored from Bandit's LOW to medium
        self.assertEqual([g["severity"] for g in groups], ["high", "medium", "medium"])
        self.assertEqual(groups[0]["count"], 2)
        self.assertEqual(groups[0]["engines"], ["bandit"])
        self.assertEqual([o["line_number"] for o in groups[0]["occurrences"]], [1, 2])


if __name__ == "__main__":
    unittest.main()
