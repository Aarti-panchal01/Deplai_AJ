"""Turn a Bandit JSON report into DeplAI's normalized finding dicts (pure, no I/O)."""
from __future__ import annotations

import json
import re
from typing import Any

_SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# "Audit" style checks that Bandit rates MEDIUM but that only matter with attacker-controlled input,
# which a static pattern cannot see: a hardcoded /tmp path (B108, mostly container-internal paths in
# tooling) and urlopen scheme auditing (B310). Reported as low so they do not bury real findings.
# Measured on a real codebase: 32 of 93 raw findings were these two rules.
_SEVERITY_OVERRIDE = {"B108": "low", "B310": "low"}

# B105/B106/B107 on an empty literal (password="" as a default argument) is not a hardcoded credential.
_HARDCODED_PASSWORD_RULES = {"B105", "B106", "B107"}
_EMPTY_LITERAL = re.compile(r":\s*(''|\"\")\s*$")
# ...nor is a template/variable reference such as "${random_password.db.result}", "{{ secret }}" or "<password>".
_PLACEHOLDER_LITERAL = re.compile(r":\s*['\"](\$\{|\{\{|<[^>]*>['\"]|\$[A-Za-z_]|%\()")


def _relative_path(path: str, project_id: str) -> str:
    cleaned = str(path or "").replace("\\", "/")
    for prefix in (f"/tmp/scan/{project_id}/", f"/repo/{project_id}/"):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix):]
    return cleaned.lstrip("/")


def flagged_line(code: str, line_number: int) -> str:
    """Bandit's `code` is a few numbered lines ("25 foo\\n26 bar"). Return only the flagged one."""
    for row in str(code or "").splitlines():
        match = re.match(r"^\s*(\d+)\s?(.*)$", row)
        if match and int(match.group(1)) == line_number:
            return match.group(2).strip()
    return ""


def parse_bandit_findings(raw: str, project_id: str) -> list[dict[str, Any]]:
    """Normalized findings from `bandit -f json`.

    Findings that are both LOW severity and LOW confidence are dropped: they are the main source of
    Bandit noise and carry almost no signal.
    """
    raw = (raw or "").strip()
    if not raw.startswith("{"):
        return []
    data = json.loads(raw)

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for item in data.get("results", []):
        severity_label = str(item.get("issue_severity") or "").upper()
        confidence = str(item.get("issue_confidence") or "").upper()
        if severity_label == "LOW" and confidence == "LOW":
            continue

        rule_id = str(item.get("test_id") or "bandit-rule")
        if rule_id in _HARDCODED_PASSWORD_RULES:
            text = str(item.get("issue_text") or "")
            if _EMPTY_LITERAL.search(text) or _PLACEHOLDER_LITERAL.search(text):
                continue
        filename = _relative_path(item.get("filename", ""), project_id)
        line = int(item.get("line_number") or 0)
        key = (rule_id, filename, line)
        if key in seen:
            continue
        seen.add(key)

        span = [int(n) for n in (item.get("line_range") or []) if isinstance(n, int)]
        cwe = item.get("issue_cwe")
        cwe_id = str(cwe.get("id")) if isinstance(cwe, dict) and cwe.get("id") else "unknown"
        findings.append({
            "engine": "bandit",
            "rule_id": rule_id,
            "title": str(item.get("issue_text") or rule_id),
            "message": str(item.get("issue_text") or ""),
            "severity": _SEVERITY_OVERRIDE.get(rule_id) or _SEVERITY.get(severity_label, "medium"),
            "confidence": confidence.lower() or "medium",
            "cwe_id": cwe_id,
            "filename": filename,
            "line_number": line,
            "start_line": min(span + [line]),
            "end_line": max(span + [line]),
            "code_extract": flagged_line(item.get("code", ""), line),
            "documentation_url": str(item.get("more_info") or ""),
        })
    return findings
