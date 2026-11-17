"""Pure helpers that turn a Semgrep JSON report into DeplAI's finding shapes.

No Docker or network access here, so it is shared by the dashboard result parser
(result_parser.py) and the remediation ingester (remediation_pipeline/ingester.py).
"""
from __future__ import annotations

import json
import re
from typing import Any

# Semgrep reports ERROR / WARNING / INFO. DeplAI uses critical/high/medium/low and Semgrep
# never marks anything critical on its own, so the mapping is deliberately conservative.
SEMGREP_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _cwe_number(metadata: dict[str, Any]) -> str:
    cwe = metadata.get("cwe")
    values = cwe if isinstance(cwe, list) else [cwe] if cwe else []
    for value in values:
        match = _CWE_RE.search(str(value))
        if match:
            return match.group(1)
    return "unknown"


def _relative_path(path: str, project_id: str) -> str:
    cleaned = str(path or "").replace("\\", "/")
    for prefix in (f"/tmp/scan/{project_id}/", f"/repo/{project_id}/"):
        if cleaned.startswith(prefix):
            return cleaned[len(prefix):]
    return cleaned.lstrip("/")


def _title(message: str, rule_id: str) -> str:
    text = " ".join(str(message or "").split())
    if not text:
        return rule_id.replace("-", " ").capitalize()
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    return first if len(first) <= 160 else first[:157] + "..."


def parse_semgrep_findings(raw: str, project_id: str) -> list[dict[str, Any]]:
    """Return normalized findings, de-duplicated on (rule, file, line).

    Each item: rule_id, title, message, severity, cwe_id, filename, line_number,
    end_line, documentation_url.
    """
    raw = (raw or "").strip()
    if not raw.startswith("{"):
        return []
    data = json.loads(raw)

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        rule_id = str(item.get("check_id") or "semgrep-rule").split(".")[-1]
        filename = _relative_path(item.get("path", ""), project_id)
        line = int((item.get("start") or {}).get("line") or 0)
        end_line = int((item.get("end") or {}).get("line") or line)
        key = (rule_id, filename, line)
        if key in seen:
            continue
        seen.add(key)

        message = str(extra.get("message") or "")
        references = metadata.get("references")
        findings.append({
            "engine": "semgrep",
            "code_extract": "",  # Semgrep withholds source lines for registry rules unless logged in
            "rule_id": rule_id,
            "title": _title(message, rule_id),
            "message": message,
            "severity": SEMGREP_SEVERITY_MAP.get(str(extra.get("severity") or "").upper(), "medium"),
            "cwe_id": _cwe_number(metadata),
            "filename": filename,
            "line_number": line,
            "start_line": line,
            "end_line": max(line, end_line),
            "documentation_url": str(metadata.get("shortlink") or (references[0] if isinstance(references, list) and references else "")),
        })
    return findings
