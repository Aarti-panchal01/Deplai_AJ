"""Cross-engine merging of static-analysis (SAST) findings.

Bearer, Semgrep and Bandit often report the same bug but disagree on the CWE id (MD5 is CWE-327
for one and CWE-328 for another), the severity, and the wording. Merging on CWE alone therefore
double-counts. This module:

1. assigns every finding a *family* (SQL injection, weak hash, ...) from the rule id/title first and
   the CWE second, so engines that disagree on the CWE still land together;
2. clusters findings by (family, file, overlapping line range) and keeps one entry per cluster,
   remembering which engines agreed (agreement from two or more independent engines is a strong correctness signal);
3. resolves severity by consensus instead of trusting any single engine's scale;
4. demotes weak-PRNG findings when the flagged line has no security context (a random number used for
   a filename prefix is not a vulnerability);
5. applies two more engine-independent severity rules: a hardcoded credential is at least MEDIUM
   (Bandit rates them LOW), and findings in test/e2e code are one level lower than the same finding in
   production code;
6. shows one canonical CWE per family where engines' CWE metadata is known to be unreliable (Semgrep
   tags SQL injection as CWE-704, Bearer tags weak PRNG as CWE-327).

Pure functions only: no Docker, network or framework imports.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

SEVERITY_ORDER = ("critical", "high", "medium", "low")
_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

# Engines report different lines of one multi-line statement (a call split over several lines), so
# findings whose line ranges overlap count as the same issue. Ranges are capped so a long block
# match cannot swallow unrelated findings below it.
MAX_SPAN_LINES = 6

# Preferred engine for the text shown to the user (most descriptive first).
ENGINE_PRIORITY = ("bearer", "semgrep", "bandit")

# Order matters: the first matching hint wins. Matched against "<rule id> <title>" in lower case.
_FAMILY_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"pseudo-?random|\bprng\b|insecure[-_ ]random|weak[-_ ]random|\bb311\b"), "weak-random"),
    (re.compile(r"\bmd5\b|\bsha-?1\b|weak[-_ ]?hash|insecure[-_ ]hash|\bb303\b|\bb324\b"), "weak-hash"),
    (re.compile(r"\bsql\b|sql[-_ ]?inject|sql_expressions|tainted-sql|\bb608\b"), "sql-injection"),
    (re.compile(r"yaml|pickle|deserializ|unserializ|marshal|\bb506\b|\bb301\b"), "deserialization"),
    (re.compile(r"template|jinja|ssti|render_template_string|\bxss\b|cross-site|raw-html|html string"), "web-injection"),
    (re.compile(r"cert(ificate)?[-_ ]?valid|ssl[-_ ]?verif|verify\s*=\s*false|no_cert|\bb501\b"), "tls-verification"),
    (re.compile(r"os[-_ ]?command|command[-_ ]?inject|shell\s*=\s*true"), "command-injection"),
    (re.compile(r"\bxxe\b|xml[-_ ]external"), "xxe"),
    (re.compile(r"hard-?coded|hardcode|\bb10[567]\b"), "hardcoded-secret"),
]

_FAMILY_BY_CWE = {
    **dict.fromkeys(("89", "564", "943"), "sql-injection"),
    **dict.fromkeys(("77", "78", "88"), "command-injection"),
    **dict.fromkeys(("79", "80", "83", "87", "96", "116", "1336"), "web-injection"),
    **dict.fromkeys(("94", "95"), "code-injection"),
    "502": "deserialization",
    **dict.fromkeys(("328", "916", "759", "760"), "weak-hash"),
    **dict.fromkeys(("326", "327", "329"), "weak-crypto"),
    **dict.fromkeys(("798", "259", "321", "547", "256"), "hardcoded-secret"),
    **dict.fromkeys(("295", "297"), "tls-verification"),
    **dict.fromkeys(("611", "776", "827"), "xxe"),
    **dict.fromkeys(("22", "23", "36", "73"), "path-traversal"),
    "918": "ssrf",
    **dict.fromkeys(("330", "331", "338"), "weak-random"),
    "601": "open-redirect",
    **dict.fromkeys(("532", "117"), "logging-sensitive"),
    "319": "insecure-transport",
    **dict.fromkeys(("732", "276"), "file-permissions"),
}

# CWE shown to the user for a family when the engines' own CWE metadata is inconsistent or wrong.
# Only families where one CWE is unambiguous are listed; others keep the lead engine's CWE.
CANONICAL_CWE = {
    "sql-injection": "89",
    "command-injection": "78",
    "deserialization": "502",
    "weak-hash": "328",
    "weak-random": "338",
    "tls-verification": "295",
    "xxe": "611",
}

# Test, fixture and end-to-end code: real weaknesses, but not production attack surface.
_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|specs?|e2e|fixtures?)(/|$)|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$",
    re.IGNORECASE,
)

# A pseudo-random value is only a vulnerability when it protects something. Looked at on the
# flagged source line only.
_SECURITY_CONTEXT = re.compile(
    r"token|secret|passw|pwd|key|salt|nonce|session|otp|csrf|auth|crypt|\biv\b|api|cookie|signature|reset|verif",
    re.IGNORECASE,
)


def family_of(finding: dict[str, Any]) -> str:
    text = f"{finding.get('rule_id', '')} {finding.get('title', '')}".lower()
    for pattern, family in _FAMILY_HINTS:
        if pattern.search(text):
            return family
    cwe = str(finding.get("cwe_id") or "")
    if cwe in _FAMILY_BY_CWE:
        return _FAMILY_BY_CWE[cwe]
    return f"cwe-{cwe}" if cwe and cwe != "unknown" else f"rule-{finding.get('rule_id', 'unknown')}"


def is_test_path(filename: str) -> bool:
    return bool(_TEST_PATH.search(str(filename or "").replace("\\", "/")))


def adjust_severity(finding: dict[str, Any], family: str | None = None) -> str:
    """Per-finding severity after engine-independent corrections."""
    severity = str(finding.get("severity") or "medium")
    if severity not in _RANK:
        severity = "medium"
    family = family or family_of(finding)

    if family == "weak-random":
        line = str(finding.get("code_extract") or "")
        # Without a source line we cannot judge, so only demote when we can see it is benign.
        if line and not _SECURITY_CONTEXT.search(line):
            return "low"
    elif family == "hardcoded-secret" and _RANK[severity] > _RANK["medium"]:
        severity = "medium"  # a credential in source is never "low" risk

    if is_test_path(finding.get("filename", "")):
        severity = SEVERITY_ORDER[min(_RANK[severity] + 1, len(SEVERITY_ORDER) - 1)]
    return severity


def consensus_severity(severities: list[str]) -> str:
    """One engine: as reported. Two: the higher (conservative). Three or more: the median, so a
    single engine with an inflated scale cannot raise the group on its own."""
    ranked = sorted((_RANK.get(s, _RANK["medium"]) for s in severities))
    if not ranked:
        return "medium"
    if len(ranked) == 1:
        return SEVERITY_ORDER[ranked[0]]
    if len(ranked) == 2:
        return SEVERITY_ORDER[ranked[0]]
    return SEVERITY_ORDER[ranked[len(ranked) // 2]]


def _span(finding: dict[str, Any]) -> tuple[int, int]:
    line = int(finding.get("line_number") or 0)
    start = int(finding.get("start_line") or line)
    end = int(finding.get("end_line") or start)
    return start, max(start, min(end, start + MAX_SPAN_LINES))


def _priority(finding: dict[str, Any]) -> int:
    engine = str(finding.get("engine") or "")
    return ENGINE_PRIORITY.index(engine) if engine in ENGINE_PRIORITY else len(ENGINE_PRIORITY)


def merge_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cluster findings by (family, file, line) and return one merged finding per cluster.

    Input items need: engine, rule_id, title, severity, cwe_id, filename, line_number, and optionally
    code_extract and documentation_url. Output items add `engines` (sorted), `family` and
    `corroborated` (two or more engines agree).
    """
    by_file: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for original in findings:
        item = dict(original)
        family = family_of(item)
        item["family"] = family
        item["severity"] = adjust_severity(item, family)
        by_file.setdefault((family, str(item.get("filename") or "")), []).append(item)

    clusters: list[tuple[str, str, list[dict[str, Any]]]] = []
    for (family, filename), items in by_file.items():
        items.sort(key=lambda i: _span(i))
        current: list[dict[str, Any]] = []
        current_end = -1
        for item in items:
            start, end = _span(item)
            if current and start <= current_end:
                current.append(item)
                current_end = max(current_end, end)
            else:
                if current:
                    clusters.append((family, filename, current))
                current, current_end = [item], end
        if current:
            clusters.append((family, filename, current))

    merged: list[dict[str, Any]] = []
    for family, filename, items in clusters:
        items.sort(key=_priority)
        lead = items[0]
        line = int(lead.get("line_number") or 0)
        engines = sorted({str(i.get("engine") or "unknown") for i in items}, key=lambda e: ENGINE_PRIORITY.index(e) if e in ENGINE_PRIORITY else 99)
        merged.append({
            "engine": lead.get("engine"),
            "engines": engines,
            "corroborated": len(engines) >= 2,
            "family": family,
            "rule_id": lead.get("rule_id"),
            "title": lead.get("title"),
            "severity": consensus_severity([i["severity"] for i in items]),
            "cwe_id": CANONICAL_CWE.get(family) or lead.get("cwe_id"),
            "filename": filename,
            "line_number": line,
            "code_extract": next((i["code_extract"] for i in items if i.get("code_extract")), ""),
            "documentation_url": next((i["documentation_url"] for i in items if i.get("documentation_url")), ""),
        })
    return merged


def group_findings(merged: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group merged findings into the `code_security` shape the dashboard already renders."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in merged:
        key = (str(item.get("cwe_id")), str(item["severity"]), str(item.get("title")))
        group = groups.setdefault(key, {
            "cwe_id": item.get("cwe_id"),
            "title": item.get("title"),
            "severity": item["severity"],
            "source": item.get("engine"),
            "engines": [],
            "occurrences": [],
        })
        group["occurrences"].append({
            "filename": item["filename"],
            "line_number": item["line_number"],
            "code_extract": item.get("code_extract", ""),
            "documentation_url": item.get("documentation_url", ""),
            "rule_id": item.get("rule_id"),
            "engines": item["engines"],
            "corroborated": item["corroborated"],
        })
        for engine in item["engines"]:
            if engine not in group["engines"]:
                group["engines"].append(engine)

    result = []
    for group in groups.values():
        group["occurrences"].sort(key=lambda o: (o["filename"], o["line_number"]))
        result.append({"count": len(group["occurrences"]), **group})
    result.sort(key=lambda g: (_RANK.get(g["severity"], 99), -g["count"], str(g["title"])))
    return result
