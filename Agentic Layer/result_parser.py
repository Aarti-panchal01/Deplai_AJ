import json
import logging
import threading

import docker

from semgrep_report import parse_semgrep_findings
from utils import SEVERITY_LEVELS, read_volume_file, find_volume_file, get_docker_client

logger = logging.getLogger(__name__)

# ── In-memory scan results cache ──
# After the first Docker volume read + parse, cache both the status and full
# results so subsequent calls skip the slow file access entirely.
# Structure: { project_id: { "status": "found"|"not_found", "data": {...} } }
_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()


def _parse_bearer_report(raw: str) -> list[dict]:
    """Parse Bearer JSON into CWE-grouped code security findings."""
    raw = raw.strip()
    if not raw or not raw.startswith("{"):
        return []
    data = json.loads(raw)

    cwe_groups: dict[tuple[str, str], dict] = {}

    for severity in SEVERITY_LEVELS:
        for item in data.get(severity, []):
            cwe_ids = item.get("cwe_ids", [])
            cwe_id = cwe_ids[0] if cwe_ids else "unknown"
            key = (cwe_id, severity)

            if key not in cwe_groups:
                cwe_groups[key] = {
                    "cwe_id": cwe_id,
                    "title": item.get("title", ""),
                    "severity": severity,
                    "occurrences": [],
                }

            filename = item.get("filename", "")
            # Bearer scans the codebase volume mounted at /tmp/scan — strip that prefix
            # so paths are relative to the repo root (e.g. "app/routes.py")
            if filename.startswith("/tmp/scan/"):
                filename = filename[len("/tmp/scan/"):]
            cwe_groups[key]["occurrences"].append({
                "filename": filename,
                "line_number": item.get("line_number", 0),
                "code_extract": item.get("code_extract", ""),
                "documentation_url": item.get("documentation_url", ""),
            })

    severity_order = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
    findings = sorted(
        [{"count": len(g["occurrences"]), **g} for g in cwe_groups.values()],
        key=lambda g: (severity_order.get(g["severity"], 99), -g["count"]),
    )
    return findings


def _parse_semgrep_report(raw: str, project_id: str) -> list[dict]:
    """Parse Semgrep JSON into the same CWE-grouped shape as the Bearer findings."""
    groups: dict[tuple[str, str, str], dict] = {}
    for item in parse_semgrep_findings(raw, project_id):
        key = (item["cwe_id"], item["severity"], item["title"])
        group = groups.setdefault(key, {
            "cwe_id": item["cwe_id"],
            "title": item["title"],
            "severity": item["severity"],
            "source": "semgrep",
            "occurrences": [],
        })
        group["occurrences"].append({
            "filename": item["filename"],
            "line_number": item["line_number"],
            # Semgrep withholds source lines for registry rules unless logged in.
            "code_extract": "",
            "documentation_url": item["documentation_url"],
            "rule_id": item["rule_id"],
        })
    return list(groups.values())


def _merge_code_security(bearer_groups: list[dict], semgrep_groups: list[dict]) -> list[dict]:
    """Combine Bearer and Semgrep groups; drop Semgrep hits that Bearer already reported
    for the same CWE/file/line, then re-sort the way the Bearer-only report was."""
    seen = {
        (g["cwe_id"], o["filename"], o["line_number"])
        for g in bearer_groups
        for o in g["occurrences"]
    }
    merged = [dict(g) for g in bearer_groups]
    for group in semgrep_groups:
        fresh = [o for o in group["occurrences"] if (group["cwe_id"], o["filename"], o["line_number"]) not in seen]
        if fresh:
            merged.append({**group, "occurrences": fresh})
    severity_order = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
    for g in merged:
        g["count"] = len(g["occurrences"])
    return sorted(merged, key=lambda g: (severity_order.get(g["severity"], 99), -g["count"]))


def _parse_grype_report(raw: str) -> list[dict]:
    """Parse Grype JSON into supply chain vulnerability data."""
    data = json.loads(raw)

    # Tool purls that identify Anchore's own scanners.  Grype extracts the
    # SBOM descriptor (Syft version) from the SBOM file and can report CVEs
    # against the tool itself — these are not project vulnerabilities.
    _SCANNER_PURL_PREFIXES = (
        "pkg:golang/github.com/anchore/syft",
        "pkg:golang/github.com/anchore/grype",
    )

    vulnerabilities = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        purl = artifact.get("purl") or ""

        # Skip SBOM-generator tool artifacts that leaked into the report
        if any(purl.startswith(prefix) for prefix in _SCANNER_PURL_PREFIXES):
            continue

        epss_list = vuln.get("epss", [])
        fix_versions = vuln.get("fix", {}).get("versions", [])

        vulnerabilities.append({
            "name": artifact.get("name", ""),
            "type": artifact.get("type", ""),
            "version": artifact.get("version", ""),
            "purl": purl or None,
            "severity": vuln.get("severity", "Unknown"),
            "epss_score": epss_list[0].get("epss") if epss_list else None,
            "fix_version": fix_versions[0] if fix_versions else None,
            "cve_id": vuln.get("id", ""),
        })

    return vulnerabilities


def _load_and_cache(project_id: str) -> tuple[bool, dict | str]:
    """Read reports from Docker volume, parse, cache, and return."""
    try:
        try:
            get_docker_client().volumes.get("security_reports")
        except docker.errors.NotFound:
            return (False, "No scan reports found. Run a scan first.")

        bearer_file = find_volume_file(project_id, "Bearer.json")
        semgrep_file = find_volume_file(project_id, "Semgrep.json")
        grype_file = find_volume_file(project_id, "Grype.json")

        bearer_raw = read_volume_file(bearer_file) if bearer_file else None
        semgrep_raw = read_volume_file(semgrep_file) if semgrep_file else None
        grype_raw = read_volume_file(grype_file) if grype_file else None

        if bearer_raw is None and semgrep_raw is None and grype_raw is None:
            return (False, "No scan reports found. Run a scan first.")

        # An empty Bearer report is only fatal when Semgrep did not produce one either.
        if bearer_file and bearer_raw is not None and not bearer_raw.strip() and not (semgrep_raw or "").strip():
            return (False, "Bearer report is empty; scan may have failed.")
        if grype_file and grype_raw is not None and not grype_raw.strip():
            return (False, "Grype report is empty; scan may have failed.")

        bearer_groups = []
        if bearer_raw and bearer_raw.strip():
            try:
                bearer_groups = _parse_bearer_report(bearer_raw)
            except Exception as e:
                return (False, f"Failed to parse Bearer report: {e}")

        semgrep_groups = []
        if semgrep_raw and semgrep_raw.strip():
            try:
                semgrep_groups = _parse_semgrep_report(semgrep_raw, project_id)
            except Exception as e:
                # Semgrep is additive; keep the Bearer/Grype results if its report is unreadable.
                logger.warning("Ignoring unreadable Semgrep report for %s: %s", project_id, e)

        code_security = _merge_code_security(bearer_groups, semgrep_groups)

        supply_chain = []
        if grype_raw:
            try:
                supply_chain = _parse_grype_report(grype_raw)
            except Exception as e:
                return (False, f"Failed to parse Grype report: {e}")

        data = {"supply_chain": supply_chain, "code_security": code_security}
        has_vulns = len(supply_chain) > 0 or len(code_security) > 0
        status = "found" if has_vulns else "not_found"

        with _cache_lock:
            _cache[project_id] = {"status": status, "data": data}

        return (True, data)
    except Exception as e:
        return (False, f"Error reading scan reports: {e}")


def get_scan_results(project_id: str) -> tuple[bool, dict | str]:
    """Return parsed scan results, serving from cache when available."""
    with _cache_lock:
        cached = _cache.get(project_id)
    if cached:
        return (True, cached["data"])
    return _load_and_cache(project_id)


def get_scan_status(project_id: str) -> str:
    """Return vulnerability status: 'found', 'not_found', or 'not_initiated'.

    Uses the cache if available; otherwise reads and parses (populating cache).
    """
    try:
        with _cache_lock:
            cached = _cache.get(project_id)
        if cached:
            return cached["status"]

        success, data = _load_and_cache(project_id)
        if not success:
            return "not_initiated"

        has_vulns = len(data.get("supply_chain", [])) > 0 or len(data.get("code_security", [])) > 0
        return "found" if has_vulns else "not_found"
    except Exception:
        return "not_initiated"


def invalidate_cache(project_id: str) -> None:
    """Remove cached results for a project so the next call re-reads volumes."""
    with _cache_lock:
        _cache.pop(project_id, None)
