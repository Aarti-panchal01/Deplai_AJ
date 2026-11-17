import json
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import read_volume_file, find_volume_file
from result_parser import build_code_security, _parse_grype_report


def _build_dependency_index(relationships: list[dict]) -> dict:
    """Build bidirectional indexes from relationship edges."""
    dependents = defaultdict(list)
    dependencies = defaultdict(list)

    for rel in relationships:
        parent = rel.get("parent")
        child = rel.get("child")
        if parent and child:
            dependents[child].append(parent)
            dependencies[parent].append(child)

    return {
        "dependents": dict(dependents),
        "dependencies": dict(dependencies)
    }


def _parse_syft_report(raw: str) -> dict:
    """Parse Syft JSON (CycloneDX) into SBOM structure with dependency index."""
    data = json.loads(raw)

    components = []
    for comp in data.get("artifacts", []):
        licenses = []
        for lic in comp.get("licenses", []):
            if "value" in lic:
                licenses.append(lic["value"])
            elif "spdxExpression" in lic:
                licenses.append(lic["spdxExpression"])
        components.append({
            "id": comp.get("id"),
            "name": comp.get("name"),
            "version": comp.get("version"),
            "type": comp.get("type"),
            "purl": comp.get("purl"),
            "licenses": licenses,
        })

    raw_relationships = []
    for rel in data.get("artifactRelationships", []):
        parent = rel.get("parent")
        child = rel.get("child")
        if parent and child:
            raw_relationships.append({
                "parent": parent,
                "child": child,
                "type": rel.get("type", "unknown")
            })

    dependency_index = _build_dependency_index(raw_relationships)

    return {
        "components": components,
        "relationships": raw_relationships,
        "dependency_index": dependency_index
    }


def get_scan_results(project_id: str) -> tuple[bool, dict | str]:
    """Read and parse all scan reports from the Docker volume."""
    bearer_file = find_volume_file(project_id, "Bearer.json")
    semgrep_file = find_volume_file(project_id, "Semgrep.json")
    bandit_file = find_volume_file(project_id, "Bandit.json")
    grype_file = find_volume_file(project_id, "Grype.json")
    syft_file = find_volume_file(project_id, "sbom.json")

    bearer_raw = read_volume_file(bearer_file) if bearer_file else None
    semgrep_raw = read_volume_file(semgrep_file) if semgrep_file else None
    bandit_raw = read_volume_file(bandit_file) if bandit_file else None
    grype_raw = read_volume_file(grype_file) if grype_file else None
    syft_raw = read_volume_file(syft_file) if syft_file else None

    if all(raw is None for raw in (bearer_raw, semgrep_raw, bandit_raw, grype_raw, syft_raw)):
        return (False, "No scan reports found. Run a scan first.")

    # Same cross-engine merge as the dashboard, so the remediation agent sees every engine's findings.
    try:
        code_security = build_code_security(project_id, bearer_raw, semgrep_raw, bandit_raw)
    except Exception as e:
        return (False, f"Failed to parse Bearer report: {e}")

    supply_chain = []
    if grype_raw:
        try:
            supply_chain = _parse_grype_report(grype_raw)
        except Exception as e:
            return (False, f"Failed to parse Grype report: {e}")

    sbom = {}
    if syft_raw:
        try:
            sbom = _parse_syft_report(syft_raw)
        except Exception as e:
            return (False, f"Failed to parse Syft report: {e}")

    return (True, {
        "supply_chain": supply_chain,
        "code_security": code_security,
        "sbom": sbom,
    })
