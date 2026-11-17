"""Bandit SAST scanner (Python-specific, Apache-2.0), run next to Bearer and Semgrep.

Bandit's rules are written for Python's standard library and common pitfalls (hardcoded passwords,
yaml.load, weak hashes, disabled TLS verification, string-built SQL) and reports a CWE id and the
flagged source line for each finding, which complements Semgrep (framework-aware taint rules) and
Bearer (Django-oriented data flow).

Configuration (all optional, read at call time):
  BANDIT_ENABLED         "true" (default) / "false"
  BANDIT_IMAGE           container image, default ghcr.io/pycqa/bandit/bandit:latest
  BANDIT_SKIP            comma separated test ids to skip, default B101 (assert_used, noisy in tests)
  BANDIT_TIMEOUT_SECONDS / SCANNER_TIMEOUT_SECONDS  scan timeout, default 1800
"""
import os
import re

from utils import CODEBASE_VOLUME, SECURITY_REPORTS_VOLUME, get_docker_client, sanitize_name

BANDIT_IMAGE = os.getenv("BANDIT_IMAGE", "ghcr.io/pycqa/bandit/bandit:latest")

DEFAULT_BANDIT_SKIP = ("B101",)
# Vendored/generated code is not the customer's code and would drown real findings.
EXCLUDED_PATHS = "*/node_modules/*,*/.git/*,*/venv/*,*/.venv/*,*/site-packages/*,*/dist/*,*/build/*"

_TRUE = {"1", "true", "yes", "on"}
_TEST_ID = re.compile(r"^B\d{3}$")


def bandit_enabled() -> bool:
    return os.getenv("BANDIT_ENABLED", "true").strip().lower() in _TRUE


def bandit_skips() -> list[str]:
    raw = os.getenv("BANDIT_SKIP")
    if raw is None:
        return list(DEFAULT_BANDIT_SKIP)
    return [t for t in (part.strip().upper() for part in re.split(r"[,\s]+", raw)) if _TEST_ID.match(t)]


def bandit_report_filename(project_name: str, project_id: str) -> str:
    return f"{sanitize_name(project_name)}_{project_id}_Bandit.json"


def build_bandit_command(project_id: str, filename: str) -> list[str]:
    command = ["-r", f"/tmp/scan/{project_id}", "-f", "json", "-o", f"/output/{filename}", "-x", EXCLUDED_PATHS, "-q"]
    skips = bandit_skips()
    if skips:
        command += ["-s", ",".join(skips)]
    return command


def run_bandit_scan(project_name: str, project_id: str) -> tuple[bool, str]:
    """Run Bandit against the project's codebase subdirectory.

    Bandit exits 0 with no issues and 1 when it found issues; both mean the scan ran. Any other code
    is a failure and the container's last log lines are returned.
    """
    timeout = int(os.getenv("BANDIT_TIMEOUT_SECONDS", os.getenv("SCANNER_TIMEOUT_SECONDS", "1800")))
    container = None
    try:
        filename = bandit_report_filename(project_name, project_id)
        container = get_docker_client().containers.run(
            BANDIT_IMAGE,
            command=build_bandit_command(project_id, filename),
            user="0:0",
            volumes={
                CODEBASE_VOLUME: {"bind": "/tmp/scan", "mode": "ro"},
                SECURITY_REPORTS_VOLUME: {"bind": "/output", "mode": "rw"},
            },
            network_mode="none",  # Bandit is fully offline; give it no network at all
            detach=True,
        )
        result = container.wait(timeout=timeout)
        exit_code = result.get("StatusCode", -1)
        if exit_code in (0, 1):
            return (True, "")
        tail = ""
        try:
            tail = container.logs(tail=15).decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return (False, f"Bandit exited with code {exit_code}" + (f": {tail}" if tail else ""))
    except Exception as e:
        return (False, str(e))
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
