"""Semgrep SAST scanner (runs next to Bearer).

Bearer's Python taint rules only understand Django request objects, so Flask/FastAPI style
code (request.json, request.files, ...) is largely invisible to it. Semgrep ships framework
aware rules for those, so the two scanners are complementary.

Configuration (all optional, read at call time):
  SEMGREP_ENABLED        "true" (default) / "false" to turn the scanner off
  SEMGREP_IMAGE          container image, default semgrep/semgrep:latest
  SEMGREP_CONFIGS        comma/space separated rule packs or rule files, default below
  SEMGREP_INCLUDE_TESTS  "true" (default): also scan tests/ (Semgrep skips them by default)
  SEMGREP_TIMEOUT_SECONDS / SCANNER_TIMEOUT_SECONDS  scan timeout, default 1800
"""
import os
import re

from utils import CODEBASE_VOLUME, SECURITY_REPORTS_VOLUME, get_docker_client, sanitize_name

SEMGREP_IMAGE = os.getenv("SEMGREP_IMAGE", "semgrep/semgrep:latest")

# Registry rule packs. Semgrep only applies rules for languages that are present, so a
# broad list costs little. Fetching packs needs outbound HTTPS to semgrep.dev.
DEFAULT_SEMGREP_CONFIGS = (
    "p/security-audit",
    "p/owasp-top-ten",
    "p/secrets",
    "p/jwt",
    "p/python",
    "p/flask",
    "p/django",
    "p/javascript",
    "p/typescript",
    "p/react",
    "p/nodejs",
    "p/expressjs",
    "p/dockerfile",
    "p/github-actions",
)

_TRUE = {"1", "true", "yes", "on"}


def semgrep_enabled() -> bool:
    return os.getenv("SEMGREP_ENABLED", "true").strip().lower() in _TRUE


def semgrep_configs() -> list[str]:
    raw = os.getenv("SEMGREP_CONFIGS", "")
    configs = [c for c in re.split(r"[,\s]+", raw) if c and not c.startswith("-")]
    return configs or list(DEFAULT_SEMGREP_CONFIGS)


def semgrep_report_filename(project_name: str, project_id: str) -> str:
    return f"{sanitize_name(project_name)}_{project_id}_Semgrep.json"


def build_semgrep_command(project_id: str, filename: str) -> list[str]:
    command = ["semgrep", "scan"]
    for config in semgrep_configs():
        command += ["--config", config]
    command += [
        "--metrics", "off",
        "--disable-version-check",
        "--json",
        "--output", f"/output/{filename}",
    ]
    if os.getenv("SEMGREP_INCLUDE_TESTS", "true").strip().lower() in _TRUE:
        # Semgrep ignores tests/ by default via its built-in .semgrepignore.
        command.append("--x-ignore-semgrepignore-files")
    command.append(f"/tmp/scan/{project_id}")
    return command


def run_semgrep_scan(project_name: str, project_id: str) -> tuple[bool, str]:
    """Run Semgrep against the project's codebase subdirectory.

    Exit code 0 (and 1, kept for parity with Bearer) means the scan ran; anything else is a
    failure and the container's last log lines are returned to explain why.
    """
    timeout = int(os.getenv("SEMGREP_TIMEOUT_SECONDS", os.getenv("SCANNER_TIMEOUT_SECONDS", "1800")))
    container = None
    try:
        filename = semgrep_report_filename(project_name, project_id)
        container = get_docker_client().containers.run(
            SEMGREP_IMAGE,
            command=build_semgrep_command(project_id, filename),
            user="0:0",
            environment={"SEMGREP_SEND_METRICS": "off"},
            volumes={
                CODEBASE_VOLUME: {"bind": "/tmp/scan", "mode": "ro"},
                SECURITY_REPORTS_VOLUME: {"bind": "/output", "mode": "rw"},
            },
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
        return (False, f"Semgrep exited with code {exit_code}" + (f": {tail}" if tail else ""))
    except Exception as e:
        return (False, str(e))
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
