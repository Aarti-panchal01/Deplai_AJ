#!/usr/bin/env python3
"""Vulnerability ratchet for Trivy JSON reports (standard library only).

Fails when the number of CRITICAL or HIGH dependency vulnerabilities is higher than the committed
baseline (.trivy-baseline.json). The baseline should only ever go down:

    python3 scripts/ci/vuln_ratchet.py trivy.json            # check
    python3 scripts/ci/vuln_ratchet.py trivy.json --update   # lock in an improvement
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

BASELINE = Path(__file__).resolve().parents[2] / ".trivy-baseline.json"
LEVELS = ("CRITICAL", "HIGH")


def count(report: dict) -> dict[str, int]:
    totals = {level.lower(): 0 for level in LEVELS}
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity", "")).upper()
            if severity in LEVELS:
                totals[severity.lower()] += 1
    return totals


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        return 2
    current = count(json.loads(Path(args[0]).read_text(encoding="utf-8")))

    if "--update" in argv:
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline updated: {current}")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    print(f"Vulnerabilities now {current} vs baseline {baseline}")

    worse = {k: (current[k], baseline.get(k, 0)) for k in current if current[k] > baseline.get(k, 0)}
    if worse:
        for level, (now, base) in worse.items():
            print(f"  {level}: {now} > baseline {base}")
        print("New critical/high dependency vulnerabilities appeared. Update the affected dependency, "
              "or (if there is no fix) document and accept the risk by updating the baseline in the PR.")
        return 1

    if any(current[k] < baseline.get(k, 0) for k in current):
        print("Improved. Lock it in with: python3 scripts/ci/vuln_ratchet.py <report> --update")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
