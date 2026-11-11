#!/usr/bin/env python3
"""Validate barzakh-scanner E2E scan results for CI."""

import json
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: validate_ci_results.py <scan_results.json>")
        sys.exit(1)

    results_path = sys.argv[1]

    try:
        with open(results_path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"FAIL: Cannot read results: {e}")
        sys.exit(1)

    errors = []
    if data.get("status") != "complete":
        errors.append("scan did not complete; failed/partial outcomes cannot pass E2E")

    # Structural validation
    for key in ("summary", "findings"):
        if key not in data:
            errors.append(f"Missing top-level key: {key}")

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        sys.exit(1)

    summary = data["summary"]
    findings = data["findings"]

    # Must have detected something in the synthetic dump
    total = summary.get("total_findings", 0)
    if total == 0:
        errors.append("total_findings is 0 — scanner found nothing in synthetic dump")

    # At least one high-severity finding expected
    severities = [f.get("severity", "").lower() for f in findings]
    has_critical_or_high = any(s in ("critical", "high") for s in severities)
    if not has_critical_or_high:
        errors.append("No Critical/High severity findings — synthetic dump should trigger at least one")

    if errors:
        print(f"VALIDATION FAILED ({len(errors)} issue(s)):")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)

    critical_high = sum(1 for s in severities if s in ("critical", "high"))
    print(f"PASS: {total} findings, {critical_high} critical/high")
    sys.exit(0)


if __name__ == "__main__":
    main()
