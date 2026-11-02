#!/usr/bin/env python3
"""Validate findings_template.csv for the Secure Code Review lab."""
import csv
import sys
import os

EXPECTED = {
    "CRV-001": {"vuln_class": "SQL Injection", "cwe": "CWE-89", "file": "scheduler/db.py"},
    "CRV-002": {"vuln_class": "Hardcoded Credentials", "cwe": "CWE-798", "file": "scheduler/db.py"},
    "CRV-003": {"vuln_class": "Insecure Deserialization", "cwe": "CWE-502", "file": "scheduler/utils.py"},
    "CRV-004": {"vuln_class": "Missing Authorization", "cwe": "CWE-862", "file": "scheduler/app.py"},
    "CRV-005": {"vuln_class": "Path Traversal", "cwe": "CWE-22", "file": "scheduler/utils.py"},
    "CRV-006": {"vuln_class": "Weak Password Hashing", "cwe": "CWE-916", "file": "scheduler/auth.py"},
    "CRV-007": {"vuln_class": "Verbose Error Message", "cwe": "CWE-209", "file": "scheduler/app.py"},
    "CRV-008": {"vuln_class": "Open Redirect", "cwe": "CWE-601", "file": "scheduler/app.py"},
}

REQUIRED_COLUMNS = ["finding_id", "file", "line_number", "vuln_class", "cwe", "code_snippet",
                    "vulnerability_description", "attack_scenario", "remediation", "severity", "confidence"]
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
VALID_CONFIDENCE = {"High", "Medium", "Low"}
# Must be verbatim substrings of the reference (unfixed) source
REFERENCE_SNIPPETS = {
    "CRV-001": "' + username + '",
    "CRV-002": "MedP0rt!Prod2026",
    "CRV-003": "pickle.loads",
    "CRV-004": "SELECT * FROM appointments",
    "CRV-005": "os.path.join(reports_dir, filename)",
    "CRV-006": "hashlib.sha1(password.encode()).hexdigest()",
    "CRV-007": "traceback.format_exc()",
    "CRV-008": "redirect(target)",
}


def validate(path):
    errors, warnings = [], []
    if not os.path.exists(path):
        return [f"File not found: {path}"], warnings
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != REQUIRED_COLUMNS:
            errors.append(f"Invalid columns. Expected {REQUIRED_COLUMNS}, got {reader.fieldnames}")
            return errors, warnings
        rows = list(reader)

    found = set()
    for i, row in enumerate(rows):
        n = i + 2
        fid = row.get("finding_id", "").strip()
        if fid not in EXPECTED:
            warnings.append(f"Row {n}: unexpected finding_id '{fid}'")
            continue
        found.add(fid)
        for field, expected in EXPECTED[fid].items():
            actual = row.get(field, "").strip()
            if actual != expected:
                errors.append(f"Row {n} ({fid}): {field} mismatch. Expected '{expected}', got '{actual}'")
        snippet = row.get("code_snippet", "").strip()
        ref = REFERENCE_SNIPPETS.get(fid, "")
        if ref and ref not in snippet:
            errors.append(f"Row {n} ({fid}): code_snippet must contain verbatim source: '{ref}'")
        if row.get("severity", "").strip() not in VALID_SEVERITIES:
            errors.append(f"Row {n} ({fid}): invalid severity '{row.get('severity')}'")
        if row.get("confidence", "").strip() not in VALID_CONFIDENCE:
            errors.append(f"Row {n} ({fid}): invalid confidence '{row.get('confidence')}'")
        for col in ("line_number", "vulnerability_description", "attack_scenario", "remediation"):
            if not row.get(col, "").strip():
                warnings.append(f"Row {n} ({fid}): empty field '{col}'")

    for fid in EXPECTED:
        if fid not in found:
            errors.append(f"Missing expected finding: {fid}")
    return errors, warnings


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "findings_template.csv"
    print(f"[*] Validating {path}...")
    errors, warnings = validate(path)
    if warnings:
        print("[WARNINGS]")
        for w in warnings:
            print(f"  ! {w}")
    if errors:
        print("[ERRORS]")
        for e in errors:
            print(f"  ✗ {e}")
        print(f"Validation FAILED: {len(errors)} errors")
        sys.exit(1)
    print("[SUCCESS] All validations passed!")
