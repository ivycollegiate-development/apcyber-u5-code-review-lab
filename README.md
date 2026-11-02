# AP Cyber Unit 5 Lab: Secure Code Review — Static Analysis & Remediation

**Course**: AP Computer Science Principles — Cybersecurity
**Unit**: 5 — Application & Data Security
**Topic**: 5.5 Secure Coding Practices (Code Review, Static Analysis)

---

## Lab Overview

You are a security engineer reviewing a **legacy patient scheduling service** (`scheduler/`). The code contains **8 planted vulnerabilities** spanning injection, authz, secrets handling, and deserialization. You will find them **by manual review**, confirm them with a **static analysis tool** (Semgrep), then **remediate** each finding and prove the fix with a regression test.

---

## Learning Objectives

By the end of this lab, you will be able to:
- ☐ Perform a structured **manual code review** (threat-model-driven)
- ☐ Use **Semgrep** to detect injection, secrets, and dangerous APIs
- ☐ Classify findings with **CWE IDs** and OWASP Top 10 categories
- ☐ **Remediate** each vulnerability and write a **regression test**
- ☐ Submit findings + fixes via GitHub Actions

---

## Repository Structure

```
apcyber-u5-code-review-lab/
├── scheduler/                  # Target application (contains planted vulns)
│   ├── app.py                  # Flask entry point
│   ├── db.py                   # Database layer
│   ├── auth.py                 # Authentication/session
│   └── utils.py                # Helpers
├── .semgrep.yml                # Semgrep rules (starter set)
├── findings_template.csv       # Submit findings here (8 rows minimum)
├── remediation_log.md          # Per-finding fix narrative
├── tests/
│   └── test_remediation.py     # Regression tests proving fixes
├── .github/workflows/
│   └── grade.yml
└── README.md
```

---

## Lab Procedure

### Phase 1: Manual Review (20 min)
Read every file in `scheduler/`. For each vulnerability, record:
- File + line number
- Vulnerability class + **CWE ID**
- Attack scenario
- Evidence (paste the vulnerable snippet verbatim — graders match it)

### Phase 2: Automated Scan (10 min)
```bash
pip install semgrep
semgrep --config .semgrep.yml scheduler/ --json > semgrep_results.json
```
Cross-check: did Semgrep find what you found? Note anything you missed.

### Phase 3: Remediate (15 min)
Fix each finding **in place**:
1. SQL injection → parameterized queries
2. Hardcoded credentials → environment variables
3. Insecure deserialization → `json` instead of `pickle`
4. Missing authz check → explicit role check
5. Path traversal → `os.path.basename` + whitelist
6. Weak hash → `bcrypt`
7. Verbose error → generic message + log server-side
8. Open redirect → URL allowlist

### Phase 4: Regression Tests (10 min)
Add one test per finding in `tests/test_remediation.py` proving the fix (e.g., injection payload is now safely parameterized; `pickle.loads` no longer called).

### Phase 5: Submit (5 min)
- Complete `findings_template.csv` (8+ findings)
- Fill `remediation_log.md`
- Push → Actions runs Semgrep + your regression tests

---

## Findings Template (findings_template.csv)

```csv
finding_id,file,line_number,vuln_class,cwe,code_snippet,vulnerability_description,attack_scenario,remediation,severity,confidence
CRV-001,scheduler/db.py,,SQL Injection,CWE-89,,,,,,,
CRV-002,scheduler/auth.py,,Hardcoded Credentials,CWE-798,,,,,,,
CRV-003,scheduler/utils.py,,Insecure Deserialization,CWE-502,,,,,,,
CRV-004,scheduler/app.py,,Missing Authorization,CWE-862,,,,,,,
CRV-005,scheduler/utils.py,,Path Traversal,CWE-22,,,,,,,
CRV-006,scheduler/auth.py,,Weak Password Hashing,CWE-916,,,,,,,
CRV-007,scheduler/app.py,,Verbose Error Message,CWE-209,,,,,,,
CRV-008,scheduler/app.py,,Open Redirect,CWE-601,,,,,,,
```

---

## Grading Rubric (GitHub Actions)

| Criterion | Points |
|-----------|--------|
| 8 findings identified with verbatim snippets | 40 |
| Correct CWE + severity for each | 15 |
| Remediation implemented (Semgrep clean or reduced) | 25 |
| Regression tests pass | 15 |
| Remediation log narrative complete | 5 |
| **Total** | **100** |

---

## Resources

- **Semgrep**: https://semgrep.dev/docs
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **OWASP Code Review Guide**: https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf

---

## Academic Integrity

- ☐ **No sharing findings** — independent review
- ☐ **Scope**: only this repo
- ☐ **Violations** → zero for lab + disciplinary referral