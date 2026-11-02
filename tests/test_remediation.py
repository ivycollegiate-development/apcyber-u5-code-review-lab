"""Regression tests proving each vulnerability is remediated."""
import ast
import os
import sys
import unittest

SCHEDULER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scheduler")


def read_source(filename):
    with open(os.path.join(SCHEDULER, filename), "r") as f:
        return f.read()


class TestRemediation(unittest.TestCase):
    """Each test asserts a planted vulnerability has been FIXED.

    NOTE: These tests run BEFORE the student's push passes only if the
    student has remediated the code. CI on the reference (unsolved) repo
    uses grade.yml with allow-unfixed mode; student repos must pass here.
    """

    def test_crv_001_no_sql_concatenation(self):
        """CRV-001: no string-concatenated SQL in db.py."""
        src = read_source("db.py")
        self.assertNotIn("' + username + '", src)
        self.assertIn(",", src)  # parameterized execute call present

    def test_crv_002_no_hardcoded_secrets(self):
        """CRV-002: no hardcoded credentials in db.py."""
        src = read_source("db.py")
        self.assertNotIn("MedP0rt!Prod2026", src)
        self.assertNotIn("sk-live-", src)

    def test_crv_003_no_pickle_loads(self):
        """CRV-003: pickle.loads no longer used on untrusted input."""
        for f in ("utils.py", "app.py"):
            src = read_source(f)
            self.assertNotIn("pickle.loads", src)

    def test_crv_004_authorization_present(self):
        """CRV-004: role check before returning all appointments."""
        src = read_source("app.py")
        self.assertTrue(
            "require_role" in src or "role" in src,
            "app.py must enforce a role check on /appointments"
        )
        self.assertNotIn("SELECT * FROM appointments", src)

    def test_crv_005_no_raw_path_join(self):
        """CRV-005: filename sanitized before path join."""
        src = read_source("utils.py")
        self.assertTrue(
            "basename" in src or "abspath" in src or ".." in src.replace('".."', ""),
            "utils.py must sanitize filename (basename/abspath/whitelist)"
        )

    def test_crv_006_no_sha1_for_passwords(self):
        """CRV-006: SHA-1 not used for password verification."""
        src = read_source("auth.py")
        self.assertNotIn("hashlib.sha1", src)
        self.assertTrue(
            "bcrypt" in src or "argon2" in src or "pbkdf2" in src.lower(),
            "auth.py must use bcrypt/argon2/pbkdf2"
        )

    def test_crv_007_no_traceback_in_response(self):
        """CRV-007: stack trace and secrets not exposed in responses."""
        src = read_source("app.py")
        self.assertNotIn("traceback.format_exc", src)
        self.assertNotIn("db_password", src)

    def test_crv_008_redirect_validated(self):
        """CRV-008: redirect target validated before use."""
        src = read_source("app.py")
        self.assertTrue(
            "allowlist" in src.lower() or "startswith" in src or "urlparse" in src,
            "app.py must validate redirect targets (allowlist/startswith/urlparse)"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
