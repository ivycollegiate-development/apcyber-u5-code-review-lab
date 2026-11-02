"""Helpers for MedPort Scheduler (contains planted vulnerabilities)."""
import pickle
import os


def load_schedule_data(data):
    # CRV-003: insecure deserialization - pickle on untrusted input
    return pickle.loads(data)


def read_report(filename):
    # CRV-005: path traversal - user-controlled path joined directly
    reports_dir = "/var/medport/reports"
    full_path = os.path.join(reports_dir, filename)
    with open(full_path, "r") as f:
        return f.read()
