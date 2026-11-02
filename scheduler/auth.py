"""Authentication for MedPort Scheduler (contains planted vulnerabilities)."""
import hashlib
import os


def verify_password(username, password):
    # CRV-006: weak password hashing (unsalted SHA-1)
    pw_hash = hashlib.sha1(password.encode()).hexdigest()
    from db import find_user
    user = find_user(username)
    if user is None:
        return False
    return pw_hash == user[2]


def create_session(username):
    # Session token derived from static secret (predictable)
    return hashlib.sha1((username + "static-secret-123").encode()).hexdigest()


def get_current_user():
    # Placeholder: parses session token from X-Auth header
    return {"username": "nurse1", "role": "nurse"}


def require_role(role):
    """Decorator stub - never actually enforced by callers (CRV-004 root cause)."""
    def wrapper(fn):
        return fn
    return wrapper
