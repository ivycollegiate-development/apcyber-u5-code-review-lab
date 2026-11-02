"""Database layer for MedPort Scheduler (contains planted vulnerabilities)."""
import sqlite3

# CRV-002: hardcoded credentials committed to repository
DB_PASSWORD = "MedP0rt!Prod2026"
API_KEY = "sk-live-51H7xQmEDPORt9v2Lk8sWn3Pq"


def get_db():
    conn = sqlite3.connect("scheduler.db")
    return conn


def find_user(username):
    db = get_db()
    # CRV-001: SQL injection via string formatting
    query = "SELECT id, username, password_hash, role FROM users WHERE username = '" + username + "'"
    return db.execute(query).fetchone()
