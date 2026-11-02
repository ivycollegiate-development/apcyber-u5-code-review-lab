"""MedPort Scheduler - legacy Flask app (contains planted vulnerabilities)."""
import os
import traceback
import pickle
from flask import Flask, request, redirect, jsonify

from db import get_db
from auth import verify_password, create_session, get_current_user
from utils import load_schedule_data, read_report

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if verify_password(username, password):
        token = create_session(username)
        return jsonify({"token": token})
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/appointments", methods=["GET"])
def list_appointments():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    db = get_db()
    # CRV-004: missing authorization - any authenticated user can read ALL patients
    rows = db.execute("SELECT * FROM appointments").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/upload_report", methods=["POST"])
def upload_report():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    filename = request.form.get("filename", "")
    # CRV-005: path traversal - filename not sanitized
    content = read_report(filename)
    return jsonify({"content": content})


@app.route("/import_schedule", methods=["POST"])
def import_schedule():
    user = get_current_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    data = request.get_data()
    # CRV-003: insecure deserialization with pickle on untrusted input
    schedule = load_schedule_data(data)
    return jsonify({"imported": schedule.get("count", 0)})


@app.route("/error_test")
def error_test():
    # CRV-007: verbose error message leaks stack trace and secrets
    try:
        db = get_db()
        db.execute("SELECT * FROM nonexistent_table")
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc(),
                        "db_password": os.environ.get("DB_PASSWORD", "fallback-secret")})
    return jsonify({"ok": True})


@app.route("/redirect")
def redirect_to():
    target = request.args.get("url", "/")
    # CRV-008: open redirect - no allowlist validation
    return redirect(target)


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
