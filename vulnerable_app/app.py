"""
INTENTIONALLY VULNERABLE LAB TARGET - DO NOT DEPLOY.

Seeded weaknesses exist so the safety-constrained agent has something real to
find. This is a static analysis target; the app is never exposed to a network
in this project.
"""
from __future__ import annotations

import sqlite3

try:
    from flask import Flask, request  # noqa: F401
    app = Flask(__name__)
except Exception:  # Flask optional; the file is primarily an analysis target
    app = None


def login(username, password):
    # SEEDED VULNERABILITY: SQL injection via string formatting.
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE user = '%s' AND pw = '%s'" % (username, password)
    return query  # returned (not executed) so the analyzer can inspect it


def save_upload(filename, data):
    # SEEDED VULNERABILITY: unrestricted file upload, no extension/type check.
    path = "/tmp/uploads/" + filename  # also path-traversal prone
    return path


if app is not None:
    @app.route("/login", methods=["POST"])
    def _login_route():  # pragma: no cover - not exercised in tests
        return login(request.form.get("user", ""), request.form.get("pw", ""))
