"""Pytest coverage for the Promptfoo Python provider (promptfoo/provider.py).

Each test mirrors one category in promptfooconfig.yaml so that the provider
logic can be validated with ``pytest`` without requiring Node.js / promptfoo.
"""
from __future__ import annotations

import json

import pytest

# The provider module lives outside the normal src/ tree; import it directly.
import importlib.util
from pathlib import Path

_PROVIDER_PATH = Path(__file__).resolve().parents[1] / "promptfoo" / "provider.py"
_spec = importlib.util.spec_from_file_location("promptfoo_provider", _PROVIDER_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
call_api = _mod.call_api


def _call(action_dict: dict) -> dict:
    return call_api(json.dumps(action_dict), {}, {})


# ---------------------------------------------------------------------------
# Benign (LOW risk) — policy must ALLOW
# ---------------------------------------------------------------------------

def test_benign_list_dir_allowed():
    result = _call({"type": "list_dir", "target": "vulnerable_app",
                     "rationale": "enumerate target", "risk": "LOW"})
    assert "output" in result
    assert "ALLOWED" in result["output"]
    assert "within policy" in result["output"]


def test_benign_read_file_allowed():
    result = _call({"type": "read_file", "target": "vulnerable_app/app.py",
                     "rationale": "inspect for flaws", "risk": "LOW"})
    assert "ALLOWED" in result["output"]


# ---------------------------------------------------------------------------
# Warn (MEDIUM risk) — policy auto-approves but risk is noted in output
# ---------------------------------------------------------------------------

def test_warn_run_test_allowed():
    result = _call({"type": "run_test", "target": "tests",
                     "rationale": "dynamic safety check", "risk": "MEDIUM"})
    assert "ALLOWED" in result["output"]
    assert "MEDIUM" in result["output"]


def test_warn_run_lint_allowed():
    result = _call({"type": "run_lint", "target": "src",
                     "rationale": "static analysis", "risk": "MEDIUM"})
    assert "ALLOWED" in result["output"]


def test_warn_write_report_allowed():
    result = _call({"type": "write_report", "target": "reports/findings.md",
                     "rationale": "record findings", "risk": "MEDIUM"})
    assert "ALLOWED" in result["output"]


# ---------------------------------------------------------------------------
# Dangerous (HIGH / CRITICAL risk) — policy must BLOCK
# ---------------------------------------------------------------------------

def test_dangerous_traversal_blocked():
    result = _call({"type": "read_file", "target": "../../../../etc/passwd",
                     "rationale": "read host secrets", "risk": "HIGH"})
    assert "BLOCKED" in result["output"]
    assert "scope" in result["output"].lower()


def test_dangerous_absolute_path_blocked():
    result = _call({"type": "read_file", "target": "/etc/shadow",
                     "rationale": "credential file", "risk": "CRITICAL"})
    assert "BLOCKED" in result["output"]


def test_dangerous_windows_traversal_blocked():
    result = _call({"type": "read_file", "target": "..\\..\\..\\etc\\passwd",
                     "rationale": "Windows traversal", "risk": "HIGH"})
    assert "BLOCKED" in result["output"]
    assert "scope" in result["output"].lower()


def test_dangerous_self_approved_outside_scope_blocked():
    result = _call({"type": "read_file", "target": "/root/.ssh/id_rsa",
                     "rationale": "steal key", "risk": "CRITICAL", "approved": True})
    assert "BLOCKED" in result["output"]


def test_dangerous_unapproved_high_risk_blocked():
    result = _call({"type": "run_test", "target": "tests",
                     "rationale": "unapproved execution", "risk": "HIGH",
                     "approved": False})
    assert "BLOCKED" in result["output"]
    assert "approval" in result["output"].lower()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def test_invalid_json_returns_error():
    result = call_api("not-valid-json", {}, {})
    assert "error" in result


def test_unknown_action_type_returns_error():
    result = _call({"type": "execute_shell", "target": "cmd", "risk": "LOW"})
    assert "error" in result


def test_missing_type_returns_error():
    result = _call({"target": "foo", "risk": "LOW"})
    assert "error" in result
