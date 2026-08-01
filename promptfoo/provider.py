"""Promptfoo Python provider — routes each test prompt through the Aegis PolicyEngine.

Promptfoo calls ``call_api(prompt, options, context)`` and expects a dict with
either an ``output`` key (success) or an ``error`` key (failure).

The prompt must be a JSON object with these fields:
    type      – ActionType value  (e.g. "read_file")
    target    – path or target string
    rationale – human-readable rationale string
    risk      – RiskLevel name  (e.g. "LOW", "MEDIUM", "HIGH", "CRITICAL")
    approved  – optional bool (default False)
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Allow imports from the repo root regardless of where promptfoo invokes us.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.policy.policy_engine import PolicyEngine          # noqa: E402
from src.policy.schemas import ActionType, ProposedAction, RiskLevel  # noqa: E402

# Re-use a single engine anchored at the repo root.
_ENGINE = PolicyEngine(_REPO_ROOT)


def call_api(prompt: str, options: dict, context: dict) -> dict:
    """Entry-point called by promptfoo for every test case.

    Returns a dict with ``output`` (string) on success or ``error`` on failure.
    The output is a human-readable verdict that assertion rules can match on.
    """
    try:
        data = json.loads(prompt)
    except json.JSONDecodeError as exc:
        return {"error": f"prompt is not valid JSON: {exc}"}

    try:
        action = ProposedAction(
            type=ActionType(data["type"]),
            target=data["target"],
            rationale=data.get("rationale", ""),
            risk=RiskLevel[data.get("risk", "LOW").upper()],
            approved=bool(data.get("approved", False)),
        )
    except (KeyError, ValueError) as exc:
        return {"error": f"invalid action payload: {exc}"}

    decision = _ENGINE.validate_action(action)

    verdict = "ALLOWED" if decision.allowed else "BLOCKED"
    output = (
        f"{verdict} | type={action.type.value} target={action.target} "
        f"risk={action.risk.name} | {decision.reason}"
    )
    return {"output": output}
