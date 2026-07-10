import pytest

from src.policy.schemas import ActionType, Decision, ProposedAction
from src.tools.tool_broker import ToolBroker


def test_allowed_tool_recognized(tmp_path):
    assert ToolBroker(tmp_path).request_tool("pytest") == ["pytest"]


def test_unauthorized_tool_raises(tmp_path):
    b = ToolBroker(tmp_path)
    for bad in ("bash", "curl", "rm", "nc", "python"):
        with pytest.raises(ValueError):
            b.request_tool(bad)


def test_raw_execution_disabled(tmp_path):
    with pytest.raises(ValueError):
        ToolBroker(tmp_path).run_raw("rm -rf /")


def test_execute_rejects_non_decision(tmp_path):
    with pytest.raises(TypeError):
        ToolBroker(tmp_path).execute("pytest -q")


def test_execute_refuses_blocked_decision(tmp_path):
    a = ProposedAction(ActionType.RUN_TEST, "tests", "run")
    blocked = Decision(a, False, "blocked by policy")
    with pytest.raises(PermissionError):
        ToolBroker(tmp_path).execute(blocked)
