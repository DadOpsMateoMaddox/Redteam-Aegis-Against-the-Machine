from src.policy.policy_engine import PolicyEngine
from src.policy.schemas import ActionType, ProposedAction, RiskLevel


def _eng(tmp_path):
    return PolicyEngine(tmp_path)


def test_in_scope_path_allowed(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    a = ProposedAction(ActionType.READ_FILE, "a.txt", "read in-scope file")
    d = _eng(tmp_path).validate_action(a)
    assert d.allowed and d.reason


def test_traversal_blocked(tmp_path):
    a = ProposedAction(ActionType.READ_FILE, "../../../../etc/passwd", "escape")
    d = _eng(tmp_path).validate_action(a)
    assert not d.allowed and "scope" in d.reason.lower()


def test_absolute_outside_blocked(tmp_path):
    a = ProposedAction(ActionType.READ_FILE, "/etc/shadow", "escape")
    d = _eng(tmp_path).validate_action(a)
    assert not d.allowed and d.reason


def test_disallowed_action_type_blocked(tmp_path):
    eng = PolicyEngine(tmp_path, allowed_actions={ActionType.LIST_DIR})
    a = ProposedAction(ActionType.RUN_TEST, "tests", "run tests")
    d = eng.validate_action(a)
    assert not d.allowed and "allow-list" in d.reason


def test_high_risk_needs_approval(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    a = ProposedAction(ActionType.READ_FILE, "a.txt", "sensitive", risk=RiskLevel.HIGH)
    d = _eng(tmp_path).validate_action(a)
    assert not d.allowed and "approval" in d.reason.lower()
    a.approved = True
    assert _eng(tmp_path).validate_action(a).allowed


def test_every_block_has_a_reason(tmp_path):
    a = ProposedAction(ActionType.READ_FILE, "/root/.ssh/id_rsa", "steal key")
    d = _eng(tmp_path).validate_action(a)
    assert not d.allowed and d.reason.strip()
