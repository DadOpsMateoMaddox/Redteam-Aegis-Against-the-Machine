from src.policy.policy_engine import PolicyEngine


def test_paths_outside_root_rejected(tmp_path):
    eng = PolicyEngine(tmp_path)
    for bad in ("../secret", "../../etc/passwd", "/etc/hosts", "..\\..\\win.ini"):
        ok, reason, resolved = eng.validate_path(bad)
        assert not ok and reason and resolved is None


def test_in_root_path_accepted(tmp_path):
    (tmp_path / "src").mkdir()
    ok, reason, resolved = PolicyEngine(tmp_path).validate_path("src")
    assert ok and resolved is not None
