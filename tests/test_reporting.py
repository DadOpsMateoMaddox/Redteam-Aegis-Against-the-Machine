import pytest

from src.reporting.reporting import Evidence, Finding, Reporter


def _finding(**kw):
    base = dict(id="F1", title="SQLi in login", severity="high",
                description="string-formatted SQL query")
    base.update(kw)
    return Finding(**base)


def test_finding_requires_evidence():
    r = Reporter()
    with pytest.raises(ValueError):
        r.record(_finding(reproduction=["call login()"], evidence=[]))


def test_finding_requires_reproduction():
    r = Reporter()
    ev = Evidence("source_snippet", "vulnerable_app/app.py:20", "query = ... % (u, p)")
    with pytest.raises(ValueError):
        r.record(_finding(reproduction=[], evidence=[ev]))


def test_evidence_hash_is_deterministic_and_recorded():
    ev = Evidence("source_snippet", "vulnerable_app/app.py:20", "same-content")
    assert ev.sha256 == Evidence("source_snippet", "x", "same-content").sha256
    r = Reporter()
    f = r.record(_finding(reproduction=["call login('a','b')"], evidence=[ev]))
    assert f.to_dict()["evidence"][0]["sha256"] == ev.sha256
    assert ev.sha256 in r.to_json()
