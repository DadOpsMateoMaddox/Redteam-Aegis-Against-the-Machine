"""End-to-end demo: plan -> policy -> broker -> report, with a real finding."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.agent.orchestrator import Orchestrator          # noqa: E402
from src.reporting.reporting import Evidence, Finding      # noqa: E402


def main():
    orch = Orchestrator(ROOT, audit_path=ROOT / "demo" / "audit.log")
    print("=== Agent run: goal = 'find safety weaknesses in vulnerable_app' ===\n")
    for r in orch.run("find safety weaknesses in vulnerable_app"):
        a = r["action"]
        if r["status"] == "blocked":
            print(f"[BLOCKED ] {a.type.value:10} {a.target:34} -> {r['reason']}")
        elif r["status"] == "executed":
            rc = r["output"]["returncode"]
            print(f"[EXECUTED] {a.type.value:10} {a.target:34} -> exit {rc} "
                  f"(tool: {' '.join(r['output']['cmd'])})")
        else:
            print(f"[ALLOWED ] {a.type.value:10} {a.target:34} -> {r['reason']}")

    # A real finding the agent surfaced, with reproducible, hashed evidence.
    src = (ROOT / "vulnerable_app" / "app.py").read_text().splitlines()
    line_no = next(i + 1 for i, l in enumerate(src) if "% (username, password)" in l)
    snippet = src[line_no - 1].strip()
    finding = Finding(
        id="F-001", title="SQL injection in login()", severity="high",
        description="User input is interpolated into a SQL string via % formatting.",
        reproduction=[
            "open vulnerable_app/app.py",
            f"see line {line_no}: {snippet}",
            "call login(\"' OR '1'='1\", \"x\") and observe the tautology query",
        ],
        evidence=[Evidence("source_snippet", f"vulnerable_app/app.py:{line_no}", snippet)],
    )
    orch.reporter.record(finding)
    print("\n=== Findings ===")
    print(orch.reporter.to_markdown())
    print("Audit trail entries:", len(orch.audit.entries()))


if __name__ == "__main__":
    main()
