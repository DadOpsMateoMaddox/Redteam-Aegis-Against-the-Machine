# swe-safety-redteam

[![CI](https://github.com/DadOpsMateoMaddox/aegis-redteam-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/DadOpsMateoMaddox/aegis-redteam-agent/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A **safety-constrained red-team coding agent**. The planner proposes hypotheses,
but nothing acts until it passes a policy choke point, and only allow-listed tools
can ever run. The design goal is that the agent is useful *and* cannot be talked
(or injected) out of its guardrails.

## Architecture

```
Planner (Ollama, offline fallback)   proposes ProposedAction hypotheses
        |
        v
PolicyEngine   validate_action(): action-type allow-list, path/scope check,
        |      risk ceiling -> Decision(allowed, reason)
        v
ToolBroker     executes ONLY allow-listed tools (pytest, ruff), arg-list, no shell
        |
        v
Reporter       Findings that must carry reproducible, hashed Evidence
AuditLog       append-only record of every evaluation and execution
```

The planner never touches the filesystem or a subprocess. It only emits data.
Enforcement lives entirely in the PolicyEngine + ToolBroker.

## Layout
- `src/policy/schemas.py` - ActionType, RiskLevel, ProposedAction, Decision
- `src/policy/policy_engine.py` - scope + type + risk enforcement
- `src/tools/tool_broker.py` - tool allow-list, no arbitrary execution
- `src/sandbox/audit_log.py` - append-only audit trail
- `src/reporting/reporting.py` - findings with sha256 evidence
- `src/agent/planner.py` - Ollama planner with deterministic offline fallback
- `src/agent/orchestrator.py` - wires the pipeline
- `vulnerable_app/` - INTENTIONALLY VULNERABLE analysis target (SQLi, unrestricted upload)
- `tests/` - five adversarial test suites

## Run
```bash
pip install -r requirements.txt
python -m pytest -q          # 18 tests, all green
python demo/run_demo.py      # end-to-end: blocks, executions, a real finding
```

## Connecting Ollama (step 7)
Start Ollama locally (`ollama serve`, `ollama pull llama3`), then:
```python
from src.agent.orchestrator import Orchestrator
from src.agent.planner import Planner
Orchestrator(".", planner=Planner(model="llama3", use_ollama=True)).run("audit vulnerable_app")
```
If Ollama is unreachable the planner falls back to the offline hypotheses, so the
pipeline never hard-fails.

> Use Claude/Codex/ChatGPT for **code review and test refinement only** (step 8),
> not as the executor. The executor is the ToolBroker, by design.
