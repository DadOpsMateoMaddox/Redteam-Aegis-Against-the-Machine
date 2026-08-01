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
- `tests/` - six adversarial test suites (includes Promptfoo provider tests)
- `promptfoo/` - Promptfoo threat-level evaluation config and Python provider

## Run
```bash
pip install -r requirements.txt
python -m pytest -q          # all tests green
python demo/run_demo.py      # end-to-end: blocks, executions, a real finding
```

## Promptfoo Threat-Level Evaluation

[Promptfoo](https://promptfoo.dev) is used to run structured red-team evaluations
against the Aegis PolicyEngine across three threat levels:

| Level | Risk | Expected verdict |
|-------|------|-----------------|
| **Benign** | LOW | ALLOWED — safe recon actions pass policy |
| **Warn** | MEDIUM | ALLOWED — auto-approved but worth noting |
| **Dangerous** | HIGH / CRITICAL | BLOCKED — path traversal, host file reads, unapproved high-risk actions |

### Quick start

```bash
# Install Node.js dependencies (requires Node ≥ 18)
npm install

# Run all threat-level evaluations
npm run test:promptfoo

# Open the interactive results viewer
npm run test:promptfoo:view
```

> **Note:** `IS_TESTING=1` (set automatically by `npm run test:promptfoo`) directs
> promptfoo to use an in-memory SQLite database, avoiding a known incompatibility
> between promptfoo's internal ORM and Node.js 24's stricter async-transaction
> enforcement in `better-sqlite3`. Omit it only if you are running an older Node
> version where the file-based store works correctly.

Alternatively, run just the Python provider unit tests (no Node.js required):

```bash
python -m pytest tests/test_promptfoo_provider.py -v
```

### How it works

`promptfoo/provider.py` is a [Promptfoo Python provider](https://promptfoo.dev/docs/providers/python/)
that accepts a JSON-encoded `ProposedAction`, runs it through the `PolicyEngine`,
and returns a one-line verdict (`ALLOWED | …` or `BLOCKED | …`).  Assertions in
`promptfoo/promptfooconfig.yaml` verify the verdict for every test case.

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
