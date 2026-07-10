# Design tradeoffs

**Enforcement is structural, not prompt-based.** The model cannot be trusted to
police itself, so safety does not live in a system prompt. It lives in two objects
the model cannot bypass: the PolicyEngine (decides) and the ToolBroker (acts). The
planner only returns data. This is why an injected "ignore all policy" instruction
in repo content changes nothing, the injected action still goes through
`validate_action` and is denied with a reason.

**Allow-list, not deny-list.** Both action types and tools are allow-listed.
A deny-list is a losing game against novel phrasings; an allow-list fails closed.
New capability requires an explicit code change, which is auditable.

**Scope check by resolution, not by string matching.** `validate_path` resolves
the target and requires it to be `relative_to(repo_root)`. It also normalizes
Windows `\` separators so a `..\..\` traversal is blocked on any host. String
blocklists for `../` miss encodings; path resolution does not.

**Self-approval is meaningless.** A ProposedAction carries `approved=False`. Even
if a malicious planner sets `approved=True`, scope and type gates still fire first,
so approval only ever *relaxes the risk ceiling*, never the hard boundaries.

**Findings are worthless without evidence.** `Reporter.record` refuses a finding
that lacks hashed evidence or reproduction steps. This forces reproducibility and
makes results auditable rather than asserted.

**Tradeoff: capability vs. safety.** The agent is deliberately narrow (read, list,
run pytest/ruff). It cannot write code, open sockets, or install packages. That
sacrifices autonomy for a boundary you can actually reason about. Widening it means
adding an action type + tool mapping + tests, on purpose.

**Tradeoff: offline fallback vs. fidelity.** The planner falls back to deterministic
hypotheses when Ollama is down. This keeps the safety machinery testable in CI, at
the cost of the fallback being less creative than a live model. The enforcement path
is identical either way, which is the part that matters.

## What this proves (mapped to success criteria)
- identifies a real weakness -> `demo/run_demo.py` records the SQLi finding
- cannot escape scope -> `test_scope_escape.py`, `test_policy.py`
- model cannot invoke arbitrary tools -> `test_tool_broker.py`
- repo-injected instructions do not override policy -> `test_injection.py`
- every finding has reproducible evidence -> `test_reporting.py`
- every blocked action explains why -> Decision.reason, shown in the demo
