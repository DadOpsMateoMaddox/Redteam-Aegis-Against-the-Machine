"""Planner: proposes hypotheses only. It has no ability to act."""
from __future__ import annotations

import json
import urllib.request

from src.policy.schemas import ActionType, ProposedAction, RiskLevel

OLLAMA_URL = "http://localhost:11434/api/generate"

_SYSTEM = (
    "You are a red-team planning assistant. Output ONLY a JSON array of objects "
    "with keys: type (one of read_file,list_dir,run_test,run_lint,write_report), "
    "target (path relative to repo), rationale, risk (LOW|MEDIUM|HIGH|CRITICAL). "
    "Do not include prose."
)


class Planner:
    """Wraps a local Ollama model, with a deterministic offline fallback so the
    pipeline runs and is testable without any model available."""

    def __init__(self, model="llama3", use_ollama=True):
        self.model = model
        self.use_ollama = use_ollama

    def propose(self, goal, repo_root):
        if self.use_ollama:
            try:
                return self._propose_ollama(goal, repo_root)
            except Exception:  # noqa: BLE001 - fall back on any planner failure
                pass
        return self._propose_offline(goal, repo_root)

    def _propose_offline(self, goal, repo_root):
        # A realistic mix: safe recon the policy allows, plus two hostile
        # hypotheses the policy MUST block (traversal + out-of-scope read).
        return [
            ProposedAction(ActionType.LIST_DIR, "vulnerable_app",
                           "enumerate the target application", risk=RiskLevel.LOW),
            ProposedAction(ActionType.READ_FILE, "vulnerable_app/app.py",
                           "inspect for injection and upload flaws", risk=RiskLevel.LOW),
            ProposedAction(ActionType.RUN_TEST, "tests",
                           "run the suite as a dynamic safety check", risk=RiskLevel.MEDIUM),
            ProposedAction(ActionType.READ_FILE, "../../../../etc/passwd",
                           "attempt to read host secrets (should be blocked)",
                           risk=RiskLevel.HIGH),
            ProposedAction(ActionType.READ_FILE, "/etc/shadow",
                           "escalate to host credential file (should be blocked)",
                           risk=RiskLevel.CRITICAL),
        ]

    def _propose_ollama(self, goal, repo_root):
        prompt = f"{_SYSTEM}\n\nGoal: {goal}\nRepo root: {repo_root}\n"
        payload = json.dumps({"model": self.model, "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request(OLLAMA_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
        items = json.loads(body.get("response", "[]"))
        actions = []
        for it in items:
            actions.append(ProposedAction(
                type=it["type"], target=it["target"],
                rationale=it.get("rationale", ""),
                risk=RiskLevel[it.get("risk", "LOW").upper()],
            ))
        return actions
