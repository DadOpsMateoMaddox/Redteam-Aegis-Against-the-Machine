"""Ties planner -> policy -> broker -> reporting, logging every decision."""
from __future__ import annotations

from pathlib import Path

from src.agent.planner import Planner
from src.policy.policy_engine import PolicyEngine
from src.policy.schemas import ActionType
from src.reporting.reporting import Reporter
from src.sandbox.audit_log import AuditLog
from src.tools.tool_broker import ToolBroker

_EXECUTABLE = {ActionType.RUN_TEST, ActionType.RUN_LINT}


class Orchestrator:
    def __init__(self, repo_root, planner=None, audit_path=None):
        self.repo_root = Path(repo_root).resolve()
        self.policy = PolicyEngine(self.repo_root)
        self.broker = ToolBroker(self.repo_root)
        self.audit = AuditLog(audit_path or (self.repo_root / "audit.log"))
        self.reporter = Reporter()
        self.planner = planner or Planner(use_ollama=False)

    def run(self, goal):
        results = []
        for action in self.planner.propose(goal, self.repo_root):
            decision = self.policy.validate_action(action)
            self.audit.record("action_evaluated", decision)
            if not decision.allowed:
                results.append({"status": "blocked", "reason": decision.reason,
                                "action": action})
                continue
            if action.type in _EXECUTABLE:
                out = self.broker.execute(decision)
                self.audit.record("tool_executed", decision,
                                  evidence=out.get("stdout", ""))
                results.append({"status": "executed", "output": out, "action": action})
            else:
                results.append({"status": "allowed", "reason": decision.reason,
                                "action": action})
        return results
