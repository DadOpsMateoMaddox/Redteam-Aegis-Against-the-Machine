"""Policy engine: the single choke point every action must pass through."""
from __future__ import annotations

import os
import re
from pathlib import Path

from src.policy.schemas import ActionType, Decision, ProposedAction, RiskLevel

# Action types that touch the filesystem and therefore need a scope check.
_PATH_ACTIONS = {ActionType.READ_FILE, ActionType.LIST_DIR}

# Everything the agent may even propose. Anything else is denied at the gate.
_DEFAULT_ALLOWED = {
    ActionType.READ_FILE,
    ActionType.LIST_DIR,
    ActionType.RUN_TEST,
    ActionType.RUN_LINT,
    ActionType.WRITE_REPORT,
}


class PolicyEngine:
    def __init__(self, repo_root, allowed_actions=None,
                 auto_approve_max_risk=RiskLevel.MEDIUM):
        self.repo_root = Path(repo_root).resolve()
        self.allowed_actions = set(allowed_actions) if allowed_actions else set(_DEFAULT_ALLOWED)
        self.auto_approve_max_risk = auto_approve_max_risk

    def validate_path(self, target: str):
        """Return (ok, reason, resolved_path). Blocks any escape from repo_root."""
        # Normalize Windows-style separators so traversal is blocked on any host.
        target = str(target).replace("\\", "/")
        try:
            if os.path.isabs(target) or re.match(r"^[A-Za-z]:", target):
                candidate = Path(target).resolve()
            else:
                candidate = (self.repo_root / target).resolve()
        except (OSError, ValueError, RuntimeError) as exc:
            return False, f"path could not be resolved: {exc}", None
        try:
            candidate.relative_to(self.repo_root)
        except ValueError:
            return False, f"path '{target}' resolves outside repo root {self.repo_root}", None
        return True, "within scope", candidate

    def validate_action(self, action: ProposedAction) -> Decision:
        """Every proposed action gets a yes/no plus a human-readable reason."""
        # 1. Action type must be on the allow-list.
        if action.type not in self.allowed_actions:
            return Decision(action, False,
                            f"action type '{action.type.value}' is not in the policy allow-list")
        # 2. Filesystem actions must stay inside the repo.
        if action.type in _PATH_ACTIONS:
            ok, reason, _ = self.validate_path(action.target)
            if not ok:
                return Decision(action, False, f"scope violation: {reason}")
        # 3. Risk ceiling: high/critical needs explicit human approval.
        if action.risk > self.auto_approve_max_risk and not action.approved:
            return Decision(action, False,
                            f"risk {action.risk.name} exceeds auto-approve ceiling "
                            f"{self.auto_approve_max_risk.name}; human approval required")
        return Decision(action, True, "within policy")
