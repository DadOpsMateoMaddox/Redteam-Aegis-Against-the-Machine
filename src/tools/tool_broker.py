"""Tool broker: the only thing that can run a process, and only allow-listed ones."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from src.policy.schemas import ActionType, Decision

# Fixed command templates. The model cannot supply the binary or flags.
ALLOWED_COMMANDS = {
    ActionType.RUN_TEST: ["pytest", "-q"],
    ActionType.RUN_LINT: ["ruff", "check"],
}
ALLOWED_TOOLS = {"pytest", "ruff"}


class ToolBroker:
    def __init__(self, repo_root, timeout=120):
        self.repo_root = Path(repo_root).resolve()
        self.timeout = timeout

    def request_tool(self, tool_name, args=None):
        """Explicit allow-list check. Unauthorized tools raise ValueError."""
        if tool_name not in ALLOWED_TOOLS:
            raise ValueError(
                f"tool '{tool_name}' is not in the allow-list {sorted(ALLOWED_TOOLS)}")
        return [tool_name, *(args or [])]

    def run_raw(self, command):
        """There is no path to arbitrary execution. Present only to prove it."""
        raise ValueError(
            f"arbitrary command execution is disabled by design: {command!r}")

    def execute(self, decision: Decision):
        # The broker consumes a Decision object, never a raw model string.
        if not isinstance(decision, Decision):
            raise TypeError("ToolBroker.execute requires a policy Decision, not a raw command")
        if not decision.allowed:
            raise PermissionError(f"refusing to execute a blocked action: {decision.reason}")
        action = decision.action
        if action.type not in ALLOWED_COMMANDS:
            raise ValueError(f"no approved tool mapping for action type '{action.type.value}'")
        base = ALLOWED_COMMANDS[action.type]
        target = action.target or "."
        cmd = [*base, target]
        exe = shutil.which(base[0])
        if exe is None:
            return {"cmd": cmd, "returncode": 127, "stdout": "",
                    "stderr": f"{base[0]} not installed", "ran": False}
        proc = subprocess.run(cmd, cwd=self.repo_root, capture_output=True,
                              text=True, timeout=self.timeout, shell=False)
        return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout,
                "stderr": proc.stderr, "ran": True}

    # convenience alias
    def run_test(self, decision):
        return self.execute(decision)
