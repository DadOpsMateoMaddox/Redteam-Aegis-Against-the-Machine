"""Core data models for proposed actions and policy decisions."""
from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field


class RiskLevel(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ActionType(str, enum.Enum):
    """The ONLY action types the agent is permitted to express."""
    READ_FILE = "read_file"
    LIST_DIR = "list_dir"
    RUN_TEST = "run_test"
    RUN_LINT = "run_lint"
    WRITE_REPORT = "write_report"


@dataclass
class ProposedAction:
    """A hypothesis emitted by the planner. Never executed directly."""
    type: ActionType
    target: str
    rationale: str
    args: list = field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    approved: bool = False  # only a human/out-of-band step may set this True
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def __post_init__(self):
        if isinstance(self.type, str):
            self.type = ActionType(self.type)
        if isinstance(self.risk, int) and not isinstance(self.risk, RiskLevel):
            self.risk = RiskLevel(self.risk)


@dataclass
class Decision:
    """Result of running a ProposedAction through the PolicyEngine."""
    action: ProposedAction
    allowed: bool
    reason: str
