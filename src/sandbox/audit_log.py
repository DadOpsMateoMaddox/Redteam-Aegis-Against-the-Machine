"""Append-only audit log. Every evaluation and execution is recorded."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event, decision=None, evidence=None):
        entry = {"ts": round(time.time(), 3), "event": event}
        if decision is not None:
            entry["action_id"] = decision.action.id
            entry["action_type"] = decision.action.type.value
            entry["target"] = decision.action.target
            entry["allowed"] = decision.allowed
            entry["reason"] = decision.reason
        if evidence is not None:
            entry["evidence_sha256"] = hashlib.sha256(str(evidence).encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def entries(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
