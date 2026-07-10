"""Findings with reproducible, hashed evidence."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class Evidence:
    kind: str        # "command_output" | "source_snippet"
    reference: str   # the exact command or file:line that produced it
    content: str

    @property
    def sha256(self) -> str:
        return _sha(self.content)


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str
    reproduction: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        for ev_dict, ev_obj in zip(d["evidence"], self.evidence):
            ev_dict["sha256"] = ev_obj.sha256
        return d


class Reporter:
    def __init__(self):
        self.findings = []

    def record(self, finding: Finding) -> Finding:
        if not finding.evidence:
            raise ValueError("a finding must carry at least one evidence item")
        if not finding.reproduction:
            raise ValueError("a finding must include reproduction steps")
        self.findings.append(finding)
        return finding

    def to_json(self):
        return json.dumps([f.to_dict() for f in self.findings], indent=2)

    def to_markdown(self):
        out = ["# Red Team Findings\n"]
        for f in self.findings:
            out.append(f"## [{f.severity}] {f.title}  (`{f.id}`)\n")
            out.append(f"{f.description}\n")
            out.append("**Reproduction:**")
            out += [f"1. {s}" for s in f.reproduction]
            out.append("\n**Evidence:**")
            for ev in f.evidence:
                out.append(f"- `{ev.kind}` from `{ev.reference}` (sha256 `{ev.sha256[:16]}...`)")
            out.append("")
        return "\n".join(out)
