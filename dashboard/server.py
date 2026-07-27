"""
dashboard/server.py

Aegis red-team agent — live pipeline console. FastAPI + WebSocket.

Drives the existing Orchestrator (planner -> policy -> broker -> reporter)
through its public API only. This module never edits policy_engine.py,
tool_broker.py, or orchestrator.py, and it cannot widen what the agent is
allowed to do: POST /api/run accepts a goal string and nothing else — no
allowed_actions override, no risk-ceiling override, no pre-approval. The
choke point the agent is built to demonstrate stays intact on the way in
through the UI too.

Usage:
    python -m dashboard.server
    python -m dashboard.server --host 127.0.0.1 --port 8090
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.agent.orchestrator import Orchestrator              # noqa: E402
from src.policy.policy_engine import PolicyEngine            # noqa: E402
from src.policy.schemas import ProposedAction                # noqa: E402
from src.reporting.reporting import Evidence, Finding        # noqa: E402
from src.tools.tool_broker import ALLOWED_COMMANDS, ALLOWED_TOOLS  # noqa: E402

REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

MAX_GOAL_LEN = 300
STEP_ANIMATION_DELAY = 0.35  # seconds between step broadcasts, cosmetic only


class RunRequest(BaseModel):
    """The only thing a caller may influence: the goal string. Extra fields
    (allowed_actions, auto_approve_max_risk, approved, ...) are rejected with
    422 rather than silently dropped, so an attempt to widen the allow-list
    through this endpoint fails loudly instead of just being ignored."""
    model_config = ConfigDict(extra="forbid")
    goal: str = Field(..., min_length=1, max_length=MAX_GOAL_LEN)


def _serialize_action(a: ProposedAction) -> dict[str, Any]:
    return {
        "id": a.id, "type": a.type.value, "target": a.target,
        "rationale": a.rationale, "risk": a.risk.name, "approved": a.approved,
    }


def _serialize_step(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"status": r["status"], "action": _serialize_action(r["action"])}
    if "reason" in r:
        out["reason"] = r["reason"]
    if "output" in r:
        o = r["output"]
        out["output"] = {k: o[k] for k in ("cmd", "returncode", "ran") if k in o}
        out["output"]["stdout_tail"] = (o.get("stdout") or "")[-800:]
        out["output"]["stderr_tail"] = (o.get("stderr") or "")[-800:]
    return out


def _canned_finding(repo_root: Path) -> Finding | None:
    """The same finding demo/run_demo.py surfaces: a real SQLi in the
    vulnerable_app fixture, located by scanning the actual source on disk
    rather than being hardcoded — so it stays true if the fixture changes."""
    app_py = repo_root / "vulnerable_app" / "app.py"
    if not app_py.exists():
        return None
    lines = app_py.read_text(encoding="utf-8").splitlines()
    line_no = next((i + 1 for i, ln in enumerate(lines) if "% (username, password)" in ln), None)
    if line_no is None:
        return None
    snippet = lines[line_no - 1].strip()
    return Finding(
        id="F-001", title="SQL injection in login()", severity="high",
        description="User input is interpolated into a SQL string via % formatting.",
        reproduction=[
            "open vulnerable_app/app.py",
            f"see line {line_no}: {snippet}",
            "call login(\"' OR '1'='1\", \"x\") and observe the tautology query",
        ],
        evidence=[Evidence("source_snippet", f"vulnerable_app/app.py:{line_no}", snippet)],
    )


def _run_pipeline_sync(goal: str, run_id: str) -> dict[str, Any]:
    """Runs entirely inside a worker thread: the ToolBroker shells out to
    pytest/ruff, so this must stay off the event loop."""
    audit_path = REPORTS_DIR / f"{run_id}_audit.log"
    orch = Orchestrator(ROOT, audit_path=audit_path)
    t0 = time.time()
    results = orch.run(goal)
    finding = _canned_finding(ROOT)
    if finding is not None:
        orch.reporter.record(finding)
    duration_ms = round((time.time() - t0) * 1000, 1)

    steps = [_serialize_step(r) for r in results]
    counts = {
        "proposed": len(results),
        "blocked": sum(1 for r in results if r["status"] == "blocked"),
        "executed": sum(1 for r in results if r["status"] == "executed"),
        "allowed": sum(1 for r in results if r["status"] == "allowed"),
        "findings": len(orch.reporter.findings),
    }
    record = {
        "run_id": run_id,
        "ts": time.time(),
        "goal": goal,
        "planner": {"model": orch.planner.model, "use_ollama": orch.planner.use_ollama},
        "steps": steps,
        "findings": [f.to_dict() for f in orch.reporter.findings],
        "audit": orch.audit.entries(),
        "counts": counts,
        "duration_ms": duration_ms,
    }
    (REPORTS_DIR / f"{run_id}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def _load_runs() -> list[dict[str, Any]]:
    runs = []
    for p in sorted(REPORTS_DIR.glob("*.json")):
        try:
            runs.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return runs


class RunBroadcaster:
    """Fans out run events to every connected /ws client. No history beyond
    the most recent run is kept in memory — persisted run JSON is the source
    of truth for anything older."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self.last_run: dict[str, Any] | None = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    async def publish(self, msg: dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass


def build_app() -> FastAPI:
    app = FastAPI(title="Aegis Red-Team Console", version="1.0.0")
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    bus = RunBroadcaster()

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "repo_root": str(ROOT),
            "runs_recorded": len(list(REPORTS_DIR.glob("*.json"))),
        }

    @app.get("/api/policy")
    async def policy() -> JSONResponse:
        engine = PolicyEngine(ROOT)
        return JSONResponse({
            "repo_root": str(ROOT),
            "allowed_action_types": sorted(t.value for t in engine.allowed_actions),
            "auto_approve_max_risk": engine.auto_approve_max_risk.name,
            "risk_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "tool_broker": {
                "allowed_tools": sorted(ALLOWED_TOOLS),
                "command_map": {k.value: v for k, v in ALLOWED_COMMANDS.items()},
            },
        })

    @app.get("/api/overview")
    async def overview() -> JSONResponse:
        runs = _load_runs()
        totals = {"proposed": 0, "blocked": 0, "executed": 0, "allowed": 0, "findings": 0}
        for r in runs:
            for k in totals:
                totals[k] += r["counts"][k]
        latest = max(runs, key=lambda r: r["ts"]) if runs else None
        return JSONResponse({
            "run_count": len(runs),
            "totals": totals,
            "latest_run_id": latest["run_id"] if latest else None,
            "latest_goal": latest["goal"] if latest else None,
            "latest_ts": latest["ts"] if latest else None,
        })

    @app.get("/api/runs")
    async def list_runs() -> JSONResponse:
        runs = sorted(_load_runs(), key=lambda r: r["ts"])
        by_planner: dict[str, dict[str, Any]] = {}
        enriched = []
        for r in runs:
            p = r["planner"]
            label = f"ollama:{p['model']}" if p["use_ollama"] else "offline"
            prev = by_planner.get(label)
            delta = None
            if prev is not None:
                delta = {k: r["counts"][k] - prev["counts"][k] for k in r["counts"]}
            enriched.append({**r, "planner_label": label, "delta": delta})
            by_planner[label] = r
        enriched.sort(key=lambda r: r["ts"], reverse=True)
        # trim heavy fields for the list view; full detail via /api/runs/{id}
        return JSONResponse([
            {k: v for k, v in r.items() if k not in ("steps", "audit")}
            for r in enriched
        ])

    @app.get("/api/runs/{run_id}")
    async def get_run(run_id: str) -> JSONResponse:
        p = REPORTS_DIR / f"{run_id}.json"
        if not p.exists():
            raise HTTPException(status_code=404, detail="run not found")
        return JSONResponse(json.loads(p.read_text(encoding="utf-8")))

    @app.get("/api/findings")
    async def findings() -> JSONResponse:
        seen: dict[str, dict[str, Any]] = {}
        for r in _load_runs():
            for f in r.get("findings", []):
                seen[f["id"]] = {**f, "run_id": r["run_id"], "ts": r["ts"]}
        return JSONResponse(sorted(seen.values(), key=lambda f: f["ts"], reverse=True))

    @app.post("/api/run")
    async def run_pipeline(req: RunRequest) -> JSONResponse:
        run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
        await bus.publish({"kind": "run_start", "run_id": run_id, "goal": req.goal})
        try:
            record = await asyncio.to_thread(_run_pipeline_sync, req.goal, run_id)
        except Exception as exc:  # noqa: BLE001 — surface to caller & UI, never crash server
            await bus.publish({"kind": "run_error", "run_id": run_id, "error": str(exc)})
            raise HTTPException(status_code=500, detail=f"pipeline error: {exc}")

        for step in record["steps"]:
            await bus.publish({"kind": "step", "run_id": run_id, "step": step})
            await asyncio.sleep(STEP_ANIMATION_DELAY)
        summary = {k: v for k, v in record.items() if k != "audit"}
        await bus.publish({"kind": "run_done", "run_id": run_id, "record": summary})
        bus.last_run = record
        return JSONResponse(record)

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        await websocket.accept()
        q = bus.subscribe()
        try:
            await websocket.send_json({"kind": "hello", "last_run": bus.last_run})
            while True:
                msg = await q.get()
                await websocket.send_json(msg)
        except WebSocketDisconnect:
            pass
        finally:
            bus.unsubscribe(q)

    return app


app = build_app()


def main() -> None:
    p = argparse.ArgumentParser(description="Aegis red-team console")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8090)
    args = p.parse_args()

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
