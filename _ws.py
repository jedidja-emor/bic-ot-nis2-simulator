import json, datetime, pathlib
p = pathlib.Path(r"E:\my-dev-office\WORKFLOW_STATE.json")
state = {
  "project": "BeeInControl OT Fleet & NIS2 Access Control Simulator",
  "active_agent": "backend-dev",
  "agents": {
    "tech-lead": {"status": "working", "current_task": "Orchestrating multi-agent pipeline"},
    "architect": {"status": "done", "current_task": "Architecture spec written to ARCHITECTURE.md"},
    "backend-dev": {"status": "working", "current_task": "Implementing FastAPI backend, SQLite schema/seed, RBAC/JIT/NIS2/audit per ARCHITECTURE.md"},
    "frontend-dev": {"status": "idle", "current_task": "Standby"},
    "qa-tester": {"status": "idle", "current_task": "Standby"},
    "security-auditor": {"status": "idle", "current_task": "Standby"}
  },
  "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
}
p.write_text(json.dumps(state, indent=2), encoding='utf-8')
print('ok')
