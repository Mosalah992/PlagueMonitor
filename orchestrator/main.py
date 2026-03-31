import asyncio
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import redis.asyncio as redis

from logger import EventLogger

app = FastAPI(title="Epidemic Lab Orchestrator")
logger = EventLogger()

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

TEMPLATES_DIR = Path(__file__).parent / "templates"
DB_PATH = "/app/logs/epidemic.db"


class InjectPayload(BaseModel):
    worm_level: str = "easy"


def _parse_json_field(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return value
    if isinstance(parsed, str):
        try:
            return json.loads(parsed)
        except json.JSONDecodeError:
            return parsed
    return parsed


@app.on_event("startup")
async def startup_event():
    await redis_client.xadd(
        "events_stream",
        {
            "ts": str(asyncio.get_event_loop().time()),
            "src": "orchestrator",
            "dst": "orchestrator",
            "event": "RUN_STARTED",
            "state_after": "running",
        },
    )
    asyncio.create_task(consume_events())


@app.on_event("shutdown")
async def shutdown_event():
    await redis_client.xadd(
        "events_stream",
        {
            "ts": str(asyncio.get_event_loop().time()),
            "src": "orchestrator",
            "dst": "orchestrator",
            "event": "RUN_ENDED",
            "state_after": "stopped",
        },
    )


async def consume_events():
    last_id = "0"
    while True:
        try:
            result = await redis_client.xread(
                {"events_stream": last_id}, count=100, block=1000
            )
            if result:
                for stream_name, messages in result:
                    for message_id, message_data in messages:
                        if "ts" not in message_data:
                            continue
                        logger.log_event(message_data)
                        last_id = message_id
        except Exception as e:
            print(f"Error consuming events: {e}")
            await asyncio.sleep(1)


# ── Dashboard ────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    html_path = TEMPLATES_DIR / "dashboard.html"
    return HTMLResponse(content=html_path.read_text())


# ── Events polling endpoint (used by web dashboard) ─────
@app.get("/events")
async def get_events(after_id: int = 0, limit: int = 100, order: str = "desc"):
    try:
        normalized_limit = max(1, min(limit, 500))
        normalized_order = "ASC" if order.lower() == "asc" else "DESC"
        if after_id > 0:
            normalized_order = "ASC"
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""SELECT id, timestamp as ts, src_agent as src, dst_agent as dst,
                          event_type as event, attack_type, payload, mutation_v,
                          agent_state as state_after, metadata
                   FROM events WHERE id > ? ORDER BY id {normalized_order} LIMIT ?""",
                (after_id, normalized_limit),
            ).fetchall()
            latest_id = conn.execute(
                "SELECT COALESCE(MAX(id), 0) AS latest_id FROM events"
            ).fetchone()["latest_id"]
            events = []
            for row in rows:
                event = dict(row)
                event["metadata"] = _parse_json_field(event.get("metadata"))
                events.append(event)
        return {"events": events, "latest_id": latest_id}
    except Exception as e:
        return {"events": [], "error": str(e)}


# ── Logs dump (download) ────────────────────────────────
@app.get("/logs/dump")
async def dump_logs():
    jsonl_path = "/app/logs/events.jsonl"
    if os.path.exists(jsonl_path):
        return FileResponse(
            jsonl_path,
            media_type="application/json",
            filename="epidemic_events.jsonl",
        )
    raise HTTPException(status_code=404, detail="No log file found")


# ── Status ───────────────────────────────────────────────
@app.get("/status")
async def get_status():
    return {"status": "running"}


# ── Inject Worm ──────────────────────────────────────────
@app.post("/inject/{agent_id}")
async def inject_worm(agent_id: str, payload: InjectPayload):
    from scenarios.worm_injection import get_worm_payload

    worm = get_worm_payload(payload.worm_level)
    injection_id = os.urandom(8).hex()
    attack_strength = {
        "easy": 0.90,
        "medium": 1.25,
        "difficult": 2.00,
    }.get(payload.worm_level, 0.90)
    metadata = {
        "level": payload.worm_level,
        "attack_type": worm["type"],
        "attack_strength": attack_strength,
        "hop_count": 0,
        "injection_id": injection_id,
        "source_plane": "control",
    }

    msg = {
        "id": injection_id,
        "src": "orchestrator",
        "dst": agent_id,
        "event_type": "infection_attempt",
        "payload": worm["content"],
        "metadata": metadata,
    }

    await redis_client.publish(f"agent_{agent_id}", json.dumps(msg))

    event_data = {
        "ts": str(asyncio.get_event_loop().time()),
        "src": "orchestrator",
        "dst": agent_id,
        "event": "WRM-INJECT",
        "attack_type": worm["type"],
        "payload": worm["content"],
        "metadata": json.dumps(metadata),
        "hop_count": "0",
        "injection_id": injection_id,
    }
    await redis_client.xadd("events_stream", event_data)

    return {
        "status": "injected",
        "agent": agent_id,
        "level": payload.worm_level,
        "injection_id": injection_id,
    }


# ── Quarantine ───────────────────────────────────────────
@app.post("/quarantine/{agent_id}")
async def quarantine_agent(agent_id: str):
    metadata = {"source_plane": "control", "action": "quarantine"}
    msg = {
        "id": os.urandom(8).hex(),
        "src": "orchestrator",
        "dst": agent_id,
        "event_type": "quarantine",
        "payload": "",
        "metadata": metadata,
    }
    await redis_client.publish(f"agent_{agent_id}", json.dumps(msg))

    await redis_client.xadd(
        "events_stream",
        {
            "ts": str(asyncio.get_event_loop().time()),
            "src": "orchestrator",
            "dst": agent_id,
            "event": "QUARANTINE_ISSUED",
            "state_after": "QUARANTINED",
            "metadata": json.dumps(metadata),
        },
    )
    return {"status": "quarantined", "agent": agent_id}


# ── Reset ────────────────────────────────────────────────
@app.post("/reset")
async def reset_agents():
    metadata = {"source_plane": "control", "action": "reset"}
    msg = {
        "id": os.urandom(8).hex(),
        "src": "orchestrator",
        "dst": "broadcast",
        "event_type": "reset",
        "payload": "",
        "metadata": metadata,
    }
    await redis_client.publish("broadcast", json.dumps(msg))

    await redis_client.xadd(
        "events_stream",
        {
            "ts": str(asyncio.get_event_loop().time()),
            "src": "orchestrator",
            "dst": "all",
            "event": "RESET_ISSUED",
            "metadata": json.dumps(metadata),
        },
    )
    return {"status": "reset_issued"}
