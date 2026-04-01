import asyncio
import json
import os
import shutil
import sqlite3
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel
import redis.asyncio as redis

from logger import EventLogger
from siem import SIEMIndexer


EVENT_STREAM_KEY = "events_stream"
SIMULATION_EPOCH_KEY = "simulation_epoch"
CURRENT_RESET_ID_KEY = "current_reset_id"
AGENT_IDS = ("agent-a", "agent-b", "agent-c")
TOPOLOGY = {
    "agent-c": ["agent-b"],
    "agent-b": ["agent-a"],
    "agent-a": [],
}
AGENT_ROLES = {
    "agent-a": "Guardian",
    "agent-b": "Analyst",
    "agent-c": "Courier",
}

app = FastAPI(title="Epidemic Lab Orchestrator")
logger = EventLogger()

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

TEMPLATES_DIR = Path(__file__).parent / "templates"
DB_PATH = "/app/logs/epidemic.db"
JSONL_PATH = "/app/logs/events.jsonl"
ATTEMPT_RESOLUTION_WINDOW_S = 5.0
RESET_QUIET_PERIOD_S = 2.0
siem_indexer = SIEMIndexer(DB_PATH, JSONL_PATH)


class InjectPayload(BaseModel):
    worm_level: str = "easy"


class ImportPayload(BaseModel):
    source: str
    path: str = ""
    source_name: str = ""
    stream_name: str = EVENT_STREAM_KEY
    count: int = 500


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


def _parse_timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except ValueError:
            return None


def _sparkline(values: List[int]) -> str:
    if not values:
        return ""
    blocks = " .:-=+*#%@"
    upper = max(values)
    if upper <= 0:
        return " ".join("." for _ in values)
    rendered = []
    for value in values:
        index = int(round((value / upper) * (len(blocks) - 1)))
        rendered.append(blocks[index])
    return "".join(rendered)


def _event_metadata(event: Dict[str, Any]) -> Dict[str, Any]:
    metadata = event.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def _event_epoch(event: Dict[str, Any]) -> int | None:
    metadata = _event_metadata(event)
    epoch = metadata.get("epoch")
    if epoch in (None, ""):
        return None
    try:
        return int(epoch)
    except (TypeError, ValueError):
        return None


def _event_reset_id(event: Dict[str, Any]) -> str:
    metadata = _event_metadata(event)
    return str(metadata.get("reset_id", "") or "")


def _normalize_event_row(row: sqlite3.Row) -> Dict[str, Any]:
    event = dict(row)
    event["metadata"] = _parse_json_field(event.get("metadata"))
    return event


def _event_attempt_id(event: Dict[str, Any]) -> str:
    metadata = _event_metadata(event)
    return str(metadata.get("attempt_id") or metadata.get("injection_id") or "")


def _load_events_from_db(
    *, after_id: int = 0, limit: int = 100, order: str = "desc"
) -> Tuple[List[Dict[str, Any]], int]:
    normalized_limit = max(1, min(limit, 1000))
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if after_id > 0:
            rows = conn.execute(
                """SELECT id, timestamp as ts, src_agent as src, dst_agent as dst,
                          event_type as event, attack_type, payload, mutation_v,
                          agent_state as state_after, metadata
                   FROM events WHERE id > ? ORDER BY id ASC LIMIT ?""",
                (after_id, normalized_limit),
            ).fetchall()
        elif order.lower() == "asc":
            rows = conn.execute(
                """SELECT * FROM (
                       SELECT id, timestamp as ts, src_agent as src, dst_agent as dst,
                              event_type as event, attack_type, payload, mutation_v,
                              agent_state as state_after, metadata
                       FROM events ORDER BY id DESC LIMIT ?
                   ) recent_events
                   ORDER BY id ASC""",
                (normalized_limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, timestamp as ts, src_agent as src, dst_agent as dst,
                          event_type as event, attack_type, payload, mutation_v,
                          agent_state as state_after, metadata
                   FROM events ORDER BY id DESC LIMIT ?""",
                (normalized_limit,),
            ).fetchall()
        latest_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS latest_id FROM events"
        ).fetchone()["latest_id"]
    return [_normalize_event_row(row) for row in rows], int(latest_id or 0)


def _latest_reset_context(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    reset_index = None
    for index, event in enumerate(events_asc):
        if event.get("event") == "RESET_ISSUED":
            reset_index = index
    if reset_index is None:
        return {
            "reset_index": None,
            "reset_event": None,
            "reset_id": "",
            "epoch": 0,
            "events": [],
        }

    reset_event = events_asc[reset_index]
    reset_id = _event_reset_id(reset_event)
    epoch = _event_epoch(reset_event) or 0
    scoped_events = [
        event for event in events_asc[reset_index:]
        if _event_reset_id(event) == reset_id
    ]
    return {
        "reset_index": reset_index,
        "reset_event": reset_event,
        "reset_id": reset_id,
        "epoch": epoch,
        "events": scoped_events,
    }


def _derive_agents(events_desc: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    agents: Dict[str, Dict[str, Any]] = {
        agent_id: {
            "id": agent_id,
            "role": AGENT_ROLES.get(agent_id, ""),
            "state": "healthy",
            "last_event": "none",
            "last_seen": "",
            "last_payload": "",
            "last_metadata": {},
            "_state_locked": False,
        }
        for agent_id in AGENT_IDS
    }

    for event in events_desc:
        event_name = str(event.get("event", ""))
        dst = str(event.get("dst", ""))
        src = str(event.get("src", ""))
        state_after = str(event.get("state_after", "") or "").lower()

        if event_name == "RESET_ISSUED":
            for agent in agents.values():
                if agent["last_event"] == "none":
                    agent["state"] = "healthy"
                    agent["last_event"] = "RESET_ISSUED"
                    agent["last_seen"] = event.get("ts", "")
            continue

        if dst in agents:
            if agents[dst]["last_event"] == "none":
                agents[dst]["last_event"] = event_name or "unknown"
                agents[dst]["last_seen"] = event.get("ts", "")
            if not agents[dst]["_state_locked"]:
                if state_after:
                    agents[dst]["state"] = state_after
                    agents[dst]["_state_locked"] = True
                elif event_name == "QUARANTINE_ISSUED":
                    agents[dst]["state"] = "quarantined"
                    agents[dst]["_state_locked"] = True
                elif event_name == "INFECTION_SUCCESSFUL":
                    agents[dst]["state"] = "infected"
                    agents[dst]["_state_locked"] = True

        if dst in agents and event.get("payload") and not agents[dst]["last_payload"]:
            agents[dst]["last_payload"] = event["payload"]

        if dst in agents and event.get("metadata") and not agents[dst]["last_metadata"]:
            agents[dst]["last_metadata"] = event["metadata"]

        if src in agents and event.get("payload") and not agents[src]["last_payload"]:
            agents[src]["last_payload"] = event["payload"]

    for agent in agents.values():
        agent.pop("_state_locked", None)

    return agents


def _compute_flow_validation(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    context = _latest_reset_context(events_asc)
    run_events = context["events"]

    def attempts(src: str, dst: str) -> int:
        return sum(
            1
            for event in run_events
            if event.get("event") == "INFECTION_ATTEMPT"
            and event.get("src") == src
            and event.get("dst") == dst
        )

    def successes(src: str, dst: str) -> int:
        return sum(
            1
            for event in run_events
            if event.get("event") == "INFECTION_SUCCESSFUL"
            and event.get("src") == src
            and event.get("dst") == dst
        )

    c_to_b_attempts = attempts("agent-c", "agent-b")
    c_to_b_successes = successes("agent-c", "agent-b")
    b_to_a_attempts = attempts("agent-b", "agent-a")
    b_to_a_successes = successes("agent-b", "agent-a")

    invalid_flows = 0
    seen_c_to_b_attempt = False
    seen_b_to_a_attempt = False

    for event in run_events:
        if (
            event.get("event") == "INFECTION_ATTEMPT"
            and event.get("src") == "agent-c"
            and event.get("dst") == "agent-b"
        ):
            seen_c_to_b_attempt = True
        if (
            event.get("event") == "INFECTION_ATTEMPT"
            and event.get("src") == "agent-b"
            and event.get("dst") == "agent-a"
        ):
            seen_b_to_a_attempt = True

        if event.get("event") in {"INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}:
            if event.get("dst") == "agent-b" and (event.get("src") != "agent-c" or not seen_c_to_b_attempt):
                invalid_flows += 1
            if event.get("dst") == "agent-a" and (event.get("src") != "agent-b" or not seen_b_to_a_attempt):
                invalid_flows += 1

    return {
        "c_to_b": {
            "attempts": c_to_b_attempts,
            "successes": c_to_b_successes,
            "success_rate": round(c_to_b_successes / c_to_b_attempts, 3) if c_to_b_attempts else 0.0,
        },
        "b_to_a": {
            "attempts": b_to_a_attempts,
            "successes": b_to_a_successes,
            "success_rate": round(b_to_a_successes / b_to_a_attempts, 3) if b_to_a_attempts else 0.0,
        },
        "invalid_flows_detected": invalid_flows,
        "epoch": context["epoch"],
        "reset_id": context["reset_id"],
    }


def _compute_run_integrity(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    context = _latest_reset_context(events_asc)
    reset_index = context["reset_index"]
    if reset_index is None:
        return {
            "events_after_reset": False,
            "bleed_through_detected": False,
            "last_event_before_reset_ts": "",
            "first_event_after_reset_ts": "",
            "acked_agents": [],
            "heartbeat_agents": [],
            "barrier_complete": False,
            "reset_id": "",
            "epoch": 0,
            "suppression_events_before_barrier": 0,
            "suppression_events_after_barrier": 0,
            "quiet_period_s": RESET_QUIET_PERIOD_S,
        }

    reset_event = context["reset_event"]
    reset_id = context["reset_id"]
    reset_epoch = context["epoch"]
    later_events = events_asc[reset_index + 1 :]
    acked_agents: List[str] = []
    heartbeat_agents: List[str] = []
    barrier_complete_index = None

    for index, event in enumerate(later_events):
        if event.get("event") == "RESET_ACK" and _event_reset_id(event) == reset_id:
            src = str(event.get("src", ""))
            if src not in acked_agents:
                acked_agents.append(src)
        if (
            event.get("event") == "HEARTBEAT"
            and _event_reset_id(event) == reset_id
            and (_event_epoch(event) or reset_epoch) == reset_epoch
        ):
            src = str(event.get("src", ""))
            if src not in heartbeat_agents:
                heartbeat_agents.append(src)
        if len(acked_agents) == len(AGENT_IDS) and len(heartbeat_agents) == len(AGENT_IDS):
            barrier_complete_index = index
            break

    before_barrier = later_events if barrier_complete_index is None else later_events[: barrier_complete_index + 1]
    non_barrier_events = [
        event
        for event in before_barrier
        if event.get("event") not in {"RESET_ACK", "HEARTBEAT"}
    ]

    after_barrier = [] if barrier_complete_index is None else later_events[barrier_complete_index + 1 :]
    suppression_before_barrier = sum(
        1 for event in before_barrier
        if event.get("event") == "PROPAGATION_SUPPRESSED"
    )
    suppression_after_barrier = sum(
        1 for event in after_barrier
        if event.get("event") == "PROPAGATION_SUPPRESSED"
    )
    bleed_through = any(
        event.get("event") in {"STALE_EVENT_DROPPED", "PROPAGATION_SUPPRESSED"}
        or (
            event.get("event") in {"INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
            and _event_reset_id(event) not in {"", reset_id}
        )
        or ((_event_epoch(event) or reset_epoch) < reset_epoch)
        for event in after_barrier
    )

    return {
        "events_after_reset": bool(
            [
                event for event in non_barrier_events
                if event.get("event") != "PROPAGATION_SUPPRESSED"
            ]
        ),
        "bleed_through_detected": bleed_through,
        "last_event_before_reset_ts": events_asc[reset_index - 1]["ts"] if reset_index > 0 else "",
        "first_event_after_reset_ts": later_events[0]["ts"] if later_events else "",
        "acked_agents": acked_agents,
        "heartbeat_agents": heartbeat_agents,
        "barrier_complete": (
            len(acked_agents) == len(AGENT_IDS)
            and len(heartbeat_agents) == len(AGENT_IDS)
            and not bleed_through
        ),
        "reset_id": reset_id,
        "epoch": reset_epoch,
        "suppression_events_before_barrier": suppression_before_barrier,
        "suppression_events_after_barrier": suppression_after_barrier,
        "quiet_period_s": RESET_QUIET_PERIOD_S,
    }


def _compute_timeline(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not events_asc:
        return {"labels": [], "infected_counts": [], "sparkline": ""}

    context = _latest_reset_context(events_asc)
    run_events = context["events"]
    if not run_events:
        return {"labels": [], "infected_counts": [], "sparkline": ""}

    timestamps = [_parse_timestamp(event.get("ts")) for event in run_events]
    timestamps = [ts for ts in timestamps if ts is not None]
    if not timestamps:
        return {"labels": [], "infected_counts": [], "sparkline": ""}

    start = min(timestamps)
    end = max(timestamps)
    span = max((end - start).total_seconds(), 1.0)
    bucket_count = 12
    buckets = [set() for _ in range(bucket_count)]

    for event in run_events:
        ts = _parse_timestamp(event.get("ts"))
        if ts is None:
            continue
        offset = (ts - start).total_seconds()
        index = min(bucket_count - 1, int((offset / span) * (bucket_count - 1)))
        if str(event.get("state_after", "")).lower() == "infected" and event.get("dst") in AGENT_IDS:
            buckets[index].add(str(event.get("dst")))

    counts = [len(bucket) for bucket in buckets]
    labels = [
        (start + ((end - start) * (index / max(bucket_count - 1, 1)))).strftime("%H:%M:%S")
        for index in range(bucket_count)
    ]
    return {"labels": labels, "infected_counts": counts, "sparkline": _sparkline(counts)}


def _compute_influence(events_asc: List[Dict[str, Any]]) -> Dict[str, int]:
    context = _latest_reset_context(events_asc)
    reset_id = context["reset_id"]
    counts = {agent_id: 0 for agent_id in AGENT_IDS}
    for event in events_asc:
        if event.get("event") == "INFECTION_SUCCESSFUL" and _event_reset_id(event) == reset_id:
            src = str(event.get("src", ""))
            if src in counts:
                counts[src] += 1
    return counts


def _compute_attempt_reconciliation(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    context = _latest_reset_context(events_asc)
    run_events = context["events"]
    if not run_events:
        return {
            "reset_id": "",
            "epoch": 0,
            "attempt_count": 0,
            "resolved_count": 0,
            "unresolved_count": 0,
            "unresolved_over_window": 0,
            "resolution_rate": 0.0,
            "sample_unresolved": [],
        }

    attempts: Dict[str, Dict[str, Any]] = {}
    resolved_ids: set[str] = set()
    latest_ts = None
    for event in run_events:
        ts = _parse_timestamp(event.get("ts"))
        if ts is not None and (latest_ts is None or ts > latest_ts):
            latest_ts = ts
        attempt_id = _event_attempt_id(event)
        if event.get("event") == "INFECTION_ATTEMPT" and attempt_id:
            attempts[attempt_id] = event
        elif event.get("event") in {"INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"} and attempt_id:
            resolved_ids.add(attempt_id)

    unresolved = []
    unresolved_over_window = 0
    for attempt_id, event in attempts.items():
        if attempt_id in resolved_ids:
            continue
        unresolved.append(
            {
                "attempt_id": attempt_id,
                "src": event.get("src", ""),
                "dst": event.get("dst", ""),
                "ts": event.get("ts", ""),
            }
        )
        event_ts = _parse_timestamp(event.get("ts"))
        if latest_ts is not None and event_ts is not None:
            age_s = (latest_ts - event_ts).total_seconds()
            if age_s >= ATTEMPT_RESOLUTION_WINDOW_S:
                unresolved_over_window += 1

    resolved_count = sum(1 for attempt_id in attempts if attempt_id in resolved_ids)
    attempt_count = len(attempts)
    return {
        "reset_id": context["reset_id"],
        "epoch": context["epoch"],
        "attempt_count": attempt_count,
        "resolved_count": resolved_count,
        "unresolved_count": len(unresolved),
        "unresolved_over_window": unresolved_over_window,
        "resolution_window_s": ATTEMPT_RESOLUTION_WINDOW_S,
        "resolution_rate": round(resolved_count / attempt_count, 3) if attempt_count else 0.0,
        "sample_unresolved": unresolved[:10],
    }


def _compute_event_rate(events_asc: List[Dict[str, Any]]) -> Dict[str, Any]:
    timestamps = [_parse_timestamp(event.get("ts")) for event in events_asc]
    timestamps = [ts for ts in timestamps if ts is not None]
    if not timestamps:
        return {"events_per_sec": 0.0, "recent_event_count": 0, "burst_detected": False}

    latest = max(timestamps)
    window_start = latest - timedelta(seconds=30)
    recent_count = sum(1 for ts in timestamps if ts >= window_start)
    rate = recent_count / 30.0
    return {
        "events_per_sec": round(rate, 2),
        "recent_event_count": recent_count,
        "burst_detected": rate >= 5.0,
        "window_seconds": 30,
    }


def _dashboard_state_payload() -> Dict[str, Any]:
    recent_events_desc, latest_id = _load_events_from_db(limit=180, order="desc")
    analytics_rows, _ = _load_events_from_db(limit=1200, order="asc")
    agents = _derive_agents(recent_events_desc)
    return {
        "status": "running",
        "latest_id": latest_id,
        "topology": TOPOLOGY,
        "events": recent_events_desc,
        "agents": agents,
        "analytics": {
            "flow_validation": _compute_flow_validation(analytics_rows),
            "run_integrity": _compute_run_integrity(analytics_rows),
            "timeline": _compute_timeline(analytics_rows),
            "agent_influence": _compute_influence(analytics_rows),
            "event_rate": _compute_event_rate(analytics_rows),
            "attempt_reconciliation": _compute_attempt_reconciliation(analytics_rows),
        },
    }


def _get_latest_run_started_ts() -> str:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT timestamp FROM events WHERE event_type = 'RUN_STARTED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return str(row[0]) if row else ""


async def _build_snapshot_manifest(snapshot_name: str) -> Dict[str, Any]:
    _, latest_id = _load_events_from_db(limit=1, order="desc")
    return {
        "snapshot_time_utc": datetime.now(timezone.utc).isoformat(),
        "snapshot_name": snapshot_name,
        "latest_event_id": latest_id,
        "active_reset_id": await _get_current_reset_id(),
        "active_epoch": await _get_current_epoch(),
        "active_run_started_at": _get_latest_run_started_ts(),
    }


async def _get_latest_stream_id() -> str:
    entries = await redis_client.xrevrange(EVENT_STREAM_KEY, count=1)
    return entries[0][0] if entries else "0-0"


async def _get_current_epoch() -> int:
    current = await redis_client.get(SIMULATION_EPOCH_KEY)
    return int(current or 0)


async def _get_current_reset_id() -> str:
    return str(await redis_client.get(CURRENT_RESET_ID_KEY) or "")


async def _wait_for_reset_acks(
    start_id: str,
    reset_id: str,
    epoch: int,
    timeout_s: float = 12.0,
    quiet_period_s: float = RESET_QUIET_PERIOD_S,
) -> Tuple[List[str], List[str], bool, bool]:
    acknowledged: List[str] = []
    heartbeat_agents: List[str] = []
    deadline = time.monotonic() + timeout_s
    last_id = start_id
    quiet_deadline = None
    saw_post_barrier_stale = False

    while time.monotonic() < deadline:
        result = await redis_client.xread({EVENT_STREAM_KEY: last_id}, count=100, block=250)
        if not result:
            if (
                len(acknowledged) == len(AGENT_IDS)
                and len(heartbeat_agents) == len(AGENT_IDS)
            ):
                if quiet_deadline is None:
                    quiet_deadline = time.monotonic() + quiet_period_s
                if time.monotonic() >= quiet_deadline:
                    return (
                        sorted(acknowledged),
                        sorted(heartbeat_agents),
                        not saw_post_barrier_stale,
                        saw_post_barrier_stale,
                    )
            continue
        for _stream_name, messages in result:
            for message_id, message_data in messages:
                last_id = message_id
                event_name = message_data.get("event", "")
                metadata = _parse_json_field(message_data.get("metadata"))
                metadata = metadata if isinstance(metadata, dict) else {}
                event_epoch = metadata.get("epoch", epoch)
                try:
                    event_epoch = int(event_epoch or epoch)
                except (TypeError, ValueError):
                    event_epoch = epoch
                event_reset_id = str(metadata.get("reset_id", "") or "")
                if event_name == "RESET_ACK" and metadata.get("reset_id") == reset_id:
                    source = str(message_data.get("src", ""))
                    if source and source not in acknowledged:
                        acknowledged.append(source)
                elif (
                    event_name == "HEARTBEAT"
                    and event_reset_id == reset_id
                    and event_epoch == epoch
                ):
                    source = str(message_data.get("src", ""))
                    if source and source not in heartbeat_agents:
                        heartbeat_agents.append(source)

                barrier_ready = (
                    len(acknowledged) == len(AGENT_IDS)
                    and len(heartbeat_agents) == len(AGENT_IDS)
                )
                if event_name in {
                    "INFECTION_ATTEMPT",
                    "INFECTION_SUCCESSFUL",
                    "INFECTION_BLOCKED",
                    "STALE_EVENT_DROPPED",
                    "PROPAGATION_SUPPRESSED",
                }:
                    is_stale = (
                        event_name in {"STALE_EVENT_DROPPED", "PROPAGATION_SUPPRESSED"}
                        or event_epoch < epoch
                        or (event_reset_id not in {"", reset_id})
                    )
                    if barrier_ready:
                        quiet_deadline = time.monotonic() + quiet_period_s
                        if is_stale:
                            saw_post_barrier_stale = True

        if len(acknowledged) == len(AGENT_IDS) and len(heartbeat_agents) == len(AGENT_IDS):
            if quiet_deadline is None:
                quiet_deadline = time.monotonic() + quiet_period_s

    return sorted(acknowledged), sorted(heartbeat_agents), False, True


@app.on_event("startup")
async def startup_event():
    await redis_client.setnx(SIMULATION_EPOCH_KEY, "0")
    start_id = await _get_latest_stream_id()
    await redis_client.xadd(
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": "orchestrator",
            "event": "RUN_STARTED",
            "state_after": "running",
        },
    )
    siem_indexer.sync_primary_events()
    asyncio.create_task(consume_events(start_id))


@app.on_event("shutdown")
async def shutdown_event():
    await redis_client.xadd(
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": "orchestrator",
            "event": "RUN_ENDED",
            "state_after": "stopped",
        },
    )


async def consume_events(start_id: str):
    last_id = start_id
    while True:
        try:
            result = await redis_client.xread({EVENT_STREAM_KEY: last_id}, count=100, block=1000)
            if not result:
                continue
            for _stream_name, messages in result:
                for message_id, message_data in messages:
                    if "ts" not in message_data:
                        continue
                    logger.log_event(message_data)
                    last_id = message_id
                siem_indexer.sync_primary_events()
        except Exception as exc:
            print(f"Error consuming events: {exc}")
            await asyncio.sleep(1)


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    html_path = TEMPLATES_DIR / "dashboard.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)


@app.get("/events")
async def get_events(after_id: int = 0, limit: int = 100, order: str = "desc"):
    try:
        events, latest_id = _load_events_from_db(after_id=after_id, limit=limit, order=order)
        return {"events": events, "latest_id": latest_id}
    except Exception as exc:
        return {"events": [], "error": str(exc)}


@app.get("/dashboard/state")
async def get_dashboard_state():
    try:
        return _dashboard_state_payload()
    except Exception as exc:
        return {"status": "error", "error": str(exc), "events": [], "latest_id": 0}


@app.get("/api/search")
async def api_search(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
    limit: int = 200,
    offset: int = 0,
    sort_field: str = "ts",
    sort_dir: str = "desc",
):
    try:
        return siem_indexer.search(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=limit,
            offset=offset,
            sort_field=sort_field,
            sort_dir=sort_dir,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/live")
async def api_live(after_id: int = 0, limit: int = 100, q: str = ""):
    try:
        return siem_indexer.live(after_id=after_id, limit=limit, query=q)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/fields")
async def api_fields(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.fields(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/stats")
async def api_stats(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.stats(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/patterns")
async def api_patterns(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.patterns(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/trace/{event_id}")
async def api_trace(event_id: str):
    try:
        return siem_indexer.trace(event_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Event not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/trace/by-injection/{injection_id}")
async def api_trace_by_injection(injection_id: str):
    try:
        return siem_indexer.trace_by_injection(injection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Injection not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/trace/by-reset/{reset_id}")
async def api_trace_by_reset(reset_id: str):
    try:
        return siem_indexer.trace_by_reset(reset_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Reset not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/related/{event_id}")
async def api_related(event_id: str):
    try:
        return siem_indexer.related(event_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Event not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/hints")
async def api_hints(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.hints(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/stats/presets")
async def api_stats_presets(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
    compare_q: str = "",
):
    try:
        return siem_indexer.stats_presets(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
            compare_q=compare_q,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/health")
async def api_health():
    try:
        return siem_indexer.health()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/import")
async def api_import(payload: ImportPayload):
    try:
        source = payload.source.lower()
        if source == "jsonl":
            return siem_indexer.import_jsonl(
                payload.path,
                source_type="jsonl_log",
                source_name=payload.source_name or Path(payload.path).name,
            )
        if source == "runtime_log":
            return siem_indexer.import_jsonl(
                payload.path,
                source_type="agent_runtime_log",
                source_name=payload.source_name or Path(payload.path).name,
            )
        if source == "redis":
            return await siem_indexer.import_redis_stream(
                redis_client,
                stream_name=payload.stream_name,
                count=payload.count,
            )
        if source == "events_table":
            return siem_indexer.sync_primary_events(limit=max(1, min(payload.count, 10000)))
        raise HTTPException(status_code=400, detail="Unsupported source")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/logs/dump")
async def dump_logs():
    jsonl_path = "/app/logs/events.jsonl"
    if os.path.exists(jsonl_path):
        snapshot_stem = f"epidemic_events_snapshot_{int(time.time())}"
        snapshot_name = f"{snapshot_stem}.jsonl"
        snapshot_path = f"/tmp/{snapshot_name}"
        archive_path = f"/tmp/{snapshot_stem}.zip"
        shutil.copyfile(jsonl_path, snapshot_path)
        manifest = await _build_snapshot_manifest(snapshot_name)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(snapshot_path, arcname=snapshot_name)
            archive.writestr(
                f"{snapshot_stem}_manifest.json",
                json.dumps(manifest, indent=2),
            )
        return FileResponse(
            archive_path,
            media_type="application/zip",
            filename=f"{snapshot_stem}.zip",
        )
    raise HTTPException(status_code=404, detail="No log file found")


@app.get("/status")
async def get_status():
    return {"status": "running", "epoch": await _get_current_epoch()}


@app.post("/inject/{agent_id}")
async def inject_worm(agent_id: str, payload: InjectPayload):
    from scenarios.worm_injection import get_worm_payload

    worm = get_worm_payload(payload.worm_level)
    injection_id = os.urandom(8).hex()
    epoch = await _get_current_epoch()
    reset_id = await _get_current_reset_id()
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
        "attempt_id": injection_id,
        "source_plane": "control",
        "epoch": epoch,
        "reset_id": reset_id,
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

    await redis_client.xadd(
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": agent_id,
            "event": "WRM-INJECT",
            "attack_type": worm["type"],
            "payload": worm["content"],
            "metadata": json.dumps(metadata),
            "hop_count": "0",
            "injection_id": injection_id,
        },
    )

    return {
        "status": "injected",
        "agent": agent_id,
        "level": payload.worm_level,
        "injection_id": injection_id,
        "epoch": epoch,
        "reset_id": reset_id,
    }


@app.post("/quarantine/{agent_id}")
async def quarantine_agent(agent_id: str):
    epoch = await _get_current_epoch()
    reset_id = await _get_current_reset_id()
    metadata = {
        "source_plane": "control",
        "action": "quarantine",
        "epoch": epoch,
        "reset_id": reset_id,
    }
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
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": agent_id,
            "event": "QUARANTINE_ISSUED",
            "state_after": "quarantined",
            "metadata": json.dumps(metadata),
        },
    )
    return {"status": "quarantined", "agent": agent_id, "epoch": epoch, "reset_id": reset_id}


@app.post("/reset")
async def reset_agents():
    new_epoch = await redis_client.incr(SIMULATION_EPOCH_KEY)
    reset_id = os.urandom(8).hex()
    await redis_client.set(CURRENT_RESET_ID_KEY, reset_id)
    metadata = {
        "source_plane": "control",
        "action": "reset",
        "epoch": new_epoch,
        "reset_id": reset_id,
    }
    msg = {
        "id": reset_id,
        "src": "orchestrator",
        "dst": "broadcast",
        "event_type": "reset",
        "payload": "",
        "metadata": metadata,
    }

    start_id = await _get_latest_stream_id()
    await redis_client.publish("broadcast", json.dumps(msg))
    await redis_client.xadd(
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": "all",
            "event": "RESET_ISSUED",
            "metadata": json.dumps(metadata),
        },
    )

    acknowledged_agents, heartbeat_agents, barrier_complete, bleed_through = await _wait_for_reset_acks(
        start_id,
        reset_id,
        int(new_epoch),
    )

    return {
        "status": "reset_issued",
        "epoch": int(new_epoch),
        "reset_id": reset_id,
        "acknowledged_agents": acknowledged_agents,
        "heartbeat_agents": heartbeat_agents,
        "barrier_complete": barrier_complete,
        "bleed_through_detected": bleed_through,
        "quiet_period_s": RESET_QUIET_PERIOD_S,
    }
