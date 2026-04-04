import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel
import redis.asyncio as redis

from logger import EventLogger
from siem import SIEMIndexer
from c2 import C2Engine


EVENT_STREAM_KEY = "events_stream"
SIMULATION_EPOCH_KEY = "simulation_epoch"
CURRENT_RESET_ID_KEY = "current_reset_id"
BEACON_SERVER_URL = os.environ.get(
    "C2_BEACON_SERVER_URL",
    "https://v0-beaconing-project-server-mdml8734h-mosalah992s-projects.vercel.app",
)
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
_BEACON_TRANSFER_SRCS = {"agent-a", "agt-001", "agt-01"}
_BEACON_TRANSFER_DSTS = {"agent-b", "agent-c", "agt-002", "agt-003", "agt-02", "agt-03"}
_BEACON_EXFIL_DST_RE = re.compile(r"^agt[-_]?0*[4-9]$", re.IGNORECASE)
_BEACON_REGISTRATION_RETRY_LIMIT = 6
_BEACON_REGISTRATION_BASE_DELAY_S = 2.0
# Vercel Deployment Protection bypass — set via env or .env
_VERCEL_BYPASS_SECRET = os.environ.get("VERCEL_PROTECTION_BYPASS", "")
# C2 event types that should be forwarded to the beacon server
_C2_FORWARD_EVENTS = {"C2_EXFIL", "C2_DATABASE_WRITE", "C2_BEACON", "C2_CHANNEL_ESTABLISHED"}

app = FastAPI(title="Epidemic Lab Orchestrator")
logger = EventLogger()
uvicorn_logger = logging.getLogger("uvicorn.error")
_beacon_client: httpx.AsyncClient | None = None

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

TEMPLATES_DIR = Path(__file__).parent / "templates"
FRONTEND_DIST_DIR = Path(__file__).parent / "static"
LEGACY_DASHBOARD_PATH = TEMPLATES_DIR / "dashboard.html"
REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = Path(os.environ.get("LOGS_DIR", "/app/logs"))
DB_PATH = "/app/logs/epidemic.db"
JSONL_PATH = "/app/logs/events.jsonl"
SIEM_DB_PATH = os.environ.get("SIEM_DB_PATH", "/tmp/siem_index.db")
SIEM_TIMING_LOG_PATH = Path("/app/logs/siem_actions.jsonl")
ATTEMPT_RESOLUTION_WINDOW_S = 5.0
RESET_QUIET_PERIOD_S = 2.0
RESET_ACK_TIMEOUT_S = float(os.environ.get("RESET_ACK_TIMEOUT_S", "12.0"))
siem_indexer = SIEMIndexer(SIEM_DB_PATH, JSONL_PATH, source_db_path=DB_PATH)


async def _c2_emit_to_stream(event_data: Dict[str, Any]) -> None:
    """Emit a C2 event to the Redis event stream."""
    try:
        mapping: Dict[str, str] = {}
        for key, value in event_data.items():
            if value is None:
                continue
            if isinstance(value, (dict, list, tuple, bool)):
                mapping[key] = json.dumps(value)
            else:
                mapping[key] = str(value)
        await redis_client.xadd(EVENT_STREAM_KEY, mapping)
    except Exception as exc:
        uvicorn_logger.warning("c2_event_emit_failed event=%s err=%s", event_data.get("event"), exc)


c2_engine = C2Engine(emit_event=_c2_emit_to_stream)

if (FRONTEND_DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST_DIR / "assets"), name="frontend-assets")


class InjectPayload(BaseModel):
    worm_level: str = "easy"


class ImportPayload(BaseModel):
    source: str
    path: str = ""
    source_name: str = ""
    stream_name: str = EVENT_STREAM_KEY
    count: int = 500


def _normalized_text(value: Any) -> str:
    return str(value or "").strip()


def _normalized_agent_id(value: Any) -> str:
    return _normalized_text(value).lower()


def _validated_agent_id(value: Any) -> str:
    agent_id = _normalized_agent_id(value)
    if agent_id not in AGENT_IDS:
        raise HTTPException(status_code=400, detail="Unsupported agent_id")
    return agent_id


def _agent_channel_name(agent_id: str) -> str:
    return f"agent_{_validated_agent_id(agent_id)}"


def _import_roots() -> List[Path]:
    configured = [
        item.strip()
        for item in os.environ.get("SIEM_IMPORT_ROOTS", "").split(os.pathsep)
        if item.strip()
    ]
    candidates = configured or [
        str(LOGS_DIR),
        str(REPO_ROOT / "logs"),
        str(Path.cwd() / "logs"),
    ]
    roots: List[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = Path(candidate).expanduser().resolve(strict=False)
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        roots.append(resolved)
    return roots


def _validated_import_path(raw_path: str) -> Path:
    candidate = Path(_normalized_text(raw_path)).expanduser()
    if not str(candidate):
        raise HTTPException(status_code=400, detail="Import path is required")
    resolved = candidate.resolve(strict=False)
    if not resolved.exists():
        raise FileNotFoundError(raw_path)
    if not resolved.is_file():
        raise HTTPException(status_code=400, detail="Import path must reference a file")
    if not any(resolved.is_relative_to(root) for root in _import_roots()):
        raise HTTPException(status_code=400, detail="Import path must stay within configured log roots")
    return resolved


def _event_metadata_dict(event: Dict[str, Any]) -> Dict[str, Any]:
    metadata = event.get("metadata", {})
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}
    return metadata if isinstance(metadata, dict) else {}


def _extract_live_event_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    metadata = _event_metadata_dict(event)
    bytes_value = (
        event.get("bytes")
        or event.get("payload_length")
        or metadata.get("bytes")
        or metadata.get("payload_length")
        or metadata.get("bytes_transferred")
    )
    return {
        "src": _normalized_text(event.get("src")),
        "dst": _normalized_text(event.get("dst")),
        "event": _normalized_text(event.get("event")).upper(),
        "payload": _normalized_text(event.get("payload")),
        "attack_type": _normalized_text(event.get("attack_type") or metadata.get("attack_type")),
        "bytes": bytes_value,
        "dst_country": _normalized_text(event.get("dst_country") or metadata.get("dst_country")),
        "proto": _normalized_text(event.get("proto") or metadata.get("proto")),
        "ts": _normalized_text(event.get("ts")),
    }


def _is_beacon_transfer(src: str, dst: str) -> bool:
    return _normalized_agent_id(src) in _BEACON_TRANSFER_SRCS and _normalized_agent_id(dst) in _BEACON_TRANSFER_DSTS


def _is_beacon_exfil(event_type: str, dst: str) -> bool:
    return _normalized_text(event_type).upper() == "EXFIL" and bool(_BEACON_EXFIL_DST_RE.match(_normalized_text(dst)))


def _should_forward_to_beacon(event: Dict[str, Any]) -> bool:
    extracted = _extract_live_event_fields(event)
    if extracted["event"] in _C2_FORWARD_EVENTS:
        return True
    if extracted["event"] == "TRANSFER":
        return _is_beacon_transfer(extracted["src"], extracted["dst"])
    return _is_beacon_exfil(extracted["event"], extracted["dst"])


def _c2_beacon_event_type(event_name: str) -> str:
    if event_name in ("C2_EXFIL", "C2_DATABASE_WRITE"):
        return "alert"
    if event_name == "C2_CHANNEL_ESTABLISHED":
        return "trigger"
    if event_name == "C2_BEACON":
        return "heartbeat"
    if event_name == "EXFIL":
        return "alert"
    return "trigger"


async def _forward_to_beacon(event: Dict[str, Any]) -> None:
    global _beacon_client
    if _beacon_client is None:
        return

    extracted = _extract_live_event_fields(event)
    beacon_event_type = _c2_beacon_event_type(extracted["event"])
    parts = [f"[{extracted['event']}] {extracted['src'] or 'unknown'} -> {extracted['dst']}"]
    if extracted["bytes"] not in (None, "", 0, "0"):
        parts.append(f"bytes={extracted['bytes']}")
    if extracted["dst_country"]:
        parts.append(f"country={extracted['dst_country']}")
    if extracted["proto"]:
        parts.append(f"proto={extracted['proto']}")
    if extracted["attack_type"]:
        parts.append(f"attack={extracted['attack_type']}")
    parts.append(f"ts={extracted['ts']}")

    try:
        response = await _beacon_client.post(
            f"{BEACON_SERVER_URL}/api/beacon/log",
            json={
                "device_id": extracted["src"] or "unknown",
                "event_type": beacon_event_type,
                "rssi": -70,
                "payload": {
                    "raw": extracted["payload"][:2000],
                    "event": extracted["event"],
                    "src": extracted["src"],
                    "dst": extracted["dst"],
                    "attack_type": extracted["attack_type"],
                    "bytes": extracted["bytes"],
                    "proto": extracted["proto"],
                    "dst_country": extracted["dst_country"],
                    "ts": extracted["ts"],
                },
                "message": " | ".join(parts),
            },
            timeout=5.0,
        )
        if response.status_code >= 400:
            uvicorn_logger.warning(
                "beacon_log_forward_failed status=%s body=%s",
                response.status_code,
                response.text[:500],
            )
    except Exception:
        uvicorn_logger.warning("beacon_log_forward_exception", exc_info=True)


def _beacon_client_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if _VERCEL_BYPASS_SECRET:
        headers["x-vercel-protection-bypass"] = _VERCEL_BYPASS_SECRET
    return headers


async def _register_beacon_devices() -> None:
    global _beacon_client
    if _beacon_client is None:
        _beacon_client = httpx.AsyncClient(timeout=10.0, headers=_beacon_client_headers())

    agent_defs = _beacon_device_definitions()
    pending = list(agent_defs)

    for attempt in range(1, _BEACON_REGISTRATION_RETRY_LIMIT + 1):
        pending = await _register_beacon_devices_once(pending)
        if not pending:
            uvicorn_logger.info(
                "beacon_device_registration_complete total=%s attempts=%s",
                len(agent_defs),
                attempt,
            )
            return
        delay_s = min(_BEACON_REGISTRATION_BASE_DELAY_S * attempt, 15.0)
        uvicorn_logger.warning(
            "beacon_device_registration_retry pending=%s attempt=%s/%s delay_s=%.1f devices=%s",
            len(pending),
            attempt,
            _BEACON_REGISTRATION_RETRY_LIMIT,
            delay_s,
            ",".join(definition["device_id"] for definition in pending),
        )
        await asyncio.sleep(delay_s)

    if pending:
        uvicorn_logger.error(
            "beacon_device_registration_incomplete pending=%s devices=%s",
            len(pending),
            ",".join(definition["device_id"] for definition in pending),
        )


def _beacon_device_definitions() -> List[Dict[str, str]]:
    agent_defs = [
        {"device_id": "agent-a", "name": "Guardian (agent-a)", "type": "defender", "location": "SUBNET-ALPHA"},
        {"device_id": "agent-b", "name": "Analyst (agent-b)", "type": "relay", "location": "SUBNET-BETA"},
        {"device_id": "agent-c", "name": "Courier (agent-c)", "type": "attacker", "location": "SUBNET-ALPHA"},
    ]
    for index in range(1, 10):
        agent_defs.append(
            {
                "device_id": f"agt-{index:03d}",
                "name": f"Synthetic AGT-{index:03d}",
                "type": "synthetic",
                "location": "SIMNET",
            }
        )
    return agent_defs


async def _register_beacon_devices_once(agent_defs: List[Dict[str, str]]) -> List[Dict[str, str]]:
    global _beacon_client
    if _beacon_client is None:
        _beacon_client = httpx.AsyncClient(timeout=10.0, headers=_beacon_client_headers())

    failed: List[Dict[str, str]] = []
    for definition in agent_defs:
        try:
            response = await _beacon_client.post(
                f"{BEACON_SERVER_URL}/api/beacon/register",
                json={**definition, "metadata": {"sim": "epidemic-lab"}},
                timeout=5.0,
            )
            if response.status_code >= 400:
                failed.append(definition)
                uvicorn_logger.warning(
                    "beacon_device_registration_failed device_id=%s status=%s body=%s",
                    definition["device_id"],
                    response.status_code,
                    response.text[:500],
                )
            else:
                uvicorn_logger.info("beacon_device_registered device_id=%s", definition["device_id"])
        except Exception:
            failed.append(definition)
            uvicorn_logger.warning(
                "beacon_device_registration_exception device_id=%s",
                definition["device_id"],
                exc_info=True,
            )
    return failed


def _log_api_timing(
    endpoint: str,
    *,
    query: str,
    time_range: str,
    result_count: int,
    elapsed_ms: float,
) -> None:
    payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "query": query,
        "time_range": time_range,
        "result_count": result_count,
        "elapsed_ms": round(elapsed_ms, 2),
    }
    encoded = json.dumps(payload, ensure_ascii=True)
    uvicorn_logger.info("siem_timing %s", encoded)
    try:
        SIEM_TIMING_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with SIEM_TIMING_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(encoded + "\n")
    except Exception:
        uvicorn_logger.warning("siem_timing_file_write_failed")


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
    c2_engine.reset()
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
    asyncio.create_task(_register_beacon_devices())
    asyncio.create_task(consume_events(start_id))


@app.on_event("shutdown")
async def shutdown_event():
    global _beacon_client
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
    if _beacon_client is not None:
        await _beacon_client.aclose()
        _beacon_client = None


async def consume_events(start_id: str):
    last_id = start_id
    while True:
        try:
            result = await redis_client.xread({EVENT_STREAM_KEY: last_id}, count=100, block=1000)
            if not result:
                # Tick C2 engine during idle periods
                if c2_engine.enabled:
                    await c2_engine.tick()
                continue
            for _stream_name, messages in result:
                for message_id, message_data in messages:
                    if "ts" not in message_data:
                        continue
                    logger.log_event(message_data)
                    if _should_forward_to_beacon(message_data):
                        asyncio.create_task(_forward_to_beacon(dict(message_data)))
                    # C2: trigger post-compromise on successful infection
                    event_name = str(message_data.get("event", "")).upper()
                    if event_name == "INFECTION_SUCCESSFUL" and c2_engine.enabled:
                        asyncio.create_task(c2_engine.on_infection_successful(dict(message_data)))
                    last_id = message_id
                siem_indexer.sync_primary_events()
            # Tick C2 engine after processing batch
            if c2_engine.enabled:
                await c2_engine.tick()
        except Exception as exc:
            print(f"Error consuming events: {exc}")
            await asyncio.sleep(1)


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    index_path = FRONTEND_DIST_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    if LEGACY_DASHBOARD_PATH.exists():
        return HTMLResponse(content=LEGACY_DASHBOARD_PATH.read_text(encoding="utf-8"))
    raise HTTPException(status_code=503, detail="Dashboard frontend is not built")


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
    started = time.perf_counter()
    try:
        payload = siem_indexer.search(
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
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/search",
            query=payload.get("structured_query", q),
            time_range=time_range,
            result_count=int(payload.get("total", 0)),
            elapsed_ms=elapsed_ms,
        )
        return payload
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/live")
async def api_live(after_id: int = 0, limit: int = 100, q: str = ""):
    try:
        return siem_indexer.live(after_id=after_id, limit=limit, query=q)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
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


@app.get("/api/validate-query")
async def api_validate_query(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.validate_query(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/query-help")
async def api_query_help():
    try:
        return siem_indexer.query_help()
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
    started = time.perf_counter()
    try:
        payload = siem_indexer.patterns(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/patterns",
            query=payload.get("structured_query", q),
            time_range=time_range,
            result_count=int(len(payload.get("pattern_cards", []))),
            elapsed_ms=elapsed_ms,
        )
        return payload
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/trace/{event_id}")
async def api_trace(event_id: str):
    started = time.perf_counter()
    try:
        payload = siem_indexer.trace(event_id)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/trace",
            query=event_id,
            time_range="trace_scope",
            result_count=int(payload.get("summary", {}).get("total_events", 0)),
            elapsed_ms=elapsed_ms,
        )
        return payload
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


@app.get("/api/event/{event_id}")
async def api_event_detail(event_id: str, include_full_payload: bool = False):
    try:
        return siem_indexer.event_detail(event_id, include_full_payload=include_full_payload)
    except KeyError:
        raise HTTPException(status_code=404, detail="Event not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/related/{event_id}")
async def api_related(event_id: str):
    started = time.perf_counter()
    try:
        payload = siem_indexer.related(event_id)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/related",
            query=event_id,
            time_range="related_scope",
            result_count=int(sum(payload.get("summary", {}).values())),
            elapsed_ms=elapsed_ms,
        )
        return payload
    except KeyError:
        raise HTTPException(status_code=404, detail="Event not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/payload-lineage/{payload_hash}")
async def api_payload_lineage(payload_hash: str):
    try:
        return siem_indexer.payload_lineage(payload_hash)
    except KeyError:
        raise HTTPException(status_code=404, detail="Payload hash not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/payload-lineage/by-injection/{injection_id}")
async def api_payload_lineage_by_injection(injection_id: str):
    try:
        return siem_indexer.payload_lineage_by_injection(injection_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Injection not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/payload-lineage/by-campaign/{campaign_id}")
async def api_payload_lineage_by_campaign(campaign_id: str):
    try:
        return siem_indexer.payload_lineage_by_campaign(campaign_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Campaign not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/mutation-analytics")
async def api_mutation_analytics(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.mutation_analytics(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/strategy-analytics")
async def api_strategy_analytics(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.strategy_analytics(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/campaign/{campaign_id}")
async def api_campaign(campaign_id: str):
    try:
        return siem_indexer.campaign(campaign_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Campaign not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/campaigns")
async def api_campaigns(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.campaigns(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/payload-families")
async def api_payload_families(
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.payload_families(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/decision-support")
async def api_decision_support(
    event_id: str = "",
    payload_hash: str = "",
    injection_id: str = "",
    campaign_id: str = "",
    q: str = "",
    mode: str = "structured",
    time_range: str = "all",
    start_ts: str = "",
    end_ts: str = "",
):
    try:
        return siem_indexer.decision_support(
            event_id=event_id,
            payload_hash=payload_hash,
            injection_id=injection_id,
            campaign_id=campaign_id,
            query=q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="Decision-support context not found")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/decision-summary/{event_id}")
async def api_decision_summary(event_id: str):
    try:
        return siem_indexer.decision_summary(event_id)
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
    started = time.perf_counter()
    try:
        payload = siem_indexer.hints(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/hints",
            query=payload.get("structured_query", q),
            time_range=time_range,
            result_count=int(len(payload.get("hints", []))),
            elapsed_ms=elapsed_ms,
        )
        return payload
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
    started = time.perf_counter()
    try:
        payload = siem_indexer.stats_presets(
            q,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
            compare_q=compare_q,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        payload["elapsed_ms"] = round(elapsed_ms, 2)
        _log_api_timing(
            "/api/stats/presets",
            query=q,
            time_range=time_range,
            result_count=int(payload.get("primary", {}).get("attempts", 0)),
            elapsed_ms=elapsed_ms,
        )
        return payload
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/health")
async def api_health():
    try:
        return siem_indexer.health()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ════════════════════════════════════════════════════════════════════════════
# C2 / KILL CHAIN API ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════


@app.get("/api/c2/sessions")
async def api_c2_sessions(
    campaign_id: str = "",
    agent_id: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
):
    return c2_engine.get_sessions(
        campaign_id=campaign_id,
        agent_id=agent_id,
        status=status,
        limit=min(limit, 500),
        offset=offset,
    )


@app.get("/api/c2/session/{c2_session_id}")
async def api_c2_session_detail(c2_session_id: str):
    detail = c2_engine.get_session_detail(c2_session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="C2 session not found")

    # Enrich beacon history with SIEM-persisted blocked beacons for this session
    blocked_beacons_result = siem_indexer.search(
        f"event=BEACON_BLOCKED AND c2_session_id={c2_session_id}",
        limit=200, time_range="all",
    )
    for ev in blocked_beacons_result.get("events", []):
        meta = ev.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        detail["beacons"].append({
            "beacon_id": meta.get("beacon_id", ev.get("event_id", "")),
            "ts": float(ev.get("ts") or 0),
            "status": "blocked",
            "blocked_by": meta.get("blocked_by", ""),
        })

    # Enrich exfil history with SIEM-persisted blocked exfils for this session
    blocked_exfils_result = siem_indexer.search(
        f"event=EXFIL_BLOCKED AND c2_session_id={c2_session_id}",
        limit=200, time_range="all",
    )
    for ev in blocked_exfils_result.get("events", []):
        meta = ev.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        detail["exfils"].append({
            "exfil_id": meta.get("exfil_id", ev.get("event_id", "")),
            "ts": float(ev.get("ts") or 0),
            "status": "blocked",
            "exfil_type": meta.get("exfil_type", ""),
            "exfil_size": meta.get("exfil_size", 0),
            "blocked_by": meta.get("blocked_by", ""),
        })

    # Sort enriched histories by ts
    detail["beacons"].sort(key=lambda x: x.get("ts", 0))
    detail["exfils"].sort(key=lambda x: x.get("ts", 0))
    return detail


@app.get("/api/c2/beacons")
async def api_c2_beacons(
    campaign_id: str = "",
    agent_id: str = "",
    limit: int = 100,
    offset: int = 0,
):
    # Successful beacons from in-memory sessions
    sessions = c2_engine.get_sessions(campaign_id=campaign_id, agent_id=agent_id, limit=500)
    all_beacons = []
    for sess_data in sessions.get("sessions", []):
        sess = c2_engine.sessions.get(sess_data["c2_session_id"])
        if sess:
            for b in sess.beacons:
                all_beacons.append({
                    **b,
                    "status": "success",
                    "agent_id": sess.agent_id,
                    "campaign_id": sess.campaign_id,
                    "c2_session_id": sess.c2_session_id,
                })

    # Blocked beacons from persisted SIEM events
    q_parts = ["event=BEACON_BLOCKED"]
    if campaign_id:
        q_parts.append(f"campaign_id={campaign_id}")
    if agent_id:
        q_parts.append(f"src={agent_id}")
    siem_result = siem_indexer.search(" AND ".join(q_parts), limit=500, time_range="all")
    for ev in siem_result.get("events", []):
        meta = ev.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        all_beacons.append({
            "beacon_id": meta.get("beacon_id", ev.get("event_id", "")),
            "ts": float(ev.get("ts") or 0),
            "status": "blocked",
            "agent_id": ev.get("src", ""),
            "campaign_id": meta.get("campaign_id", ""),
            "c2_session_id": meta.get("c2_session_id", ""),
            "blocked_by": meta.get("blocked_by", ""),
        })

    all_beacons.sort(key=lambda x: x.get("ts", 0), reverse=True)
    total = len(all_beacons)
    return {"total": total, "beacons": all_beacons[offset:offset + min(limit, 500)]}


@app.get("/api/c2/exfil")
async def api_c2_exfil(
    campaign_id: str = "",
    agent_id: str = "",
    limit: int = 100,
    offset: int = 0,
):
    # Successful exfils from in-memory sessions
    sessions = c2_engine.get_sessions(campaign_id=campaign_id, agent_id=agent_id, limit=500)
    all_exfils = []
    for sess_data in sessions.get("sessions", []):
        sess = c2_engine.sessions.get(sess_data["c2_session_id"])
        if sess:
            for e in sess.exfils:
                all_exfils.append({
                    **e,
                    "status": "success",
                    "agent_id": sess.agent_id,
                    "campaign_id": sess.campaign_id,
                    "c2_session_id": sess.c2_session_id,
                })

    # Blocked exfils from persisted SIEM events
    q_parts = ["event=EXFIL_BLOCKED"]
    if campaign_id:
        q_parts.append(f"campaign_id={campaign_id}")
    if agent_id:
        q_parts.append(f"src={agent_id}")
    siem_result = siem_indexer.search(" AND ".join(q_parts), limit=500, time_range="all")
    for ev in siem_result.get("events", []):
        meta = ev.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        all_exfils.append({
            "exfil_id": meta.get("exfil_id", ev.get("event_id", "")),
            "ts": float(ev.get("ts") or 0),
            "status": "blocked",
            "agent_id": ev.get("src", ""),
            "campaign_id": meta.get("campaign_id", ""),
            "c2_session_id": meta.get("c2_session_id", ""),
            "exfil_type": meta.get("exfil_type", ""),
            "exfil_size": meta.get("exfil_size", 0),
            "blocked_by": meta.get("blocked_by", ""),
        })

    all_exfils.sort(key=lambda x: x.get("ts", 0), reverse=True)
    total = len(all_exfils)
    return {"total": total, "exfils": all_exfils[offset:offset + min(limit, 500)]}


@app.get("/api/kill-chain")
async def api_kill_chain(campaign_id: str = ""):
    return c2_engine.get_kill_chain_summary(campaign_id=campaign_id)


@app.get("/api/kill-chain/campaign/{campaign_id}")
async def api_kill_chain_campaign(campaign_id: str):
    return c2_engine.get_kill_chain_summary(campaign_id=campaign_id)


@app.get("/api/objectives")
async def api_objectives(campaign_id: str = ""):
    return c2_engine.get_objectives(campaign_id=campaign_id)


@app.get("/api/objective/{campaign_id}")
async def api_objective_campaign(campaign_id: str):
    return c2_engine.get_objectives(campaign_id=campaign_id)


@app.get("/api/c2/metrics")
async def api_c2_metrics():
    return c2_engine.get_live_metrics()


@app.get("/api/runs")
async def api_runs():
    """List available soak runs from the logs directory, newest first."""
    logs_root = Path("/app/logs")
    runs = []
    for run_dir in sorted(logs_root.glob("soak_run_*")):
        if not run_dir.is_dir():
            continue
        run_id = run_dir.name
        summary_path = run_dir / "summary.json"
        events_path = run_dir / "all_events.jsonl"
        summary: Dict[str, Any] = {}
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        event_count = 0
        if events_path.exists():
            try:
                event_count = sum(1 for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip())
            except Exception:
                pass
        runs.append({
            "id": run_id,
            "label": run_id.replace("_", " ").title(),
            "events_path": str(events_path),
            "has_events": events_path.exists(),
            "event_count": event_count,
            "start_time": summary.get("start_time", ""),
            "end_time": summary.get("end_time", ""),
            "status": summary.get("status", "unknown"),
            "block_ratio": summary.get("block_ratio", None),
            "total_injections": summary.get("total_injections", None),
        })
    return {"runs": list(reversed(runs))}


@app.post("/api/import")
async def api_import(payload: ImportPayload):
    try:
        source = payload.source.lower()
        if source == "jsonl":
            import_path = _validated_import_path(payload.path)
            return siem_indexer.import_jsonl(
                str(import_path),
                source_type="jsonl_log",
                source_name=payload.source_name or import_path.name,
            )
        if source == "runtime_log":
            import_path = _validated_import_path(payload.path)
            return siem_indexer.import_jsonl(
                str(import_path),
                source_type="agent_runtime_log",
                source_name=payload.source_name or import_path.name,
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
    except HTTPException:
        raise
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
    from scenarios.worm_injection import get_attack_strength, get_worm_payload

    agent_id = _validated_agent_id(agent_id)
    worm = get_worm_payload(payload.worm_level)
    injection_id = os.urandom(8).hex()
    epoch = await _get_current_epoch()
    reset_id = await _get_current_reset_id()
    attack_strength = get_attack_strength(payload.worm_level)
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
    await redis_client.publish(_agent_channel_name(agent_id), json.dumps(msg))

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
    agent_id = _validated_agent_id(agent_id)
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
    await redis_client.publish(_agent_channel_name(agent_id), json.dumps(msg))

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
        timeout_s=RESET_ACK_TIMEOUT_S,
    )

    if not barrier_complete:
        await redis_client.xadd(
            EVENT_STREAM_KEY,
            {
                "ts": str(time.time()),
                "src": "orchestrator",
                "dst": "all",
                "event": "RESET_TIMEOUT",
                "metadata": json.dumps(
                    {
                        "epoch": int(new_epoch),
                        "reset_id": reset_id,
                        "acknowledged_agents": acknowledged_agents,
                        "heartbeat_agents": heartbeat_agents,
                        "bleed_through_detected": bleed_through,
                        "timeout_s": RESET_ACK_TIMEOUT_S,
                    }
                ),
            },
        )

    c2_engine.reset()

    return {
        "status": "reset_issued",
        "epoch": int(new_epoch),
        "reset_id": reset_id,
        "acknowledged_agents": acknowledged_agents,
        "heartbeat_agents": heartbeat_agents,
        "barrier_complete": barrier_complete,
        "bleed_through_detected": bleed_through,
        "quiet_period_s": RESET_QUIET_PERIOD_S,
        "ack_timeout_s": RESET_ACK_TIMEOUT_S,
    }


@app.post("/vaccine")
async def apply_vaccine():
    epoch = await _get_current_epoch()
    reset_id = await _get_current_reset_id()
    vaccine_id = os.urandom(8).hex()
    metadata = {
        "source_plane": "control",
        "action": "vaccine",
        "duration_s": 120,
        "defense_boost": 0.4,
        "vaccine_id": vaccine_id,
        "epoch": epoch,
        "reset_id": reset_id,
    }
    msg = {
        "id": vaccine_id,
        "src": "orchestrator",
        "dst": "broadcast",
        "event_type": "vaccine",
        "payload": "",
        "metadata": metadata,
    }

    await redis_client.publish("broadcast", json.dumps(msg))
    await redis_client.xadd(
        EVENT_STREAM_KEY,
        {
            "ts": str(time.time()),
            "src": "orchestrator",
            "dst": "all",
            "event": "VACCINE_ISSUED",
            "state_after": "vaccinated",
            "metadata": json.dumps(metadata),
        },
    )
    return {
        "status": "vaccine_applied",
        "vaccine_id": vaccine_id,
        "duration_s": 120,
        "defense_boost": 0.4,
        "epoch": epoch,
        "reset_id": reset_id,
    }
