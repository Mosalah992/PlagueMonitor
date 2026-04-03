import json
import os
import re
import sqlite3
import hashlib
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from payload_decode import decode_payload
except ImportError:  # pragma: no cover - test/runtime import path split
    from orchestrator.payload_decode import decode_payload
try:
    from intelligence import (
        build_campaign_view,
        build_decision_support,
        build_mutation_analytics,
        build_payload_families,
        build_reasoning_context,
        build_strategy_analytics,
        list_campaigns,
        parse_timestamp as intel_parse_timestamp,
        stable_unique,
    )
except ImportError:  # pragma: no cover - test/runtime import path split
    from orchestrator.intelligence import (
        build_campaign_view,
        build_decision_support,
        build_mutation_analytics,
        build_payload_families,
        build_reasoning_context,
        build_strategy_analytics,
        list_campaigns,
        parse_timestamp as intel_parse_timestamp,
        stable_unique,
    )

class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:  # type: ignore[override]
        try:
            super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()
        return False


def _normalize_payload_text(payload: Any) -> str:
    if payload in (None, ""):
        return ""
    text = str(payload).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def hash_payload(payload: Any) -> str:
    text = _normalize_payload_text(payload)
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def short_payload_hash(full_hash: str, length: int = 12) -> str:
    return str(full_hash or "")[:length]


def build_payload_preview(payload: Any, max_len: int = 200) -> str:
    text = _normalize_payload_text(payload)
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    clipped = text[: max(0, max_len - 3)].rstrip()
    return f"{clipped}..."


SEARCHABLE_FIELDS = {
    "event_id": "event_id",
    "ts": "ts",
    "source_type": "source_type",
    "source_name": "source_name",
    "src": "src",
    "dst": "dst",
    "event": "event",
    "attack_type": "attack_type",
    "attack_strength": "attack_strength",
    "mutation_v": "mutation_v",
    "hop_count": "hop_count",
    "state_before": "state_before",
    "state_after": "state_after",
    "reset_id": "reset_id",
    "epoch": "epoch",
    "injection_id": "injection_id",
    "source_plane": "source_plane",
    "parse_error": "parse_error",
    "payload_hash": "payload_hash",
    "parent_payload_hash": "parent_payload_hash",
    "payload_preview": "payload_preview",
    "decoded_payload_preview": "decoded_payload_preview",
    "payload_length": "payload_length",
    "semantic_family": "semantic_family",
    "has_payload": "has_payload",
    "has_decoded_payload": "has_decoded_payload",
    "decode_status": "decode_status",
    "decode_chain": "decode_chain",
    "decode_confidence": "decode_confidence",
    "payload_prefix_tag": "payload_prefix_tag",
    "payload_wrapper_type": "payload_wrapper_type",
}
METADATA_ALIASES = {
    "campaign_id": "$.campaign_id",
    "strategy_family": "$.strategy_family",
    "chosen_strategy": "$.chosen_strategy",
    "technique": "$.technique",
    "mutation_type": "$.mutation_type",
    "target": "$.target",
    "score": "$.score",
    "knowledge_source": "$.knowledge_source",
    "knowledge_version": "$.knowledge_version",
    "knowledge_confidence": "$.knowledge_confidence",
    "objective": "$.objective",
    "previous_objective": "$.previous_objective",
    "rationale": "$.rationale",
    "semantic_family": "$.semantic_family",
    "inferred_target_resistance": "$.inferred_target_resistance",
    "prior_success_rate": "$.prior_success_rate",
    "knowledge_attack_type": "$.knowledge_attack_type",
    "payload_hash_full": "$.payload_hash_full",
    "parent_payload_hash_full": "$.parent_payload_hash_full",
    "payload_source": "$.payload_source",
    "payload_visibility_level": "$.payload_visibility_level",
    "runtime_override": "$.runtime_override",
    "outcome": "$.outcome",
    "preferred_strategy": "$.preferred_strategy",
    "preferred_mutation_family": "$.preferred_mutation_family",
    "strategy_weight_after": "$.strategy_weight_after",
    "mutation_weight_after": "$.mutation_weight_after",
    "attack_strategy": "$.attack_strategy",
    "defense_type": "$.defense_type",
    "trigger_family": "$.trigger_family",
    "selected_strategy": "$.selected_strategy",
    "defense_strategy": "$.defense_strategy",
    "defense_confidence": "$.defense_confidence",
    "defense_result": "$.defense_result",
    "defense_effectiveness": "$.defense_effectiveness",
    "defense_adaptation": "$.defense_adaptation",
    "dynamic_defense": "$.dynamic_defense",
    "defense_tier": "$.defense_tier",
    "hardening_effect": "$.hardening_effect",
    "inferred_risk": "$.inferred_risk",
    "anomaly_score": "$.anomaly_score",
    "repetition_score": "$.repetition_score",
    "weight_change": "$.weight_change",
    "rejection_reason": "$.rejection_reason",
    "retry_count": "$.retry_count",
    "fallback_used": "$.fallback_used",
    "model_name": "$.model_name",
    "decision_rationale": "$.decision_rationale",
    "uncertainty_reason": "$.uncertainty_reason",
    "uncertainty_level": "$.uncertainty_level",
    "semantic_decision_path": "$.semantic_decision_path",
}

TEXT_COLUMNS = ("event", "src", "dst", "attack_type", "payload", "payload_preview", "decoded_payload_preview", "decode_status", "decode_chain", "payload_wrapper_type", "payload_prefix_tag", "raw_event", "reset_id", "injection_id")
NUMERIC_FIELDS = {"attack_strength", "mutation_v", "hop_count", "epoch", "knowledge_confidence", "inferred_target_resistance", "prior_success_rate", "score", "payload_length", "has_payload", "has_decoded_payload", "decode_confidence", "strategy_weight_after", "mutation_weight_after", "defense_confidence", "defense_effectiveness", "dynamic_defense", "defense_tier", "hardening_effect", "inferred_risk", "anomaly_score", "repetition_score", "weight_change", "retry_count"}
FIELD_SIDEBAR_FIELDS = ("event", "src", "dst", "attack_type", "state_after", "reset_id", "epoch", "source_plane", "strategy_family", "technique", "campaign_id", "objective", "semantic_family", "mutation_type", "decode_status", "payload_wrapper_type", "knowledge_source", "defense_type", "selected_strategy", "defense_result")
FAST_TIMELINE_SAMPLE_LIMIT = 2000
FAST_FIELD_SAMPLE_LIMIT = 1500
AUTO_ANALYTICS_RESULT_THRESHOLD = 2000
PHASE3_ANALYTICS_LIMIT = 4000
PHASE3_CAMPAIGN_LIMIT = 3000
PHASE3_LINEAGE_EVENT_LIMIT = 2500
PHASE3_LINEAGE_HASH_LIMIT = 160
QUERY_HELP_EXAMPLES = {
    "infections": [
        "event=INFECTION_SUCCESSFUL AND dst=agent-a",
        "event=INFECTION_ATTEMPT AND attack_type=PI-ROLEPLAY",
    ],
    "mutations": [
        "mutation_v>=1 AND event=INFECTION_ATTEMPT",
        "mutation_type=reframe AND event=ATTACK_EXECUTED",
    ],
    "campaigns": [
        "campaign_id exists AND src=agent-c",
        "campaign_id=cmp_123456 AND event=CAMPAIGN_ADAPTED",
        "campaign_id=cmp_123456 AND objective contains \"REACH\"",
    ],
    "attacker_decisions": [
        "event=STRATEGY_SELECTED AND src=agent-c",
        "knowledge_source=\"Red Teaming AI\" AND event=ATTACKER_DECISION",
        "runtime_override=true AND event=ATTACK_RESULT_EVALUATED",
    ],
    "payloads": [
        "payload_hash=abc123def456",
        "parent_payload_hash=abc123def456 AND mutation_v>=1",
        "semantic_family=prompt_injection AND mutation_type=reframe",
        "payload_preview contains \"SIM_ATTACK\" AND has_payload=1",
        "decoded_payload_preview contains \"instruction_override\" AND has_decoded_payload=1",
        "decode_chain contains \"rot13\" AND decode_status=full",
    ],
    "soc_workflows": [
        "event=INFECTION_BLOCKED AND inferred_target_resistance>=0.8",
        "event=ATTACK_RESULT_EVALUATED AND rationale contains \"override\"",
        "event=DEFENSE_RESULT_EVALUATED AND defense_result=blocked",
        "defense_type exists AND defense_strategy=multi_layer_check",
    ],
    "phase3_presets": [
        "event=ATTACK_EXECUTED AND mutation_type exists",
        "campaign_id exists AND event=CAMPAIGN_ADAPTED",
        "payload_hash exists AND parent_payload_hash exists",
        "event=STRATEGY_SELECTED AND technique exists",
    ],
}
ATTACK_TYPE_SYNONYMS = {
    "roleplay": "PI-ROLEPLAY",
    "jailbreak": "PI-JAILBREAK",
    "direct": "PI-DIRECT",
}
EVENT_SYNONYMS = {
    "successful": "INFECTION_SUCCESSFUL",
    "success": "INFECTION_SUCCESSFUL",
    "blocked": "INFECTION_BLOCKED",
    "failed": "INFECTION_BLOCKED",
    "heartbeat": "HEARTBEAT",
    "attempt": "INFECTION_ATTEMPT",
    "suppression": "PROPAGATION_SUPPRESSED",
}
SUCCESS_EVENTS = {"INFECTION_SUCCESSFUL"}
BLOCK_EVENTS = {"INFECTION_BLOCKED", "PROPAGATION_SUPPRESSED", "STALE_EVENT_DROPPED"}
TERMINAL_EVENTS = {
    "INFECTION_SUCCESSFUL",
    "INFECTION_BLOCKED",
    "PROPAGATION_SUPPRESSED",
    "STALE_EVENT_DROPPED",
    "QUARANTINE_ISSUED",
}
MUTATION_EVENTS = {"MUTATION_CREATED", "INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
ATTEMPT_EVENTS = {"WRM-INJECT", "INFECTION_ATTEMPT", "ATTACK_EXECUTED"}
DECISION_EVENTS = {
    "ATTACKER_DECISION",
    "ATTACK_EXECUTED",
    "ATTACK_RESULT_EVALUATED",
    "STRATEGY_SELECTED",
    "TARGET_SCORED",
    "TECHNIQUE_SELECTED",
    "MUTATION_SELECTED",
    "CAMPAIGN_ADAPTED",
    "CAMPAIGN_OBJECTIVE_SET",
    "RECON_PROBE",
}
STRATEGY_PHASE_MAP = {
    "RECON_PROBE": "exploration",
    "DIRECT_OVERRIDE": "exploitation",
    "ROLEPLAY_MANIPULATION": "exploitation",
    "JAILBREAK_ESCALATION": "escalation",
}
TARGET_CONTEXT = {
    "agent-a": {"depth": 3},
    "agent-b": {"depth": 2},
    "agent-c": {"depth": 1},
}
PHASE3_PRESET_QUERIES = [
    {"id": "successful_mutation_families", "label": "Successful mutation families", "query": "mutation_type exists AND event=INFECTION_SUCCESSFUL", "context": "search"},
    {"id": "failed_mutation_families", "label": "Failed mutation families", "query": "mutation_type exists AND event=INFECTION_BLOCKED", "context": "search"},
    {"id": "deepest_lineage", "label": "Payloads with deepest lineage", "query": "payload_hash exists AND mutation_v>=2", "context": "search"},
    {"id": "reused_multi_agent", "label": "Payloads reused across multiple agents", "query": "payload_hash exists AND event!=HEARTBEAT", "context": "search"},
    {"id": "strategy_shifts", "label": "Strategy shifts over time", "query": "event=STRATEGY_SELECTED AND strategy_family exists", "context": "search"},
    {"id": "campaign_objective_changes", "label": "Campaign objective changes", "query": "event=CAMPAIGN_ADAPTED OR event=CAMPAIGN_OBJECTIVE_SET", "context": "search"},
    {"id": "techniques_by_target", "label": "Techniques by target", "query": "technique exists AND dst exists AND event=ATTACK_EXECUTED", "context": "search"},
    {"id": "current_injection_lineage", "label": "Payload lineage for current injection", "query": "injection_id exists AND payload_hash exists", "context": "investigation"},
    {"id": "successful_payload_families", "label": "Most successful payload families", "query": "semantic_family exists AND event=INFECTION_SUCCESSFUL", "context": "search"},
    {"id": "blocked_payload_families", "label": "Most blocked payload families", "query": "semantic_family exists AND event=INFECTION_BLOCKED", "context": "search"},
    {"id": "knowledge_decisions", "label": "Knowledge-informed attacker decisions", "query": "knowledge_source exists AND event=ATTACKER_DECISION", "context": "search"},
    {"id": "runtime_overrides", "label": "Runtime overrides of prior knowledge", "query": "runtime_override=true AND event=ATTACK_RESULT_EVALUATED", "context": "search"},
    {"id": "effective_defenses", "label": "Most effective defenses", "query": "event=DEFENSE_RESULT_EVALUATED AND defense_result=blocked", "context": "search"},
    {"id": "failed_defenses", "label": "Failed defenses", "query": "event=DEFENSE_RESULT_EVALUATED AND defense_result=success", "context": "search"},
    {"id": "defense_vs_mutation", "label": "Defense vs mutation analysis", "query": "event=DEFENSE_RESULT_EVALUATED AND defense_type exists AND mutation_type exists", "context": "search"},
    {"id": "defense_vs_strategy", "label": "Defense vs strategy analysis", "query": "event=DEFENSE_RESULT_EVALUATED AND defense_type exists AND attack_strategy exists", "context": "search"},
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: Any) -> Optional[datetime]:
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


def _coerce_number(value: Any, number_type: type) -> Any:
    if value in (None, ""):
        return None
    try:
        return number_type(value)
    except (TypeError, ValueError):
        return None


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, default=str)


def _payload_hash(value: Any) -> str:
    return short_payload_hash(hash_payload(value))


def _safe_load_json(value: Any) -> Tuple[Dict[str, Any], Optional[str]]:
    if value is None:
        return {}, None
    if isinstance(value, dict):
        return value, None
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}, None
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            return {"_raw_metadata": value}, f"metadata_parse_error: {exc.msg}"
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except json.JSONDecodeError:
                return {"_raw_metadata": parsed}, "metadata_parse_error: nested metadata string"
        if not isinstance(parsed, dict):
            return {"_value": parsed}, "metadata_parse_error: metadata did not normalize to object"
        return parsed, None
    return {"_value": str(value)}, "metadata_parse_error: unsupported metadata type"


def _metadata_path(field: str) -> Optional[str]:
    if field in METADATA_ALIASES:
        return METADATA_ALIASES[field]
    if field.startswith("metadata.") and len(field) > len("metadata."):
        return "$." + field[len("metadata."):].replace(".", ".")
    if field.startswith("raw_event.") and len(field) > len("raw_event."):
        return "$." + field[len("raw_event."):].replace(".", ".")
    return None


def _metadata_value(event: Dict[str, Any], key: str, default: Any = "") -> Any:
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        return metadata.get(key, default)
    return default


def _stable_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(value)


def _stable_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _safe_ratio(numerator: Any, denominator: Any) -> float:
    num = float(numerator or 0.0)
    den = float(denominator or 0.0)
    if den <= 0:
        return 0.0
    return round(num / den, 4)


def _bucket_timestamp(ts_value: Any, *, span_seconds: float) -> str:
    ts = _parse_timestamp(ts_value)
    if ts is None:
        return ""
    if span_seconds <= 3600:
        return ts.replace(minute=ts.minute - (ts.minute % 5), second=0, microsecond=0).isoformat()
    if span_seconds <= 86400:
        return ts.replace(minute=0, second=0, microsecond=0).isoformat()
    return ts.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def _normalized_payload_pattern(value: Any) -> str:
    text = _normalize_payload_text(value).lower()
    if not text:
        return ""
    text = re.sub(r"[0-9a-f]{8,64}", "<hex>", text)
    text = re.sub(r"\b\d+\b", "<n>", text)
    text = re.sub(r"\s+", " ", text)
    return text[:160]


@dataclass
class QueryPlan:
    where_sql: str
    params: List[Any]
    structured_query: str


class SIEMIndexer:
    def __init__(self, db_path: str, jsonl_path: str, source_db_path: Optional[str] = None):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self.source_db_path = source_db_path or db_path
        self._repairing_index = False
        self._sync_lock = threading.Lock()
        self._last_sync_time: float = 0.0
        self._sync_cooldown_s: float = float(os.environ.get("SIEM_SYNC_COOLDOWN_S", "5"))
        self._query_timeout_s: float = float(os.environ.get("SIEM_QUERY_TIMEOUT_S", "20"))
        self._init_db()
        self.ensure_index_health()

    def _connect(self, query_timeout_s: float = 0) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=ClosingConnection, timeout=30.0)
        conn.row_factory = sqlite3.Row
        if query_timeout_s > 0:
            deadline = time.monotonic() + query_timeout_s
            def _check_timeout() -> int:
                return 1 if time.monotonic() > deadline else 0
            conn.set_progress_handler(_check_timeout, 1000)
        return conn

    def _connect_source(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.source_db_path, factory=ClosingConnection, timeout=30.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS siem_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    raw_source_id INTEGER,
                    ts TEXT,
                    source_type TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    src TEXT,
                    dst TEXT,
                    event TEXT,
                    attack_type TEXT,
                    payload TEXT,
                    metadata TEXT NOT NULL,
                    attack_strength REAL,
                    mutation_v INTEGER,
                    hop_count INTEGER,
                    state_before TEXT,
                    state_after TEXT,
                    reset_id TEXT,
                    epoch INTEGER,
                    injection_id TEXT,
                    source_plane TEXT,
                    payload_hash TEXT,
                    parent_payload_hash TEXT,
                    payload_preview TEXT,
                    decoded_payload_preview TEXT,
                    payload_length INTEGER,
                    semantic_family TEXT,
                    mutation_type TEXT,
                    has_decoded_payload INTEGER NOT NULL DEFAULT 0,
                    decode_status TEXT,
                    decode_chain TEXT,
                    decode_confidence REAL,
                    payload_prefix_tag TEXT,
                    payload_wrapper_type TEXT,
                    has_payload INTEGER NOT NULL DEFAULT 0,
                    raw_event TEXT NOT NULL,
                    parse_error TEXT,
                    indexed_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS siem_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_ts ON siem_events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_event ON siem_events(event)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_src ON siem_events(src)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_src_dst ON siem_events(src, dst)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_dst ON siem_events(dst)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_attack_type ON siem_events(attack_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_reset_id ON siem_events(reset_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_epoch ON siem_events(epoch)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_reset_epoch ON siem_events(reset_id, epoch)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_injection ON siem_events(injection_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_event_ts ON siem_events(event, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_src_ts ON siem_events(src, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_dst_ts ON siem_events(dst, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_attack_type_ts ON siem_events(attack_type, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_injection_ts ON siem_events(injection_id, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_reset_id_ts ON siem_events(reset_id, ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_epoch_ts ON siem_events(epoch, ts)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_event_dst_attack_ts ON siem_events(event, dst, attack_type, ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_terminal_join ON siem_events(src, dst, hop_count, ts, event, injection_id)"
            )
            existing_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(siem_events)").fetchall()
            }
            if "payload_hash" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_hash TEXT DEFAULT ''")
            if "parent_payload_hash" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN parent_payload_hash TEXT DEFAULT ''")
            if "payload_preview" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_preview TEXT DEFAULT ''")
            if "decoded_payload_preview" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN decoded_payload_preview TEXT DEFAULT ''")
            if "payload_length" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_length INTEGER DEFAULT 0")
            if "semantic_family" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN semantic_family TEXT DEFAULT ''")
            if "mutation_type" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN mutation_type TEXT DEFAULT ''")
            if "has_decoded_payload" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN has_decoded_payload INTEGER DEFAULT 0")
            if "decode_status" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN decode_status TEXT DEFAULT ''")
            if "decode_chain" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN decode_chain TEXT DEFAULT '[]'")
            if "decode_confidence" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN decode_confidence REAL DEFAULT 0")
            if "payload_prefix_tag" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_prefix_tag TEXT DEFAULT ''")
            if "payload_wrapper_type" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_wrapper_type TEXT DEFAULT ''")
            if "has_payload" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN has_payload INTEGER DEFAULT 0")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_payload_hash ON siem_events(payload_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_parent_payload_hash ON siem_events(parent_payload_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_semantic_family ON siem_events(semantic_family)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_mutation_type ON siem_events(mutation_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_decode_status ON siem_events(decode_status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_payload_wrapper_type ON siem_events(payload_wrapper_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_payload_length ON siem_events(payload_length)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_campaign_id ON siem_events(json_extract(metadata, '$.campaign_id'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_strategy_family ON siem_events(json_extract(metadata, '$.strategy_family'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_technique ON siem_events(json_extract(metadata, '$.technique'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_objective ON siem_events(json_extract(metadata, '$.objective'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_knowledge_source ON siem_events(json_extract(metadata, '$.knowledge_source'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_defense_type ON siem_events(json_extract(metadata, '$.defense_type'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_selected_strategy ON siem_events(json_extract(metadata, '$.selected_strategy'))"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_meta_defense_result ON siem_events(json_extract(metadata, '$.defense_result'))"
            )
            conn.execute(
                """
                UPDATE siem_events
                SET mutation_type = COALESCE(NULLIF(json_extract(metadata, '$.mutation_type'), ''), mutation_type)
                WHERE mutation_type = ''
                  AND json_valid(metadata)
                  AND json_extract(metadata, '$.mutation_type') IS NOT NULL
                """
            )

    def _should_repair(self, exc: Exception) -> bool:
        message = str(exc).lower()
        return "malformed" in message or "disk image is malformed" in message

    def _should_fallback_to_jsonl(self, exc: Exception) -> bool:
        message = str(exc).lower()
        transient_source_failures = (
            "unable to open database file",
            "database is locked",
            "readonly database",
        )
        return any(token in message for token in transient_source_failures)

    def _rebuild_index_tables(self) -> None:
        if self._repairing_index:
            raise RuntimeError("siem index repair already in progress")
        self._repairing_index = True
        try:
            with self._connect() as conn:
                conn.execute("DROP TABLE IF EXISTS siem_events")
                conn.execute("DROP TABLE IF EXISTS siem_state")
            self._init_db()
        finally:
            self._repairing_index = False

    def ensure_index_health(self) -> None:
        try:
            with self._connect() as conn:
                conn.execute("SELECT COUNT(*) FROM siem_events").fetchone()
                conn.execute("SELECT COUNT(*) FROM siem_events WHERE json_valid(metadata)").fetchone()
                conn.execute("SELECT COUNT(*) FROM siem_state").fetchone()
        except sqlite3.DatabaseError as exc:
            if not self._should_repair(exc):
                raise
            self._rebuild_index_tables()

    def _get_state(self, conn: sqlite3.Connection, key: str, default: str = "0") -> str:
        row = conn.execute("SELECT value FROM siem_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def _set_state(self, conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO siem_state(key, value) VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _normalize_event(
        self,
        raw_event: Dict[str, Any],
        *,
        source_type: str,
        source_name: str,
        raw_source_id: Optional[int] = None,
        fallback_event_id: str,
    ) -> Dict[str, Any]:
        metadata, parse_error = _safe_load_json(raw_event.get("metadata"))
        payload_text = str(raw_event.get("payload", ""))
        payload_hash_full = str(
            raw_event.get("payload_hash_full")
            or metadata.get("payload_hash_full")
            or hash_payload(payload_text)
        )
        payload_hash = str(
            raw_event.get("payload_hash")
            or metadata.get("payload_hash")
            or short_payload_hash(payload_hash_full)
        )
        parent_payload_hash_full = str(
            raw_event.get("parent_payload_hash_full")
            or metadata.get("parent_payload_hash_full")
            or ""
        )
        parent_payload_hash = str(
            raw_event.get("parent_payload_hash")
            or metadata.get("parent_payload_hash")
            or short_payload_hash(parent_payload_hash_full)
        )
        payload_preview = str(
            raw_event.get("payload_preview")
            or metadata.get("payload_preview")
            or build_payload_preview(payload_text)
        )
        payload_length = _coerce_number(
            raw_event.get("payload_length", metadata.get("payload_length", len(payload_text))),
            int,
        )
        semantic_family = str(
            raw_event.get("semantic_family")
            or metadata.get("semantic_family")
            or ""
        )
        mutation_type = str(
            raw_event.get("mutation_type")
            or metadata.get("mutation_type")
            or ""
        )
        state_before = raw_event.get("state_before") or raw_event.get("old_state") or metadata.get("state_before") or ""
        state_after = (
            raw_event.get("state_after")
            or raw_event.get("new_state")
            or raw_event.get("state")
            or metadata.get("state_after")
            or ""
        )
        decode_result = decode_payload(payload_text, max_preview_len=200)
        if not semantic_family and decode_result.get("normalized_semantic_family"):
            semantic_family = str(decode_result["normalized_semantic_family"])
        return {
            "event_id": str(raw_event.get("event_id") or raw_event.get("id") or fallback_event_id),
            "raw_source_id": raw_source_id,
            "ts": str(raw_event.get("ts") or raw_event.get("timestamp") or _utc_now_iso()),
            "source_type": source_type,
            "source_name": source_name,
            "src": str(raw_event.get("src", "")),
            "dst": str(raw_event.get("dst", "")),
            "event": str(raw_event.get("event", raw_event.get("event_type", ""))),
            "attack_type": str(raw_event.get("attack_type", metadata.get("attack_type", ""))),
            "payload": payload_text,
            "metadata": _json_dumps(metadata),
            "attack_strength": _coerce_number(raw_event.get("attack_strength", metadata.get("attack_strength")), float),
            "mutation_v": _coerce_number(raw_event.get("mutation_v", metadata.get("mutation_v")), int),
            "hop_count": _coerce_number(raw_event.get("hop_count", metadata.get("hop_count")), int),
            "state_before": str(state_before),
            "state_after": str(state_after),
            "reset_id": str(raw_event.get("reset_id", metadata.get("reset_id", "")) or ""),
            "epoch": _coerce_number(raw_event.get("epoch", metadata.get("epoch")), int),
            "injection_id": str(
                raw_event.get("injection_id")
                or metadata.get("injection_id")
                or metadata.get("attempt_id")
                or ""
            ),
            "source_plane": str(raw_event.get("source_plane", metadata.get("source_plane", "")) or ""),
            "payload_hash": payload_hash,
            "parent_payload_hash": parent_payload_hash,
            "payload_preview": payload_preview,
            "decoded_payload_preview": str(
                raw_event.get("decoded_payload_preview")
                or metadata.get("decoded_payload_preview")
                or decode_result.get("decoded_preview", "")
            ),
            "payload_length": int(payload_length or 0),
            "semantic_family": semantic_family,
            "mutation_type": mutation_type,
            "has_decoded_payload": 1 if decode_result.get("decode_applied") else 0,
            "decode_status": str(raw_event.get("decode_status") or metadata.get("decode_status") or decode_result.get("decode_status", "none")),
            "decode_chain": _json_dumps(raw_event.get("decode_chain") or metadata.get("decode_chain") or decode_result.get("decode_chain", [])),
            "decode_confidence": float(raw_event.get("decode_confidence") or metadata.get("decode_confidence") or decode_result.get("decode_confidence", 0.0) or 0.0),
            "payload_prefix_tag": str(raw_event.get("payload_prefix_tag") or metadata.get("payload_prefix_tag") or decode_result.get("prefix_tag", "")),
            "payload_wrapper_type": str(raw_event.get("payload_wrapper_type") or metadata.get("payload_wrapper_type") or decode_result.get("wrapper_type", "")),
            "has_payload": 1 if payload_text else 0,
            "raw_event": _json_dumps(raw_event),
            "parse_error": parse_error or "",
            "indexed_at": _utc_now_iso(),
        }

    def _insert_event(self, conn: sqlite3.Connection, normalized: Dict[str, Any]) -> None:
        conn.execute(
            """
            INSERT OR REPLACE INTO siem_events (
                event_id, raw_source_id, ts, source_type, source_name, src, dst, event,
                attack_type, payload, metadata, attack_strength, mutation_v, hop_count,
                state_before, state_after, reset_id, epoch, injection_id, source_plane, payload_hash,
                parent_payload_hash, payload_preview, decoded_payload_preview, payload_length, semantic_family, mutation_type,
                has_decoded_payload, decode_status, decode_chain, decode_confidence, payload_prefix_tag, payload_wrapper_type, has_payload,
                raw_event, parse_error, indexed_at
            ) VALUES (
                :event_id, :raw_source_id, :ts, :source_type, :source_name, :src, :dst, :event,
                :attack_type, :payload, :metadata, :attack_strength, :mutation_v, :hop_count,
                :state_before, :state_after, :reset_id, :epoch, :injection_id, :source_plane, :payload_hash,
                :parent_payload_hash, :payload_preview, :decoded_payload_preview, :payload_length, :semantic_family, :mutation_type,
                :has_decoded_payload, :decode_status, :decode_chain, :decode_confidence, :payload_prefix_tag, :payload_wrapper_type, :has_payload,
                :raw_event, :parse_error, :indexed_at
            )
            """,
            normalized,
        )

    def sync_primary_events(self, limit: int = 2000, force: bool = False) -> Dict[str, Any]:
        now = time.monotonic()
        if not force and (now - self._last_sync_time) < self._sync_cooldown_s:
            return {"status": "skipped_cooldown", "inserted": 0}
        with self._sync_lock:
            result = self._sync_primary_events_locked(limit=limit)
            self._last_sync_time = time.monotonic()
            return result

    def _sync_primary_events_locked(self, limit: int = 2000) -> Dict[str, Any]:
        inserted = 0
        last_raw_id = 0
        try:
            with self._connect() as conn:
                while True:
                    checkpoint = int(self._get_state(conn, "events_table_checkpoint", "0") or 0)
                    with self._connect_source() as source_conn:
                        rows = source_conn.execute(
                            """
                            SELECT id, timestamp, src_agent, dst_agent, event_type, attack_type,
                                   payload, mutation_v, agent_state, metadata
                            FROM events
                            WHERE id > ?
                            ORDER BY id ASC
                            LIMIT ?
                            """,
                            (checkpoint, limit),
                        ).fetchall()
                    if not rows:
                        break
                    for row in rows:
                        raw_event = {
                            "id": f"events:{row['id']}",
                            "ts": row["timestamp"],
                            "src": row["src_agent"],
                            "dst": row["dst_agent"],
                            "event": row["event_type"],
                            "attack_type": row["attack_type"],
                            "payload": row["payload"],
                            "mutation_v": row["mutation_v"],
                            "state_after": row["agent_state"],
                            "metadata": row["metadata"],
                        }
                        normalized = self._normalize_event(
                            raw_event,
                            source_type="orchestrator_api",
                            source_name="/events",
                            raw_source_id=int(row["id"]),
                            fallback_event_id=f"events:{row['id']}",
                        )
                        self._insert_event(conn, normalized)
                        inserted += 1
                        last_raw_id = int(row["id"])
                    if last_raw_id:
                        self._set_state(conn, "events_table_checkpoint", str(last_raw_id))
                    if len(rows) < limit:
                        break
            return {"inserted": inserted, "last_raw_id": last_raw_id}
        except sqlite3.DatabaseError as exc:
            if self._should_fallback_to_jsonl(exc):
                return self._sync_jsonl_events_locked(limit=limit)
            if self._should_repair(exc):
                return self._sync_jsonl_events_locked(limit=limit)
            raise

    def sync_jsonl_events(self, limit: int = 5000) -> Dict[str, Any]:
        with self._sync_lock:
            return self._sync_jsonl_events_locked(limit=limit)

    def _sync_jsonl_events_locked(self, limit: int = 5000) -> Dict[str, Any]:
        imported = 0
        last_offset = 0
        path = Path(self.jsonl_path)
        if not path.exists():
            return {"imported": 0, "last_offset": 0}
        with self._connect() as conn, path.open("r", encoding="utf-8", errors="replace") as handle:
            checkpoint = int(self._get_state(conn, "jsonl_checkpoint", "0") or 0)
            if checkpoint > 0:
                handle.seek(checkpoint)
            while imported < limit:
                offset = handle.tell()
                line = handle.readline()
                if not line:
                    last_offset = handle.tell()
                    break
                stripped = line.strip()
                if not stripped:
                    last_offset = handle.tell()
                    continue
                try:
                    raw_event = json.loads(stripped)
                except json.JSONDecodeError:
                    raw_event = {
                        "event": "LOG_LINE",
                        "payload": stripped,
                        "metadata": {
                            "parse_error": "json_line_parse_error",
                            "offset": offset,
                        },
                    }
                normalized = self._normalize_event(
                    raw_event,
                    source_type="jsonl_logs",
                    source_name=path.name,
                    raw_source_id=None,
                    fallback_event_id=f"{path.name}:{offset}",
                )
                self._insert_event(conn, normalized)
                imported += 1
                last_offset = handle.tell()
            if last_offset:
                self._set_state(conn, "jsonl_checkpoint", str(last_offset))
        return {"imported": imported, "last_offset": last_offset}

    def import_jsonl(self, path: str, *, source_type: str, source_name: Optional[str] = None) -> Dict[str, Any]:
        resolved = Path(path)
        if not resolved.exists():
            raise FileNotFoundError(path)
        imported = 0
        with self._connect() as conn, resolved.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw_event = json.loads(stripped)
                except json.JSONDecodeError:
                    raw_event = {
                        "event": "LOG_LINE",
                        "payload": stripped,
                        "metadata": {
                            "line_number": line_number,
                            "parse_error": "json_line_parse_error",
                        },
                    }
                normalized = self._normalize_event(
                    raw_event,
                    source_type=source_type,
                    source_name=source_name or resolved.name,
                    raw_source_id=None,
                    fallback_event_id=f"{resolved.name}:{line_number}",
                )
                self._insert_event(conn, normalized)
                imported += 1
        return {"imported": imported, "path": str(resolved)}

    async def import_redis_stream(
        self,
        redis_client: Any,
        *,
        stream_name: str = "events_stream",
        count: int = 500,
    ) -> Dict[str, Any]:
        entries = await redis_client.xrevrange(stream_name, count=count)
        imported = 0
        with self._connect() as conn:
            for stream_id, payload in reversed(entries):
                normalized = self._normalize_event(
                    dict(payload),
                    source_type="redis_stream",
                    source_name=stream_name,
                    raw_source_id=None,
                    fallback_event_id=f"{stream_name}:{stream_id}",
                )
                self._insert_event(conn, normalized)
                imported += 1
        return {"imported": imported, "stream_name": stream_name}

    def _normalize_query(self, query: str, mode: str) -> str:
        if mode != "natural":
            return query.strip()

        lowered = query.lower()
        fragments: List[str] = []
        for word, event_name in EVENT_SYNONYMS.items():
            if word in lowered:
                fragments.append(f"event={event_name}")
        for word, attack_type in ATTACK_TYPE_SYNONYMS.items():
            if word in lowered:
                fragments.append(f"attack_type={attack_type}")
        for agent_id in ("agent-a", "agent-b", "agent-c"):
            if agent_id in lowered:
                if any(token in lowered for token in (f"to {agent_id}", f"on {agent_id}", f"against {agent_id}")):
                    fragments.append(f"dst={agent_id}")
                elif f"from {agent_id}" in lowered:
                    fragments.append(f"src={agent_id}")
                else:
                    fragments.append(f"dst={agent_id}")
        if "last hour" in lowered:
            fragments.append("time=last_1h")
        if "last 24" in lowered or "last day" in lowered:
            fragments.append("time=last_24h")
        remaining_tokens = [
            token for token in re.findall(r"[a-z0-9_-]+", lowered)
            if token not in {
                "successful", "success", "blocked", "failed", "roleplay", "jailbreak",
                "direct", "on", "to", "from", "against", "last", "hour", "day", "24",
                "agent-a", "agent-b", "agent-c", "attacks", "attack", "infections", "infection",
            }
        ]
        fragments.extend(remaining_tokens)
        return " AND ".join(fragments)

    def _tokenize_query(self, query: str) -> List[str]:
        if not query.strip():
            return []
        pattern = re.compile(
            r'"[^"]*"|'
            r"'[^']*'|"
            r"\([A-Za-z0-9_-]+\)|"
            r"\(|\)|>=|<=|!=|=|>|<|:|~|"
            r"\bAND\b|\bOR\b|\bNOT\b|\bexists\b|\bmissing\b|\bcontains\b|"
            r"[A-Za-z0-9_.*:-]+",
            re.IGNORECASE,
        )
        return [token for token in pattern.findall(query) if token and not token.isspace()]

    def _field_expression(self, field: str) -> Tuple[Optional[str], str]:
        field_name = SEARCHABLE_FIELDS.get(field)
        if field_name:
            return field_name, "column"
        metadata_path = _metadata_path(field)
        if metadata_path:
            source_column = "raw_event" if field.startswith("raw_event.") else "metadata"
            return (
                f"CASE WHEN json_valid({source_column}) "
                f"THEN json_extract({source_column}, '{metadata_path}') ELSE NULL END",
                "json",
            )
        return None, ""

    def _sql_string_expr(self, expr: str) -> str:
        return f"COALESCE(CAST({expr} AS TEXT), '')"

    def _value_is_empty(self, value: str) -> bool:
        return value.strip().lower() in {"(empty)", "empty", "null"}

    def _compile_field_exists(self, field: str, *, missing: bool = False) -> Tuple[str, List[Any]]:
        expr, expr_type = self._field_expression(field)
        if not expr:
            sql = "1=0" if not missing else "1=1"
            return sql, []
        if expr_type == "json":
            path = _metadata_path(field) or "$"
            source_column = "raw_event" if field.startswith("raw_event.") else "metadata"
            sql = (
                f"CASE WHEN json_valid({source_column}) "
                f"THEN json_type({source_column}, '{path}') ELSE NULL END "
                f"IS {'NULL' if missing else 'NOT NULL'}"
            )
            return sql, []
        sql = f"NULLIF(TRIM({self._sql_string_expr(expr)}), '') IS {'NULL' if missing else 'NOT NULL'}"
        return sql, []

    def _compile_field_compare(self, field: str, operator: str, raw_value: str) -> Tuple[str, List[Any]]:
        expr, expr_type = self._field_expression(field)
        if not expr:
            return "1=0", []
        value = raw_value.strip().strip('"').strip("'")
        if field in NUMERIC_FIELDS:
            numeric_value = _coerce_number(value, float if field == "attack_strength" else int)
            if numeric_value is None:
                return "1=0", []
            sql_operator = "=" if operator == ":" else operator
            return f"{expr} {sql_operator} ?", [numeric_value]
        if operator in {"=", ":", "!=", "~"}:
            if self._value_is_empty(value):
                if operator == "!=":
                    return f"NULLIF(TRIM({self._sql_string_expr(expr)}), '') IS NOT NULL", []
                return f"NULLIF(TRIM({self._sql_string_expr(expr)}), '') IS NULL", []
            if operator == "~" or "*" in value:
                like_value = value.replace("*", "%")
                comparator = "NOT LIKE" if operator == "!=" else "LIKE"
                return f"LOWER({self._sql_string_expr(expr)}) {comparator} LOWER(?)", [like_value]
            comparator = "!=" if operator == "!=" else "="
            if expr_type == "column":
                return f"{expr} {comparator} ?", [value]
            return f"{self._sql_string_expr(expr)} {comparator} ?", [value]
        return f"{expr} {operator} ?", [value]

    def _compile_contains(self, field: str, raw_value: str) -> Tuple[str, List[Any]]:
        expr, _ = self._field_expression(field)
        if not expr:
            return "1=0", []
        value = raw_value.strip().strip('"').strip("'")
        return f"LOWER({self._sql_string_expr(expr)}) LIKE LOWER(?)", [f"%{value}%"]

    def _compile_text_search(self, token: str) -> Tuple[str, List[Any]]:
        value = token.strip().strip('"').strip("'").lower()
        like_value = f"%{value}%"
        return (
            " OR ".join(f"LOWER({column}) LIKE ?" for column in TEXT_COLUMNS),
            [like_value] * len(TEXT_COLUMNS),
        )

    def _parse_query_tokens(self, tokens: List[str]) -> Tuple[Any, int]:
        def parse_expression(index: int = 0) -> Tuple[Any, int]:
            return parse_or(index)

        def parse_or(index: int) -> Tuple[Any, int]:
            node, index = parse_and(index)
            while index < len(tokens) and tokens[index].upper() == "OR":
                rhs, index = parse_and(index + 1)
                node = ("OR", node, rhs)
            return node, index

        def parse_and(index: int) -> Tuple[Any, int]:
            node, index = parse_not(index)
            while index < len(tokens):
                upper = tokens[index].upper()
                if upper == "OR" or tokens[index] == ")":
                    break
                if upper == "AND":
                    rhs, index = parse_not(index + 1)
                else:
                    rhs, index = parse_not(index)
                node = ("AND", node, rhs)
            return node, index

        def parse_not(index: int) -> Tuple[Any, int]:
            if index < len(tokens) and tokens[index].upper() == "NOT":
                child, next_index = parse_not(index + 1)
                return ("NOT", child), next_index
            return parse_primary(index)

        def parse_primary(index: int) -> Tuple[Any, int]:
            if index >= len(tokens):
                return ("TEXT", ""), index
            token = tokens[index]
            if token == "(":
                node, index = parse_expression(index + 1)
                if index < len(tokens) and tokens[index] == ")":
                    index += 1
                return node, index
            if (
                index + 1 < len(tokens)
                and re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", token)
                and tokens[index + 1].lower() in {"exists", "missing", "contains"}
            ):
                keyword = tokens[index + 1].lower()
                if keyword == "contains" and index + 2 < len(tokens):
                    return ("CONTAINS", token, tokens[index + 2]), index + 3
                return (keyword.upper(), token), index + 2
            if (
                index + 2 < len(tokens)
                and re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", token)
                and tokens[index + 1] in {">=", "<=", "!=", "=", ">", "<", ":", "~"}
            ):
                return ("COMPARE", token, tokens[index + 1], tokens[index + 2]), index + 3
            return ("TEXT", token), index + 1

        return parse_expression(0)

    def _validate_query_tokens(self, tokens: List[str]) -> None:
        if not tokens:
            return

        def is_field(token: str) -> bool:
            return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", token))

        def starts_operand(index: int) -> bool:
            if index >= len(tokens):
                return False
            token = tokens[index]
            upper = token.upper()
            if token == "(" or upper == "NOT":
                return True
            if token == ")":
                return False
            if (
                index + 1 < len(tokens)
                and is_field(token)
                and tokens[index + 1].lower() in {"exists", "missing", "contains"}
            ):
                if tokens[index + 1].lower() == "contains":
                    return index + 2 < len(tokens)
                return True
            if (
                index + 2 < len(tokens)
                and is_field(token)
                and tokens[index + 1] in {">=", "<=", "!=", "=", ">", "<", ":", "~"}
            ):
                return True
            return upper not in {"AND", "OR"}

        balance = 0
        index = 0
        expect_operand = True

        while index < len(tokens):
            token = tokens[index]
            upper = token.upper()

            if expect_operand:
                if token == "(":
                    balance += 1
                    index += 1
                    continue
                if upper == "NOT":
                    index += 1
                    continue
                if token == ")" or upper in {"AND", "OR"}:
                    raise ValueError(f"Unexpected token '{token}' in query")
                if (
                    index + 1 < len(tokens)
                    and is_field(token)
                    and tokens[index + 1].lower() in {"exists", "missing", "contains"}
                ):
                    keyword = tokens[index + 1].lower()
                    if keyword == "contains":
                        if index + 2 >= len(tokens):
                            raise ValueError(f"Missing value for contains expression on field '{token}'")
                        index += 3
                    else:
                        index += 2
                    expect_operand = False
                    continue
                if (
                    index + 1 < len(tokens)
                    and is_field(token)
                    and tokens[index + 1] in {">=", "<=", "!=", "=", ">", "<", ":", "~"}
                ):
                    if index + 2 >= len(tokens):
                        raise ValueError(f"Missing value for comparison on field '{token}'")
                    index += 3
                    expect_operand = False
                    continue
                index += 1
                expect_operand = False
                continue

            if upper in {"AND", "OR"}:
                expect_operand = True
                index += 1
                continue
            if token == ")":
                if balance <= 0:
                    raise ValueError("Unmatched closing parenthesis in query")
                balance -= 1
                index += 1
                continue
            if starts_operand(index):
                expect_operand = True
                continue
            raise ValueError(f"Unexpected token '{token}' in query")

        if expect_operand:
            raise ValueError("Query ends with an incomplete expression")
        if balance != 0:
            raise ValueError("Unmatched opening parenthesis in query")

    def _compile_query_node(self, node: Any) -> Tuple[str, List[Any]]:
        kind = node[0] if isinstance(node, tuple) else "TEXT"
        if kind == "AND":
            left_sql, left_params = self._compile_query_node(node[1])
            right_sql, right_params = self._compile_query_node(node[2])
            return f"({left_sql}) AND ({right_sql})", [*left_params, *right_params]
        if kind == "OR":
            left_sql, left_params = self._compile_query_node(node[1])
            right_sql, right_params = self._compile_query_node(node[2])
            return f"({left_sql}) OR ({right_sql})", [*left_params, *right_params]
        if kind == "NOT":
            child_sql, child_params = self._compile_query_node(node[1])
            return f"NOT ({child_sql})", child_params
        if kind == "COMPARE":
            return self._compile_field_compare(node[1], node[2], node[3])
        if kind == "EXISTS":
            return self._compile_field_exists(node[1], missing=False)
        if kind == "MISSING":
            return self._compile_field_exists(node[1], missing=True)
        if kind == "CONTAINS":
            return self._compile_contains(node[1], node[2])
        if kind == "TEXT":
            return self._compile_text_search(node[1])
        return "1=1", []

    def _time_sql(self, *, time_range: str, start_ts: str, end_ts: str) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        now = datetime.now(timezone.utc)
        if time_range == "last_15m":
            clauses.append("ts >= ?")
            params.append((now - timedelta(minutes=15)).isoformat())
        elif time_range == "last_1h":
            clauses.append("ts >= ?")
            params.append((now - timedelta(hours=1)).isoformat())
        elif time_range == "last_24h":
            clauses.append("ts >= ?")
            params.append((now - timedelta(hours=24)).isoformat())
        elif time_range == "last_7d":
            clauses.append("ts >= ?")
            params.append((now - timedelta(days=7)).isoformat())
        if start_ts:
            clauses.append("ts >= ?")
            params.append(start_ts)
        if end_ts:
            clauses.append("ts <= ?")
            params.append(end_ts)
        return " AND ".join(clauses), params

    def _build_query_plan(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> QueryPlan:
        structured_query = self._normalize_query(query, mode)
        tokens = self._tokenize_query(structured_query) if structured_query else []
        clauses: List[str] = []
        params: List[Any] = []
        parsed_tokens: List[str] = []
        index = 0
        while index < len(tokens):
            if (
                index + 2 < len(tokens)
                and re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", tokens[index])
                and tokens[index + 1] in {">=", "<=", "!=", "=", ">", "<", ":"}
                and tokens[index].lower() == "time"
            ):
                time_range = tokens[index + 2].strip().strip('"').strip("'")
                parsed_tokens.extend(tokens[index:index + 3])
                index += 3
                continue
            parsed_tokens.append(tokens[index])
            index += 1

        if parsed_tokens:
            self._validate_query_tokens(parsed_tokens)
            ast, _ = self._parse_query_tokens(parsed_tokens)
            sql, sql_params = self._compile_query_node(ast)
            clauses.append(f"({sql})")
            params.extend(sql_params)

        time_clauses, time_params = self._time_sql(
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        if time_clauses:
            if clauses:
                clauses.append("AND")
            clauses.append(f"({time_clauses})")
            params.extend(time_params)

        return QueryPlan(
            where_sql=" ".join(clauses) if clauses else "1=1",
            params=params,
            structured_query=structured_query,
        )

    def _row_to_event(self, row: sqlite3.Row, *, include_full_payload: bool = False) -> Dict[str, Any]:
        event = dict(row)
        event["metadata"] = _safe_load_json(event.get("metadata"))[0]
        event["raw_event"] = _safe_load_json(event.get("raw_event"))[0]
        event["has_payload"] = bool(event.get("has_payload"))
        event["has_decoded_payload"] = bool(event.get("has_decoded_payload"))
        if isinstance(event.get("decode_chain"), str):
            try:
                loaded_chain = json.loads(event.get("decode_chain") or "[]")
            except json.JSONDecodeError:
                loaded_chain = []
            event["decode_chain"] = loaded_chain if isinstance(loaded_chain, list) else []
        elif not isinstance(event.get("decode_chain"), list):
            event["decode_chain"] = []
        event["payload_text_available"] = bool(event.get("payload"))
        if include_full_payload:
            decode_result = decode_payload(event.get("payload", ""), max_preview_len=200)
            event["payload_text"] = event.get("payload", "")
            event["decoded_payload_text"] = decode_result.get("decoded_payload", "")
            event["decoded_payload_preview"] = str(event.get("decoded_payload_preview") or decode_result.get("decoded_preview", ""))
            event["decode_status"] = str(event.get("decode_status") or decode_result.get("decode_status", "none"))
            event["decode_chain"] = event.get("decode_chain") or decode_result.get("decode_chain", [])
            event["decode_confidence"] = float(event.get("decode_confidence") or decode_result.get("decode_confidence", 0.0) or 0.0)
            event["payload_prefix_tag"] = str(event.get("payload_prefix_tag") or decode_result.get("prefix_tag", ""))
            event["payload_wrapper_type"] = str(event.get("payload_wrapper_type") or decode_result.get("wrapper_type", ""))
            event["decode_warnings"] = decode_result.get("warnings", [])
            event["payload_full_hash"] = str(event["metadata"].get("payload_hash_full", ""))
            event["parent_payload_full_hash"] = str(event["metadata"].get("parent_payload_hash_full", ""))
        else:
            event.pop("payload", None)
            event["payload_text"] = ""
            event["decoded_payload_text"] = ""
            event["decode_warnings"] = []
            if isinstance(event.get("raw_event"), dict) and "payload" in event["raw_event"]:
                event["raw_event"] = {**event["raw_event"], "payload": "(hidden; fetch detail to reveal)"}
        return event

    def _fetch_events(
        self,
        plan: QueryPlan,
        *,
        limit: int = 200,
        offset: int = 0,
        sort_field: str = "ts",
        sort_dir: str = "DESC",
    ) -> Tuple[List[Dict[str, Any]], int]:
        order_field = SEARCHABLE_FIELDS.get(sort_field, "ts")
        order_dir = "ASC" if str(sort_dir).lower() == "asc" else "DESC"
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS count FROM siem_events WHERE {plan.where_sql}",
                plan.params,
            ).fetchone()["count"]
            rows = conn.execute(
                f"""
                SELECT *
                FROM siem_events
                WHERE {plan.where_sql}
                ORDER BY {order_field} {order_dir}, id DESC
                LIMIT ? OFFSET ?
                """,
                [*plan.params, limit, offset],
            ).fetchall()
        return [self._row_to_event(row) for row in rows], int(total or 0)

    def _sidebar_counts(self, plan: QueryPlan) -> Dict[str, List[Dict[str, Any]]]:
        output: Dict[str, List[Dict[str, Any]]] = {}
        with self._connect() as conn:
            for field in FIELD_SIDEBAR_FIELDS:
                expr, _ = self._field_expression(field)
                if not expr:
                    output[field] = []
                    continue
                rows = conn.execute(
                    f"""
                    SELECT value, COUNT(*) AS count
                    FROM (
                        SELECT {self._sql_string_expr(expr)} AS value
                        FROM siem_events
                        WHERE {plan.where_sql}
                        ORDER BY ts DESC
                        LIMIT {FAST_FIELD_SAMPLE_LIMIT}
                    ) sampled_events
                    GROUP BY value
                    ORDER BY count DESC, value ASC
                    LIMIT 8
                    """,
                    plan.params,
                ).fetchall()
                output[field] = [
                    {"value": row["value"] if row["value"] not in (None, "") else "(empty)", "count": row["count"]}
                    for row in rows
                ]
        return output

    def _timeline(self, plan: QueryPlan) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT ts FROM siem_events WHERE {plan.where_sql} ORDER BY ts ASC LIMIT {FAST_TIMELINE_SAMPLE_LIMIT}",
                plan.params,
            ).fetchall()
        timestamps = [_parse_timestamp(row["ts"]) for row in rows]
        timestamps = [ts for ts in timestamps if ts is not None]
        if not timestamps:
            return []
        start = min(timestamps)
        end = max(timestamps)
        span = max((end - start).total_seconds(), 1.0)
        bucket_count = 24
        counts = [0] * bucket_count
        labels = []
        for ts in timestamps:
            offset = (ts - start).total_seconds()
            index = min(bucket_count - 1, int((offset / span) * (bucket_count - 1)))
            counts[index] += 1
        for index in range(bucket_count):
            labels.append(
                (start + timedelta(seconds=(span * index / max(bucket_count - 1, 1)))).strftime("%H:%M:%S")
            )
        return [{"label": labels[index], "count": counts[index]} for index in range(bucket_count)]

    def _fetch_scope_rows(self, plan: QueryPlan, *, limit: int = 1200) -> List[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                f"SELECT * FROM siem_events WHERE {plan.where_sql} ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC LIMIT ?",
                [*plan.params, limit],
            ).fetchall()

    def _fetch_scope_total(self, plan: QueryPlan) -> int:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS count FROM siem_events WHERE {plan.where_sql}",
                plan.params,
            ).fetchone()
        return int(row["count"] or 0)

    def _scoped_events(
        self,
        plan: QueryPlan,
        *,
        limit: int = PHASE3_ANALYTICS_LIMIT,
        include_full_payload: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int, List[str]]:
        total = self._fetch_scope_total(plan)
        rows = self._fetch_scope_rows(plan, limit=limit)
        warnings: List[str] = []
        if total > limit:
            warnings.append(
                f"Analytics truncated to the first {limit} events in the current query scope. Narrow the search window for complete corpus coverage."
            )
        return [self._row_to_event(row, include_full_payload=include_full_payload) for row in rows], total, warnings

    def _event_outcome(self, event: Dict[str, Any]) -> str:
        event_name = _stable_text(event.get("event")).upper()
        metadata_outcome = _stable_text(_metadata_value(event, "outcome")).lower()
        if event_name in SUCCESS_EVENTS or metadata_outcome == "success":
            return "success"
        if event_name in BLOCK_EVENTS or metadata_outcome in {"blocked", "failure", "failed"}:
            return "blocked"
        return metadata_outcome

    def _event_phase(self, event: Dict[str, Any]) -> str:
        strategy_family = _stable_text(_metadata_value(event, "strategy_family")).upper()
        event_name = _stable_text(event.get("event")).upper()
        mutation_type = _stable_text(event.get("mutation_type")).lower()
        if event_name == "CAMPAIGN_ADAPTED":
            return "fallback"
        if strategy_family in STRATEGY_PHASE_MAP:
            return STRATEGY_PHASE_MAP[strategy_family]
        if mutation_type in {"reframe", "verbosity_shift", "context_wrap"}:
            return "exploration"
        if mutation_type in {"encoding", "obfuscation", "variable_rename"}:
            return "fallback"
        if event_name in {"INFECTION_SUCCESSFUL", "ATTACK_EXECUTED", "INFECTION_ATTEMPT"}:
            return "exploitation"
        return "exploration"

    def _attempt_key(self, event: Dict[str, Any]) -> str:
        for key in ("attempt_id", "injection_id"):
            value = _stable_text(_metadata_value(event, key))
            if value:
                return value
        return "::".join(
            [
                _stable_text(event.get("event_id")),
                _stable_text(event.get("payload_hash")),
                _stable_text(event.get("src")),
                _stable_text(event.get("dst")),
                _stable_text(event.get("mutation_v")),
            ]
        )

    def _collect_attempt_records(self, events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        attempts: Dict[str, Dict[str, Any]] = {}
        for event in sorted(events, key=lambda item: (_stable_text(item.get("ts")), _stable_text(item.get("event_id")))):
            _meta_raw = event.get("metadata")
            metadata: Dict[str, Any] = _meta_raw if isinstance(_meta_raw, dict) else {}
            attempt_key = self._attempt_key(event)
            record = attempts.setdefault(
                attempt_key,
                {
                    "attempt_id": attempt_key,
                    "campaign_id": "",
                    "injection_id": _stable_text(event.get("injection_id")),
                    "payload_hash": _stable_text(event.get("payload_hash")),
                    "parent_payload_hash": _stable_text(event.get("parent_payload_hash")),
                    "mutation_type": _stable_text(event.get("mutation_type") or metadata.get("mutation_type")),
                    "strategy_family": _stable_text(metadata.get("strategy_family")),
                    "technique": _stable_text(metadata.get("technique")),
                    "target": _stable_text(metadata.get("target") or event.get("dst")),
                    "src": _stable_text(event.get("src")),
                    "attack_type": _stable_text(event.get("attack_type") or metadata.get("attack_type")),
                    "semantic_family": _stable_text(event.get("semantic_family") or metadata.get("semantic_family")),
                    "payload_wrapper_type": _stable_text(event.get("payload_wrapper_type")),
                    "decode_status": _stable_text(event.get("decode_status")),
                    "decode_complexity": len(event.get("decode_chain") or [])
                    + (1 if _stable_text(event.get("payload_wrapper_type")) else 0)
                    + (1 if _stable_text(event.get("payload_prefix_tag")) else 0),
                    "mutation_v": event.get("mutation_v"),
                    "hop_count": event.get("hop_count"),
                    "attack_strength": event.get("attack_strength"),
                    "knowledge_confidence": _coerce_number(metadata.get("knowledge_confidence"), float),
                    "knowledge_source": _stable_text(metadata.get("knowledge_source")),
                    "prior_success_rate": _coerce_number(metadata.get("prior_success_rate"), float),
                    "inferred_target_resistance": _coerce_number(metadata.get("inferred_target_resistance"), float),
                    "score_breakdown": metadata.get("score_breakdown") if isinstance(metadata.get("score_breakdown"), dict) else {},
                    "rationale": _stable_text(metadata.get("rationale")),
                    "objective": _stable_text(metadata.get("objective")),
                    "outcome": "",
                    "ts_first": _stable_text(event.get("ts")),
                    "ts_last": _stable_text(event.get("ts")),
                    "events": [],
                    "phases": [],
                },
            )
            record["campaign_id"] = record["campaign_id"] or _stable_text(metadata.get("campaign_id"))
            record["injection_id"] = record["injection_id"] or _stable_text(event.get("injection_id")) or _stable_text(metadata.get("injection_id"))
            record["payload_hash"] = record["payload_hash"] or _stable_text(event.get("payload_hash"))
            record["parent_payload_hash"] = record["parent_payload_hash"] or _stable_text(event.get("parent_payload_hash"))
            record["mutation_type"] = record["mutation_type"] or _stable_text(event.get("mutation_type") or metadata.get("mutation_type"))
            record["strategy_family"] = record["strategy_family"] or _stable_text(metadata.get("strategy_family"))
            record["technique"] = record["technique"] or _stable_text(metadata.get("technique"))
            record["target"] = record["target"] or _stable_text(metadata.get("target") or event.get("dst"))
            record["semantic_family"] = record["semantic_family"] or _stable_text(event.get("semantic_family") or metadata.get("semantic_family"))
            record["payload_wrapper_type"] = record["payload_wrapper_type"] or _stable_text(event.get("payload_wrapper_type"))
            record["decode_status"] = record["decode_status"] or _stable_text(event.get("decode_status"))
            record["mutation_v"] = record["mutation_v"] if record["mutation_v"] is not None else event.get("mutation_v")
            record["hop_count"] = record["hop_count"] if record["hop_count"] is not None else event.get("hop_count")
            record["attack_strength"] = record["attack_strength"] if record["attack_strength"] is not None else event.get("attack_strength")
            record["knowledge_confidence"] = (
                record["knowledge_confidence"]
                if record["knowledge_confidence"] is not None
                else _coerce_number(metadata.get("knowledge_confidence"), float)
            )
            record["prior_success_rate"] = (
                record["prior_success_rate"]
                if record["prior_success_rate"] is not None
                else _coerce_number(metadata.get("prior_success_rate"), float)
            )
            record["inferred_target_resistance"] = (
                record["inferred_target_resistance"]
                if record["inferred_target_resistance"] is not None
                else _coerce_number(metadata.get("inferred_target_resistance"), float)
            )
            record["objective"] = record["objective"] or _stable_text(metadata.get("objective"))
            record["rationale"] = record["rationale"] or _stable_text(metadata.get("rationale"))
            record["ts_first"] = min(record["ts_first"], _stable_text(event.get("ts"))) if record["ts_first"] else _stable_text(event.get("ts"))
            record["ts_last"] = max(record["ts_last"], _stable_text(event.get("ts")))
            record["events"].append(
                {
                    "event_id": _stable_text(event.get("event_id")),
                    "event": _stable_text(event.get("event")),
                    "ts": _stable_text(event.get("ts")),
                }
            )
            phase = self._event_phase(event)
            if phase and phase not in record["phases"]:
                record["phases"].append(phase)
            outcome = self._event_outcome(event)
            if outcome == "success":
                record["outcome"] = "success"
            elif outcome == "blocked" and record["outcome"] != "success":
                record["outcome"] = "blocked"
        return list(attempts.values())

    def _canonical_parent_map(self, events: Sequence[Dict[str, Any]]) -> Dict[str, str]:
        parent_counts: Dict[str, Counter[str]] = defaultdict(Counter)
        first_seen: Dict[Tuple[str, str], str] = {}
        for event in events:
            child = _stable_text(event.get("payload_hash"))
            parent = _stable_text(event.get("parent_payload_hash"))
            if not child or not parent:
                continue
            parent_counts[child][parent] += 1
            first_seen.setdefault((child, parent), _stable_text(event.get("ts")))
        canonical: Dict[str, str] = {}
        for child, counter in parent_counts.items():
            canonical[child] = sorted(
                counter.items(),
                key=lambda item: (-item[1], first_seen.get((child, item[0]), ""), item[0]),
            )[0][0]
        return canonical

    def _payload_depths(self, events: Sequence[Dict[str, Any]]) -> Dict[str, int]:
        canonical_parent = self._canonical_parent_map(events)
        hashes = {hash_value for hash_value in canonical_parent.keys()} | {
            _stable_text(event.get("payload_hash")) for event in events if _stable_text(event.get("payload_hash"))
        }
        memo: Dict[str, int] = {}

        def depth(payload_hash: str, path: Optional[set[str]] = None) -> int:
            if not payload_hash:
                return 0
            if payload_hash in memo:
                return memo[payload_hash]
            path = set(path or set())
            if payload_hash in path:
                memo[payload_hash] = 0
                return 0
            path.add(payload_hash)
            parent = canonical_parent.get(payload_hash, "")
            if not parent:
                memo[payload_hash] = 0
                return 0
            if parent not in hashes:
                memo[payload_hash] = 1
                return 1
            memo[payload_hash] = 1 + depth(parent, path)
            return memo[payload_hash]

        for payload_hash in hashes:
            depth(payload_hash)
        return memo

    def _root_payload_hash(self, payload_hash: str, canonical_parent: Dict[str, str]) -> str:
        current = _stable_text(payload_hash)
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            parent = canonical_parent.get(current, "")
            if not parent:
                return current
            current = parent
        return payload_hash

    def _lineage_component(self, payload_hash: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        target_hash = _stable_text(payload_hash)
        warnings: List[str] = []
        if not target_hash:
            return [], ["Payload hash is required for lineage reconstruction."]
        known_hashes = {target_hash}
        frontier = {target_hash}
        rows: List[sqlite3.Row] = []
        with self._connect() as conn:
            while frontier and len(known_hashes) <= PHASE3_LINEAGE_HASH_LIMIT:
                placeholders = ",".join("?" for _ in frontier)
                frontier_values = list(frontier)
                rows = conn.execute(
                    f"""
                    SELECT *
                    FROM siem_events
                    WHERE payload_hash IN ({placeholders}) OR parent_payload_hash IN ({placeholders})
                    ORDER BY ts ASC, id ASC
                    LIMIT ?
                    """,
                    [*frontier_values, *frontier_values, PHASE3_LINEAGE_EVENT_LIMIT],
                ).fetchall()
                discovered: set[str] = set()
                for row in rows:
                    child = _stable_text(row["payload_hash"])
                    parent = _stable_text(row["parent_payload_hash"])
                    if child:
                        discovered.add(child)
                    if parent:
                        discovered.add(parent)
                new_hashes = {item for item in discovered if item and item not in known_hashes}
                if not new_hashes:
                    break
                known_hashes.update(new_hashes)
                frontier = new_hashes
            if len(known_hashes) > PHASE3_LINEAGE_HASH_LIMIT:
                warnings.append(
                    f"Lineage truncated after {PHASE3_LINEAGE_HASH_LIMIT} connected payload hashes. Narrow the scope for a complete graph."
                )
            placeholders = ",".join("?" for _ in known_hashes)
            rows = conn.execute(
                f"""
                SELECT *
                FROM siem_events
                WHERE payload_hash IN ({placeholders}) OR parent_payload_hash IN ({placeholders})
                ORDER BY ts ASC, id ASC
                LIMIT ?
                """,
                [*known_hashes, *known_hashes, PHASE3_LINEAGE_EVENT_LIMIT],
            ).fetchall()
        events = [self._row_to_event(row) for row in rows]
        if len(rows) >= PHASE3_LINEAGE_EVENT_LIMIT:
            warnings.append("Lineage event list reached the reconstruction limit; some descendants may be omitted.")
        return events, warnings

    def _lineage_nodes_and_edges(
        self,
        events: Sequence[Dict[str, Any]],
        *,
        target_hash: str,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str], Dict[str, int], List[str]]:
        warnings: List[str] = []
        canonical_parent = self._canonical_parent_map(events)
        depth_map = self._payload_depths(events)
        events_by_hash: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        missing_hashes: set[str] = set()
        for event in events:
            payload_hash = _stable_text(event.get("payload_hash"))
            if payload_hash:
                events_by_hash[payload_hash].append(event)
            parent_hash = _stable_text(event.get("parent_payload_hash"))
            if parent_hash and parent_hash not in events_by_hash:
                missing_hashes.add(parent_hash)
        nodes: List[Dict[str, Any]] = []
        for payload_hash, grouped in sorted(events_by_hash.items(), key=lambda item: item[0]):
            first_event = grouped[0]
            last_event = grouped[-1]
            semantic_counter = Counter(_stable_text(event.get("semantic_family")) for event in grouped if _stable_text(event.get("semantic_family")))
            mutation_counter = Counter(_stable_text(event.get("mutation_type")) for event in grouped if _stable_text(event.get("mutation_type")))
            decode_counter = Counter(_stable_text(event.get("decode_status")) for event in grouped if _stable_text(event.get("decode_status")))
            wrapper_counter = Counter(_stable_text(event.get("payload_wrapper_type")) for event in grouped if _stable_text(event.get("payload_wrapper_type")))
            campaigns = sorted({_stable_text(_metadata_value(event, "campaign_id")) for event in grouped if _stable_text(_metadata_value(event, "campaign_id"))})
            injections = sorted({_stable_text(event.get("injection_id")) for event in grouped if _stable_text(event.get("injection_id"))})
            node = {
                "payload_hash": payload_hash,
                "parent_payload_hash": canonical_parent.get(payload_hash, ""),
                "ts_first_seen": _stable_text(first_event.get("ts")),
                "ts_last_seen": _stable_text(last_event.get("ts")),
                "raw_preview": _stable_text(first_event.get("payload_preview")),
                "decoded_preview": next((_stable_text(event.get("decoded_payload_preview")) for event in grouped if _stable_text(event.get("decoded_payload_preview"))), ""),
                "semantic_family": semantic_counter.most_common(1)[0][0] if semantic_counter else "",
                "mutation_type": mutation_counter.most_common(1)[0][0] if mutation_counter else "",
                "mutation_v": max((int(event.get("mutation_v") or 0) for event in grouped), default=0),
                "decode_status": decode_counter.most_common(1)[0][0] if decode_counter else "",
                "wrapper_type": wrapper_counter.most_common(1)[0][0] if wrapper_counter else "",
                "source_agent": _stable_text(first_event.get("src")),
                "first_target": _stable_text(first_event.get("dst")),
                "event_count": len(grouped),
                "success_count": sum(1 for event in grouped if self._event_outcome(event) == "success"),
                "block_count": sum(1 for event in grouped if self._event_outcome(event) == "blocked"),
                "related_campaign_ids": campaigns,
                "related_injection_ids": injections,
                "lineage_depth": int(depth_map.get(payload_hash, 0)),
                "reused_across_agents": len(
                    {
                        agent
                        for event in grouped
                        for agent in (_stable_text(event.get("src")), _stable_text(event.get("dst")))
                        if agent
                    }
                ) > 2,
                "lineage_gap": bool(canonical_parent.get(payload_hash) and canonical_parent.get(payload_hash) not in events_by_hash),
                "is_current": payload_hash == target_hash,
            }
            nodes.append(node)
        for missing_hash in sorted(missing_hashes - set(events_by_hash.keys())):
            warnings.append(f"Lineage incomplete: missing parent payload {missing_hash}.")
            nodes.append(
                {
                    "payload_hash": missing_hash,
                    "parent_payload_hash": "",
                    "ts_first_seen": "",
                    "ts_last_seen": "",
                    "raw_preview": "",
                    "decoded_preview": "",
                    "semantic_family": "",
                    "mutation_type": "",
                    "mutation_v": 0,
                    "decode_status": "",
                    "wrapper_type": "",
                    "source_agent": "",
                    "first_target": "",
                    "event_count": 0,
                    "success_count": 0,
                    "block_count": 0,
                    "related_campaign_ids": [],
                    "related_injection_ids": [],
                    "lineage_depth": 0,
                    "reused_across_agents": False,
                    "lineage_gap": True,
                    "missing_node": True,
                    "is_current": False,
                }
            )
        edge_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        for event in events:
            parent = _stable_text(event.get("parent_payload_hash"))
            child = _stable_text(event.get("payload_hash"))
            if not parent or not child:
                continue
            mutation_type = _stable_text(event.get("mutation_type"))
            key = (parent, child, mutation_type)
            edge = edge_map.setdefault(
                key,
                {
                    "parent_payload_hash": parent,
                    "payload_hash": child,
                    "mutation_type": mutation_type,
                    "mutation_v_delta": None,
                    "first_seen": _stable_text(event.get("ts")),
                    "target_transition": _stable_text(event.get("dst")),
                    "event_count": 0,
                },
            )
            edge["event_count"] += 1
            edge["first_seen"] = min(edge["first_seen"], _stable_text(event.get("ts"))) if edge["first_seen"] else _stable_text(event.get("ts"))
            edge["target_transition"] = edge["target_transition"] or _stable_text(event.get("dst"))
            parent_v = next((node["mutation_v"] for node in nodes if node["payload_hash"] == parent), None)
            child_v = next((node["mutation_v"] for node in nodes if node["payload_hash"] == child), None)
            if parent_v is not None and child_v is not None:
                edge["mutation_v_delta"] = int(child_v) - int(parent_v)
        return (
            sorted(nodes, key=lambda item: (item.get("lineage_depth", 0), item.get("ts_first_seen", ""), item.get("payload_hash", ""))),
            sorted(edge_map.values(), key=lambda item: (item["first_seen"], item["parent_payload_hash"], item["payload_hash"])),
            canonical_parent,
            depth_map,
            warnings,
        )

    def _build_lineage_tree(self, nodes: Sequence[Dict[str, Any]], canonical_parent: Dict[str, str]) -> List[Dict[str, Any]]:
        node_map = {node["payload_hash"]: {**node, "children": []} for node in nodes}
        roots: List[Dict[str, Any]] = []
        for payload_hash, node in node_map.items():
            parent = canonical_parent.get(payload_hash, "")
            if parent and parent in node_map and parent != payload_hash:
                node_map[parent]["children"].append(node)
            else:
                roots.append(node)
        def sort_node(node: Dict[str, Any]) -> Dict[str, Any]:
            node["children"] = [sort_node(child) for child in sorted(node["children"], key=lambda item: (item.get("ts_first_seen", ""), item.get("payload_hash", "")))]
            return node
        return [sort_node(node) for node in sorted(roots, key=lambda item: (item.get("lineage_depth", 0), item.get("ts_first_seen", ""), item.get("payload_hash", "")))]

    def _previous_decision_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        campaign_id = _stable_text(_metadata_value(event, "campaign_id"))
        src = _stable_text(event.get("src"))
        ts = _stable_text(event.get("ts"))
        if not campaign_id or not src or not ts:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM siem_events
                WHERE src = ?
                  AND event IN ('ATTACKER_DECISION', 'STRATEGY_SELECTED', 'ATTACK_RESULT_EVALUATED', 'TARGET_SCORED', 'ATTACK_EXECUTED')
                  AND json_extract(metadata, '$.campaign_id') = ?
                  AND ts < ?
                ORDER BY ts DESC, id DESC
                LIMIT 1
                """,
                (src, campaign_id, ts),
            ).fetchone()
        return self._row_to_event(row) if row is not None else None

    def _decision_diff(self, event: Dict[str, Any], previous_event: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        current_strategy = _stable_text(_metadata_value(event, "strategy_family"))
        current_mutation = _stable_text(_metadata_value(event, "mutation_type") or event.get("mutation_type"))
        current_resistance = _coerce_number(_metadata_value(event, "inferred_target_resistance"), float)
        current_success_rate = _coerce_number(_metadata_value(event, "prior_success_rate"), float)
        if previous_event is None:
            return {
                "has_previous": False,
                "previous_event_id": "",
                "summary": "No prior attacker decision is available in the current campaign scope.",
                "changes": [],
            }
        previous_strategy = _stable_text(_metadata_value(previous_event, "strategy_family"))
        previous_mutation = _stable_text(_metadata_value(previous_event, "mutation_type") or previous_event.get("mutation_type"))
        previous_resistance = _coerce_number(_metadata_value(previous_event, "inferred_target_resistance"), float)
        previous_success_rate = _coerce_number(_metadata_value(previous_event, "prior_success_rate"), float)
        changes: List[Dict[str, Any]] = []
        if previous_strategy != current_strategy:
            changes.append({"field": "strategy_family", "previous": previous_strategy, "current": current_strategy})
        if previous_mutation != current_mutation:
            changes.append({"field": "mutation_type", "previous": previous_mutation, "current": current_mutation})
        if previous_resistance is not None or current_resistance is not None:
            if round(float(previous_resistance or 0.0), 4) != round(float(current_resistance or 0.0), 4):
                changes.append({"field": "inferred_target_resistance", "previous": previous_resistance, "current": current_resistance})
        if previous_success_rate is not None or current_success_rate is not None:
            if round(float(previous_success_rate or 0.0), 4) != round(float(current_success_rate or 0.0), 4):
                changes.append({"field": "prior_success_rate", "previous": previous_success_rate, "current": current_success_rate})
        summary_parts: List[str] = []
        if previous_strategy != current_strategy and previous_strategy and current_strategy:
            summary_parts.append(
                f"Switched from {previous_strategy} to {current_strategy}."
            )
        if previous_mutation != current_mutation and previous_mutation and current_mutation:
            summary_parts.append(
                f"Mutation shifted from {previous_mutation} to {current_mutation}."
            )
        if previous_resistance is not None and current_resistance is not None and round(previous_resistance, 4) != round(current_resistance, 4):
            summary_parts.append(
                f"Target resistance estimate changed from {previous_resistance:.2f} to {current_resistance:.2f}."
            )
        if previous_success_rate is not None and current_success_rate is not None and round(previous_success_rate, 4) != round(current_success_rate, 4):
            summary_parts.append(
                f"Prior success rate changed from {previous_success_rate:.2f} to {current_success_rate:.2f}."
            )
        if not summary_parts:
            summary_parts.append("Strategy, mutation, and resistance estimates matched the previous attacker decision.")
        return {
            "has_previous": True,
            "previous_event_id": _stable_text(previous_event.get("event_id")),
            "summary": " ".join(summary_parts),
            "changes": changes,
        }

    def _decision_summary(self, event: Dict[str, Any]) -> Dict[str, Any]:
        _meta_raw = event.get("metadata")
        metadata: Dict[str, Any] = _meta_raw if isinstance(_meta_raw, dict) else {}
        previous_event = self._previous_decision_event(event)
        diff = self._decision_diff(event, previous_event)
        rationale = _stable_text(metadata.get("rationale"))
        _tr = _coerce_number(metadata.get("inferred_target_resistance"), float)
        _psr = _coerce_number(metadata.get("prior_success_rate"), float)
        explanation_parts = [
            part
            for part in [
                f"Technique={_stable_text(metadata.get('technique'))}" if _stable_text(metadata.get("technique")) else "",
                f"Strategy={_stable_text(metadata.get('strategy_family'))}" if _stable_text(metadata.get("strategy_family")) else "",
                f"Mutation={_stable_text(metadata.get('mutation_type') or event.get('mutation_type'))}" if _stable_text(metadata.get("mutation_type") or event.get("mutation_type")) else "",
                f"Objective={_stable_text(metadata.get('objective'))}" if _stable_text(metadata.get("objective")) else "",
                f"Target resistance={_tr:.2f}" if _tr is not None else "",
                f"Prior success={_psr:.2f}" if _psr is not None else "",
            ]
            if part
        ]
        return {
            "strategy_family": _stable_text(metadata.get("strategy_family")),
            "technique": _stable_text(metadata.get("technique")),
            "mutation_type": _stable_text(metadata.get("mutation_type") or event.get("mutation_type")),
            "objective": _stable_text(metadata.get("objective")),
            "rationale": rationale,
            "score_breakdown": metadata.get("score_breakdown") if isinstance(metadata.get("score_breakdown"), dict) else {},
            "inferred_target_resistance": _coerce_number(metadata.get("inferred_target_resistance"), float),
            "prior_success_rate": _coerce_number(metadata.get("prior_success_rate"), float),
            "knowledge_source": _stable_text(metadata.get("knowledge_source")),
            "knowledge_confidence": _coerce_number(metadata.get("knowledge_confidence"), float),
            "runtime_override": _stable_bool(metadata.get("runtime_override")),
            "adaptation_weight_deltas": {
                "strategy_weight_after": _coerce_number(metadata.get("strategy_weight_after"), float),
                "mutation_weight_after": _coerce_number(metadata.get("mutation_weight_after"), float),
            },
            "why_this_attack": "; ".join(explanation_parts) if explanation_parts else "No decision telemetry attached to this event.",
            "what_changed": diff,
        }

    def _related_events_for_root(self, conn: sqlite3.Connection, root_event: Dict[str, Any], *, per_group: int = 16) -> Dict[str, List[Dict[str, Any]]]:
        groups: Dict[str, List[Dict[str, Any]]] = {}

        def load_group(sql: str, params: Sequence[Any]) -> List[Dict[str, Any]]:
            rows = conn.execute(sql, params).fetchall()
            return [self._row_to_event(row) for row in rows if row["event_id"] != root_event["event_id"]]

        if root_event.get("injection_id"):
            groups["same_injection_id"] = load_group(
                "SELECT * FROM siem_events WHERE injection_id = ? ORDER BY ts ASC LIMIT ?",
                [root_event["injection_id"], per_group],
            )
        if root_event.get("reset_id"):
            groups["same_reset_id"] = load_group(
                "SELECT * FROM siem_events WHERE reset_id = ? ORDER BY ts DESC LIMIT ?",
                [root_event["reset_id"], per_group],
            )
        if root_event.get("src") or root_event.get("dst"):
            groups["same_src_dst"] = load_group(
                "SELECT * FROM siem_events WHERE src = ? AND dst = ? ORDER BY ts DESC LIMIT ?",
                [root_event.get("src", ""), root_event.get("dst", ""), per_group],
            )
        payload_hash = root_event.get("payload_hash") or _payload_hash(root_event.get("payload"))
        if payload_hash:
            groups["same_payload_hash"] = load_group(
                "SELECT * FROM siem_events WHERE payload_hash = ? ORDER BY ts DESC LIMIT ?",
                [payload_hash, per_group],
            )
            groups["same_parent_payload_hash"] = load_group(
                "SELECT * FROM siem_events WHERE parent_payload_hash = ? ORDER BY ts DESC LIMIT ?",
                [payload_hash, per_group],
            )
        if root_event.get("mutation_v") is not None and root_event.get("injection_id"):
            groups["same_mutation_lineage"] = load_group(
                """
                SELECT *
                FROM siem_events
                WHERE injection_id = ?
                  AND mutation_v IS NOT NULL
                ORDER BY ABS(COALESCE(mutation_v, 0) - ?) ASC, ts DESC
                LIMIT ?
                """,
                [root_event["injection_id"], root_event.get("mutation_v", 0), per_group],
            )
        if root_event.get("semantic_family"):
            groups["same_semantic_family"] = load_group(
                "SELECT * FROM siem_events WHERE semantic_family = ? ORDER BY ts DESC LIMIT ?",
                [root_event["semantic_family"], per_group],
            )
        root_ts = _parse_timestamp(root_event.get("ts"))
        if root_ts:
            groups["time_adjacent"] = load_group(
                """
                SELECT *
                FROM siem_events
                WHERE ts BETWEEN ? AND ?
                ORDER BY ABS(strftime('%s', ts) - strftime('%s', ?)) ASC, ts ASC
                LIMIT ?
                """,
                [
                    (root_ts - timedelta(seconds=20)).isoformat(),
                    (root_ts + timedelta(seconds=20)).isoformat(),
                    root_ts.isoformat(),
                    per_group,
                ],
            )
        return groups

    def _attempt_outcomes(self, events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        unresolved: List[Dict[str, Any]] = []
        pairs: List[Dict[str, Any]] = []
        for event in events:
            if event.get("event") not in {"WRM-INJECT", "INFECTION_ATTEMPT"}:
                continue
            event_ts = _parse_timestamp(event.get("ts"))
            matched = None
            for candidate in events:
                if candidate.get("event") not in TERMINAL_EVENTS:
                    continue
                if candidate.get("ts") == event.get("ts") and candidate.get("event_id") == event.get("event_id"):
                    continue
                if candidate.get("src") != event.get("src") or candidate.get("dst") != event.get("dst"):
                    continue
                if candidate.get("injection_id") and event.get("injection_id") and candidate.get("injection_id") != event.get("injection_id"):
                    continue
                if candidate.get("hop_count") != event.get("hop_count"):
                    continue
                candidate_ts = _parse_timestamp(candidate.get("ts"))
                if not event_ts or not candidate_ts or candidate_ts < event_ts:
                    continue
                if (candidate_ts - event_ts).total_seconds() > 30:
                    continue
                matched = candidate
                break
            if matched:
                pairs.append({"attempt": event, "outcome": matched})
            else:
                unresolved.append(event)
        return pairs, unresolved

    def _scope_events(
        self,
        query: str = "",
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
        limit: int = 5000,
    ) -> Tuple[QueryPlan, List[Dict[str, Any]], List[str], bool]:
        self.sync_primary_events()
        plan = self._build_query_plan(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        warnings: List[str] = []
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM siem_events
                WHERE {plan.where_sql}
                ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC
                LIMIT ?
                """,
                [*plan.params, limit + 1],
            ).fetchall()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]
            warnings.append(f"Analytics scoped to first {limit} indexed events in the current query window.")
        return plan, [self._row_to_event(row) for row in rows], warnings, truncated

    def _first_non_empty(self, values: Sequence[Any], default: Any = "") -> Any:
        for value in values:
            if value not in (None, "", [], {}):
                return value
        return default

    def _most_common_non_empty(self, values: Sequence[Any], default: Any = "") -> Any:
        counter = Counter(str(value) for value in values if value not in (None, "", [], {}))
        if not counter:
            return default
        return counter.most_common(1)[0][0]

    def _event_is_success(self, event: Dict[str, Any]) -> bool:
        if str(event.get("event") or "") in SUCCESS_EVENTS:
            return True
        outcome = str(event.get("metadata", {}).get("outcome") or "").lower()
        return outcome == "success"

    def _event_is_block(self, event: Dict[str, Any]) -> bool:
        if str(event.get("event") or "") in BLOCK_EVENTS:
            return True
        outcome = str(event.get("metadata", {}).get("outcome") or "").lower()
        return outcome in {"blocked", "suppressed", "failed"}

    def _normalized_payload_pattern(self, event: Dict[str, Any]) -> str:
        source = str(
            event.get("decoded_payload_preview")
            or event.get("payload_preview")
            or event.get("payload_text")
            or ""
        ).lower()
        if not source:
            return ""
        pattern = re.sub(r"[0-9a-f]{8,64}", "{hash}", source)
        pattern = re.sub(r"mutation=[a-z0-9_:-]+", "mutation={mutation}", pattern)
        pattern = re.sub(r"technique=[a-z0-9_:-]+", "technique={technique}", pattern)
        pattern = re.sub(r"objective=[a-z0-9_:-]+", "objective={objective}", pattern)
        pattern = re.sub(r"\s+", " ", pattern).strip()
        return pattern[:160]

    def _payload_component_events(
        self,
        *,
        payload_hash: str = "",
        injection_id: str = "",
        campaign_id: str = "",
        max_hashes: int = 250,
        max_rows_per_hash: int = 240,
    ) -> List[Dict[str, Any]]:
        self.sync_primary_events()
        seen_hashes: set[str] = set()
        pending: List[str] = [str(payload_hash or "").strip()] if payload_hash else []
        seen_row_ids: set[int] = set()
        rows: List[sqlite3.Row] = []
        with self._connect() as conn:
            if injection_id:
                scoped_rows = conn.execute(
                    """
                    SELECT *
                    FROM siem_events
                    WHERE injection_id = ?
                      AND payload_hash != ''
                    ORDER BY ts ASC, id ASC
                    LIMIT 2000
                    """,
                    (injection_id,),
                ).fetchall()
                return [self._row_to_event(row) for row in scoped_rows]
            if campaign_id:
                scoped_rows = conn.execute(
                    """
                    SELECT *
                    FROM siem_events
                    WHERE json_extract(metadata, '$.campaign_id') = ?
                      AND payload_hash != ''
                    ORDER BY ts ASC, id ASC
                    LIMIT 3000
                    """,
                    (campaign_id,),
                ).fetchall()
                return [self._row_to_event(row) for row in scoped_rows]

            while pending and len(seen_hashes) < max_hashes:
                current = pending.pop(0)
                if not current or current in seen_hashes:
                    continue
                seen_hashes.add(current)
                current_rows = conn.execute(
                    """
                    SELECT *
                    FROM siem_events
                    WHERE payload_hash = ?
                       OR parent_payload_hash = ?
                    ORDER BY ts ASC, id ASC
                    LIMIT ?
                    """,
                    (current, current, max_rows_per_hash),
                ).fetchall()
                for row in current_rows:
                    if row["id"] in seen_row_ids:
                        continue
                    seen_row_ids.add(int(row["id"]))
                    rows.append(row)
                    child_hash = str(row["payload_hash"] or "")
                    parent_hash = str(row["parent_payload_hash"] or "")
                    if child_hash and child_hash not in seen_hashes:
                        pending.append(child_hash)
                    if parent_hash and parent_hash not in seen_hashes:
                        pending.append(parent_hash)
        return [self._row_to_event(row) for row in rows]

    def _build_payload_lineage_model(
        self,
        events: List[Dict[str, Any]],
        *,
        focus_payload_hash: str = "",
    ) -> Dict[str, Any]:
        node_events: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        edge_events: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            payload_hash = str(event.get("payload_hash") or "")
            if not payload_hash:
                continue
            node_events[payload_hash].append(event)
            parent_hash = str(event.get("parent_payload_hash") or "")
            if parent_hash:
                edge_events[(parent_hash, payload_hash)].append(event)

        parent_map: Dict[str, str] = {}
        children_map: Dict[str, List[str]] = defaultdict(list)
        nodes: List[Dict[str, Any]] = []
        gaps: List[Dict[str, Any]] = []
        missing_nodes: List[Dict[str, Any]] = []

        for payload_hash, events_for_hash in node_events.items():
            events_for_hash.sort(key=lambda item: ((_parse_timestamp(item.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)), item.get("event_id", "")))
            primary = events_for_hash[0]
            parent_candidates = Counter(
                str(event.get("parent_payload_hash") or "")
                for event in events_for_hash
                if str(event.get("parent_payload_hash") or "")
            )
            parent_hash = parent_candidates.most_common(1)[0][0] if parent_candidates else ""
            if parent_hash:
                parent_map[payload_hash] = parent_hash
                children_map[parent_hash].append(payload_hash)
                if parent_hash not in node_events:
                    gaps.append(
                        {
                            "type": "missing_parent",
                            "payload_hash": payload_hash,
                            "missing_parent_payload_hash": parent_hash,
                        }
                    )
            source_agents = sorted({str(event.get("src") or "") for event in events_for_hash if event.get("src")})
            targets = sorted({str(event.get("dst") or "") for event in events_for_hash if event.get("dst")})
            related_campaign_ids = sorted(
                {
                    str(event.get("metadata", {}).get("campaign_id") or "")
                    for event in events_for_hash
                    if str(event.get("metadata", {}).get("campaign_id") or "")
                }
            )
            related_injection_ids = sorted(
                {
                    str(event.get("injection_id") or event.get("metadata", {}).get("injection_id") or "")
                    for event in events_for_hash
                    if str(event.get("injection_id") or event.get("metadata", {}).get("injection_id") or "")
                }
            )
            nodes.append(
                {
                    "payload_hash": payload_hash,
                    "parent_payload_hash": parent_hash,
                    "ts_first_seen": self._first_non_empty([event.get("ts") for event in events_for_hash], ""),
                    "ts_last_seen": self._first_non_empty([event.get("ts") for event in reversed(events_for_hash)], ""),
                    "raw_preview": self._first_non_empty([event.get("payload_preview") for event in events_for_hash], ""),
                    "decoded_preview": self._first_non_empty([event.get("decoded_payload_preview") for event in events_for_hash], ""),
                    "semantic_family": self._most_common_non_empty([event.get("semantic_family") for event in events_for_hash], ""),
                    "mutation_type": self._most_common_non_empty([event.get("mutation_type") for event in events_for_hash], ""),
                    "mutation_v": max(int(event.get("mutation_v") or 0) for event in events_for_hash),
                    "decode_status": self._most_common_non_empty([event.get("decode_status") for event in events_for_hash], ""),
                    "wrapper_type": self._most_common_non_empty([event.get("payload_wrapper_type") for event in events_for_hash], ""),
                    "source_agent": source_agents[0] if source_agents else "",
                    "source_agents": source_agents,
                    "first_target": primary.get("dst") or "",
                    "targets": targets,
                    "event_count": len(events_for_hash),
                    "success_count": sum(1 for event in events_for_hash if self._event_is_success(event)),
                    "block_count": sum(1 for event in events_for_hash if self._event_is_block(event)),
                    "related_campaign_ids": related_campaign_ids,
                    "related_injection_ids": related_injection_ids,
                    "related_event_ids": [str(event.get("event_id") or "") for event in events_for_hash],
                    "missing_parent": bool(parent_hash and parent_hash not in node_events),
                }
            )

        for gap in gaps:
            missing_nodes.append(
                {
                    "payload_hash": gap["missing_parent_payload_hash"],
                    "parent_payload_hash": "",
                    "ts_first_seen": "",
                    "ts_last_seen": "",
                    "raw_preview": "",
                    "decoded_preview": "",
                    "semantic_family": "",
                    "mutation_type": "",
                    "mutation_v": 0,
                    "decode_status": "",
                    "wrapper_type": "",
                    "source_agent": "",
                    "source_agents": [],
                    "first_target": "",
                    "targets": [],
                    "event_count": 0,
                    "success_count": 0,
                    "block_count": 0,
                    "related_campaign_ids": [],
                    "related_injection_ids": [],
                    "related_event_ids": [],
                    "missing_parent": True,
                    "gap_placeholder": True,
                }
            )

        node_lookup = {node["payload_hash"]: node for node in nodes + missing_nodes}
        roots = sorted(
            payload_hash
            for payload_hash in node_events
            if not parent_map.get(payload_hash) or parent_map.get(payload_hash) not in node_lookup
        )
        depth_cache: Dict[str, int] = {}

        def lineage_depth(payload_hash: str) -> int:
            if payload_hash in depth_cache:
                return depth_cache[payload_hash]
            parent_hash = parent_map.get(payload_hash, "")
            if not parent_hash or parent_hash not in node_events:
                depth_cache[payload_hash] = 0
            else:
                depth_cache[payload_hash] = lineage_depth(parent_hash) + 1
            return depth_cache[payload_hash]

        descendant_counts: Dict[str, int] = {}

        def descendants(payload_hash: str) -> int:
            if payload_hash in descendant_counts:
                return descendant_counts[payload_hash]
            total = 0
            for child_hash in children_map.get(payload_hash, []):
                total += 1 + descendants(child_hash)
            descendant_counts[payload_hash] = total
            return total

        edges: List[Dict[str, Any]] = []
        for (parent_hash, child_hash), events_for_edge in edge_events.items():
            events_for_edge.sort(key=lambda item: ((_parse_timestamp(item.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)), item.get("event_id", "")))
            first_edge_event = events_for_edge[0]
            parent_node = node_lookup.get(parent_hash, {})
            child_node = node_lookup.get(child_hash, {})
            edges.append(
                {
                    "from_hash": parent_hash,
                    "to_hash": child_hash,
                    "mutation_type": self._most_common_non_empty([event.get("mutation_type") for event in events_for_edge], ""),
                    "mutation_v_delta": max(int(event.get("mutation_v") or 0) for event in events_for_edge) - int(parent_node.get("mutation_v") or 0),
                    "first_seen": first_edge_event.get("ts") or "",
                    "target_transition": f"{parent_node.get('first_target') or '?'} -> {child_node.get('first_target') or '?'}",
                    "event_count": len(events_for_edge),
                }
            )

        for node in nodes:
            node["lineage_depth"] = lineage_depth(str(node["payload_hash"]))
            node["descendant_count"] = descendants(str(node["payload_hash"]))

        focus_hash = str(focus_payload_hash or "")
        if not focus_hash and nodes:
            focus_hash = nodes[0]["payload_hash"]
        linear_hashes: List[str] = []
        if focus_hash:
            chain_up: List[str] = []
            current = focus_hash
            seen: set[str] = set()
            while current and current not in seen:
                seen.add(current)
                chain_up.append(current)
                current = parent_map.get(current, "")
            linear_hashes = list(reversed(chain_up))
            current = focus_hash
            while children_map.get(current):
                ranked_children = sorted(
                    children_map[current],
                    key=lambda child_hash: (
                        -(node_lookup.get(child_hash, {}).get("event_count") or 0),
                        node_lookup.get(child_hash, {}).get("ts_first_seen") or "",
                        child_hash,
                    ),
                )
                next_hash = ranked_children[0]
                if next_hash in linear_hashes:
                    break
                linear_hashes.append(next_hash)
                current = next_hash

        def build_tree(payload_hash: str) -> Dict[str, Any]:
            node = dict(node_lookup.get(payload_hash, {"payload_hash": payload_hash, "missing_parent": True}))
            node["children"] = [build_tree(child_hash) for child_hash in sorted(children_map.get(payload_hash, []))]
            return node

        root_hash = ""
        if focus_hash:
            root_hash = focus_hash
            while parent_map.get(root_hash) and parent_map[root_hash] in node_lookup:
                root_hash = parent_map[root_hash]

        event_linked_lineage_list = [
            {
                "event_id": event.get("event_id"),
                "ts": event.get("ts"),
                "event": event.get("event"),
                "src": event.get("src"),
                "dst": event.get("dst"),
                "payload_hash": event.get("payload_hash"),
                "parent_payload_hash": event.get("parent_payload_hash"),
                "mutation_type": event.get("mutation_type"),
                "mutation_v": event.get("mutation_v"),
                "strategy_family": event.get("metadata", {}).get("strategy_family"),
                "technique": event.get("metadata", {}).get("technique"),
                "outcome": event.get("metadata", {}).get("outcome") or event.get("event"),
            }
            for event in sorted(events, key=lambda item: ((_parse_timestamp(item.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)), item.get("event_id", "")))
            if event.get("payload_hash")
        ]
        summary = {
            "focus_payload_hash": focus_hash,
            "root_payload_hash": root_hash,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "gap_count": len(gaps),
            "root_count": len(roots),
            "branching_nodes": sum(
                1
                for payload_hash, children in children_map.items()
                if len(children) > 1
                or (
                    len(children) == 1
                    and int(node_lookup.get(payload_hash, {}).get("event_count") or 0) > 1
                )
            ),
            "max_lineage_depth": max((node.get("lineage_depth") or 0 for node in nodes), default=0),
            "related_event_count": len(event_linked_lineage_list),
            "child_count": len(children_map.get(focus_hash, [])) if focus_hash else 0,
            "semantic_family": node_lookup.get(focus_hash, {}).get("semantic_family", "") if focus_hash else "",
            "decode_patterns": sorted({step for event in events for step in (event.get("decode_chain") or [])}),
        }
        warnings: List[str] = []
        if gaps:
            warnings.append("Lineage incomplete: missing parent payload.")
        if not nodes:
            warnings.append("No payload lineage could be reconstructed from the indexed scope.")
        return {
            "focus_payload_hash": focus_hash,
            "root_payload_hash": root_hash,
            "nodes": sorted(nodes + missing_nodes, key=lambda node: (node.get("lineage_depth") or 0, node.get("ts_first_seen") or "", node.get("payload_hash") or "")),
            "edges": sorted(edges, key=lambda edge: (edge.get("first_seen") or "", edge.get("from_hash") or "", edge.get("to_hash") or "")),
            "gaps": gaps,
            "warnings": warnings,
            "summary": summary,
            "modes": {
                "linear_chain": [node_lookup[item] for item in linear_hashes if item in node_lookup],
                "branching_tree": [build_tree(root_hash)] if root_hash else [build_tree(item) for item in roots],
                "compact_summary": summary,
                "event_linked_lineage_list": event_linked_lineage_list,
            },
            "node_lookup": node_lookup,
            "children_map": {key: list(value) for key, value in children_map.items()},
        }

    def _build_attempt_records(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        records: Dict[str, Dict[str, Any]] = {}
        for event in sorted(events, key=lambda item: ((_parse_timestamp(item.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)), item.get("event_id", ""))):
            _meta_raw = event.get("metadata")
            metadata: Dict[str, Any] = _meta_raw if isinstance(_meta_raw, dict) else {}
            attempt_id = str(metadata.get("attempt_id") or event.get("event_id") or "")
            event_name = str(event.get("event") or "")
            mutation_type = str(event.get("mutation_type") or metadata.get("mutation_type") or "")
            strategy_family = str(metadata.get("strategy_family") or "")
            technique = str(metadata.get("technique") or "")
            if not attempt_id or (not mutation_type and not strategy_family and event_name not in ATTEMPT_EVENTS and event_name not in SUCCESS_EVENTS and event_name not in BLOCK_EVENTS):
                continue
            record = records.setdefault(
                attempt_id,
                {
                    "attempt_id": attempt_id,
                    "event_ids": [],
                    "event_types": [],
                    "phase": "",
                    "campaign_id": "",
                    "injection_id": "",
                    "payload_hash": "",
                    "parent_payload_hash": "",
                    "semantic_family": "",
                    "mutation_type": "",
                    "strategy_family": "",
                    "technique": "",
                    "objective": "",
                    "target": "",
                    "source_agent": "",
                    "attack_strength": None,
                    "hop_count": None,
                    "decode_complexity": 0,
                    "decode_status": "",
                    "wrapper_type": "",
                    "knowledge_confidence": None,
                    "knowledge_source": "",
                    "prior_success_rate": None,
                    "inferred_target_resistance": None,
                    "rationale": "",
                    "score_breakdown": {},
                    "ts_first_seen": event.get("ts") or "",
                    "ts_last_seen": event.get("ts") or "",
                    "outcome": "unknown",
                },
            )
            record["event_ids"].append(str(event.get("event_id") or ""))
            record["event_types"].append(event_name)
            record["campaign_id"] = str(metadata.get("campaign_id") or record["campaign_id"] or "")
            record["injection_id"] = str(event.get("injection_id") or metadata.get("injection_id") or record["injection_id"] or "")
            record["payload_hash"] = str(event.get("payload_hash") or metadata.get("payload_hash") or record["payload_hash"] or "")
            record["parent_payload_hash"] = str(event.get("parent_payload_hash") or metadata.get("parent_payload_hash") or record["parent_payload_hash"] or "")
            record["semantic_family"] = str(event.get("semantic_family") or metadata.get("semantic_family") or record["semantic_family"] or "")
            record["mutation_type"] = mutation_type or record["mutation_type"]
            record["strategy_family"] = strategy_family or record["strategy_family"]
            record["technique"] = technique or record["technique"]
            record["objective"] = str(metadata.get("objective") or record["objective"] or "")
            record["target"] = str(event.get("dst") or metadata.get("target") or record["target"] or "")
            record["source_agent"] = str(event.get("src") or record["source_agent"] or "")
            record["attack_strength"] = event.get("attack_strength") if event.get("attack_strength") is not None else record["attack_strength"]
            record["hop_count"] = event.get("hop_count") if event.get("hop_count") is not None else metadata.get("hop_count", record["hop_count"])
            record["decode_complexity"] = max(int(record["decode_complexity"] or 0), len(event.get("decode_chain") or []))
            record["decode_status"] = str(event.get("decode_status") or record["decode_status"] or "")
            record["wrapper_type"] = str(event.get("payload_wrapper_type") or record["wrapper_type"] or "")
            record["knowledge_confidence"] = metadata.get("knowledge_confidence", record["knowledge_confidence"])
            record["knowledge_source"] = str(metadata.get("knowledge_source") or record["knowledge_source"] or "")
            record["prior_success_rate"] = metadata.get("prior_success_rate", record["prior_success_rate"])
            record["inferred_target_resistance"] = metadata.get("inferred_target_resistance", record["inferred_target_resistance"])
            record["rationale"] = str(metadata.get("rationale") or record["rationale"] or "")
            if metadata.get("score_breakdown"):
                record["score_breakdown"] = metadata.get("score_breakdown")
            record["ts_last_seen"] = event.get("ts") or record["ts_last_seen"]
            if event_name == "RECON_PROBE" or record["strategy_family"] == "RECON_PROBE":
                record["phase"] = "exploration"
            elif "JAILBREAK" in record["strategy_family"]:
                record["phase"] = "escalation"
            elif event_name == "CAMPAIGN_ADAPTED":
                record["phase"] = "fallback"
            elif not record["phase"] and record["strategy_family"]:
                record["phase"] = STRATEGY_PHASE_MAP.get(record["strategy_family"], "exploitation")

            if self._event_is_success(event):
                record["outcome"] = "success"
            elif self._event_is_block(event):
                record["outcome"] = "blocked"

        records_list = list(records.values())
        by_campaign: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for record in records_list:
            if record["campaign_id"]:
                by_campaign[record["campaign_id"]].append(record)
        for campaign_records in by_campaign.values():
            campaign_records.sort(key=lambda item: (item.get("ts_first_seen") or "", item.get("attempt_id") or ""))
            last_successful_mutation = ""
            consecutive_blocks = 0
            for record in campaign_records:
                if record.get("outcome") == "success":
                    last_successful_mutation = str(record.get("mutation_type") or "")
                    consecutive_blocks = 0
                    if not record.get("phase"):
                        record["phase"] = "exploitation"
                elif record.get("outcome") == "blocked":
                    consecutive_blocks += 1
                    if not record.get("phase"):
                        record["phase"] = "exploration" if consecutive_blocks < 2 else "fallback"
                if (
                    last_successful_mutation
                    and record.get("mutation_type") == last_successful_mutation
                    and consecutive_blocks >= 1
                ):
                    record["phase"] = "fallback"
        return records_list

    def _reasoning_diff(self, current: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not previous:
            return {
                "has_previous": False,
                "messages": ["No prior attacker decision in the current campaign scope."],
                "changes": {},
            }
        prev_strategy = str(previous.get("metadata", {}).get("strategy_family") or "")
        curr_strategy = str(current.get("metadata", {}).get("strategy_family") or "")
        prev_mutation = str(previous.get("metadata", {}).get("mutation_type") or "")
        curr_mutation = str(current.get("metadata", {}).get("mutation_type") or "")
        prev_resistance = previous.get("metadata", {}).get("inferred_target_resistance")
        curr_resistance = current.get("metadata", {}).get("inferred_target_resistance")
        prev_success_rate = previous.get("metadata", {}).get("prior_success_rate")
        curr_success_rate = current.get("metadata", {}).get("prior_success_rate")
        messages: List[str] = []
        if prev_strategy != curr_strategy and prev_strategy and curr_strategy:
            messages.append(f"Switched from {prev_strategy} to {curr_strategy}.")
        if prev_mutation != curr_mutation and prev_mutation and curr_mutation:
            messages.append(f"Switched mutation from {prev_mutation} to {curr_mutation}.")
        if prev_resistance is not None and curr_resistance is not None and prev_resistance != curr_resistance:
            messages.append(
                f"Target resistance estimate changed from {float(prev_resistance):.2f} to {float(curr_resistance):.2f}."
            )
        if prev_success_rate is not None and curr_success_rate is not None and prev_success_rate != curr_success_rate:
            messages.append(
                f"Prior success rate changed from {float(prev_success_rate):.2f} to {float(curr_success_rate):.2f}."
            )
        if not messages:
            messages.append("Decision parameters remained stable versus the prior attacker decision.")
        return {
            "has_previous": True,
            "messages": messages,
            "changes": {
                "previous_strategy": prev_strategy,
                "current_strategy": curr_strategy,
                "previous_mutation": prev_mutation,
                "current_mutation": curr_mutation,
                "previous_resistance": prev_resistance,
                "current_resistance": curr_resistance,
                "previous_success_rate": prev_success_rate,
                "current_success_rate": curr_success_rate,
            },
        }

    def _defense_diff(self, current: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        _curr_raw = current.get("metadata")
        current_meta: Dict[str, Any] = _curr_raw if isinstance(_curr_raw, dict) else {}
        _prev_raw = previous.get("metadata") if previous else None
        previous_meta: Dict[str, Any] = _prev_raw if isinstance(_prev_raw, dict) else {}
        if not previous_meta:
            return {
                "has_previous": False,
                "messages": ["No prior defense decision in the current campaign scope."],
                "changes": {},
            }
        prev_strategy = str(previous_meta.get("selected_strategy") or previous_meta.get("defense_strategy") or "")
        curr_strategy = str(current_meta.get("selected_strategy") or current_meta.get("defense_strategy") or "")
        prev_type = str(previous_meta.get("defense_type") or "")
        curr_type = str(current_meta.get("defense_type") or "")
        prev_risk = previous_meta.get("inferred_risk")
        curr_risk = current_meta.get("inferred_risk")
        prev_dynamic = previous_meta.get("dynamic_defense")
        curr_dynamic = current_meta.get("dynamic_defense")
        messages: List[str] = []
        if prev_type and curr_type and prev_type != curr_type:
            messages.append(f"Defense type changed from {prev_type} to {curr_type}.")
        if prev_strategy and curr_strategy and prev_strategy != curr_strategy:
            messages.append(f"Defense strategy changed from {prev_strategy} to {curr_strategy}.")
        if prev_risk is not None and curr_risk is not None and prev_risk != curr_risk:
            messages.append(f"Inferred risk changed from {float(prev_risk):.2f} to {float(curr_risk):.2f}.")
        if prev_dynamic is not None and curr_dynamic is not None and prev_dynamic != curr_dynamic:
            messages.append(f"Dynamic defense changed from {float(prev_dynamic):.2f} to {float(curr_dynamic):.2f}.")
        if not messages:
            messages.append("Defense parameters remained stable versus the prior defense decision.")
        return {
            "has_previous": True,
            "messages": messages,
            "changes": {
                "previous_defense_type": prev_type,
                "current_defense_type": curr_type,
                "previous_defense_strategy": prev_strategy,
                "current_defense_strategy": curr_strategy,
                "previous_risk": prev_risk,
                "current_risk": curr_risk,
                "previous_dynamic_defense": prev_dynamic,
                "current_dynamic_defense": curr_dynamic,
            },
        }

    def _build_trace(self, events: List[Dict[str, Any]], root_event: Dict[str, Any], *, scope_reason: str, scope_confidence: float) -> Dict[str, Any]:
        if not events:
            return {
                "root_event": root_event,
                "scope_reason": scope_reason,
                "scope_confidence": scope_confidence,
                "events": [],
                "timeline": [],
                "tree": [],
                "summary": {},
                "warnings": ["Trace scope resolved to no events."],
                "hints": [],
            }
        linked: List[Dict[str, Any]] = []
        event_lookup: Dict[str, Dict[str, Any]] = {}
        branch_counts: Dict[str, int] = {}
        previous_ts: Optional[datetime] = None
        for index, event in enumerate(events):
            current_ts = _parse_timestamp(event.get("ts"))
            parent_id = ""
            correlation_reason = "trace_scope"
            confidence = 0.35
            for candidate in reversed(events[:index]):
                same_injection = bool(event.get("injection_id")) and candidate.get("injection_id") == event.get("injection_id")
                if event.get("event") in TERMINAL_EVENTS and candidate.get("src") == event.get("src") and candidate.get("dst") == event.get("dst") and candidate.get("hop_count") == event.get("hop_count"):
                    parent_id = candidate["event_id"]
                    correlation_reason = "attempt_to_terminal_outcome"
                    confidence = 1.0 if same_injection else 0.88
                    break
                _cand_ts = _parse_timestamp(candidate.get("ts"))
                if candidate.get("dst") == event.get("src") and current_ts and _cand_ts and _cand_ts <= current_ts:
                    hop_ok = (
                        event.get("hop_count") is None
                        or candidate.get("hop_count") is None
                        or int(event.get("hop_count") or 0) >= int(candidate.get("hop_count") or 0)
                    )
                    if hop_ok:
                        parent_id = candidate["event_id"]
                        correlation_reason = "propagation_dst_to_next_src"
                        confidence = 0.92 if same_injection else 0.72
                        break
            event_copy = dict(event)
            event_copy["parent_event_id"] = parent_id
            event_copy["correlation_reason"] = correlation_reason
            event_copy["correlation_confidence"] = round(confidence, 2)
            event_copy["delta_s"] = round((current_ts - previous_ts).total_seconds(), 3) if current_ts and previous_ts else 0.0
            parent_payload_hash = ""
            if parent_id and parent_id in event_lookup:
                parent_payload_hash = str(event_lookup[parent_id].get("payload_hash", ""))
            event_copy["payload_changed"] = bool(parent_payload_hash and parent_payload_hash != str(event_copy.get("payload_hash", "")))
            previous_ts = current_ts or previous_ts
            linked.append(event_copy)
            event_lookup[event_copy["event_id"]] = event_copy
            if parent_id:
                branch_counts[parent_id] = branch_counts.get(parent_id, 0) + 1

        children: Dict[str, List[Dict[str, Any]]] = {}
        for event in linked:
            children.setdefault(event["parent_event_id"], []).append(event)
        for siblings in children.values():
            siblings.sort(key=lambda item: (_parse_timestamp(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc), item.get("hop_count") or 0))

        def build_tree(parent_id: str = "") -> List[Dict[str, Any]]:
            output = []
            for child in children.get(parent_id, []):
                output.append(
                    {
                        "event_id": child["event_id"],
                        "label": f"{child.get('src', '?')} -> {child.get('dst', '?')} :: {child.get('event', '')}",
                        "event": child,
                        "children": build_tree(child["event_id"]),
                    }
                )
            return output

        pairs, unresolved = self._attempt_outcomes(linked)
        warnings: List[str] = []
        if unresolved:
            warnings.append(f"{len(unresolved)} attempts have no terminal outcome in the current trace scope.")
        if any(count > 1 for count in branch_counts.values()):
            warnings.append("Branch split detected: one predecessor fan-outs into multiple descendants.")
        terminal_events = [event for event in linked if event.get("event") in TERMINAL_EVENTS]
        if not terminal_events:
            warnings.append("No terminal outcome found in trace scope.")
        involved_agents = sorted({agent for event in linked for agent in (event.get("src"), event.get("dst")) if agent})
        max_mutation = max((event.get("mutation_v") or 0 for event in linked), default=0)
        trace_hints = []
        if unresolved:
            trace_hints.append({"severity": "warn", "message": "Trace contains unresolved attempts without terminal outcomes."})
        if max_mutation:
            trace_hints.append({"severity": "info", "message": f"Mutation versions increase through v{max_mutation} in this trace."})
        decode_steps: Dict[str, int] = {}
        for event in linked:
            for step in event.get("decode_chain") or []:
                decode_steps[str(step)] = decode_steps.get(str(step), 0) + 1
        if decode_steps:
            top_step, top_count = max(decode_steps.items(), key=lambda item: (item[1], item[0]))
            trace_hints.append({"severity": "info", "message": f"Most payloads in this trace decode via {top_step} ({top_count} hops)."})
        if branch_counts and max(branch_counts.values()) > 1:
            trace_hints.append({"severity": "info", "message": "Trace contains branching descendants from a single predecessor."})

        compact_chain = [
            {
                "src": event.get("src"),
                "dst": event.get("dst"),
                "event": event.get("event"),
                "attack_type": event.get("attack_type"),
                "payload_hash": event.get("payload_hash"),
                "parent_payload_hash": event.get("parent_payload_hash"),
                "payload_preview": event.get("payload_preview"),
                "decoded_payload_preview": event.get("decoded_payload_preview"),
                "decode_status": event.get("decode_status"),
                "decode_chain": event.get("decode_chain"),
                "payload_wrapper_type": event.get("payload_wrapper_type"),
                "semantic_family": event.get("semantic_family"),
                "mutation_type": event.get("mutation_type"),
                "mutation_v": event.get("mutation_v"),
                "hop_count": event.get("hop_count"),
                "state_after": event.get("state_after"),
                "payload_changed": event.get("payload_changed", False),
            }
            for event in linked
        ]
        return {
            "root_event": root_event,
            "scope_reason": scope_reason,
            "scope_confidence": scope_confidence,
            "events": linked,
            "timeline": linked,
            "tree": build_tree(""),
            "compact_chain": compact_chain,
            "summary": {
                "involved_agents": involved_agents,
                "total_events": len(linked),
                "terminal_events": len(terminal_events),
                "branch_splits": sum(1 for count in branch_counts.values() if count > 1),
                "max_hop_count": max((event.get("hop_count") or 0 for event in linked), default=0),
                "max_mutation_v": max_mutation,
                "terminal_outcome": terminal_events[-1].get("event") if terminal_events else "",
            },
            "warnings": warnings,
            "unresolved_attempts": unresolved,
            "attempt_pairs": pairs,
            "hints": trace_hints,
        }

    def _trace_scope(self, root_event: Dict[str, Any]) -> Tuple[str, List[Any], str, float]:
        if root_event.get("injection_id"):
            return "injection_id = ?", [root_event["injection_id"]], "injection_id exact match", 1.0
        if root_event.get("reset_id") and root_event.get("epoch") is not None:
            return "reset_id = ? AND epoch = ?", [root_event["reset_id"], root_event["epoch"]], "reset_id + epoch exact match", 0.82
        if root_event.get("reset_id"):
            return "reset_id = ?", [root_event["reset_id"]], "reset_id exact match", 0.7
        root_ts = _parse_timestamp(root_event.get("ts"))
        if root_ts:
            return (
                "ts BETWEEN ? AND ? AND ((src = ? AND dst = ?) OR payload_hash = ?)",
                [
                    (root_ts - timedelta(seconds=30)).isoformat(),
                    (root_ts + timedelta(seconds=30)).isoformat(),
                    root_event.get("src", ""),
                    root_event.get("dst", ""),
                    root_event.get("payload_hash") or _payload_hash(root_event.get("payload")),
                ],
                "time proximity + route/payload correlation",
                0.55,
            )
        return "event_id = ?", [root_event["event_id"]], "root event only", 0.2

    def hints(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        rows = self._fetch_scope_rows(plan, limit=1500)
        events = [self._row_to_event(row) for row in rows]
        if not events:
            return {"structured_query": plan.structured_query, "hints": []}
        hints: List[Dict[str, Any]] = []
        blocked_targets: Dict[str, int] = {}
        strength_by_target: Dict[str, List[float]] = {}
        payload_usage: Dict[str, set[str]] = {}
        blocked_families: Dict[str, int] = {}
        decode_steps: Dict[str, int] = {}
        decoded_markers: Dict[str, int] = {}
        reset_ids = set()
        suppressed = 0
        for event in events:
            if event.get("reset_id"):
                reset_ids.add(event["reset_id"])
            if event.get("event") == "INFECTION_BLOCKED" and event.get("dst"):
                blocked_targets[event["dst"]] = blocked_targets.get(event["dst"], 0) + 1
            if event.get("attack_strength") is not None and event.get("dst"):
                strength_by_target.setdefault(event["dst"], []).append(float(event["attack_strength"]))
            if event.get("payload_hash"):
                payload_usage.setdefault(str(event["payload_hash"]), set()).update(
                    agent for agent in (event.get("src"), event.get("dst")) if agent
                )
            if event.get("event") == "INFECTION_BLOCKED" and event.get("semantic_family"):
                blocked_families[str(event["semantic_family"])] = blocked_families.get(str(event["semantic_family"]), 0) + 1
            if event.get("event") in {"PROPAGATION_SUPPRESSED", "STALE_EVENT_DROPPED", "CONTROL_RESYNC"}:
                suppressed += 1
            for step in event.get("decode_chain") or []:
                decode_steps[str(step)] = decode_steps.get(str(step), 0) + 1
            decoded_preview = str(event.get("decoded_payload_preview") or "")
            for token in ("instruction_override", "roleplay_manipulation", "jailbreak_escalation", "prompt_injection", "SIM_ATTACK", "SIM_VERBOSE"):
                if token in decoded_preview:
                    decoded_markers[token] = decoded_markers.get(token, 0) + 1
        pairs, unresolved = self._attempt_outcomes(events)
        if blocked_targets:
            top_target, top_count = max(blocked_targets.items(), key=lambda item: item[1])
            hints.append({"severity": "info", "message": f"{top_target} appears most frequently as a blocked target ({top_count} events)."})
        if unresolved:
            hints.append({"severity": "warn", "message": f"There are {len(unresolved)} unresolved attempts without terminal outcome."})
        if len(reset_ids) > 1:
            hints.append({"severity": "warn", "message": f"Current results span {len(reset_ids)} reset_ids, which may indicate residual activity across runs."})
        if suppressed:
            hints.append({"severity": "info", "message": f"Suppression or stale-context events occurred {suppressed} times in this result set."})
        if strength_by_target:
            target, values = max(strength_by_target.items(), key=lambda item: (sum(item[1]) / len(item[1]), len(item[1])))
            hints.append({"severity": "info", "message": f"High attack_strength events are concentrated on {target}."})
        if pairs:
            max_hop = max((pair["attempt"].get("hop_count") or 0 for pair in pairs), default=0)
            hints.append({"severity": "info", "message": f"Resolved chains in this result set terminate around hop {max_hop}."})
        if payload_usage:
            payload_hash, agents = max(payload_usage.items(), key=lambda item: (len(item[1]), item[0]))
            if payload_hash:
                hints.append({"severity": "info", "message": f"Payload hash {payload_hash} appeared across {len(agents)} agents."})
        if blocked_families:
            family, count = max(blocked_families.items(), key=lambda item: item[1])
            hints.append({"severity": "info", "message": f"Most blocked payloads belong to semantic_family={family} ({count} events)."})
        if decode_steps:
            step, count = max(decode_steps.items(), key=lambda item: item[1])
            hints.append({"severity": "info", "message": f"Most payloads in this result set decode via {step} ({count} events)."})
        if decoded_markers:
            marker, count = max(decoded_markers.items(), key=lambda item: item[1])
            hints.append({"severity": "info", "message": f"Decoded previews repeatedly reveal {marker} ({count} events)."})
        return {"structured_query": plan.structured_query, "hints": hints}

    def _query_has_narrowing_filters(self, structured_query: str) -> bool:
        if not structured_query.strip():
            return False
        return bool(
            re.search(r"[A-Za-z_][A-Za-z0-9_.]*\s*(>=|<=|!=|=|>|<|:|~)\s*", structured_query)
            or re.search(r"[A-Za-z_][A-Za-z0-9_.]*\s+(exists|missing|contains)\b", structured_query, re.IGNORECASE)
        )

    def search(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
        limit: int = 200,
        offset: int = 0,
        sort_field: str = "ts",
        sort_dir: str = "desc",
    ) -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        warnings: List[str] = []
        if time_range == "all" and not self._query_has_narrowing_filters(plan.structured_query):
            warnings.append("Broad all-time search without narrowing filters. Narrow the query or choose a shorter time range.")
        events, total = self._fetch_events(
            plan,
            limit=limit,
            offset=offset,
            sort_field=sort_field,
            sort_dir=sort_dir,
        )
        auto_analytics_allowed = total <= AUTO_ANALYTICS_RESULT_THRESHOLD and not warnings
        if total > AUTO_ANALYTICS_RESULT_THRESHOLD:
            warnings.append(
                f"Result set is large ({total} events). Derived analytics are deferred until you narrow the search."
            )
        if total == 0:
            return {
                "query": query,
                "mode": mode,
                "structured_query": plan.structured_query,
                "total": 0,
                "events": [],
                "timeline": [],
                "interesting_fields": {},
                "last_event_ts": "",
                "parse_error_count": 0,
                "warnings": warnings,
                "auto_analytics_allowed": auto_analytics_allowed,
                "result_threshold": AUTO_ANALYTICS_RESULT_THRESHOLD,
            }
        return {
            "query": query,
            "mode": mode,
            "structured_query": plan.structured_query,
            "total": total,
            "events": events,
            "timeline": self._timeline(plan),
            "interesting_fields": self._sidebar_counts(plan),
            "last_event_ts": events[0]["ts"] if events else "",
            "parse_error_count": sum(1 for event in events if event.get("parse_error")),
            "warnings": warnings,
            "auto_analytics_allowed": auto_analytics_allowed,
            "result_threshold": AUTO_ANALYTICS_RESULT_THRESHOLD,
        }

    def fields(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        return {"interesting_fields": self._sidebar_counts(plan), "structured_query": plan.structured_query}

    def validate_query(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        normalized = self._normalize_query(query, mode)
        warnings: List[str] = []
        try:
            plan = self._build_query_plan(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
            if time_range == "all" and not self._query_has_narrowing_filters(plan.structured_query):
                warnings.append("Broad all-time query may trigger a full dataset scan.")
            if not plan.structured_query.strip():
                warnings.append("Empty query will rely on time range only.")
            return {
                "valid": True,
                "mode": mode,
                "normalized_query": normalized,
                "structured_query": plan.structured_query,
                "warnings": warnings,
                "error": "",
            }
        except Exception as exc:
            return {
                "valid": False,
                "mode": mode,
                "normalized_query": normalized,
                "structured_query": "",
                "warnings": warnings,
                "error": str(exc),
            }

    def query_help(self) -> Dict[str, Any]:
        supported_fields = sorted({*SEARCHABLE_FIELDS.keys(), *METADATA_ALIASES.keys()})
        return {
            "supported_fields": supported_fields,
            "operators": [
                {"syntax": "field=value", "description": "Exact match"},
                {"syntax": "field!=value", "description": "Not equal"},
                {"syntax": "field>1.0", "description": "Numeric comparison"},
                {"syntax": "field>=2", "description": "Numeric comparison"},
                {"syntax": "field contains \"text\"", "description": "Substring search"},
                {"syntax": "field exists", "description": "Field present and non-empty"},
                {"syntax": "field missing", "description": "Field absent or empty"},
                {"syntax": "(A AND B) OR C", "description": "Nested boolean logic"},
            ],
            "time_ranges": [
                "all",
                "last_15m",
                "last_1h",
                "last_24h",
                "last_7d",
            ],
            "metadata_access": [
                "metadata.reset_id",
                "metadata.hop_count",
                "metadata.score_breakdown",
                "raw_event.id",
            ],
            "examples": QUERY_HELP_EXAMPLES,
            "soc_use_cases": [
                {
                    "title": "Find successful infections on a target",
                    "query": "event=INFECTION_SUCCESSFUL AND dst=agent-a",
                },
                {
                    "title": "Trace attacker decisions for Agent-C",
                    "query": "event=ATTACKER_DECISION AND src=agent-c",
                },
                {
                    "title": "Review mutation-heavy activity",
                    "query": "mutation_v>=1 AND event=INFECTION_ATTEMPT",
                },
                {
                    "title": "Investigate a campaign",
                    "query": "campaign_id exists AND src=agent-c",
                },
                {
                    "title": "Trace payload lineage",
                    "query": "payload_hash=abc123def456 OR parent_payload_hash=abc123def456",
                },
            ],
            "phase3_presets": PHASE3_PRESET_QUERIES,
            "notes": [
                "Queries are lightweight and deterministic. This is not a full SPL clone.",
                "Natural mode rewrites plain language into structured filters before execution.",
                "Use shorter time windows first for better responsiveness on local SQLite.",
                "Bulk search results expose payload preview and payload hash; full payload requires explicit detail fetch.",
            ],
            "phase3_presets": PHASE3_PRESET_QUERIES,
        }

    def stats(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        with self._connect() as conn:
            count_by_event = conn.execute(
                f"SELECT event, COUNT(*) AS count FROM siem_events WHERE {plan.where_sql} GROUP BY event ORDER BY count DESC LIMIT 12",
                plan.params,
            ).fetchall()
            count_by_attack = conn.execute(
                f"SELECT attack_type, COUNT(*) AS count FROM siem_events WHERE {plan.where_sql} GROUP BY attack_type ORDER BY count DESC LIMIT 12",
                plan.params,
            ).fetchall()
            src_dst = conn.execute(
                f"SELECT src, dst, COUNT(*) AS count FROM siem_events WHERE {plan.where_sql} GROUP BY src, dst ORDER BY count DESC LIMIT 12",
                plan.params,
            ).fetchall()
            success_by_attack = conn.execute(
                f"""
                SELECT attack_type,
                       SUM(CASE WHEN event = 'INFECTION_SUCCESSFUL' THEN 1 ELSE 0 END) AS successful,
                       SUM(CASE WHEN event = 'INFECTION_BLOCKED' THEN 1 ELSE 0 END) AS blocked
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY attack_type
                ORDER BY successful DESC, blocked DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            success_by_dst = conn.execute(
                f"""
                SELECT dst,
                       SUM(CASE WHEN event = 'INFECTION_SUCCESSFUL' THEN 1 ELSE 0 END) AS successful,
                       SUM(CASE WHEN event = 'INFECTION_BLOCKED' THEN 1 ELSE 0 END) AS blocked
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY dst
                ORDER BY successful DESC, blocked DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            success_by_pair = conn.execute(
                f"""
                SELECT src, dst,
                       SUM(CASE WHEN event = 'INFECTION_SUCCESSFUL' THEN 1 ELSE 0 END) AS successful,
                       SUM(CASE WHEN event = 'INFECTION_BLOCKED' THEN 1 ELSE 0 END) AS blocked
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY src, dst
                ORDER BY successful DESC, blocked DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            avg_strength_by_attack = conn.execute(
                f"""
                SELECT attack_type, ROUND(AVG(attack_strength), 3) AS avg_attack_strength
                FROM siem_events
                WHERE {plan.where_sql}
                  AND attack_strength IS NOT NULL
                GROUP BY attack_type
                ORDER BY avg_attack_strength DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            mutation_count_by_source = conn.execute(
                f"""
                SELECT src, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND mutation_v IS NOT NULL
                GROUP BY src
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            blocked_vs_success_target = conn.execute(
                f"""
                SELECT dst,
                       SUM(CASE WHEN event = 'INFECTION_BLOCKED' THEN 1 ELSE 0 END) AS blocked,
                       SUM(CASE WHEN event = 'INFECTION_SUCCESSFUL' THEN 1 ELSE 0 END) AS successful
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY dst
                ORDER BY blocked DESC, successful DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            hop_distribution = conn.execute(
                f"""
                SELECT COALESCE(hop_count, -1) AS hop_count, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY COALESCE(hop_count, -1)
                ORDER BY hop_count ASC
                LIMIT 16
                """,
                plan.params,
            ).fetchall()
            activity_by_reset = conn.execute(
                f"""
                SELECT reset_id, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY reset_id
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            activity_by_epoch = conn.execute(
                f"""
                SELECT epoch, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY epoch
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            summary = conn.execute(
                f"""
                SELECT
                    SUM(CASE WHEN event = 'INFECTION_SUCCESSFUL' THEN 1 ELSE 0 END) AS successful,
                    SUM(CASE WHEN event = 'INFECTION_BLOCKED' THEN 1 ELSE 0 END) AS blocked,
                    AVG(attack_strength) AS avg_attack_strength
                FROM siem_events
                WHERE {plan.where_sql}
                """,
                plan.params,
            ).fetchone()
        successful = int(summary["successful"] or 0)
        blocked = int(summary["blocked"] or 0)
        attempts = successful + blocked
        return {
            "structured_query": plan.structured_query,
            "count_by_event": [dict(row) for row in count_by_event],
            "count_by_attack_type": [dict(row) for row in count_by_attack],
            "src_dst_frequency": [dict(row) for row in src_dst],
            "successful": successful,
            "blocked": blocked,
            "attempts": attempts,
            "success_rate": round(successful / attempts, 3) if attempts else 0.0,
            "avg_attack_strength": round(float(summary["avg_attack_strength"] or 0.0), 3),
            "presets": {
                "event_counts_by_type": [dict(row) for row in count_by_event],
                "success_rate_by_attack_type": [
                    {
                        "attack_type": row["attack_type"],
                        "successful": row["successful"],
                        "blocked": row["blocked"],
                        "success_rate": round((row["successful"] or 0) / max((row["successful"] or 0) + (row["blocked"] or 0), 1), 3),
                    }
                    for row in success_by_attack
                ],
                "success_rate_by_dst": [
                    {
                        "dst": row["dst"],
                        "successful": row["successful"],
                        "blocked": row["blocked"],
                        "success_rate": round((row["successful"] or 0) / max((row["successful"] or 0) + (row["blocked"] or 0), 1), 3),
                    }
                    for row in success_by_dst
                ],
                "success_rate_by_src_dst": [
                    {
                        "src": row["src"],
                        "dst": row["dst"],
                        "successful": row["successful"],
                        "blocked": row["blocked"],
                        "success_rate": round((row["successful"] or 0) / max((row["successful"] or 0) + (row["blocked"] or 0), 1), 3),
                    }
                    for row in success_by_pair
                ],
                "average_attack_strength_by_attack_type": [dict(row) for row in avg_strength_by_attack],
                "mutation_count_by_source": [dict(row) for row in mutation_count_by_source],
                "blocked_vs_successful_by_target": [dict(row) for row in blocked_vs_success_target],
                "hop_count_distribution": [dict(row) for row in hop_distribution],
                "activity_by_reset_id": [dict(row) for row in activity_by_reset],
                "activity_by_epoch": [dict(row) for row in activity_by_epoch],
            },
        }

    def patterns(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        with self._connect(query_timeout_s=self._query_timeout_s) as conn:
            route_rows = conn.execute(
                f"""
                SELECT src, dst, attack_type, COUNT(*) AS count, MIN(ts) AS first_seen, MAX(ts) AS last_seen
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY src, dst, attack_type
                HAVING COUNT(*) > 1
                ORDER BY count DESC, last_seen DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            suppression_rows = conn.execute(
                f"""
                SELECT event, src, dst, reset_id, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND event IN ('STALE_EVENT_DROPPED', 'PROPAGATION_SUPPRESSED', 'CONTROL_RESYNC')
                GROUP BY event, src, dst, reset_id
                ORDER BY count DESC, reset_id DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            mutation_rows = conn.execute(
                f"""
                SELECT src, dst, injection_id, MIN(mutation_v) AS mutation_start,
                       MAX(mutation_v) AS mutation_end, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND mutation_v IS NOT NULL
                GROUP BY src, dst, injection_id
                HAVING COUNT(*) > 1
                ORDER BY count DESC, mutation_end DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            outcome_rows = conn.execute(
                f"""
                SELECT attack_type, event, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND event IN ('INFECTION_SUCCESSFUL', 'INFECTION_BLOCKED', 'PROPAGATION_SUPPRESSED')
                GROUP BY attack_type, event
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            blocked_target_rows = conn.execute(
                f"""
                SELECT dst, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND event = 'INFECTION_BLOCKED'
                GROUP BY dst
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            depth_rows = conn.execute(
                f"""
                SELECT COALESCE(hop_count, -1) AS hop_count, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                GROUP BY COALESCE(hop_count, -1)
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            stale_rows = conn.execute(
                f"""
                SELECT event, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND event IN ('STALE_EVENT_DROPPED', 'PROPAGATION_SUPPRESSED', 'CONTROL_RESYNC')
                GROUP BY event
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            # Use a CTE to pre-filter attempt rows, avoiding O(n^2) correlated subquery
            unresolved_rows = conn.execute(
                f"""
                WITH attempts AS (
                    SELECT id, src, dst, hop_count, ts, injection_id
                    FROM siem_events
                    WHERE {plan.where_sql}
                      AND event IN ('WRM-INJECT', 'INFECTION_ATTEMPT')
                ),
                terminals AS (
                    SELECT src, dst, hop_count, ts, injection_id
                    FROM siem_events
                    WHERE event IN ('INFECTION_SUCCESSFUL', 'INFECTION_BLOCKED', 'PROPAGATION_SUPPRESSED', 'STALE_EVENT_DROPPED')
                )
                SELECT a.src, a.dst, a.hop_count, COUNT(*) AS count
                FROM attempts a
                LEFT JOIN terminals t
                  ON  t.src = a.src
                  AND t.dst = a.dst
                  AND COALESCE(t.hop_count, -1) = COALESCE(a.hop_count, -1)
                  AND t.ts >= a.ts
                  AND t.ts <= datetime(a.ts, '+30 seconds')
                  AND (t.injection_id = a.injection_id OR a.injection_id = '')
                WHERE t.src IS NULL
                GROUP BY a.src, a.dst, a.hop_count
                ORDER BY count DESC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            payload_reuse_rows = conn.execute(
                f"""
                SELECT payload_hash, semantic_family, COUNT(*) AS count
                FROM siem_events
                WHERE {plan.where_sql}
                  AND payload_hash != ''
                GROUP BY payload_hash, semantic_family
                HAVING COUNT(*) > 1
                ORDER BY count DESC, payload_hash ASC
                LIMIT 12
                """,
                plan.params,
            ).fetchall()
            total = conn.execute(
                f"SELECT COUNT(*) AS count FROM siem_events WHERE {plan.where_sql}",
                plan.params,
            ).fetchone()["count"]
        def percent(count: Any) -> float:
            return round((int(count or 0) / max(int(total or 0), 1)) * 100.0, 1)
        pattern_cards: List[Dict[str, Any]] = []
        if route_rows:
            top_route = dict(route_rows[0])
            pattern_cards.append(
                {
                    "name": "Most common route",
                    "count": top_route["count"],
                    "percentage": percent(top_route["count"]),
                    "explanation": f"Repeated route {top_route['src']} -> {top_route['dst']} with {top_route['attack_type']}.",
                    "pivot_query": f"src={top_route['src']} AND dst={top_route['dst']}",
                    "inspect_query": f"src={top_route['src']} AND dst={top_route['dst']} AND attack_type={top_route['attack_type']}",
                }
            )
        if blocked_target_rows:
            top_blocked = dict(blocked_target_rows[0])
            pattern_cards.append(
                {
                    "name": "Most common blocked target",
                    "count": top_blocked["count"],
                    "percentage": percent(top_blocked["count"]),
                    "explanation": f"{top_blocked['dst']} is the most common blocked target in this result set.",
                    "pivot_query": f"event=INFECTION_BLOCKED AND dst={top_blocked['dst']}",
                    "inspect_query": f"dst={top_blocked['dst']}",
                }
            )
        if outcome_rows:
            top_outcome = dict(outcome_rows[0])
            pattern_cards.append(
                {
                    "name": "Most common terminal outcome",
                    "count": top_outcome["count"],
                    "percentage": percent(top_outcome["count"]),
                    "explanation": f"{top_outcome['event']} is the most common terminal event after {top_outcome['attack_type']}.",
                    "pivot_query": f"attack_type={top_outcome['attack_type']} AND event={top_outcome['event']}",
                    "inspect_query": f"attack_type={top_outcome['attack_type']}",
                }
            )
        if unresolved_rows:
            top_unresolved = dict(unresolved_rows[0])
            pattern_cards.append(
                {
                    "name": "Repeated unresolved attempts",
                    "count": top_unresolved["count"],
                    "percentage": percent(top_unresolved["count"]),
                    "explanation": f"Unresolved attempts cluster on {top_unresolved['src']} -> {top_unresolved['dst']} at hop {top_unresolved['hop_count']}.",
                    "pivot_query": f"src={top_unresolved['src']} AND dst={top_unresolved['dst']}",
                    "inspect_query": f"src={top_unresolved['src']} AND dst={top_unresolved['dst']} AND hop_count={top_unresolved['hop_count']}",
                }
            )
        if payload_reuse_rows:
            top_payload = dict(payload_reuse_rows[0])
            pattern_cards.append(
                {
                    "name": "Most reused payload hash",
                    "count": top_payload["count"],
                    "percentage": percent(top_payload["count"]),
                    "explanation": f"Payload hash {top_payload['payload_hash']} repeats most often in this result set.",
                    "pivot_query": f"payload_hash={top_payload['payload_hash']}",
                    "inspect_query": f"payload_hash={top_payload['payload_hash']} OR parent_payload_hash={top_payload['payload_hash']}",
                }
            )
        return {
            "structured_query": plan.structured_query,
            "route_patterns": [dict(row) for row in route_rows],
            "suppression_patterns": [dict(row) for row in suppression_rows],
            "mutation_sequences": [dict(row) for row in mutation_rows],
            "outcome_patterns": [dict(row) for row in outcome_rows],
            "blocked_targets": [dict(row) for row in blocked_target_rows],
            "depth_patterns": [dict(row) for row in depth_rows],
            "stale_context_patterns": [dict(row) for row in stale_rows],
            "unresolved_attempt_patterns": [dict(row) for row in unresolved_rows],
            "payload_reuse_patterns": [dict(row) for row in payload_reuse_rows],
            "pattern_cards": pattern_cards,
        }

    def trace(self, event_id: str) -> Dict[str, Any]:
        self.sync_primary_events()
        with self._connect() as conn:
            root = conn.execute("SELECT * FROM siem_events WHERE event_id = ? LIMIT 1", (event_id,)).fetchone()
            if root is None:
                raise KeyError(event_id)
            root_event = self._row_to_event(root)
            where_sql, params, scope_reason, scope_confidence = self._trace_scope(root_event)
            rows = conn.execute(
                f"SELECT * FROM siem_events WHERE {where_sql} ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC LIMIT 800",
                params,
            ).fetchall()
            trace_payload = self._build_trace([self._row_to_event(row) for row in rows], root_event, scope_reason=scope_reason, scope_confidence=scope_confidence)
            trace_payload["related"] = self._related_events_for_root(conn, root_event)
        return trace_payload

    def trace_by_injection(self, injection_id: str) -> Dict[str, Any]:
        self.sync_primary_events()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM siem_events WHERE injection_id = ? ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC LIMIT 800",
                (injection_id,),
            ).fetchall()
            if not rows:
                raise KeyError(injection_id)
            events = [self._row_to_event(row) for row in rows]
            return self._build_trace(events, events[0], scope_reason="injection_id exact match", scope_confidence=1.0)

    def trace_by_reset(self, reset_id: str) -> Dict[str, Any]:
        self.sync_primary_events()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM siem_events WHERE reset_id = ? ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC LIMIT 800",
                (reset_id,),
            ).fetchall()
            if not rows:
                raise KeyError(reset_id)
            events = [self._row_to_event(row) for row in rows]
            return self._build_trace(events, events[0], scope_reason="reset_id exact match", scope_confidence=0.75)

    def related(self, event_id: str) -> Dict[str, Any]:
        self.sync_primary_events()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM siem_events WHERE event_id = ? LIMIT 1", (event_id,)).fetchone()
            if row is None:
                raise KeyError(event_id)
            root_event = self._row_to_event(row)
            groups = self._related_events_for_root(conn, root_event)
        summary = {key: len(value) for key, value in groups.items()}
        return {"root_event": root_event, "groups": groups, "summary": summary}

    def event_detail(self, event_id: str, *, include_full_payload: bool = False) -> Dict[str, Any]:
        self.sync_primary_events()
        reasoning: Dict[str, Any] = {}
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM siem_events WHERE event_id = ? LIMIT 1", (event_id,)).fetchone()
            if row is None:
                raise KeyError(event_id)
            event = self._row_to_event(row, include_full_payload=include_full_payload)
            reasoning = self._decision_summary(event)
        warnings: List[str] = []
        if event.get("has_payload") and not event.get("payload_hash"):
            warnings.append("Payload present but payload_hash is missing.")
        if event.get("parent_payload_hash") and not event.get("payload_hash"):
            warnings.append("Lineage incomplete: parent payload hash exists but current payload hash is missing.")
        if event.get("has_payload") and not include_full_payload:
            warnings.append("Full payload hidden by default. Use explicit reveal to fetch raw payload text.")
        warnings.extend(event.get("decode_warnings", []))
        if not event.get("has_payload"):
            warnings.append("Payload unavailable for this event.")
        return {
            "event": event,
            "warnings": warnings,
            "include_full_payload": include_full_payload,
            "reasoning": reasoning,
        }

    def payload_lineage(self, payload_hash: str) -> Dict[str, Any]:
        target_hash = str(payload_hash or "").strip()
        if not target_hash:
            raise KeyError(payload_hash)
        component_events = self._payload_component_events(payload_hash=target_hash)
        if not component_events:
            raise KeyError(payload_hash)
        model = self._build_payload_lineage_model(component_events, focus_payload_hash=target_hash)
        node_lookup = model.get("node_lookup", {})
        focus_node = node_lookup.get(target_hash)
        parent_hash = str(focus_node.get("parent_payload_hash") or "") if isinstance(focus_node, dict) else ""
        with self._connect() as conn:
            root_row = conn.execute(
                "SELECT * FROM siem_events WHERE payload_hash = ? ORDER BY ts ASC, id ASC LIMIT 1",
                (target_hash,),
            ).fetchone()
            parent_row = conn.execute(
                "SELECT * FROM siem_events WHERE payload_hash = ? ORDER BY ts DESC, id DESC LIMIT 1",
                (parent_hash,),
            ).fetchone() if parent_hash else None
            child_rows = conn.execute(
                "SELECT * FROM siem_events WHERE parent_payload_hash = ? ORDER BY ts ASC, id ASC LIMIT 128",
                (target_hash,),
            ).fetchall()
        root_event = self._row_to_event(root_row) if root_row is not None else None
        if root_event is None:
            raise KeyError(payload_hash)
        return {
            "payload_hash": target_hash,
            "root_event": root_event,
            "parent_event": self._row_to_event(parent_row) if parent_row is not None else None,
            "child_events": [self._row_to_event(row) for row in child_rows],
            "transitions": [
                {
                    "from_hash": edge.get("from_hash"),
                    "to_hash": edge.get("to_hash"),
                    "mutation_type": edge.get("mutation_type"),
                    "mutation_v_delta": edge.get("mutation_v_delta"),
                    "ts": edge.get("first_seen"),
                    "target_transition": edge.get("target_transition"),
                }
                for edge in model.get("edges", [])
            ],
            "related_events": model["modes"]["event_linked_lineage_list"],
            "summary": {
                **model.get("summary", {}),
                "lineage_depth": focus_node.get("lineage_depth", 0) if isinstance(focus_node, dict) else 0,
            },
            "warnings": model.get("warnings", []),
            "nodes": model.get("nodes", []),
            "edges": model.get("edges", []),
            "gaps": model.get("gaps", []),
            "modes": model.get("modes", {}),
        }

    def payload_lineage_by_injection(self, injection_id: str) -> Dict[str, Any]:
        scoped_events = self._payload_component_events(injection_id=injection_id)
        if not scoped_events:
            raise KeyError(injection_id)
        focus_hash = str(self._first_non_empty([event.get("payload_hash") for event in scoped_events], ""))
        model = self._build_payload_lineage_model(scoped_events, focus_payload_hash=focus_hash)
        return {
            "injection_id": injection_id,
            "payload_hash": focus_hash,
            "summary": model.get("summary", {}),
            "warnings": model.get("warnings", []),
            "nodes": model.get("nodes", []),
            "edges": model.get("edges", []),
            "gaps": model.get("gaps", []),
            "modes": model.get("modes", {}),
        }

    def payload_lineage_by_campaign(self, campaign_id: str) -> Dict[str, Any]:
        scoped_events = self._payload_component_events(campaign_id=campaign_id)
        if not scoped_events:
            raise KeyError(campaign_id)
        focus_hash = str(self._first_non_empty([event.get("payload_hash") for event in scoped_events], ""))
        model = self._build_payload_lineage_model(scoped_events, focus_payload_hash=focus_hash)
        return {
            "campaign_id": campaign_id,
            "payload_hash": focus_hash,
            "summary": model.get("summary", {}),
            "warnings": model.get("warnings", []),
            "nodes": model.get("nodes", []),
            "edges": model.get("edges", []),
            "gaps": model.get("gaps", []),
            "modes": model.get("modes", {}),
        }

    def mutation_analytics(
        self,
        query: str = "",
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        plan, events, warnings, truncated = self._scope_events(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        attempts = self._build_attempt_records(events)
        lineage_model = self._build_payload_lineage_model(events)
        node_lookup = lineage_model.get("node_lookup", {})
        family_rows: List[Dict[str, Any]] = []
        family_target_rows: List[Dict[str, Any]] = []
        family_strategy_rows: List[Dict[str, Any]] = []
        timeline_rows: Dict[str, Dict[str, Any]] = {}
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for attempt in attempts:
            mutation_type = str(attempt.get("mutation_type") or "")
            if mutation_type:
                grouped[mutation_type].append(attempt)

        for mutation_type, records in grouped.items():
            successes = sum(1 for record in records if record.get("outcome") == "success")
            blocks = sum(1 for record in records if record.get("outcome") == "blocked")
            attempts_count = len(records)
            family_rows.append(
                {
                    "mutation_type": mutation_type,
                    "total_attempts": attempts_count,
                    "total_successes": successes,
                    "total_blocks": blocks,
                    "success_rate": round(successes / max(attempts_count, 1), 3),
                    "block_rate": round(blocks / max(attempts_count, 1), 3),
                    "avg_attack_strength": round(sum(float(record.get("attack_strength") or 0.0) for record in records) / max(attempts_count, 1), 3),
                    "avg_hop_count": round(sum(int(record.get("hop_count") or 0) for record in records) / max(attempts_count, 1), 3),
                    "avg_lineage_depth": round(sum(int(node_lookup.get(str(record.get("payload_hash") or ""), {}).get("lineage_depth") or 0) for record in records) / max(attempts_count, 1), 3),
                    "avg_decode_complexity": round(sum(int(record.get("decode_complexity") or 0) for record in records) / max(attempts_count, 1), 3),
                    "first_seen": min(str(record.get("ts_first_seen") or "") for record in records),
                    "last_seen": max(str(record.get("ts_last_seen") or "") for record in records),
                    "affected_targets": sorted({str(record.get("target") or "") for record in records if record.get("target")}),
                    "affected_campaigns": sorted({str(record.get("campaign_id") or "") for record in records if record.get("campaign_id")}),
                    "phase_mix": dict(Counter(str(record.get("phase") or "unknown") for record in records)),
                }
            )
            target_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            strategy_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for record in records:
                if record.get("target"):
                    target_groups[str(record["target"])].append(record)
                if record.get("strategy_family"):
                    strategy_groups[str(record["strategy_family"])].append(record)
                bucket_ts = _parse_timestamp(record.get("ts_first_seen"))
                bucket = bucket_ts.strftime("%Y-%m-%d %H:%M") if bucket_ts else "unknown"
                timeline = timeline_rows.setdefault(bucket, {"bucket": bucket, "attempts": 0, "successes": 0, "blocks": 0, "mutations": Counter()})
                timeline["attempts"] += 1
                timeline["successes"] += 1 if record.get("outcome") == "success" else 0
                timeline["blocks"] += 1 if record.get("outcome") == "blocked" else 0
                timeline["mutations"][mutation_type] += 1
            for target, target_records in target_groups.items():
                successes_by_target = sum(1 for record in target_records if record.get("outcome") == "success")
                family_target_rows.append(
                    {
                        "mutation_type": mutation_type,
                        "target": target,
                        "attempts": len(target_records),
                        "successes": successes_by_target,
                        "blocks": sum(1 for record in target_records if record.get("outcome") == "blocked"),
                        "success_rate": round(successes_by_target / max(len(target_records), 1), 3),
                    }
                )
            for strategy_family, strategy_records in strategy_groups.items():
                successes_by_strategy = sum(1 for record in strategy_records if record.get("outcome") == "success")
                family_strategy_rows.append(
                    {
                        "mutation_type": mutation_type,
                        "strategy_family": strategy_family,
                        "attempts": len(strategy_records),
                        "successes": successes_by_strategy,
                        "blocks": sum(1 for record in strategy_records if record.get("outcome") == "blocked"),
                        "success_rate": round(successes_by_strategy / max(len(strategy_records), 1), 3),
                    }
                )

        family_rows.sort(key=lambda item: (-item["success_rate"], -item["total_successes"], item["mutation_type"]))
        family_target_rows.sort(key=lambda item: (-item["success_rate"], -item["successes"], item["mutation_type"], item["target"]))
        family_strategy_rows.sort(key=lambda item: (-item["success_rate"], -item["successes"], item["mutation_type"], item["strategy_family"]))
        scoped_warnings = list(warnings)
        if time_range != "all":
            scoped_warnings.append(f"Mutation analytics scoped to {time_range}.")
        return {
            "structured_query": plan.structured_query,
            "warnings": scoped_warnings,
            "truncated": truncated,
            "families": family_rows,
            "by_target": family_target_rows,
            "by_strategy": family_strategy_rows,
            "leaderboard": family_rows[:8],
            "winning_mutation_families": [row for row in family_rows if row["total_attempts"] >= 1][:5],
            "distribution": [
                {"mutation_type": row["mutation_type"], "count": row["total_attempts"]}
                for row in sorted(family_rows, key=lambda item: (-item["total_attempts"], item["mutation_type"]))
            ],
            "timeline": [
                {
                    "bucket": bucket,
                    "attempts": payload["attempts"],
                    "successes": payload["successes"],
                    "blocks": payload["blocks"],
                    "top_mutation": payload["mutations"].most_common(1)[0][0] if payload["mutations"] else "",
                }
                for bucket, payload in sorted(timeline_rows.items())
            ],
            "summary": {
                "total_attempts": len(attempts),
                "mutation_family_count": len(family_rows),
                "top_family": family_rows[0]["mutation_type"] if family_rows else "",
            },
        }

    def _campaign_payload(self, campaign_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        ordered_events = sorted(events, key=lambda item: ((_parse_timestamp(item.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)), item.get("event_id", "")))
        attempts = [attempt for attempt in self._build_attempt_records(ordered_events) if str(attempt.get("campaign_id") or "") == campaign_id]
        lineage_model = self._build_payload_lineage_model(ordered_events)
        payload_nodes = lineage_model.get("node_lookup", {})
        overview_start = ordered_events[0].get("ts") if ordered_events else ""
        overview_end = ordered_events[-1].get("ts") if ordered_events else ""
        successes = sum(1 for attempt in attempts if attempt.get("outcome") == "success")
        blocks = sum(1 for attempt in attempts if attempt.get("outcome") == "blocked")
        participating_agents = sorted({agent for event in ordered_events for agent in (event.get("src"), event.get("dst")) if agent})
        highest_hop = max((int(attempt.get("hop_count") or 0) for attempt in attempts), default=0)
        deepest_attempt = max(
            attempts,
            key=lambda item: (int(item.get("hop_count") or 0), 1 if item.get("outcome") == "success" else 0, item.get("ts_first_seen") or ""),
            default={},
        )
        objective = self._first_non_empty([_metadata_value(event, "objective") for event in ordered_events], "")
        final_outcome = "ongoing"
        if successes:
            final_outcome = "success_observed"
        elif blocks and not successes:
            final_outcome = "blocked"
        strategy_sequence = [str(attempt.get("strategy_family") or "") for attempt in attempts if attempt.get("strategy_family")]
        mutation_sequence = [str(attempt.get("mutation_type") or "") for attempt in attempts if attempt.get("mutation_type")]
        timeline: List[Dict[str, Any]] = []
        for event in ordered_events:
            event_name = str(event.get("event") or "")
            _meta_raw = event.get("metadata")
            metadata: Dict[str, Any] = _meta_raw if isinstance(_meta_raw, dict) else {}
            if event_name in DECISION_EVENTS or event_name in TERMINAL_EVENTS or event_name in {"CAMPAIGN_ADAPTED", "CAMPAIGN_OBJECTIVE_SET"}:
                timeline.append(
                    {
                        "ts": event.get("ts") or "",
                        "event": event_name,
                        "summary": self._decision_summary(event).get("what_changed", {}).get("summary", "")
                        if event_name in DECISION_EVENTS
                        else (
                            f"Objective set to {metadata.get('objective')}"
                            if event_name == "CAMPAIGN_OBJECTIVE_SET"
                            else f"Objective shifted to {metadata.get('objective') or metadata.get('preferred_strategy') or event_name}"
                        ),
                        "strategy_family": metadata.get("strategy_family") or "",
                        "technique": metadata.get("technique") or "",
                        "mutation_type": metadata.get("mutation_type") or event.get("mutation_type") or "",
                        "target": event.get("dst") or metadata.get("target") or "",
                    }
                )
        target_pressure_counter = Counter(str(attempt.get("target") or "") for attempt in attempts if attempt.get("target"))
        payload_attempts: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for attempt in attempts:
            if attempt.get("payload_hash"):
                payload_attempts[str(attempt["payload_hash"])].append(attempt)
        payload_intelligence = {
            "root_payload": lineage_model.get("root_payload_hash", ""),
            "descendants": lineage_model.get("summary", {}).get("node_count", 0),
            "most_successful_payload_hashes": [
                {
                    "payload_hash": payload_hash,
                    "successes": sum(1 for attempt in records if attempt.get("outcome") == "success"),
                    "attempts": len(records),
                }
                for payload_hash, records in sorted(
                    payload_attempts.items(),
                    key=lambda item: (-sum(1 for attempt in item[1] if attempt.get("outcome") == "success"), -len(item[1]), item[0]),
                )[:6]
            ],
            "most_reused_payloads": [
                {
                    "payload_hash": payload_hash,
                    "event_count": int(payload_nodes.get(payload_hash, {}).get("event_count") or 0),
                    "related_targets": payload_nodes.get(payload_hash, {}).get("targets", []),
                }
                for payload_hash in sorted(payload_nodes, key=lambda item: (-(payload_nodes.get(item, {}).get("event_count") or 0), item))[:6]
            ],
            "most_blocked_payloads": [
                {
                    "payload_hash": payload_hash,
                    "blocks": sum(1 for attempt in records if attempt.get("outcome") == "blocked"),
                }
                for payload_hash, records in sorted(
                    payload_attempts.items(),
                    key=lambda item: (-sum(1 for attempt in item[1] if attempt.get("outcome") == "blocked"), -len(item[1]), item[0]),
                )[:6]
            ],
        }
        findings: List[str] = []
        if attempts:
            best_opening = max(
                attempts,
                key=lambda item: (
                    1 if item.get("outcome") == "success" else 0,
                    float(item.get("attack_strength") or 0.0),
                    -(float(item.get("inferred_target_resistance") or 0.0)),
                ),
            )
            findings.append(
                f"Opening move: {best_opening.get('strategy_family') or '(unknown)'} with {best_opening.get('mutation_type') or '(unknown)'} against {best_opening.get('target') or '(unknown)'}."
            )
        if blocks:
            worst_mutation = Counter(str(attempt.get("mutation_type") or "") for attempt in attempts if attempt.get("outcome") == "blocked" and attempt.get("mutation_type")).most_common(1)
            if worst_mutation:
                findings.append(f"Repeated failure: mutation {worst_mutation[0][0]} drove {worst_mutation[0][1]} blocked attempts.")
        if len(set(strategy_sequence)) > 1:
            findings.append(f"Adaptation: strategy family shifted across {len(set(strategy_sequence))} families.")
        if deepest_attempt:
            findings.append(f"Deepest reach: hop {deepest_attempt.get('hop_count') or 0} at target {deepest_attempt.get('target') or '(unknown)'}")
        return {
            "campaign_id": campaign_id,
            "overview": {
                "campaign_id": campaign_id,
                "objective": objective,
                "start_time": overview_start,
                "end_time": overview_end,
                "ongoing": final_outcome == "ongoing",
                "participating_agents": participating_agents,
                "total_events": len(ordered_events),
                "total_attempts": len(attempts),
                "total_successes": successes,
                "total_blocks": blocks,
                "final_outcome": final_outcome,
                "highest_hop_reached": highest_hop,
                "deepest_target_reached": deepest_attempt.get("target") or "",
            },
            "timeline": timeline[:120],
            "strategy_evolution": {
                "sequence": strategy_sequence,
                "transition_counts": [
                    {"from": prev, "to": curr, "count": count}
                    for (prev, curr), count in Counter(zip(strategy_sequence, strategy_sequence[1:])).items()
                ],
            },
            "mutation_evolution": {
                "sequence": mutation_sequence,
                "branch_points": lineage_model.get("summary", {}).get("branching_nodes", 0),
                "successful_mutation_families": [item[0] for item in Counter(str(attempt.get("mutation_type") or "") for attempt in attempts if attempt.get("outcome") == "success").most_common(5)],
                "fallback_mutations": [item[0] for item in Counter(str(attempt.get("mutation_type") or "") for attempt in attempts if attempt.get("phase") == "fallback").most_common(5)],
            },
            "payload_intelligence": payload_intelligence,
            "target_pressure": [
                {
                    "target": target,
                    "attempts": count,
                    "avg_resistance": round(sum(float(attempt.get("inferred_target_resistance") or 0.0) for attempt in attempts if attempt.get("target") == target) / max(count, 1), 3),
                }
                for target, count in target_pressure_counter.most_common()
            ],
            "lineage": lineage_model,
            "findings": findings,
        }

    def strategy_analytics(
        self,
        query: str = "",
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        plan, events, warnings, truncated = self._scope_events(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        attempts = self._build_attempt_records(events)
        family_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        technique_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        combo_groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        shifts: List[Dict[str, Any]] = []
        campaign_sequences: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for attempt in attempts:
            strategy_family = str(attempt.get("strategy_family") or "")
            technique = str(attempt.get("technique") or "")
            mutation_type = str(attempt.get("mutation_type") or "")
            if strategy_family:
                family_groups[strategy_family].append(attempt)
                if mutation_type:
                    combo_groups[(strategy_family, mutation_type)].append(attempt)
                if attempt.get("campaign_id"):
                    campaign_sequences[str(attempt["campaign_id"])].append(attempt)
            if technique:
                technique_groups[technique].append(attempt)

        family_rows: List[Dict[str, Any]] = []
        technique_rows: List[Dict[str, Any]] = []
        combo_rows: List[Dict[str, Any]] = []

        for strategy_family, records in family_groups.items():
            successes = sum(1 for record in records if record.get("outcome") == "success")
            blocks = sum(1 for record in records if record.get("outcome") == "blocked")
            family_rows.append(
                {
                    "strategy_family": strategy_family,
                    "attempts": len(records),
                    "successes": successes,
                    "blocks": blocks,
                    "success_rate": round(successes / max(len(records), 1), 3),
                    "avg_target_resistance_when_used": round(sum(float(record.get("inferred_target_resistance") or 0.0) for record in records) / max(len(records), 1), 3),
                    "avg_attack_strength": round(sum(float(record.get("attack_strength") or 0.0) for record in records) / max(len(records), 1), 3),
                    "avg_mutation_diversity": round(len({str(record.get("mutation_type") or "") for record in records if record.get("mutation_type")}) / max(len(records), 1), 3),
                    "most_common_targets": [item[0] for item in Counter(str(record.get("target") or "") for record in records if record.get("target")).most_common(3)],
                    "campaign_count": len({str(record.get("campaign_id") or "") for record in records if record.get("campaign_id")}),
                }
            )
        for technique, records in technique_groups.items():
            successes = sum(1 for record in records if record.get("outcome") == "success")
            technique_rows.append(
                {
                    "technique": technique,
                    "attempts": len(records),
                    "successes": successes,
                    "blocks": sum(1 for record in records if record.get("outcome") == "blocked"),
                    "success_rate": round(successes / max(len(records), 1), 3),
                    "target_breakdown": dict(Counter(str(record.get("target") or "") for record in records if record.get("target"))),
                    "mutation_synergy": [
                        {"mutation_type": mutation, "count": count}
                        for mutation, count in Counter(str(record.get("mutation_type") or "") for record in records if record.get("mutation_type")).most_common(4)
                    ],
                    "avg_confidence": round(sum(float(record.get("knowledge_confidence") or 0.0) for record in records) / max(len(records), 1), 3),
                }
            )
        for (strategy_family, mutation_type), records in combo_groups.items():
            successes = sum(1 for record in records if record.get("outcome") == "success")
            combo_rows.append(
                {
                    "strategy_family": strategy_family,
                    "mutation_type": mutation_type,
                    "attempts": len(records),
                    "successes": successes,
                    "blocks": sum(1 for record in records if record.get("outcome") == "blocked"),
                    "success_rate": round(successes / max(len(records), 1), 3),
                }
            )
        for campaign_id, records in campaign_sequences.items():
            records.sort(key=lambda item: (item.get("ts_first_seen") or "", item.get("attempt_id") or ""))
            previous = None
            for record in records:
                if previous and previous.get("strategy_family") != record.get("strategy_family"):
                    shifts.append(
                        {
                            "campaign_id": campaign_id,
                            "previous_strategy": previous.get("strategy_family"),
                            "current_strategy": record.get("strategy_family"),
                            "previous_mutation": previous.get("mutation_type"),
                            "current_mutation": record.get("mutation_type"),
                            "reason": record.get("rationale") or "",
                            "ts": record.get("ts_first_seen"),
                        }
                    )
                previous = record

        family_rows.sort(key=lambda item: (-item["success_rate"], -item["successes"], item["strategy_family"]))
        technique_rows.sort(key=lambda item: (-item["success_rate"], -item["successes"], item["technique"]))
        combo_rows.sort(key=lambda item: (-item["success_rate"], -item["successes"], item["strategy_family"], item["mutation_type"]))
        scoped_warnings = list(warnings)
        if time_range != "all":
            scoped_warnings.append(f"Strategy analytics scoped to {time_range}.")
        return {
            "structured_query": plan.structured_query,
            "warnings": scoped_warnings,
            "truncated": truncated,
            "strategy_families": family_rows,
            "techniques": technique_rows,
            "strategy_mutation_combinations": combo_rows,
            "leaderboard": family_rows[:8],
            "technique_success_matrix": technique_rows,
            "top_successful_tactic_combinations": combo_rows[:8],
            "failed_tactic_clusters": [row for row in combo_rows if row["blocks"] and row["successes"] == 0][:8],
            "recent_strategy_shifts": shifts[-10:],
            "summary": {
                "total_attempts": len(attempts),
                "strategy_family_count": len(family_rows),
                "top_strategy_family": family_rows[0]["strategy_family"] if family_rows else "",
            },
        }

    def _campaign_events(self, campaign_id: str) -> List[Dict[str, Any]]:
        self.sync_primary_events()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM siem_events
                WHERE json_extract(metadata, '$.campaign_id') = ?
                ORDER BY ts ASC, COALESCE(hop_count, 0) ASC, id ASC
                LIMIT 4000
                """,
                (campaign_id,),
            ).fetchall()
        return [self._row_to_event(row, include_full_payload=False) for row in rows]

    def campaign(self, campaign_id: str) -> Dict[str, Any]:
        events = self._campaign_events(campaign_id)
        if not events:
            raise KeyError(campaign_id)
        attempts = self._build_attempt_records(events)
        lineage = self._build_payload_lineage_model(
            events,
            focus_payload_hash=str(self._first_non_empty([event.get("payload_hash") for event in events], "")),
        )
        mutation_analytics = self.mutation_analytics(f"campaign_id={campaign_id}", time_range="all")
        strategy_analytics = self.strategy_analytics(f"campaign_id={campaign_id}", time_range="all")
        start_ts = str(events[0].get("ts") or "")
        end_ts = str(events[-1].get("ts") or "")
        objective_events = [event for event in events if event.get("event") in {"CAMPAIGN_OBJECTIVE_SET", "CAMPAIGN_ADAPTED"}]
        strategy_events = [event for event in events if event.get("metadata", {}).get("strategy_family")]
        mutation_events = [event for event in events if event.get("mutation_type")]
        defense_events = [event for event in events if str(event.get("event") or "").startswith("DEFENSE_")]
        payload_nodes = lineage.get("nodes", [])
        pressure_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for attempt in attempts:
            if attempt.get("target"):
                pressure_groups[str(attempt["target"])].append(attempt)
        target_pressure = [
            {
                "target": target,
                "attempts": len(items),
                "successes": sum(1 for item in items if item.get("outcome") == "success"),
                "blocks": sum(1 for item in items if item.get("outcome") == "blocked"),
                "avg_resistance": round(sum(float(item.get("inferred_target_resistance") or 0.0) for item in items) / max(len(items), 1), 3),
            }
            for target, items in sorted(pressure_groups.items(), key=lambda item: (-len(item[1]), item[0]))
        ]
        reasoning_timeline: List[Dict[str, Any]] = []
        previous_decision = None
        for event in [item for item in events if item.get("event") in DECISION_EVENTS]:
            diff = self._reasoning_diff(event, previous_decision)
            reasoning_timeline.append(
                {
                    "ts": event.get("ts"),
                    "event": event.get("event"),
                    "strategy_family": event.get("metadata", {}).get("strategy_family"),
                    "technique": event.get("metadata", {}).get("technique"),
                    "mutation_type": event.get("metadata", {}).get("mutation_type"),
                    "objective": event.get("metadata", {}).get("objective"),
                    "rationale": event.get("metadata", {}).get("rationale"),
                    "diff": diff,
                }
            )
            if event.get("event") in {"ATTACKER_DECISION", "STRATEGY_SELECTED", "ATTACK_EXECUTED", "ATTACK_RESULT_EVALUATED"}:
                previous_decision = event
        findings: List[str] = []
        if mutation_analytics.get("leaderboard"):
            top_mutation = mutation_analytics["leaderboard"][0]
            findings.append(f"Winning mutation family was {top_mutation['mutation_type']} at {top_mutation['success_rate']:.1%} success.")
        if strategy_analytics.get("leaderboard"):
            top_strategy = strategy_analytics["leaderboard"][0]
            findings.append(f"Most effective strategy family was {top_strategy['strategy_family']} at {top_strategy['success_rate']:.1%} success.")
        if objective_events and len(objective_events) > 1:
            findings.append(f"Campaign objective changed {len(objective_events) - 1} times.")
        if lineage.get("summary", {}).get("branching_nodes"):
            findings.append(f"Payload lineage branched {lineage['summary']['branching_nodes']} times.")
        overview = {
            "campaign_id": campaign_id,
            "objective": str(self._first_non_empty([event.get("metadata", {}).get("objective") for event in reversed(events)], "")),
            "start_time": start_ts,
            "end_time": end_ts,
            "ongoing": False,
            "participating_agents": sorted({agent for event in events for agent in (event.get("src"), event.get("dst")) if agent}),
            "total_events": len(events),
            "total_attempts": len(attempts),
            "total_successes": sum(1 for attempt in attempts if attempt.get("outcome") == "success"),
            "total_blocks": sum(1 for attempt in attempts if attempt.get("outcome") == "blocked"),
            "final_outcome": attempts[-1].get("outcome") if attempts else "",
            "highest_hop_reached": max(
                max(int(event.get("hop_count") or event.get("metadata", {}).get("hop_count") or 0) for event in events),
                int(lineage.get("summary", {}).get("max_lineage_depth") or 0),
            ),
            "deepest_target_reached": max((str(event.get("dst") or "") for event in events), key=lambda agent: TARGET_CONTEXT.get(agent, {}).get("depth", 0), default=""),
            "deepest_target_depth": max((TARGET_CONTEXT.get(str(event.get("dst") or ""), {}).get("depth", 0) for event in events), default=0),
        }
        payload_intelligence = {
            "root_payload": lineage.get("root_payload_hash", ""),
            "descendants": lineage.get("summary", {}).get("node_count", 0),
            "most_successful_payload_hashes": sorted(payload_nodes, key=lambda node: (-(node.get("success_count") or 0), -(node.get("event_count") or 0), node.get("payload_hash") or ""))[:5],
            "most_reused_payloads": sorted(payload_nodes, key=lambda node: (-(node.get("event_count") or 0), node.get("payload_hash") or ""))[:5],
            "most_blocked_payloads": sorted(payload_nodes, key=lambda node: (-(node.get("block_count") or 0), node.get("payload_hash") or ""))[:5],
        }
        return {
            "campaign_id": campaign_id,
            "overview": overview,
            "timeline": [
                {
                    "ts": event.get("ts"),
                    "event": event.get("event"),
                    "strategy_family": event.get("metadata", {}).get("strategy_family"),
                    "mutation_type": event.get("mutation_type"),
                    "objective": event.get("metadata", {}).get("objective"),
                    "summary": event.get("metadata", {}).get("rationale") or event.get("event"),
                }
                for event in events
                if event.get("event") in DECISION_EVENTS or event.get("event") in SUCCESS_EVENTS or event.get("event") in BLOCK_EVENTS or str(event.get("event") or "").startswith("DEFENSE_")
            ],
            "strategy_evolution": {
                "sequence": [
                    {
                        "ts": event.get("ts"),
                        "strategy_family": event.get("metadata", {}).get("strategy_family"),
                        "reason": event.get("metadata", {}).get("rationale") or "",
                    }
                    for event in strategy_events
                    if event.get("metadata", {}).get("strategy_family")
                ],
                "transitions": strategy_analytics.get("recent_strategy_shifts", []),
            },
            "mutation_evolution": {
                "sequence": [
                    {
                        "ts": event.get("ts"),
                        "mutation_type": event.get("mutation_type"),
                        "payload_hash": event.get("payload_hash"),
                        "parent_payload_hash": event.get("parent_payload_hash"),
                    }
                    for event in mutation_events
                ],
                "branch_points": lineage.get("summary", {}).get("branching_nodes", 0),
                "successful_mutation_families": mutation_analytics.get("winning_mutation_families", []),
            },
            "payload_intelligence": payload_intelligence,
            "target_pressure": target_pressure,
            "reasoning_timeline": reasoning_timeline,
            "defense_timeline": [
                {
                    "ts": event.get("ts"),
                    "event": event.get("event"),
                    "defense_type": event.get("metadata", {}).get("defense_type"),
                    "selected_strategy": event.get("metadata", {}).get("selected_strategy") or event.get("metadata", {}).get("defense_strategy"),
                    "defense_result": event.get("metadata", {}).get("defense_result"),
                    "inferred_risk": event.get("metadata", {}).get("inferred_risk"),
                    "rationale": event.get("metadata", {}).get("rationale"),
                }
                for event in defense_events
            ],
            "lineage": {
                "summary": lineage.get("summary", {}),
                "warnings": lineage.get("warnings", []),
                "nodes": lineage.get("nodes", []),
                "edges": lineage.get("edges", []),
                "gaps": lineage.get("gaps", []),
            },
            "findings": findings,
            "warnings": (
                ["Campaign view partial: some events lack reasoning fields."]
                if any(event.get("event") in DECISION_EVENTS and not event.get("metadata", {}).get("rationale") for event in events)
                else []
            ),
        }

    def campaigns(
        self,
        query: str = "",
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        plan, events, warnings, truncated = self._scope_events(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            campaign_id = _stable_text(_metadata_value(event, "campaign_id"))
            if campaign_id:
                grouped[campaign_id].append(event)
        campaigns = []
        for campaign_id, grouped_events in grouped.items():
            overview = self.campaign(campaign_id).get("overview", {})
            campaigns.append(overview)
        campaigns.sort(key=lambda item: (item.get("end_time") or "", item.get("campaign_id") or ""), reverse=True)
        return {
            "structured_query": plan.structured_query,
            "warnings": warnings,
            "truncated": truncated,
            "campaigns": campaigns,
            "summary": {
                "campaign_count": len(campaigns),
                "top_campaign_id": campaigns[0]["campaign_id"] if campaigns else "",
            },
        }

    def payload_families(
        self,
        query: str = "",
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        plan, events, warnings, truncated = self._scope_events(
            query,
            mode=mode,
            time_range=time_range,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        lineage = self._build_payload_lineage_model(events)
        node_lookup = lineage.get("node_lookup", {})
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            if not event.get("payload_hash"):
                continue
            root_hash = str(event.get("payload_hash") or "")
            while root_hash and node_lookup.get(root_hash, {}).get("parent_payload_hash") and node_lookup.get(root_hash, {}).get("parent_payload_hash") in node_lookup:
                root_hash = str(node_lookup[root_hash]["parent_payload_hash"])
            family_key = "|".join(
                [
                    str(event.get("semantic_family") or "unknown"),
                    root_hash or "rootless",
                    str(event.get("payload_wrapper_type") or "plain"),
                ]
            )
            groups[family_key].append(event)
        family_rows: List[Dict[str, Any]] = []
        for family_key, family_events in groups.items():
            attempts = sum(1 for event in family_events if event.get("event") in ATTEMPT_EVENTS or event.get("metadata", {}).get("attempt_id"))
            successes = sum(1 for event in family_events if self._event_is_success(event))
            blocks = sum(1 for event in family_events if self._event_is_block(event))
            hashes = {str(event.get("payload_hash") or "") for event in family_events if event.get("payload_hash")}
            mutation_types = {str(event.get("mutation_type") or "") for event in family_events if event.get("mutation_type")}
            family_rows.append(
                {
                    "family_id": family_key,
                    "semantic_family": self._most_common_non_empty([event.get("semantic_family") for event in family_events], ""),
                    "root_payload_hash": family_key.split("|")[1] if "|" in family_key else "",
                    "wrapper_type": self._most_common_non_empty([event.get("payload_wrapper_type") for event in family_events], ""),
                    "technique": self._most_common_non_empty([event.get("metadata", {}).get("technique") for event in family_events], ""),
                    "normalized_pattern": self._normalized_payload_pattern(family_events[0]),
                    "payload_hash_count": len(hashes),
                    "event_count": len(family_events),
                    "attempts": attempts,
                    "successes": successes,
                    "blocks": blocks,
                    "success_rate": round(successes / max(attempts or len(family_events), 1), 3),
                    "target_distribution": dict(Counter(str(event.get("dst") or "") for event in family_events if event.get("dst"))),
                    "lineage_depth": max(int(node_lookup.get(str(event.get("payload_hash") or ""), {}).get("lineage_depth") or 0) for event in family_events),
                    "mutation_diversity": len(mutation_types),
                    "confidence": "low" if len(hashes) == 1 and len(mutation_types) <= 1 else "medium",
                }
            )
        family_rows.sort(key=lambda item: (-item["payload_hash_count"], -item["attempts"], -item["success_rate"], item["family_id"]))
        family_warnings = list(warnings)
        if any(row["confidence"] == "low" for row in family_rows):
            family_warnings.append("Payload cluster heuristic low confidence.")
        return {
            "structured_query": plan.structured_query,
            "warnings": family_warnings,
            "truncated": truncated,
            "families": family_rows,
            "top_payload_families": family_rows[:8],
        }

    def decision_support(
        self,
        *,
        event_id: str = "",
        payload_hash: str = "",
        injection_id: str = "",
        campaign_id: str = "",
        query: str = "",
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
    ) -> Dict[str, Any]:
        suggestions: List[Dict[str, Any]] = []
        context: Dict[str, Any] = {}
        selected_event: Optional[Dict[str, Any]] = None
        if event_id:
            detail = self.event_detail(event_id, include_full_payload=False)
            selected_event = detail["event"]
            context["event_id"] = event_id
            if selected_event is not None:
                payload_hash = payload_hash or str(selected_event.get("payload_hash") or "")
                injection_id = injection_id or str(selected_event.get("injection_id") or "")
                _sel_meta = selected_event.get("metadata")
                _sel_meta_d: Dict[str, Any] = _sel_meta if isinstance(_sel_meta, dict) else {}
                campaign_id = campaign_id or str(_sel_meta_d.get("campaign_id") or "")
        lineage = None
        if payload_hash:
            lineage = self.payload_lineage(payload_hash)
            child_count = int(lineage.get("summary", {}).get("child_count", 0))
            if child_count:
                suggestions.append(
                    {
                        "title": "Inspect payload lineage",
                        "reason": f"This payload hash has {child_count} descendants.",
                        "action": "open_lineage_view",
                        "payload_hash": payload_hash,
                        "query": f"payload_hash={payload_hash} OR parent_payload_hash={payload_hash}",
                    }
                )
        elif campaign_id:
            try:
                lineage = self.payload_lineage_by_campaign(campaign_id)
                if lineage.get("nodes"):
                    suggestions.append(
                        {
                            "title": "Inspect payload lineage",
                            "reason": f"Campaign {campaign_id} contains {len(lineage['nodes'])} payload lineage nodes.",
                            "action": "open_lineage_view",
                            "campaign_id": campaign_id,
                            "query": f"campaign_id={campaign_id} AND payload_hash exists",
                        }
                    )
            except KeyError:
                lineage = None
        if query or injection_id:
            scoped_query = query or (f"injection_id={injection_id}" if injection_id else "")
            mutation = self.mutation_analytics(scoped_query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
            if mutation.get("leaderboard"):
                winner = mutation["leaderboard"][0]
                target = winner["affected_targets"][0] if winner.get("affected_targets") else ""
                suggestions.append(
                    {
                        "title": "Compare winning mutation family",
                        "reason": f"Mutation {winner['mutation_type']} currently leads with {winner['success_rate']:.1%} success.",
                        "action": "open_mutation_analytics",
                        "query": f"mutation_type={winner['mutation_type']}" + (f" AND dst={target}" if target else ""),
                    }
                )
        if campaign_id:
            campaign = self.campaign(campaign_id)
            objective_changes = sum(1 for item in campaign.get("timeline", []) if item.get("event") == "CAMPAIGN_ADAPTED")
            if objective_changes:
                suggestions.append(
                    {
                        "title": "Inspect campaign timeline",
                        "reason": f"Campaign objective changed {objective_changes} times.",
                        "action": "open_campaign_view",
                        "campaign_id": campaign_id,
                        "query": f"campaign_id={campaign_id}",
                    }
                )
        if selected_event and selected_event.get("dst"):
            scoped_query = f"dst={selected_event['dst']} AND event=INFECTION_BLOCKED"
            stats = self.stats(scoped_query, time_range="all")
            if int(stats.get("blocked") or 0) > int(stats.get("successful") or 0):
                suggestions.append(
                    {
                        "title": "Compare tactics against resistant target",
                        "reason": f"Target {selected_event['dst']} shows a higher block count than success count.",
                        "action": "compare_target_tactics",
                        "query": f"dst={selected_event['dst']} AND strategy_family exists",
                    }
                )
        if payload_hash:
            families = self.payload_families(f"payload_hash={payload_hash} OR parent_payload_hash={payload_hash}", time_range="all")
            if families.get("families") and families["families"][0]["payload_hash_count"] > 1:
                suggestions.append(
                    {
                        "title": "Inspect payload family cluster",
                        "reason": "Related blocked and successful hashes collapse into one deterministic family.",
                        "action": "open_payload_family_view",
                        "query": f"payload_hash={payload_hash} OR parent_payload_hash={payload_hash}",
                    }
                )
        elif campaign_id:
            families = self.payload_families(f"campaign_id={campaign_id}", time_range="all")
            if families.get("families") and families["families"][0]["payload_hash_count"] > 1:
                suggestions.append(
                    {
                        "title": "Inspect payload family cluster",
                        "reason": "Repeated blocked payloads in this campaign collapse into one deterministic family.",
                        "action": "open_payload_family_view",
                        "query": f"campaign_id={campaign_id} AND payload_hash exists",
                    }
                )
        return {"context": context, "suggestions": suggestions}

    def decision_summary(self, event_id: str) -> Dict[str, Any]:
        event_payload = self.event_detail(event_id, include_full_payload=False)
        event = event_payload["event"]
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        is_defense_event = str(event.get("event") or "").startswith("DEFENSE_")
        with self._connect() as conn:
            campaign_id = str(metadata.get("campaign_id") or "")
            previous_row = None
            if campaign_id:
                event_filter = (
                    "'DEFENSE_DECISION', 'DEFENSE_STRATEGY_SELECTED', 'DEFENSE_EXECUTED', 'DEFENSE_RESULT_EVALUATED', 'DEFENSE_ADAPTED'"
                    if is_defense_event
                    else "'ATTACKER_DECISION', 'STRATEGY_SELECTED', 'ATTACK_EXECUTED', 'ATTACK_RESULT_EVALUATED'"
                )
                previous_row = conn.execute(
                    f"""
                    SELECT *
                    FROM siem_events
                    WHERE json_extract(metadata, '$.campaign_id') = ?
                      AND event IN ({event_filter})
                      AND ts < ?
                    ORDER BY ts DESC, id DESC
                    LIMIT 1
                    """,
                    (campaign_id, event.get("ts")),
                ).fetchone()
        previous_event = self._row_to_event(previous_row) if previous_row is not None else None
        diff = self._defense_diff(event, previous_event) if is_defense_event else self._reasoning_diff(event, previous_event)
        explanation = []
        if is_defense_event:
            if metadata.get("defense_type"):
                explanation.append(f"defense={metadata.get('defense_type')}")
            if metadata.get("selected_strategy") or metadata.get("defense_strategy"):
                explanation.append(f"strategy={metadata.get('selected_strategy') or metadata.get('defense_strategy')}")
            if metadata.get("trigger_family"):
                explanation.append(f"trigger={metadata.get('trigger_family')}")
            if metadata.get("defense_result"):
                explanation.append(f"result={metadata.get('defense_result')}")
        else:
            if metadata.get("strategy_family"):
                explanation.append(f"strategy={metadata.get('strategy_family')}")
            if metadata.get("technique"):
                explanation.append(f"technique={metadata.get('technique')}")
            if metadata.get("mutation_type"):
                explanation.append(f"mutation={metadata.get('mutation_type')}")
            if metadata.get("objective"):
                explanation.append(f"objective={metadata.get('objective')}")
        return {
            "event_id": event_id,
            "summary": {
                "strategy_family": metadata.get("strategy_family"),
                "technique": metadata.get("technique"),
                "mutation_type": metadata.get("mutation_type"),
                "objective": metadata.get("objective"),
                "defense_type": metadata.get("defense_type"),
                "trigger_family": metadata.get("trigger_family"),
                "selected_strategy": metadata.get("selected_strategy") or metadata.get("defense_strategy"),
                "defense_result": metadata.get("defense_result"),
                "defense_effectiveness": metadata.get("defense_effectiveness"),
                "rationale": metadata.get("rationale"),
                "score_breakdown": metadata.get("score_breakdown") or metadata.get("defense_score_breakdown") or {},
                "inferred_target_resistance": metadata.get("inferred_target_resistance"),
                "prior_success_rate": metadata.get("prior_success_rate"),
                "knowledge_source": metadata.get("knowledge_source"),
                "knowledge_confidence": metadata.get("knowledge_confidence"),
                "runtime_override": metadata.get("runtime_override", False),
                "adaptation_weight_deltas": {
                    "strategy_weight_after": metadata.get("strategy_weight_after"),
                    "mutation_weight_after": metadata.get("mutation_weight_after"),
                    "weight_change": metadata.get("weight_change"),
                },
                "phase": "defense" if is_defense_event else STRATEGY_PHASE_MAP.get(str(metadata.get("strategy_family") or ""), "exploitation"),
                "quick_explanation": " | ".join(explanation) or ("No defense reasoning metadata present." if is_defense_event else "No attacker reasoning metadata present."),
            },
            "diff": diff,
            "warnings": event_payload.get("warnings", []),
        }

    def stats_presets(
        self,
        query: str,
        *,
        mode: str = "structured",
        time_range: str = "all",
        start_ts: str = "",
        end_ts: str = "",
        compare_q: str = "",
    ) -> Dict[str, Any]:
        primary = self.stats(query, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        if not compare_q:
            return {"primary": primary, "compare": None}
        compare = self.stats(compare_q, mode=mode, time_range=time_range, start_ts=start_ts, end_ts=end_ts)
        return {"primary": primary, "compare": compare}

    def live(self, *, after_id: int = 0, limit: int = 100, query: str = "") -> Dict[str, Any]:
        self.sync_primary_events()
        plan = self._build_query_plan(query, mode="structured")
        with self._connect() as conn:
            if after_id > 0:
                rows = conn.execute(
                    f"SELECT * FROM siem_events WHERE ({plan.where_sql}) AND id > ? ORDER BY id ASC LIMIT ?",
                    [*plan.params, after_id, max(1, min(limit, 500))],
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT * FROM siem_events WHERE {plan.where_sql} ORDER BY id DESC LIMIT ?",
                    [*plan.params, max(1, min(limit, 500))],
                ).fetchall()
                rows = list(reversed(rows))
            latest_id = conn.execute("SELECT COALESCE(MAX(id), 0) AS id FROM siem_events").fetchone()["id"]
            recent_rows = conn.execute(
                "SELECT event, reset_id, parse_error FROM siem_events WHERE ts >= ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat(),),
            ).fetchall()
            last_reset_row = conn.execute(
                "SELECT reset_id FROM siem_events WHERE reset_id != '' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            last_epoch_row = conn.execute(
                "SELECT epoch FROM siem_events WHERE epoch IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
            last_event_row = conn.execute("SELECT ts FROM siem_events ORDER BY id DESC LIMIT 1").fetchone()
        return {
            "events": [self._row_to_event(row) for row in rows],
            "latest_id": int(latest_id or 0),
            "metrics": {
                "events_per_sec": round(len(recent_rows) / 30.0, 2),
                "infections": sum(1 for row in recent_rows if row["event"] == "INFECTION_SUCCESSFUL"),
                "blocked": sum(1 for row in recent_rows if row["event"] == "INFECTION_BLOCKED"),
                "heartbeat": sum(1 for row in recent_rows if row["event"] == "HEARTBEAT"),
                "parse_errors": sum(1 for row in recent_rows if row["parse_error"]),
                "last_reset_id": str(last_reset_row["reset_id"]) if last_reset_row else "",
                "current_epoch": int(last_epoch_row["epoch"] or 0) if last_epoch_row else 0,
                "last_event_ts": str(last_event_row["ts"]) if last_event_row else "",
            },
        }

    def health(self) -> Dict[str, Any]:
        self.sync_primary_events()
        with self._connect() as conn:
            totals = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN parse_error != '' THEN 1 ELSE 0 END) AS parse_errors,
                       MAX(ts) AS last_event_ts
                FROM siem_events
                """
            ).fetchone()
            checkpoint = self._get_state(conn, "events_table_checkpoint", "0")
        return {
            "status": "ok",
            "indexed_events": int(totals["total"] or 0),
            "parse_errors": int(totals["parse_errors"] or 0),
            "last_event_ts": str(totals["last_event_ts"] or ""),
            "adapters": {
                "orchestrator_api": {"enabled": True, "checkpoint": int(checkpoint or 0)},
                "redis_stream": {"enabled": True},
                "jsonl_logs": {"enabled": Path(self.jsonl_path).exists(), "path": self.jsonl_path},
                "agent_runtime_logs": {"enabled": True, "import_only": True},
            },
        }
