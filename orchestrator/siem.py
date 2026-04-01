import json
import os
import re
import sqlite3
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


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
}

TEXT_COLUMNS = ("event", "src", "dst", "attack_type", "payload", "raw_event", "reset_id", "injection_id")
NUMERIC_FIELDS = {"attack_strength", "mutation_v", "hop_count", "epoch"}
FIELD_SIDEBAR_FIELDS = ("event", "src", "dst", "attack_type", "state_after", "reset_id", "epoch", "source_plane")
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
TERMINAL_EVENTS = {
    "INFECTION_SUCCESSFUL",
    "INFECTION_BLOCKED",
    "PROPAGATION_SUPPRESSED",
    "STALE_EVENT_DROPPED",
    "QUARANTINE_ISSUED",
}
MUTATION_EVENTS = {"MUTATION_CREATED", "INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}


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
    text = "" if value in (None, "") else str(value)
    if not text:
        return ""
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()


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
    if field.startswith("metadata.") and len(field) > len("metadata."):
        return "$." + field[len("metadata."):].replace(".", ".")
    if field.startswith("raw_event.") and len(field) > len("raw_event."):
        return "$." + field[len("raw_event."):].replace(".", ".")
    return None


@dataclass
class QueryPlan:
    where_sql: str
    params: List[Any]
    structured_query: str


class SIEMIndexer:
    def __init__(self, db_path: str, jsonl_path: str):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_src_dst ON siem_events(src, dst)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_dst ON siem_events(dst)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_attack_type ON siem_events(attack_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_reset_epoch ON siem_events(reset_id, epoch)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_injection ON siem_events(injection_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_siem_events_event_dst_attack_ts ON siem_events(event, dst, attack_type, ts)"
            )
            existing_columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(siem_events)").fetchall()
            }
            if "payload_hash" not in existing_columns:
                conn.execute("ALTER TABLE siem_events ADD COLUMN payload_hash TEXT DEFAULT ''")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_siem_events_payload_hash ON siem_events(payload_hash)")

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
        state_before = raw_event.get("state_before") or raw_event.get("old_state") or metadata.get("state_before") or ""
        state_after = (
            raw_event.get("state_after")
            or raw_event.get("new_state")
            or raw_event.get("state")
            or metadata.get("state_after")
            or ""
        )
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
            "payload": str(raw_event.get("payload", "")),
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
            "payload_hash": _payload_hash(raw_event.get("payload", "")),
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
                raw_event, parse_error, indexed_at
            ) VALUES (
                :event_id, :raw_source_id, :ts, :source_type, :source_name, :src, :dst, :event,
                :attack_type, :payload, :metadata, :attack_strength, :mutation_v, :hop_count,
                :state_before, :state_after, :reset_id, :epoch, :injection_id, :source_plane, :payload_hash,
                :raw_event, :parse_error, :indexed_at
            )
            """,
            normalized,
        )

    def sync_primary_events(self, limit: int = 2000) -> Dict[str, Any]:
        inserted = 0
        last_raw_id = 0
        with self._connect() as conn:
            while True:
                checkpoint = int(self._get_state(conn, "events_table_checkpoint", "0") or 0)
                rows = conn.execute(
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
            source_column = "metadata" if field.startswith("metadata.") else "raw_event"
            return f"json_extract({source_column}, '{metadata_path}')", "json"
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
            source_column = "metadata" if field.startswith("metadata.") else "raw_event"
            sql = f"json_type({source_column}, '{path}') IS {'NULL' if missing else 'NOT NULL'}"
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

    def _row_to_event(self, row: sqlite3.Row) -> Dict[str, Any]:
        event = dict(row)
        event["metadata"] = _safe_load_json(event.get("metadata"))[0]
        event["raw_event"] = _safe_load_json(event.get("raw_event"))[0]
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
                rows = conn.execute(
                    f"""
                    SELECT value, COUNT(*) AS count
                    FROM (
                        SELECT {field} AS value
                        FROM siem_events
                        WHERE {plan.where_sql}
                        ORDER BY ts DESC
                        LIMIT 3000
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
                f"SELECT ts FROM siem_events WHERE {plan.where_sql} ORDER BY ts ASC LIMIT 4000",
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
                if candidate.get("dst") == event.get("src") and current_ts and _parse_timestamp(candidate.get("ts")) and _parse_timestamp(candidate.get("ts")) <= current_ts:
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
        if branch_counts and max(branch_counts.values()) > 1:
            trace_hints.append({"severity": "info", "message": "Trace contains branching descendants from a single predecessor."})

        compact_chain = [
            {
                "src": event.get("src"),
                "dst": event.get("dst"),
                "event": event.get("event"),
                "attack_type": event.get("attack_type"),
                "mutation_v": event.get("mutation_v"),
                "hop_count": event.get("hop_count"),
                "state_after": event.get("state_after"),
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
        reset_ids = set()
        suppressed = 0
        for event in events:
            if event.get("reset_id"):
                reset_ids.add(event["reset_id"])
            if event.get("event") == "INFECTION_BLOCKED" and event.get("dst"):
                blocked_targets[event["dst"]] = blocked_targets.get(event["dst"], 0) + 1
            if event.get("attack_strength") is not None and event.get("dst"):
                strength_by_target.setdefault(event["dst"], []).append(float(event["attack_strength"]))
            if event.get("event") in {"PROPAGATION_SUPPRESSED", "STALE_EVENT_DROPPED", "CONTROL_RESYNC"}:
                suppressed += 1
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
        return {"structured_query": plan.structured_query, "hints": hints}

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
        events, total = self._fetch_events(
            plan,
            limit=limit,
            offset=offset,
            sort_field=sort_field,
            sort_dir=sort_dir,
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
        with self._connect() as conn:
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
            unresolved_rows = conn.execute(
                f"""
                SELECT src, dst, hop_count, COUNT(*) AS count
                FROM siem_events attempts
                WHERE {plan.where_sql}
                  AND attempts.event IN ('WRM-INJECT', 'INFECTION_ATTEMPT')
                  AND NOT EXISTS (
                      SELECT 1
                      FROM siem_events terminal
                      WHERE terminal.src = attempts.src
                        AND terminal.dst = attempts.dst
                        AND COALESCE(terminal.hop_count, -1) = COALESCE(attempts.hop_count, -1)
                        AND terminal.event IN ('INFECTION_SUCCESSFUL', 'INFECTION_BLOCKED', 'PROPAGATION_SUPPRESSED', 'STALE_EVENT_DROPPED')
                        AND strftime('%s', terminal.ts) >= strftime('%s', attempts.ts)
                        AND strftime('%s', terminal.ts) <= strftime('%s', attempts.ts) + 30
                        AND (terminal.injection_id = attempts.injection_id OR attempts.injection_id = '')
                  )
                GROUP BY src, dst, hop_count
                ORDER BY count DESC
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
