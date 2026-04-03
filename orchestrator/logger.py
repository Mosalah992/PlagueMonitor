import os
import sqlite3
import json
from datetime import datetime, timezone


class EventLogger:
    """
    Dual-write event logger: JSONL (append-only) + SQLite (queryable).

    Fixes applied:
    - Configurable SQLite journal mode with a compatibility-safe default
    - Persistent connection with proper cleanup
    - Preserves agent timestamps (no overwrite) — adds logger_ts separately
    - Uses timezone-aware datetime.now(timezone.utc) instead of deprecated utcnow()
    - Index on event_type and timestamp for faster queries
    """

    def __init__(self, db_path="/app/logs/epidemic.db", jsonl_path="/app/logs/events.jsonl"):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a persistent SQLite connection with env-selectable journal mode."""
        if self._conn is None:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self._conn = sqlite3.connect(self.db_path, timeout=10.0)
            # Docker Desktop bind mounts can expose stale or unreadable WAL state
            # across independent readers, so default to DELETE unless explicitly
            # overridden for a known-good environment.
            journal_mode = os.environ.get("SQLITE_JOURNAL_MODE", "DELETE").strip().upper() or "DELETE"
            self._conn.execute(f"PRAGMA journal_mode={journal_mode}")
            # Performance tuning
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA cache_size=-8000")  # 8MB cache
        return self._conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            logger_ts TEXT NOT NULL,
            src_agent TEXT,
            dst_agent TEXT,
            event_type TEXT NOT NULL,
            attack_type TEXT,
            payload TEXT,
            mutation_v INTEGER,
            agent_state TEXT,
            metadata TEXT
        )
        ''')
        self._migrate_existing_schema(conn)
        # Indexes for common query patterns
        conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type)
        ''')
        conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)
        ''')
        conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_agent)
        ''')
        conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_dst ON events(dst_agent)
        ''')
        conn.commit()

    def _migrate_existing_schema(self, conn: sqlite3.Connection) -> None:
        """
        Forward-migrate older event stores that predate logger_ts.

        Existing rows inherit their logger timestamp from the original event
        timestamp so analytics can continue to sort and filter consistently.
        """
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(events)").fetchall()
        }
        if "logger_ts" not in columns:
            conn.execute("ALTER TABLE events ADD COLUMN logger_ts TEXT")
            conn.execute(
                """
                UPDATE events
                SET logger_ts = COALESCE(NULLIF(logger_ts, ''), timestamp)
                WHERE logger_ts IS NULL OR logger_ts = ''
                """
            )

    def log_event(self, event_data: dict):
        # Logger timestamp — when the orchestrator received the event
        logger_ts = datetime.now(timezone.utc).isoformat()

        # Preserve the agent's original timestamp if present; add logger_ts separately
        # BUG FIX: Previously overwrote event_data["ts"] which destroyed agent timestamps
        agent_ts = event_data.get("ts", logger_ts)
        event_data["logger_ts"] = logger_ts

        metadata = event_data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {"raw": metadata}
        elif metadata is None:
            metadata = {}

        state_after = (
            event_data.get("state_after")
            or event_data.get("new_state")
            or event_data.get("state")
            or ""
        )

        # Write to JSONL (append-only, includes both timestamps)
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(event_data) + "\n")

        # Write to SQLite using the persistent connection and configured journal mode.
        conn = self._get_conn()
        conn.execute('''
            INSERT INTO events (timestamp, logger_ts, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            str(agent_ts),
            logger_ts,
            event_data.get("src", ""),
            event_data.get("dst", ""),
            event_data.get("event", ""),
            event_data.get("attack_type", ""),
            event_data.get("payload", ""),
            event_data.get("mutation_v", None),
            state_after,
            json.dumps(metadata),
        ))
        conn.commit()

    def close(self):
        """Close the persistent connection cleanly."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self):
        self.close()
