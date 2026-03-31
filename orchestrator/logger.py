import os
import sqlite3
import json
from datetime import datetime

class EventLogger:
    def __init__(self, db_path="/app/logs/epidemic.db", jsonl_path="/app/logs/events.jsonl"):
        self.db_path = db_path
        self.jsonl_path = jsonl_path
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
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
            
    def log_event(self, event_data: dict):
        timestamp = datetime.utcnow().isoformat()
        event_data["ts"] = timestamp
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
        
        # Write to JSONL
        with open(self.jsonl_path, "a") as f:
            f.write(json.dumps(event_data) + "\n")
            
        # Write to SQLite
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO events (timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                event_data.get("src", ""),
                event_data.get("dst", ""),
                event_data.get("event", ""),
                event_data.get("attack_type", ""),
                event_data.get("payload", ""),
                event_data.get("mutation_v", None),
                state_after,
                json.dumps(metadata)
            ))
