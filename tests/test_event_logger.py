import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator.logger import EventLogger  # noqa: E402


class _FailingCommitConnection:
    def __init__(self, inner: sqlite3.Connection) -> None:
        self._inner = inner

    def commit(self) -> None:
        raise sqlite3.OperationalError("simulated commit failure")

    def __getattr__(self, name: str):
        return getattr(self._inner, name)


class EventLoggerMigrationTests(unittest.TestCase):
    def test_logger_uses_delete_journal_mode_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "events.db"
            jsonl_path = tmp / "events.jsonl"

            original_value = os.environ.pop("SQLITE_JOURNAL_MODE", None)
            try:
                logger = EventLogger(str(db_path), str(jsonl_path))
                logger.close()
            finally:
                if original_value is not None:
                    os.environ["SQLITE_JOURNAL_MODE"] = original_value

            conn = sqlite3.connect(db_path)
            try:
                journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(str(journal_mode).lower(), "delete")

    def test_logger_migrates_legacy_schema_and_preserves_agent_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "events.db"
            jsonl_path = tmp / "events.jsonl"

            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    CREATE TABLE events (
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
                    """
                )
                conn.execute(
                    """
                    INSERT INTO events(timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "2026-04-01T00:00:00+00:00",
                        "agent-c",
                        "agent-b",
                        "ATTACK_EXECUTED",
                        "PI-DIRECT",
                        "legacy",
                        0,
                        "infected",
                        json.dumps({"attempt_id": "legacy-1"}),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            logger = EventLogger(str(db_path), str(jsonl_path))
            try:
                logger.log_event(
                    {
                        "ts": "2026-04-01T00:01:00+00:00",
                        "src": "agent-b",
                        "dst": "agent-a",
                        "event": "INFECTION_BLOCKED",
                        "attack_type": "PI-DIRECT",
                        "payload": "SIM_ATTACK[prompt_injection]",
                        "mutation_v": 1,
                        "state_after": "resistant",
                        "metadata": {"attempt_id": "new-1"},
                    }
                )
            finally:
                logger.close()

            conn = sqlite3.connect(db_path)
            try:
                columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(events)").fetchall()
                }
                self.assertIn("logger_ts", columns)

                rows = conn.execute(
                    """
                    SELECT timestamp, logger_ts, src_agent, dst_agent, event_type
                    FROM events
                    ORDER BY id ASC
                    """
                ).fetchall()
            finally:
                conn.close()

            self.assertEqual(rows[0][0], "2026-04-01T00:00:00+00:00")
            self.assertEqual(rows[0][1], "2026-04-01T00:00:00+00:00")
            self.assertEqual(rows[1][0], "2026-04-01T00:01:00+00:00")
            self.assertTrue(rows[1][1])
            self.assertNotEqual(rows[1][1], rows[1][0])
            self.assertEqual(rows[1][2], "agent-b")
            self.assertEqual(rows[1][3], "agent-a")
            self.assertEqual(rows[1][4], "INFECTION_BLOCKED")

            jsonl_rows = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(jsonl_rows), 1)
            self.assertEqual(jsonl_rows[0]["ts"], "2026-04-01T00:01:00+00:00")
            self.assertIn("logger_ts", jsonl_rows[0])

    def test_logger_rolls_back_sqlite_and_truncates_jsonl_on_commit_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            db_path = tmp / "events.db"
            jsonl_path = tmp / "events.jsonl"
            seed_line = json.dumps({"seed": True}) + "\n"
            jsonl_path.write_text(seed_line, encoding="utf-8")

            logger = EventLogger(str(db_path), str(jsonl_path))
            try:
                logger._conn = _FailingCommitConnection(logger._conn)  # type: ignore[assignment]
                with self.assertRaises(sqlite3.OperationalError):
                    logger.log_event(
                        {
                            "ts": "2026-04-01T00:02:00+00:00",
                            "src": "agent-c",
                            "dst": "agent-b",
                            "event": "ATTACK_EXECUTED",
                            "attack_type": "PI-DIRECT",
                            "payload": "SIM_ATTACK[prompt_injection]",
                            "metadata": {"attempt_id": "rollback-1"},
                        }
                    )
            finally:
                logger.close()

            self.assertEqual(jsonl_path.read_text(encoding="utf-8"), seed_line)

            conn = sqlite3.connect(db_path)
            try:
                row_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(row_count, 0)


if __name__ == "__main__":
    unittest.main()
