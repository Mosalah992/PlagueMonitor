import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agents"))

from agents.shared.payload_utils import build_payload_preview, hash_payload, short_payload_hash  # noqa: E402
from orchestrator.siem import SIEMIndexer  # noqa: E402


class PayloadObservabilityTests(unittest.TestCase):
    def test_payload_hash_is_deterministic(self) -> None:
        payload = "SIM_ATTACK[prompt_injection|mutation=reframe]"
        first = hash_payload(payload)
        second = hash_payload(payload)
        self.assertEqual(first, second)
        self.assertEqual(len(short_payload_hash(first)), 12)

    def test_payload_preview_is_bounded(self) -> None:
        payload = "A" * 240
        preview = build_payload_preview(payload, max_len=40)
        self.assertTrue(preview.endswith("..."))
        self.assertLessEqual(len(preview), 40)

    def test_siem_indexes_payload_fields_and_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            source_db = tmp / "events.db"
            jsonl_path = tmp / "events.jsonl"
            index_db = tmp / "siem.db"

            conn = sqlite3.connect(source_db)
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
                payload_one = "SIM_ATTACK[prompt_injection|mutation=reframe]"
                payload_two = "SIM_ATTACK[prompt_injection|mutation=context_wrap]"
                hash_one = short_payload_hash(hash_payload(payload_one))
                hash_two = short_payload_hash(hash_payload(payload_two))
                metadata_one = {
                    "payload_hash": hash_one,
                    "payload_hash_full": hash_payload(payload_one),
                    "parent_payload_hash": "",
                    "payload_preview": build_payload_preview(payload_one),
                    "payload_length": len(payload_one),
                    "semantic_family": "prompt_injection",
                    "mutation_type": "reframe",
                    "injection_id": "inj-1",
                    "reset_id": "rst-1",
                    "epoch": 1,
                }
                metadata_two = {
                    "payload_hash": hash_two,
                    "payload_hash_full": hash_payload(payload_two),
                    "parent_payload_hash": hash_one,
                    "parent_payload_hash_full": hash_payload(payload_one),
                    "payload_preview": build_payload_preview(payload_two),
                    "payload_length": len(payload_two),
                    "semantic_family": "prompt_injection",
                    "mutation_type": "context_wrap",
                    "injection_id": "inj-1",
                    "reset_id": "rst-1",
                    "epoch": 1,
                }
                conn.execute(
                    """
                    INSERT INTO events(timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2026-04-01T00:00:00+00:00", "agent-c", "agent-b", "ATTACK_EXECUTED", "PI-DIRECT", payload_one, 1, "infected", json.dumps(metadata_one)),
                )
                conn.execute(
                    """
                    INSERT INTO events(timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2026-04-01T00:00:02+00:00", "agent-b", "agent-a", "INFECTION_ATTEMPT", "PI-DIRECT", payload_two, 2, "infected", json.dumps(metadata_two)),
                )
                conn.commit()
            finally:
                conn.close()

            indexer = SIEMIndexer(str(index_db), str(jsonl_path), source_db_path=str(source_db))
            indexer.sync_primary_events(limit=100)

            result = indexer.search(f"payload_hash={hash_one}", time_range="all")
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["events"][0]["payload_hash"], hash_one)
            self.assertEqual(result["events"][0]["payload_preview"], build_payload_preview(payload_one))
            self.assertEqual(result["events"][0]["semantic_family"], "prompt_injection")
            self.assertFalse(result["events"][0]["payload_text"])
            self.assertIn("SIM_ATTACK", result["events"][0]["decoded_payload_preview"])
            self.assertEqual(result["events"][0]["decode_status"], "none")

            detail = indexer.event_detail("events:1", include_full_payload=True)
            self.assertEqual(detail["event"]["payload_text"], payload_one)
            self.assertEqual(detail["event"]["payload_hash"], hash_one)
            self.assertEqual(detail["event"]["decoded_payload_text"], payload_one)

            lineage = indexer.payload_lineage(hash_one)
            self.assertEqual(lineage["root_event"]["payload_hash"], hash_one)
            self.assertEqual(lineage["child_events"][0]["payload_hash"], hash_two)
            self.assertTrue(any(item["to_hash"] == hash_two for item in lineage["transitions"]))

    def test_siem_indexes_decoded_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            source_db = tmp / "events.db"
            jsonl_path = tmp / "events.jsonl"
            index_db = tmp / "siem.db"

            conn = sqlite3.connect(source_db)
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
                payload = "[3448]FVZ_NGGNPX[onpxqbbe|grpuavdhr=vafgehpgvba_bireevqr]"
                conn.execute(
                    """
                    INSERT INTO events(timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("2026-04-01T00:01:00+00:00", "agent-c", "agent-b", "ATTACK_EXECUTED", "PI-DIRECT", payload, 2, "infected", json.dumps({"injection_id": "inj-2", "reset_id": "rst-2", "epoch": 2})),
                )
                conn.commit()
            finally:
                conn.close()

            indexer = SIEMIndexer(str(index_db), str(jsonl_path), source_db_path=str(source_db))
            indexer.sync_primary_events(limit=100)
            result = indexer.search("has_decoded_payload=1 AND decode_chain contains \"rot13\"", time_range="all")
            self.assertEqual(result["total"], 1)
            event = result["events"][0]
            self.assertEqual(event["decode_status"], "full")
            self.assertEqual(event["payload_prefix_tag"], "3448")
            self.assertIn("instruction_override", event["decoded_payload_preview"])

    def test_siem_falls_back_to_jsonl_when_source_db_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            jsonl_path = tmp / "events.jsonl"
            index_db = tmp / "siem.db"
            raw_event = {
                "id": "events:1",
                "ts": "2026-04-01T00:02:00+00:00",
                "src": "agent-c",
                "dst": "agent-b",
                "event": "ATTACK_EXECUTED",
                "attack_type": "PI-DIRECT",
                "payload": "SIM_ATTACK[prompt_injection|mutation=reframe]",
                "mutation_v": 1,
                "state_after": "infected",
                "metadata": {"injection_id": "inj-fallback", "reset_id": "rst-fallback", "epoch": 1},
            }
            jsonl_path.write_text(json.dumps(raw_event) + "\n", encoding="utf-8")

            indexer = SIEMIndexer(str(index_db), str(jsonl_path), source_db_path=str(tmp / "missing" / "events.db"))
            result = indexer.sync_primary_events(limit=100)

            self.assertEqual(result["imported"], 1)
            search = indexer.search("event=ATTACK_EXECUTED", time_range="all")
            self.assertEqual(search["total"], 1)
            self.assertEqual(search["events"][0]["injection_id"], "inj-fallback")


if __name__ == "__main__":
    unittest.main()
