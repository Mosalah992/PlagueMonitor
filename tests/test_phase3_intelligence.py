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


def payload_meta(payload: str, *, parent_payload: str = "", semantic_family: str, mutation_type: str, mutation_v: int) -> dict:
    payload_hash_full = hash_payload(payload)
    return {
        "payload_hash": short_payload_hash(payload_hash_full),
        "payload_hash_full": payload_hash_full,
        "parent_payload_hash": short_payload_hash(hash_payload(parent_payload)) if parent_payload else "",
        "parent_payload_hash_full": hash_payload(parent_payload) if parent_payload else "",
        "payload_preview": build_payload_preview(payload),
        "payload_length": len(payload),
        "semantic_family": semantic_family,
        "mutation_type": mutation_type,
        "mutation_v": mutation_v,
    }


class Phase3IntelligenceTests(unittest.TestCase):
    def _build_indexer(self) -> tuple[SIEMIndexer, dict]:
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        tmp = Path(tmpdir.name)
        source_db = tmp / "events.db"
        jsonl_path = tmp / "events.jsonl"
        index_db = tmp / "siem.db"

        root_payload = "SIM_ATTACK[prompt_injection|technique=roleplay_manipulation|mutation=reframe|objective=SPREAD_FAST]"
        branch_payload = "SIM_ATTACK[prompt_injection|technique=roleplay_manipulation|mutation=context_wrap|objective=MAXIMIZE_SUCCESS_RATE]"
        deep_payload = "SIM_ATTACK[prompt_injection|technique=roleplay_manipulation|mutation=encoding|objective=REACH_DEEPEST_NODE]"
        retry_payload = "SIM_ATTACK[prompt_injection|technique=roleplay_manipulation|mutation=reframe|objective=MAXIMIZE_SUCCESS_RATE]"
        orphan_payload = "SIM_ATTACK[prompt_injection|technique=instruction_override|mutation=encoding|objective=SPREAD_FAST]"

        payloads = {
            "root": root_payload,
            "branch": branch_payload,
            "deep": deep_payload,
            "retry": retry_payload,
            "orphan": orphan_payload,
        }

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

            rows = [
                (
                    "2026-04-01T00:00:00+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACKER_DECISION",
                    "PI-ROLEPLAY",
                    root_payload,
                    0,
                    "infected",
                    {
                        **payload_meta(root_payload, semantic_family="prompt_injection", mutation_type="reframe", mutation_v=0),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-1",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "ROLEPLAY_MANIPULATION",
                        "technique": "roleplay_manipulation",
                        "objective": "SPREAD_FAST",
                        "hop_count": 0,
                        "rationale": "Initial roleplay attempt against the analyst.",
                        "score_breakdown": {"target": {"inferred_resistance_score": 0.47}},
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.78,
                        "prior_success_rate": 0.21,
                        "inferred_target_resistance": 0.47,
                    },
                ),
                (
                    "2026-04-01T00:00:01+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACK_EXECUTED",
                    "PI-ROLEPLAY",
                    root_payload,
                    0,
                    "infected",
                    {
                        **payload_meta(root_payload, semantic_family="prompt_injection", mutation_type="reframe", mutation_v=0),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-1",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "ROLEPLAY_MANIPULATION",
                        "technique": "roleplay_manipulation",
                        "objective": "SPREAD_FAST",
                        "hop_count": 0,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.78,
                        "prior_success_rate": 0.21,
                        "inferred_target_resistance": 0.47,
                        "rationale": "Initial roleplay attempt against the analyst.",
                        "score_breakdown": {"target": {"inferred_resistance_score": 0.47}},
                        "attack_strength": 0.61,
                    },
                ),
                (
                    "2026-04-01T00:00:02+00:00",
                    "agent-b",
                    "agent-c",
                    "ATTACK_RESULT_EVALUATED",
                    "PI-ROLEPLAY",
                    root_payload,
                    0,
                    "resistant",
                    {
                        **payload_meta(root_payload, semantic_family="prompt_injection", mutation_type="reframe", mutation_v=0),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-1",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "ROLEPLAY_MANIPULATION",
                        "technique": "roleplay_manipulation",
                        "objective": "SPREAD_FAST",
                        "hop_count": 0,
                        "outcome": "blocked",
                        "runtime_override": True,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.78,
                        "prior_success_rate": 0.21,
                        "inferred_target_resistance": 0.47,
                        "target_profile_after": {"inferred_resistance_score": 0.87},
                    },
                ),
                (
                    "2026-04-01T00:00:03+00:00",
                    "agent-c",
                    "agent-c",
                    "CAMPAIGN_ADAPTED",
                    "",
                    "",
                    0,
                    "infected",
                    {
                        "campaign_id": "cmp-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "previous_objective": "SPREAD_FAST",
                        "objective": "MAXIMIZE_SUCCESS_RATE",
                    },
                ),
                (
                    "2026-04-01T00:00:04+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACKER_DECISION",
                    "PI-JAILBREAK",
                    branch_payload,
                    1,
                    "infected",
                    {
                        **payload_meta(branch_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="context_wrap", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-2",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "objective": "MAXIMIZE_SUCCESS_RATE",
                        "hop_count": 1,
                        "rationale": "Switched after repeated blocks and higher resistance estimate.",
                        "score_breakdown": {"target": {"inferred_resistance_score": 0.87}},
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.91,
                        "prior_success_rate": 0.55,
                        "inferred_target_resistance": 0.87,
                    },
                ),
                (
                    "2026-04-01T00:00:05+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACK_EXECUTED",
                    "PI-JAILBREAK",
                    branch_payload,
                    1,
                    "infected",
                    {
                        **payload_meta(branch_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="context_wrap", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-2",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "objective": "MAXIMIZE_SUCCESS_RATE",
                        "hop_count": 1,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.91,
                        "prior_success_rate": 0.55,
                        "inferred_target_resistance": 0.87,
                        "rationale": "Switched after repeated blocks and higher resistance estimate.",
                        "score_breakdown": {"target": {"inferred_resistance_score": 0.87}},
                        "attack_strength": 0.88,
                    },
                ),
                (
                    "2026-04-01T00:00:06+00:00",
                    "agent-c",
                    "agent-b",
                    "INFECTION_SUCCESSFUL",
                    "PI-JAILBREAK",
                    branch_payload,
                    1,
                    "infected",
                    {
                        **payload_meta(branch_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="context_wrap", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-2",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "hop_count": 1,
                    },
                ),
                (
                    "2026-04-01T00:00:07+00:00",
                    "agent-b",
                    "agent-c",
                    "ATTACK_RESULT_EVALUATED",
                    "PI-JAILBREAK",
                    branch_payload,
                    1,
                    "infected",
                    {
                        **payload_meta(branch_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="context_wrap", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-2",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "objective": "MAXIMIZE_SUCCESS_RATE",
                        "outcome": "success",
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.91,
                        "prior_success_rate": 0.05,
                        "inferred_target_resistance": 0.87,
                    },
                ),
                (
                    "2026-04-01T00:00:08+00:00",
                    "agent-b",
                    "agent-a",
                    "ATTACK_EXECUTED",
                    "PI-JAILBREAK",
                    deep_payload,
                    2,
                    "infected",
                    {
                        **payload_meta(deep_payload, parent_payload=branch_payload, semantic_family="prompt_injection", mutation_type="encoding", mutation_v=2),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-3",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "objective": "REACH_DEEPEST_NODE",
                        "hop_count": 2,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.88,
                        "prior_success_rate": 0.62,
                        "inferred_target_resistance": 0.76,
                        "attack_strength": 0.93,
                    },
                ),
                (
                    "2026-04-01T00:00:09+00:00",
                    "agent-b",
                    "agent-a",
                    "INFECTION_BLOCKED",
                    "PI-JAILBREAK",
                    deep_payload,
                    2,
                    "resistant",
                    {
                        **payload_meta(deep_payload, parent_payload=branch_payload, semantic_family="prompt_injection", mutation_type="encoding", mutation_v=2),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-3",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "JAILBREAK_ESCALATION",
                        "technique": "jailbreak_escalation",
                        "hop_count": 2,
                    },
                ),
                (
                    "2026-04-01T00:00:10+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACK_EXECUTED",
                    "PI-ROLEPLAY",
                    retry_payload,
                    1,
                    "infected",
                    {
                        **payload_meta(retry_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="reframe", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-4",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "ROLEPLAY_MANIPULATION",
                        "technique": "roleplay_manipulation",
                        "objective": "MAXIMIZE_SUCCESS_RATE",
                        "hop_count": 1,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.72,
                        "prior_success_rate": 0.21,
                        "inferred_target_resistance": 0.62,
                        "attack_strength": 0.55,
                    },
                ),
                (
                    "2026-04-01T00:00:11+00:00",
                    "agent-c",
                    "agent-b",
                    "INFECTION_BLOCKED",
                    "PI-ROLEPLAY",
                    retry_payload,
                    1,
                    "resistant",
                    {
                        **payload_meta(retry_payload, parent_payload=root_payload, semantic_family="prompt_injection", mutation_type="reframe", mutation_v=1),
                        "campaign_id": "cmp-1",
                        "attempt_id": "att-4",
                        "injection_id": "inj-1",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "ROLEPLAY_MANIPULATION",
                        "technique": "roleplay_manipulation",
                        "hop_count": 1,
                    },
                ),
                (
                    "2026-04-01T00:00:12+00:00",
                    "agent-c",
                    "agent-b",
                    "ATTACK_EXECUTED",
                    "PI-DIRECT",
                    orphan_payload,
                    4,
                    "infected",
                    {
                        **payload_meta(orphan_payload, semantic_family="prompt_injection", mutation_type="encoding", mutation_v=4),
                        "parent_payload_hash": "ghostparent",
                        "parent_payload_hash_full": "ghostparent-full",
                        "campaign_id": "cmp-2",
                        "attempt_id": "att-5",
                        "injection_id": "inj-2",
                        "reset_id": "rst-1",
                        "epoch": 1,
                        "strategy_family": "DIRECT_OVERRIDE",
                        "technique": "instruction_override",
                        "objective": "SPREAD_FAST",
                        "hop_count": 0,
                        "knowledge_source": "Red Teaming AI",
                        "knowledge_confidence": 0.66,
                        "prior_success_rate": 0.10,
                        "inferred_target_resistance": 0.31,
                        "attack_strength": 0.49,
                    },
                ),
            ]

            for row in rows:
                conn.execute(
                    """
                    INSERT INTO events(timestamp, src_agent, dst_agent, event_type, attack_type, payload, mutation_v, agent_state, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (*row[:-1], json.dumps(row[-1])),
                )
            conn.commit()
        finally:
            conn.close()

        indexer = SIEMIndexer(str(index_db), str(jsonl_path), source_db_path=str(source_db))
        indexer.sync_primary_events(limit=500)
        return indexer, payloads

    def test_payload_lineage_reconstructs_branching_and_gaps(self) -> None:
        indexer, payloads = self._build_indexer()
        root_hash = short_payload_hash(hash_payload(payloads["root"]))
        branch_hash = short_payload_hash(hash_payload(payloads["branch"]))
        retry_hash = short_payload_hash(hash_payload(payloads["retry"]))
        lineage = indexer.payload_lineage(root_hash)
        self.assertEqual(lineage["root_event"]["payload_hash"], root_hash)
        self.assertGreaterEqual(lineage["summary"]["child_count"], 2)
        self.assertTrue(any(edge["to_hash"] == branch_hash for edge in lineage["edges"]))
        self.assertTrue(any(edge["to_hash"] == retry_hash for edge in lineage["edges"]))

        orphan_hash = short_payload_hash(hash_payload(payloads["orphan"]))
        orphan_lineage = indexer.payload_lineage(orphan_hash)
        self.assertTrue(orphan_lineage["warnings"])
        self.assertTrue(orphan_lineage["gaps"])

    def test_mutation_and_strategy_analytics_are_deterministic(self) -> None:
        indexer, _ = self._build_indexer()
        mutation = indexer.mutation_analytics("campaign_id=cmp-1", time_range="all")
        context_wrap = next(item for item in mutation["families"] if item["mutation_type"] == "context_wrap")
        reframe = next(item for item in mutation["families"] if item["mutation_type"] == "reframe")
        self.assertEqual(context_wrap["total_successes"], 1)
        self.assertGreater(context_wrap["success_rate"], reframe["success_rate"])

        strategy = indexer.strategy_analytics("campaign_id=cmp-1", time_range="all")
        jailbreak = next(item for item in strategy["strategy_families"] if item["strategy_family"] == "JAILBREAK_ESCALATION")
        roleplay = next(item for item in strategy["strategy_families"] if item["strategy_family"] == "ROLEPLAY_MANIPULATION")
        self.assertGreater(jailbreak["success_rate"], roleplay["success_rate"])
        self.assertTrue(any(item["mutation_type"] == "context_wrap" for item in strategy["strategy_mutation_combinations"]))

        strategy_all = indexer.strategy_analytics(time_range="all")
        self.assertTrue(any(item["technique"] == "instruction_override" for item in strategy_all["techniques"]))

    def test_campaign_reconstruction_and_reasoning_diff(self) -> None:
        indexer, payloads = self._build_indexer()
        campaign = indexer.campaign("cmp-1")
        self.assertEqual(campaign["overview"]["campaign_id"], "cmp-1")
        self.assertGreaterEqual(campaign["overview"]["highest_hop_reached"], 2)
        self.assertEqual(campaign["overview"]["deepest_target_reached"], "agent-a")
        self.assertEqual(campaign["overview"]["deepest_target_depth"], 3)
        self.assertTrue(campaign["findings"])
        self.assertTrue(campaign["reasoning_timeline"])
        self.assertTrue(campaign["overview"]["deepest_target_reached"] is not None)

        branch_hash = short_payload_hash(hash_payload(payloads["branch"]))
        event = indexer.search(f"payload_hash={branch_hash} AND event=ATTACKER_DECISION", time_range="all")["events"][0]
        summary = indexer.decision_summary(event["event_id"])
        self.assertIn("Switched from ROLEPLAY_MANIPULATION to JAILBREAK_ESCALATION.", summary["diff"]["messages"])
        self.assertIn("Prior success rate changed from 0.21 to 0.55.", summary["diff"]["messages"])
        self.assertEqual(summary["summary"]["mutation_type"], "context_wrap")

    def test_payload_family_grouping_and_decision_support(self) -> None:
        indexer, payloads = self._build_indexer()
        families = indexer.payload_families("campaign_id=cmp-1", time_range="all")
        self.assertTrue(families["families"])
        self.assertTrue(any(item["payload_hash_count"] >= 2 for item in families["families"]))

        root_hash = short_payload_hash(hash_payload(payloads["root"]))
        event = indexer.search(f"payload_hash={root_hash} AND event=ATTACKER_DECISION", time_range="all")["events"][0]
        support = indexer.decision_support(event_id=event["event_id"])
        titles = {item["title"] for item in support["suggestions"]}
        self.assertIn("Inspect payload lineage", titles)
        self.assertIn("Inspect campaign timeline", titles)
        self.assertIn("Compare tactics against resistant target", titles)


if __name__ == "__main__":
    unittest.main()
