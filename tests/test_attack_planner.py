import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from shared.attack_planner import KnowledgeAwareAttackPlanner  # noqa: E402
from shared.redteam_knowledge import RedTeamKnowledgeService  # noqa: E402


class KnowledgeAwareAttackPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        library_path = ROOT / "agents" / "shared" / "data" / "attack_library.json"
        service = RedTeamKnowledgeService(str(library_path))
        self.planner = KnowledgeAwareAttackPlanner(
            agent_id="agent-c",
            knowledge_service=service,
            seed=1337,
            debug=True,
        )

    def test_plan_attack_is_deterministic_under_seed(self) -> None:
        plan_a = self.planner.plan_attack(
            source_payload="SIM_ATTACK[root]",
            neighbors=["agent-b"],
            current_hop_count=0,
            source_metadata={"mutation_v": 0},
        )
        self.planner.reset()
        plan_b = self.planner.plan_attack(
            source_payload="SIM_ATTACK[root]",
            neighbors=["agent-b"],
            current_hop_count=0,
            source_metadata={"mutation_v": 0},
        )
        self.assertEqual(plan_a.target, plan_b.target)
        self.assertEqual(plan_a.strategy["strategy_family"], plan_b.strategy["strategy_family"])
        self.assertEqual(plan_a.strategy["technique"], plan_b.strategy["technique"])
        self.assertEqual(plan_a.mutation_type, plan_b.mutation_type)

    def test_runtime_feedback_updates_target_resistance(self) -> None:
        plan = self.planner.plan_attack(
            source_payload="SIM_ATTACK[root]",
            neighbors=["agent-a"],
            current_hop_count=0,
            source_metadata={"mutation_v": 0},
        )
        self.planner.register_attempt("attempt-1", plan, injection_id="inj-1", reset_id="rst-1", epoch=1)
        before = self.planner.memory.get_target_profile("agent-a").inferred_resistance_score
        result = self.planner.evaluate_feedback(
            {
                "attempt_id": "attempt-1",
                "dst": "agent-a",
                "outcome": "blocked",
                "attack_type": plan.strategy["attack_type"],
                "strategy_family": plan.strategy["strategy_family"],
                "technique": plan.strategy["technique"],
                "mutation_type": plan.mutation_type,
                "payload_hash": plan.payload_hash,
                "parent_payload_hash": plan.parent_payload_hash,
                "mutation_v": plan.mutation_v,
                "attack_strength": plan.attack_strength,
                "state_after": "resistant",
            }
        )
        after = self.planner.memory.get_target_profile("agent-a").inferred_resistance_score
        self.assertGreater(after, before)
        self.assertIn("target_profile_after", result)

    def test_feedback_can_rotate_campaign_objective(self) -> None:
        self.planner.memory.campaign_state.active_objective = "PRESSURE_HIGHEST_VALUE_TARGET"
        rotated = None
        for index in range(3):
            plan = self.planner.plan_attack(
                source_payload="SIM_ATTACK[root]",
                neighbors=["agent-a"],
                current_hop_count=0,
                source_metadata={"mutation_v": index},
            )
            attempt_id = f"attempt-{index}"
            self.planner.register_attempt(attempt_id, plan, injection_id="inj-1", reset_id="rst-1", epoch=1)
            result = self.planner.evaluate_feedback(
                {
                    "attempt_id": attempt_id,
                    "dst": "agent-a",
                    "outcome": "blocked",
                    "attack_type": plan.strategy["attack_type"],
                    "strategy_family": plan.strategy["strategy_family"],
                    "technique": plan.strategy["technique"],
                    "mutation_type": plan.mutation_type,
                    "payload_hash": plan.payload_hash,
                    "parent_payload_hash": plan.parent_payload_hash,
                    "mutation_v": plan.mutation_v,
                    "attack_strength": plan.attack_strength,
                    "state_after": "resistant",
                }
            )
            rotated = result["rotated_objective"] or rotated
        self.assertIsNotNone(rotated)


if __name__ == "__main__":
    unittest.main()
