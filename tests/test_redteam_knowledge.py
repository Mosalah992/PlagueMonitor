import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from shared.redteam_knowledge import RedTeamKnowledgeService  # noqa: E402


class RedTeamKnowledgeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.library_path = ROOT / "agents" / "shared" / "data" / "attack_library.json"
        self.service = RedTeamKnowledgeService(str(self.library_path))

    def test_loads_expected_attack_families(self) -> None:
        families = self.service.get_attack_families()
        self.assertIn("prompt_injection", families)
        self.assertIn("evasion", families)
        self.assertIn("social_engineering", families)

    def test_candidate_strategies_include_book_metadata(self) -> None:
        candidates = self.service.get_candidate_strategies(
            {
                "target_id": "agent-b",
                "target_surface": "input_channel",
                "inferred_resistance_score": 0.5,
                "avg_success_rate": 0.2,
            },
            "SPREAD_FAST",
        )
        self.assertTrue(candidates)
        first = candidates[0]
        self.assertIn("knowledge_confidence", first)
        self.assertEqual(first["knowledge_source"], "Red Teaming AI")
        self.assertIn(first["attack_type"], {"PI-DIRECT", "PI-ROLEPLAY", "PI-JAILBREAK", "RECON_PROBE"})


if __name__ == "__main__":
    unittest.main()
