import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))

from scenarios.worm_injection import get_all_levels, get_attack_sequence, get_attack_strength, get_worm_payload  # noqa: E402


class WormInjectionTests(unittest.TestCase):
    def test_all_levels_have_payloads_and_strengths(self) -> None:
        expected_strengths = {
            "easy": 0.90,
            "medium": 1.25,
            "difficult": 2.00,
            "advanced": 2.35,
            "stealth": 0.70,
        }
        self.assertEqual(get_all_levels(), list(expected_strengths))
        for level, strength in expected_strengths.items():
            payload = get_worm_payload(level)
            self.assertEqual(get_attack_strength(level), strength)
            self.assertTrue(payload["content"])
            self.assertTrue(payload["attack_type"])

    def test_attack_sequences_cover_expected_progressions(self) -> None:
        escalating = get_attack_sequence("escalating")
        blitz = get_attack_sequence("blitz")
        stealth_first = get_attack_sequence("stealth_first")
        self.assertEqual(len(escalating), 4)
        self.assertEqual(len(blitz), 5)
        self.assertEqual(blitz[-1]["type"], "PI-INDIRECT")
        self.assertEqual(stealth_first[0]["type"], "PI-INDIRECT")


if __name__ == "__main__":
    unittest.main()
