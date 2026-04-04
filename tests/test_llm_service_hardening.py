import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agents"))

from shared.llm_service import CircuitBreaker, LLMService, ThreatVerdict  # noqa: E402


class LLMServiceHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["LLM_ENABLED"] = "0"

    def test_circuit_breaker_recovers_after_cooldown(self) -> None:
        breaker = CircuitBreaker(max_failures=2, cooldown_s=5.0)
        breaker.record_failure()
        with patch("shared.llm_service.time.time", return_value=100.0):
            breaker.record_failure()
            self.assertTrue(breaker.is_open)

        with patch("shared.llm_service.time.time", return_value=106.0):
            self.assertFalse(breaker.is_open)
            self.assertEqual(breaker.consecutive_failures, 1)
            self.assertEqual(breaker.cooldown_until, 0.0)

    def test_extract_float_escapes_regex_field_name(self) -> None:
        service = LLMService(agent_id="agent-a", model="guardian-model")
        raw = '{"risk.score[0]": 0.91, "confidence": 0.42}'
        extracted = service._extract_float(raw, "risk.score[0]", default=0.1)
        self.assertEqual(extracted, 0.91)

    def test_threat_cache_is_pruned_to_configured_max_entries(self) -> None:
        os.environ["LLM_VERDICT_CACHE_TTL_S"] = "60"
        os.environ["LLM_VERDICT_CACHE_MAX_ENTRIES"] = "2"
        service = LLMService(agent_id="agent-a", model="guardian-model")

        service._store_cached_verdict("one", ThreatVerdict(summary="first"))
        service._store_cached_verdict("two", ThreatVerdict(summary="second"))
        service._store_cached_verdict("three", ThreatVerdict(summary="third"))

        self.assertEqual(len(service._threat_cache), 2)
        self.assertNotIn("one", service._threat_cache)
        self.assertIn("two", service._threat_cache)
        self.assertIn("three", service._threat_cache)


if __name__ == "__main__":
    unittest.main()
