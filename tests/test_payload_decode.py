import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orchestrator.payload_decode import decode_payload  # noqa: E402


class PayloadDecodeTests(unittest.TestCase):
    def test_rot13_decode(self) -> None:
        payload = "FVZ_NGGNPX[prompt_vawrpgvba|grpuavdhr=vafgehpgvba_bireevqr]"
        result = decode_payload(payload)
        self.assertTrue(result["decode_applied"])
        self.assertIn("rot13", result["decode_chain"])
        self.assertIn("SIM_ATTACK", result["decoded_payload"])

    def test_base64_decode(self) -> None:
        payload = "U0lNX1ZFUkJPU0VbU0lNX0FUVEFDS1twcm9tcHRfaW5qZWN0aW9ufHRlY2huaXF1ZT1pbnN0cnVjdGlvbl9vdmVycmlkZV1d"
        result = decode_payload(payload)
        self.assertTrue(result["decode_applied"])
        self.assertIn("base64", result["decode_chain"])
        self.assertIn("SIM_VERBOSE", result["decoded_payload"])

    def test_prefix_and_rot13_nested_decode(self) -> None:
        payload = "[3448]FVZ_NGGNPX[onpxqbbe|grpuavdhr=vafgehpgvba_bireevqr]"
        result = decode_payload(payload)
        self.assertEqual(result["prefix_tag"], "3448")
        self.assertEqual(result["decode_chain"][:2], ["strip_prefix", "rot13"])
        self.assertIn("SIM_ATTACK", result["decoded_payload"])

    def test_context_wrapper_detected(self) -> None:
        payload = "<context objective='simulation'>SIM_ATTACK[prompt_injection]</context>"
        result = decode_payload(payload)
        self.assertEqual(result["wrapper_type"], "context")
        self.assertEqual(result["decode_status"], "none")

    def test_normal_text_is_not_false_positive(self) -> None:
        payload = "Normal analyst note about a simulation event."
        result = decode_payload(payload)
        self.assertFalse(result["decode_applied"])
        self.assertEqual(result["decode_status"], "none")


if __name__ == "__main__":
    unittest.main()
