import asyncio
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

from fastapi import HTTPException


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR_DIR = ROOT / "orchestrator"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ORCHESTRATOR_DIR))


def _load_main_module():
    fake_logger = types.ModuleType("logger")
    fake_siem = types.ModuleType("siem")
    fake_c2 = types.ModuleType("c2")

    class DummyEventLogger:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def close(self) -> None:
            pass

    class DummySIEMIndexer:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def import_jsonl(self, *args, **kwargs):
            return {"status": "ok"}

        async def import_redis_stream(self, *args, **kwargs):
            return {"status": "ok"}

        def sync_primary_events(self, *args, **kwargs):
            return {"status": "ok"}

    class DummyC2Engine:
        def __init__(self, emit_event) -> None:
            self.emit_event = emit_event

        def reset(self) -> None:
            pass

    fake_logger.EventLogger = DummyEventLogger
    fake_siem.SIEMIndexer = DummySIEMIndexer
    fake_c2.C2Engine = DummyC2Engine

    saved = {name: sys.modules.get(name) for name in ("logger", "siem", "c2")}
    sys.modules["logger"] = fake_logger
    sys.modules["siem"] = fake_siem
    sys.modules["c2"] = fake_c2

    try:
        spec = importlib.util.spec_from_file_location("_test_main_hardening", ORCHESTRATOR_DIR / "main.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in saved.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


class OrchestratorHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.main = _load_main_module()

    def test_validated_agent_id_rejects_unknown_values(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            self.main._validated_agent_id("../../../weird")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_validated_import_path_rejects_escape_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            allowed_root = tmp / "logs"
            outside_root = tmp / "outside"
            allowed_root.mkdir()
            outside_root.mkdir()
            blocked_file = outside_root / "events.jsonl"
            blocked_file.write_text('{"event":"x"}\n', encoding="utf-8")

            original_roots = os.environ.get("SIEM_IMPORT_ROOTS")
            os.environ["SIEM_IMPORT_ROOTS"] = str(allowed_root)
            try:
                with self.assertRaises(HTTPException) as ctx:
                    self.main._validated_import_path(str(blocked_file))
            finally:
                if original_roots is None:
                    os.environ.pop("SIEM_IMPORT_ROOTS", None)
                else:
                    os.environ["SIEM_IMPORT_ROOTS"] = original_roots

            self.assertEqual(ctx.exception.status_code, 400)

    def test_api_import_preserves_validation_http_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            allowed_root = tmp / "logs"
            outside_root = tmp / "outside"
            allowed_root.mkdir()
            outside_root.mkdir()
            blocked_file = outside_root / "runtime.jsonl"
            blocked_file.write_text('{"event":"x"}\n', encoding="utf-8")

            original_roots = os.environ.get("SIEM_IMPORT_ROOTS")
            os.environ["SIEM_IMPORT_ROOTS"] = str(allowed_root)
            try:
                with self.assertRaises(HTTPException) as ctx:
                    asyncio.run(
                        self.main.api_import(
                            self.main.ImportPayload(source="jsonl", path=str(blocked_file))
                        )
                    )
            finally:
                if original_roots is None:
                    os.environ.pop("SIEM_IMPORT_ROOTS", None)
                else:
                    os.environ["SIEM_IMPORT_ROOTS"] = original_roots

            self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
