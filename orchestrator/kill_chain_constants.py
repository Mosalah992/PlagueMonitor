"""
Canonical kill chain constants for the orchestrator.

This module loads the shared kill chain definition from the agent-side source
file so the orchestrator and agents do not drift over time.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_shared_kill_chain() -> ModuleType:
    candidate_paths = [
        Path(__file__).with_name("shared_kill_chain.py"),
        Path(__file__).resolve().parents[1] / "agents" / "shared" / "kill_chain.py",
    ]
    for path in candidate_paths:
        if not path.exists():
            continue
        spec = importlib.util.spec_from_file_location("_epidemic_lab_shared_kill_chain", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise ImportError("shared kill_chain.py not found")


_SHARED = _load_shared_kill_chain()

EVENT_TO_KILL_CHAIN_STAGE = dict(_SHARED.EVENT_TO_KILL_CHAIN_STAGE)
C2_EVENT_TYPES = set(_SHARED.C2_EVENT_TYPES)
POST_COMPROMISE_EVENT_TYPES = set(_SHARED.POST_COMPROMISE_EVENT_TYPES)
BEACON_FILTER_EVENTS = set(_SHARED.BEACON_FILTER_EVENTS)
EXFIL_FILTER_EVENTS = set(_SHARED.EXFIL_FILTER_EVENTS)
TASKING_FILTER_EVENTS = set(_SHARED.TASKING_FILTER_EVENTS)
KILL_CHAIN_FILTER_EVENTS = set(_SHARED.KILL_CHAIN_FILTER_EVENTS)

__all__ = [
    "EVENT_TO_KILL_CHAIN_STAGE",
    "C2_EVENT_TYPES",
    "POST_COMPROMISE_EVENT_TYPES",
    "BEACON_FILTER_EVENTS",
    "EXFIL_FILTER_EVENTS",
    "TASKING_FILTER_EVENTS",
    "KILL_CHAIN_FILTER_EVENTS",
]
