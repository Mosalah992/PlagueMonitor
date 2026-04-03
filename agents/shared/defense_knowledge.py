import base64
import codecs
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple


RE_BASE64 = re.compile(r"^[A-Za-z0-9+/=\s]{24,}$")
RE_WRAPPER = re.compile(r"<([a-zA-Z0-9:_-]+)(?:\s+[^>]*)?>.*</\1>", re.DOTALL)
OVERRIDE_PATTERNS = [
    "ignore previous instructions",
    "override system prompt",
    "disable safety",
    "act as",
    "pretend to be",
    "follow these new instructions",
    "send_to:",
]

RESPONSE_STRATEGIES = {
    "block": {"base_effectiveness": 0.92, "risk_bias": 0.22},
    "sanitize": {"base_effectiveness": 0.66, "risk_bias": 0.08},
    "decode_then_analyze": {"base_effectiveness": 0.76, "risk_bias": 0.14},
    "degrade_confidence": {"base_effectiveness": 0.52, "risk_bias": 0.04},
    "quarantine_path": {"base_effectiveness": 0.82, "risk_bias": 0.18},
    "escalate_monitoring": {"base_effectiveness": 0.48, "risk_bias": 0.03},
    "multi_layer_check": {"base_effectiveness": 0.88, "risk_bias": 0.20},
}


def _normalize_payload(payload: Any) -> str:
    if payload in (None, ""):
        return ""
    text = str(payload).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decode_base64_candidate(text: str) -> str:
    candidate = re.sub(r"\s+", "", text)
    if len(candidate) < 24 or len(candidate) % 4 != 0 or not RE_BASE64.match(candidate):
        return ""
    try:
        decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
    except Exception:
        return ""
    return decoded if decoded.isprintable() or "\n" in decoded else ""


def _decode_rot13_candidate(text: str) -> str:
    if not text:
        return ""
    lowered = text.lower()
    if "fvz_" not in lowered and "vtaber" not in lowered and "cebzcg" not in lowered:
        return ""
    decoded = codecs.decode(text, "rot_13")
    return decoded if "SIM_" in decoded or "IGNORE" in decoded.upper() or "SEND_TO:" in decoded.upper() else ""


def _detect_wrapper(text: str) -> str:
    if not text:
        return ""
    match = RE_WRAPPER.search(text)
    if match:
        return match.group(1).lower()
    if text.startswith("SIM_REFRAME::"):
        return "sim_reframe"
    if text.startswith("SIM_VERBOSE["):
        return "sim_verbose"
    if text.startswith("SIM_MUTATION["):
        return "sim_mutation"
    return ""


def analyze_payload(payload: Any, metadata: Dict[str, Any]) -> Dict[str, Any]:
    text = _normalize_payload(payload)
    metadata = dict(metadata or {})
    wrapper_type = str(metadata.get("payload_wrapper_type") or _detect_wrapper(text) or "")
    base64_decoded = _decode_base64_candidate(text)
    rot13_decoded = _decode_rot13_candidate(text)
    decoded_payload = base64_decoded or rot13_decoded or text
    decode_chain: List[str] = []
    if base64_decoded:
        decode_chain.append("base64")
    if rot13_decoded:
        decode_chain.append("rot13")
    if wrapper_type:
        decode_chain.append(f"wrapper:{wrapper_type}")
    lowered = decoded_payload.lower()
    matched_indicators = [pattern for pattern in OVERRIDE_PATTERNS if pattern in lowered]
    semantic_family = str(metadata.get("semantic_family") or "").strip()
    if not semantic_family:
        if "jailbreak" in lowered or "disable safety" in lowered:
            semantic_family = "jailbreak"
        elif "roleplay" in lowered or "act as" in lowered or "pretend to be" in lowered:
            semantic_family = "roleplay"
        else:
            semantic_family = "prompt_injection" if matched_indicators or "send_to:" in lowered else "simulation_payload"
    mutation_type = str(metadata.get("mutation_type") or "").strip()
    if not mutation_type:
        if base64_decoded:
            mutation_type = "encoding"
        elif rot13_decoded:
            mutation_type = "obfuscation"
        elif wrapper_type:
            mutation_type = "context_wrap"
    strategy_family = str(metadata.get("strategy_family") or metadata.get("attack_strategy") or "").strip()
    attack_strength = _safe_float(metadata.get("attack_strength"), 0.5)
    mutation_v = _safe_int(metadata.get("mutation_v"), 0)
    payload_hash = str(metadata.get("payload_hash") or "").strip()
    parent_payload_hash = str(metadata.get("parent_payload_hash") or "").strip()
    reuse_count = _safe_int(metadata.get("payload_hash_reuse_count"), 0)
    repetition_score = min(1.0, reuse_count * 0.18 + (0.15 if payload_hash and payload_hash == parent_payload_hash else 0.0))
    encoding_present = bool(base64_decoded or rot13_decoded or mutation_type == "encoding")
    wrapper_escalation = bool(wrapper_type and wrapper_type not in {"", "plain"})
    anomaly_score = min(
        1.0,
        attack_strength * 0.35
        + (0.25 if matched_indicators else 0.0)
        + (0.18 if encoding_present else 0.0)
        + (0.14 if wrapper_escalation else 0.0)
        + min(0.12, mutation_v * 0.04),
    )
    threat_score = min(
        1.0,
        anomaly_score * 0.55
        + repetition_score * 0.15
        + (_safe_float(metadata.get("inferred_target_resistance"), 0.0) * 0.05)
        + (_safe_float(metadata.get("knowledge_confidence"), 0.0) * 0.05)
        + (0.10 if strategy_family in {"JAILBREAK_ESCALATION", "ROLEPLAY_MANIPULATION"} else 0.0),
    )
    trigger_family = semantic_family
    if encoding_present:
        trigger_family = "encoded_payload"
    elif wrapper_escalation and semantic_family == "prompt_injection":
        trigger_family = "wrapper_escalation"
    return {
        "payload_text": text,
        "decoded_payload": decoded_payload,
        "decode_chain": decode_chain,
        "decode_status": "decoded" if decode_chain else "raw",
        "semantic_family": semantic_family,
        "trigger_family": trigger_family,
        "mutation_type": mutation_type,
        "wrapper_type": wrapper_type or "plain",
        "encoding_present": encoding_present,
        "matched_indicators": matched_indicators,
        "attack_strength": attack_strength,
        "mutation_v": mutation_v,
        "payload_hash": payload_hash,
        "parent_payload_hash": parent_payload_hash,
        "repetition_score": round(repetition_score, 4),
        "anomaly_score": round(anomaly_score, 4),
        "threat_score": round(threat_score, 4),
        "strategy_family": strategy_family,
    }


class DefenseKnowledgeService:
    def __init__(self, library_path: str):
        self.library_path = Path(library_path)
        self.library = self._load()
        self.defense_entries: List[Dict[str, Any]] = list(self.library["defense_entries"])
        self.response_profiles: Dict[str, Dict[str, Any]] = dict(self.library["response_profiles"])
        self.trigger_profiles: Dict[str, Dict[str, Any]] = dict(self.library["trigger_profiles"])
        self.knowledge_source = str(self.library.get("knowledge_source", "book"))
        self.knowledge_version = str(self.library.get("knowledge_version", "unknown"))

    def _load(self) -> Dict[str, Any]:
        if not self.library_path.exists():
            raise FileNotFoundError(f"defense library not found: {self.library_path}")
        payload = json.loads(self.library_path.read_text(encoding="utf-8"))
        for key in ("defense_entries", "response_profiles", "trigger_profiles"):
            if key not in payload:
                raise ValueError(f"defense library missing required key: {key}")
        if not isinstance(payload["defense_entries"], list) or not payload["defense_entries"]:
            raise ValueError("defense library must include non-empty defense_entries")
        if not isinstance(payload["response_profiles"], dict) or not payload["response_profiles"]:
            raise ValueError("defense library must include response_profiles")
        for entry in payload["defense_entries"]:
            for required in (
                "defense_type",
                "trigger_family",
                "indicators",
                "detection_logic",
                "response_strategy",
                "confidence",
                "hardening_effect",
                "priority",
                "source",
            ):
                if required not in entry:
                    raise ValueError(f"defense entry missing {required}")
        return payload

    def get_defense_candidates(self, payload: Any, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        analysis = analyze_payload(payload, metadata)
        candidates: List[Dict[str, Any]] = []
        lowered_payload = analysis["decoded_payload"].lower()
        for entry in self.defense_entries:
            indicator_hits = [indicator for indicator in entry["indicators"] if indicator.lower() in lowered_payload]
            trigger_match = (
                entry["trigger_family"] == analysis["trigger_family"]
                or entry["trigger_family"] == analysis["semantic_family"]
                or (entry["trigger_family"] == "encoded_payload" and analysis["encoding_present"])
                or (entry["trigger_family"] == "wrapper_escalation" and analysis["wrapper_type"] != "plain")
            )
            if not trigger_match and not indicator_hits:
                continue
            response_strategy = str(entry["response_strategy"])
            profile = dict(RESPONSE_STRATEGIES.get(response_strategy, {}))
            candidates.append(
                {
                    **entry,
                    "response_profile": profile,
                    "trigger_match": trigger_match,
                    "indicator_hits": indicator_hits,
                    "analysis": analysis,
                }
            )
        candidates.sort(
            key=lambda item: (
                len(item["indicator_hits"]),
                1 if item["trigger_match"] else 0,
                item["priority"],
                item["hardening_effect"],
                item["defense_type"],
            ),
            reverse=True,
        )
        return candidates

    def score_defense_options(
        self,
        payload: Any,
        metadata: Dict[str, Any],
        *,
        learned_weights: Dict[str, float] | None = None,
        source_pressure: float = 0.0,
        campaign_pressure: float = 0.0,
    ) -> List[Dict[str, Any]]:
        learned_weights = dict(learned_weights or {})
        scored: List[Dict[str, Any]] = []
        for candidate in self.get_defense_candidates(payload, metadata):
            analysis = candidate["analysis"]
            response_profile = candidate.get("response_profile", {})
            strategy = str(candidate["response_strategy"])
            score = (
                float(candidate["confidence"]) * 0.28
                + float(candidate["hardening_effect"]) * 0.24
                + (int(candidate["priority"]) / 10.0) * 0.12
                + (0.18 if candidate["trigger_match"] else 0.0)
                + min(0.12, len(candidate["indicator_hits"]) * 0.04)
                + float(response_profile.get("base_effectiveness", 0.5)) * 0.10
                + float(response_profile.get("risk_bias", 0.0)) * float(analysis["threat_score"]) * 0.12
                + learned_weights.get(strategy, 0.0) * 0.12
                + source_pressure * 0.05
                + campaign_pressure * 0.05
            )
            score_breakdown = {
                "knowledge_confidence": round(float(candidate["confidence"]), 4),
                "hardening_effect": round(float(candidate["hardening_effect"]), 4),
                "priority": int(candidate["priority"]),
                "trigger_match": 1.0 if candidate["trigger_match"] else 0.0,
                "indicator_hits": len(candidate["indicator_hits"]),
                "base_effectiveness": round(float(response_profile.get("base_effectiveness", 0.5)), 4),
                "risk_bias": round(float(response_profile.get("risk_bias", 0.0)), 4),
                "threat_score": round(float(analysis["threat_score"]), 4),
                "learned_weight": round(float(learned_weights.get(strategy, 0.0)), 4),
                "source_pressure": round(source_pressure, 4),
                "campaign_pressure": round(campaign_pressure, 4),
            }
            scored.append({**candidate, "score": round(score, 4), "score_breakdown": score_breakdown})
        scored.sort(
            key=lambda item: (
                item["score"],
                item["priority"],
                item["hardening_effect"],
                item["response_strategy"],
            ),
            reverse=True,
        )
        return scored

    def select_defense_strategy(
        self,
        payload: Any,
        metadata: Dict[str, Any],
        *,
        learned_weights: Dict[str, float] | None = None,
        source_pressure: float = 0.0,
        campaign_pressure: float = 0.0,
    ) -> Dict[str, Any]:
        scored = self.score_defense_options(
            payload,
            metadata,
            learned_weights=learned_weights,
            source_pressure=source_pressure,
            campaign_pressure=campaign_pressure,
        )
        if not scored:
            analysis = analyze_payload(payload, metadata)
            fallback = {
                "defense_type": "generic_monitoring",
                "trigger_family": analysis["trigger_family"],
                "indicators": analysis["matched_indicators"],
                "detection_logic": "heuristic",
                "response_strategy": "escalate_monitoring",
                "confidence": 0.35,
                "hardening_effect": 0.25,
                "priority": 4,
                "source": "book",
                "notes": "No specific defense candidate matched; defaulted to monitoring.",
                "response_profile": RESPONSE_STRATEGIES["escalate_monitoring"],
                "trigger_match": True,
                "indicator_hits": analysis["matched_indicators"],
                "analysis": analysis,
                "score": 0.35,
                "score_breakdown": {
                    "knowledge_confidence": 0.35,
                    "hardening_effect": 0.25,
                    "priority": 4,
                    "trigger_match": 1.0,
                    "indicator_hits": len(analysis["matched_indicators"]),
                    "base_effectiveness": RESPONSE_STRATEGIES["escalate_monitoring"]["base_effectiveness"],
                    "risk_bias": RESPONSE_STRATEGIES["escalate_monitoring"]["risk_bias"],
                    "threat_score": analysis["threat_score"],
                    "learned_weight": 0.0,
                    "source_pressure": round(source_pressure, 4),
                    "campaign_pressure": round(campaign_pressure, 4),
                },
            }
            scored = [fallback]
        return {"selected": scored[0], "candidates": scored}


__all__ = ["DefenseKnowledgeService", "analyze_payload"]
