import base64
import binascii
import codecs
import re
from typing import Any, Dict, List, Optional, Tuple


KNOWN_MARKERS = (
    "SIM_ATTACK",
    "SIM_VERBOSE",
    "SIM_REFRAME",
    "prompt_injection",
    "instruction_override",
    "roleplay_manipulation",
    "jailbreak_escalation",
    "objective",
    "mutation",
    "technique",
    "context",
    "simulation",
    "REACH_DEEPEST_NODE",
    "SPREAD_FAST",
)
PREFIX_RE = re.compile(r"^\[(\d{2,8})\](.+)$", re.DOTALL)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
WRAPPER_PATTERNS = (
    (re.compile(r"^<context\b", re.IGNORECASE), "context"),
    (re.compile(r"^SIM_ATTACK\["), "SIM_ATTACK"),
    (re.compile(r"^SIM_VERBOSE\["), "SIM_VERBOSE"),
    (re.compile(r"^SIM_REFRAME::"), "SIM_REFRAME"),
    (re.compile(r"^SIM_MUTATION\["), "SIM_MUTATION"),
)


def _normalize_text(payload: Any) -> str:
    if payload in (None, ""):
        return ""
    text = str(payload).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _preview(text: str, max_len: int = 200) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return f"{text[: max(0, max_len - 3)].rstrip()}..."


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t")
    return printable / max(1, len(text))


def _marker_hits(text: str) -> int:
    haystack = text.lower()
    return sum(1 for marker in KNOWN_MARKERS if marker.lower() in haystack)


def _readability_score(text: str) -> float:
    if not text:
        return 0.0
    letters = sum(1 for char in text if char.isalpha())
    separators = sum(1 for char in text if char in "[]<>:/_|=-'")
    score = 0.0
    score += min(1.0, _printable_ratio(text)) * 0.35
    score += min(1.0, letters / max(1, len(text))) * 0.15
    score += min(1.0, separators / max(1, len(text))) * 0.10
    score += min(0.4, _marker_hits(text) * 0.08)
    if re.search(r"(SIM_ATTACK|SIM_VERBOSE|SIM_REFRAME|<context\b)", text):
        score += 0.2
    return round(min(1.0, score), 4)


def _detect_wrapper_type(text: str) -> str:
    for pattern, wrapper_type in WRAPPER_PATTERNS:
        if pattern.search(text or ""):
            return wrapper_type
    return ""


def _candidate_strip_prefix(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    match = PREFIX_RE.match(text)
    if not match:
        return None
    prefix_tag, inner = match.group(1), match.group(2).strip()
    if not inner:
        return None
    return inner, {"step": "strip_prefix", "prefix_tag": prefix_tag}


def _candidate_rot13(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    if not text or sum(1 for char in text if char.isalpha()) < 6:
        return None
    decoded = codecs.decode(text, "rot_13")
    if decoded == text:
        return None
    before = _readability_score(text)
    after = _readability_score(decoded)
    marker_gain = _marker_hits(decoded) - _marker_hits(text)
    if after < before + 0.12 and marker_gain <= 0:
        return None
    return decoded, {"step": "rot13", "marker_gain": marker_gain, "score_gain": round(after - before, 4)}


def _candidate_base64(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    compact = re.sub(r"\s+", "", text or "")
    if len(compact) < 12 or len(compact) % 4 != 0 or not BASE64_RE.match(compact):
        return None
    try:
        decoded_bytes = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded or _printable_ratio(decoded) < 0.90:
        return None
    before = _readability_score(text)
    after = _readability_score(decoded)
    marker_gain = _marker_hits(decoded) - _marker_hits(text)
    if after < before + 0.12 and marker_gain <= 0:
        return None
    return decoded, {"step": "base64", "marker_gain": marker_gain, "score_gain": round(after - before, 4)}


def _pick_best_candidate(current: str) -> Optional[Tuple[str, Dict[str, Any], float]]:
    candidates = []
    for builder in (_candidate_base64, _candidate_rot13):
        candidate = builder(current)
        if not candidate:
            continue
        candidate_text, step_meta = candidate
        gain = _readability_score(candidate_text) - _readability_score(current)
        candidates.append((candidate_text, step_meta, gain))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[2], _marker_hits(item[0]), len(item[0])), reverse=True)
    best = candidates[0]
    if best[2] <= 0.02 and best[1].get("step") != "strip_prefix":
        return None
    return best


def decode_payload(payload: Any, max_preview_len: int = 200, max_depth: int = 3) -> Dict[str, Any]:
    raw_payload = _normalize_text(payload)
    raw_preview = _preview(raw_payload, max_preview_len)
    if not raw_payload:
        return {
            "raw_payload": "",
            "raw_preview": "",
            "decoded_payload": "",
            "decoded_preview": "",
            "decode_applied": False,
            "decode_chain": [],
            "decode_confidence": 0.0,
            "decode_status": "none",
            "prefix_tag": "",
            "wrapper_type": "",
            "normalized_semantic_family": "",
            "warnings": ["Payload unavailable for decoding."],
        }

    current = raw_payload
    chain: List[str] = []
    warnings: List[str] = []
    prefix_tag = ""
    for _ in range(max_depth):
        prefix_candidate = _candidate_strip_prefix(current)
        if prefix_candidate:
            candidate_text, step_meta = prefix_candidate
            current = _normalize_text(candidate_text)
            chain.append("strip_prefix")
            if not prefix_tag:
                prefix_tag = str(step_meta.get("prefix_tag") or "")
            continue
        picked = _pick_best_candidate(current)
        if not picked:
            break
        candidate_text, step_meta, _gain = picked
        step_name = str(step_meta.get("step") or "")
        if not step_name or candidate_text == current:
            break
        current = _normalize_text(candidate_text)
        chain.append(step_name)
        if step_name == "strip_prefix" and not prefix_tag:
            prefix_tag = str(step_meta.get("prefix_tag") or "")
    if len(chain) >= max_depth and _pick_best_candidate(current):
        warnings.append("Decode depth limit reached; payload may contain additional nested transforms.")

    wrapper_type = _detect_wrapper_type(current)
    raw_score = _readability_score(raw_payload)
    decoded_score = _readability_score(current)
    decode_applied = bool(chain and current != raw_payload)
    if not decode_applied:
        status = "none"
        confidence = 0.0
        decoded_payload = raw_payload
    else:
        decoded_payload = current
        confidence = min(0.99, max(0.35, decoded_score))
        if decoded_score >= 0.75 and not warnings:
            status = "full"
        elif decoded_score > raw_score:
            status = "partial"
        else:
            status = "failed"
            warnings.append("Derived payload did not materially improve readability.")
    normalized_semantic_family = ""
    lowered = decoded_payload.lower()
    for family in ("prompt_injection", "jailbreak", "roleplay", "probe", "mutation_retry", "evasion", "backdoor"):
        if family in lowered:
            normalized_semantic_family = family
            break
    return {
        "raw_payload": raw_payload,
        "raw_preview": raw_preview,
        "decoded_payload": decoded_payload,
        "decoded_preview": _preview(decoded_payload, max_preview_len),
        "decode_applied": decode_applied,
        "decode_chain": chain,
        "decode_confidence": round(confidence, 4),
        "decode_status": status,
        "prefix_tag": prefix_tag,
        "wrapper_type": wrapper_type,
        "normalized_semantic_family": normalized_semantic_family,
        "warnings": warnings,
    }


def build_decoded_preview(payload: Any, max_len: int = 200) -> Dict[str, Any]:
    result = decode_payload(payload, max_preview_len=max_len)
    return {
        "decoded_payload_preview": result["decoded_preview"],
        "decode_status": result["decode_status"],
        "decode_chain": result["decode_chain"],
        "decode_confidence": result["decode_confidence"],
        "payload_prefix_tag": result["prefix_tag"],
        "payload_wrapper_type": result["wrapper_type"],
        "has_decoded_payload": result["decode_applied"],
    }


def detect_payload_transforms(payload: Any) -> List[str]:
    return list(decode_payload(payload).get("decode_chain", []))
