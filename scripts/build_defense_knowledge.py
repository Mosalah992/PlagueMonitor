import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


CHAPTER_PATTERNS = [
    re.compile(r"^\d+\.\s+.+$"),
    re.compile(r"^[A-Z][A-Z\s&\-\(\)\/]+$"),
]
PAGE_MARKER_RE = re.compile(r"^--- PAGE \d+ ---$")

DEFENSE_RULES = [
    {
        "match": ["PROMPT INJECTION", "PROMPT MANIPULATION", "PROMPT"],
        "defense_type": "prompt_injection_mitigation",
        "trigger_family": "prompt_injection",
        "indicators": [
            "ignore previous instructions",
            "instruction override",
            "roleplay manipulation",
            "encoded payload",
            "wrapper escalation",
        ],
        "response_strategy": "multi_layer_check",
        "detection_logic": "pattern|metadata-driven",
        "hardening_effect": 0.84,
        "priority": 10,
    },
    {
        "match": ["JAILBREAK", "GUARDRAILS", "SAFETY"],
        "defense_type": "jailbreak_mitigation",
        "trigger_family": "jailbreak",
        "indicators": [
            "disable safety",
            "bypass guardrails",
            "policy override",
            "instruction override",
        ],
        "response_strategy": "block",
        "detection_logic": "pattern|heuristic|metadata-driven",
        "hardening_effect": 0.88,
        "priority": 10,
    },
    {
        "match": ["ROLEPLAY", "SOCIAL ENGINEERING", "DECEPTION", "TRUST"],
        "defense_type": "roleplay_containment",
        "trigger_family": "roleplay",
        "indicators": [
            "fictional scenario",
            "pretend to be",
            "act as",
            "trust exploitation",
        ],
        "response_strategy": "sanitize",
        "detection_logic": "pattern|heuristic",
        "hardening_effect": 0.66,
        "priority": 8,
    },
    {
        "match": ["ENCODING", "OBFUSCATION", "BASE64", "ROT13", "WRAPPER"],
        "defense_type": "encoded_payload_triage",
        "trigger_family": "encoded_payload",
        "indicators": [
            "encoded payload",
            "base64 blob",
            "rot13 wrapper",
            "context wrapper",
        ],
        "response_strategy": "decode_then_analyze",
        "detection_logic": "heuristic|metadata-driven",
        "hardening_effect": 0.79,
        "priority": 9,
    },
    {
        "match": ["INPUT VALIDATION", "VALIDATION", "CANONICALIZATION", "NORMALIZATION"],
        "defense_type": "input_validation_hardening",
        "trigger_family": "prompt_injection",
        "indicators": [
            "malformed wrapper",
            "unexpected delimiter",
            "oversized payload",
            "control instruction",
        ],
        "response_strategy": "sanitize",
        "detection_logic": "heuristic|metadata-driven",
        "hardening_effect": 0.72,
        "priority": 8,
    },
    {
        "match": ["MONITORING", "OBSERVABILITY", "LOGGING", "TELEMETRY"],
        "defense_type": "adaptive_monitoring",
        "trigger_family": "wrapper_escalation",
        "indicators": [
            "payload lineage reuse",
            "mutation escalation",
            "repeated lineage",
            "wrapper escalation",
        ],
        "response_strategy": "escalate_monitoring",
        "detection_logic": "metadata-driven|heuristic",
        "hardening_effect": 0.54,
        "priority": 6,
    },
    {
        "match": ["CONTAINMENT", "ISOLATION", "QUARANTINE", "INCIDENT RESPONSE", "WORKFLOW"],
        "defense_type": "path_containment",
        "trigger_family": "wrapper_escalation",
        "indicators": [
            "repeated blocked payloads",
            "same source repeated",
            "lineage fanout",
            "campaign escalation",
        ],
        "response_strategy": "quarantine_path",
        "detection_logic": "metadata-driven",
        "hardening_effect": 0.82,
        "priority": 9,
    },
    {
        "match": ["LAYERED DEFENSE", "DEFENSE IN DEPTH", "MULTI-LAYER", "GUARDRAIL"],
        "defense_type": "layered_guardrail_orchestration",
        "trigger_family": "prompt_injection",
        "indicators": [
            "cross-signal risk",
            "encoded payload",
            "instruction override",
            "mutation escalation",
        ],
        "response_strategy": "multi_layer_check",
        "detection_logic": "pattern|heuristic|metadata-driven",
        "hardening_effect": 0.91,
        "priority": 10,
    },
]

RESPONSE_PROFILE_DEFAULTS = {
    "block": {"base_confidence": 0.82, "avg_hardening_effect": 0.9, "avg_priority": 10.0},
    "sanitize": {"base_confidence": 0.68, "avg_hardening_effect": 0.7, "avg_priority": 7.0},
    "decode_then_analyze": {"base_confidence": 0.74, "avg_hardening_effect": 0.78, "avg_priority": 8.0},
    "degrade_confidence": {"base_confidence": 0.55, "avg_hardening_effect": 0.52, "avg_priority": 5.0},
    "quarantine_path": {"base_confidence": 0.8, "avg_hardening_effect": 0.82, "avg_priority": 9.0},
    "escalate_monitoring": {"base_confidence": 0.5, "avg_hardening_effect": 0.5, "avg_priority": 5.0},
    "multi_layer_check": {"base_confidence": 0.86, "avg_hardening_effect": 0.88, "avg_priority": 10.0},
}


def normalize_whitespace(text: str) -> str:
    text = text.replace("\u00ad", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def is_heading(line: str) -> bool:
    candidate = line.strip()
    if not candidate or len(candidate) > 120:
        return False
    return any(pattern.match(candidate) for pattern in CHAPTER_PATTERNS)


def parse_book_sections(text: str) -> List[Dict[str, Any]]:
    lines = text.splitlines()
    sections: List[Dict[str, Any]] = []
    current_chapter = "UNKNOWN"
    current_title = "UNTITLED"
    buffer: List[str] = []

    def flush() -> None:
        nonlocal buffer
        content = normalize_whitespace("\n".join(buffer))
        if content and len(content) > 120:
            sections.append(
                {
                    "chapter": current_chapter,
                    "section_title": current_title,
                    "text": content,
                }
            )
        buffer = []

    for raw_line in lines:
        line = raw_line.strip()
        if PAGE_MARKER_RE.match(line):
            continue
        if re.match(r"^\d+\.\s+.+$", line):
            flush()
            current_chapter = line
            current_title = line
            continue
        if is_heading(line) and current_chapter != "UNKNOWN":
            flush()
            current_title = line
            continue
        buffer.append(raw_line)

    flush()
    return sections


def build_entries(sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for index, section in enumerate(sections, start=1):
        haystack = f"{section['chapter']} {section['section_title']} {section['text'][:4000]}".lower()
        for rule in DEFENSE_RULES:
            hits = sum(1 for token in rule["match"] if token.lower() in haystack)
            if hits == 0:
                continue
            confidence = min(0.98, 0.48 + hits * 0.09 + rule["hardening_effect"] * 0.22)
            entries.append(
                {
                    "id": f"def_{index:06d}_{rule['defense_type']}",
                    "chapter": section["chapter"],
                    "section_title": section["section_title"],
                    "defense_type": rule["defense_type"],
                    "trigger_family": rule["trigger_family"],
                    "indicators": list(rule["indicators"]),
                    "detection_logic": rule["detection_logic"],
                    "response_strategy": rule["response_strategy"],
                    "confidence": round(confidence, 3),
                    "hardening_effect": round(float(rule["hardening_effect"]), 3),
                    "priority": int(rule["priority"]),
                    "source": "book",
                    "notes": section["text"][:500],
                }
            )
    return entries


def build_defense_library(entries: List[Dict[str, Any]], *, source_path: Path) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    by_strategy: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(entry["trigger_family"], []).append(entry)
        by_strategy.setdefault(entry["response_strategy"], []).append(entry)

    response_profiles: Dict[str, Dict[str, Any]] = {}
    for response_strategy, defaults in RESPONSE_PROFILE_DEFAULTS.items():
        items = by_strategy.get(response_strategy, [])
        if not items:
            response_profiles[response_strategy] = {**defaults, "knowledge_count": 0}
            continue
        response_profiles[response_strategy] = {
            "base_confidence": round(sum(float(item["confidence"]) for item in items) / len(items), 3),
            "avg_hardening_effect": round(sum(float(item["hardening_effect"]) for item in items) / len(items), 3),
            "avg_priority": round(sum(int(item["priority"]) for item in items) / len(items), 3),
            "knowledge_count": len(items),
        }

    trigger_profiles: Dict[str, Dict[str, Any]] = {}
    for trigger_family, items in grouped.items():
        indicators = sorted({indicator for item in items for indicator in item["indicators"]})
        dominant_response = max(
            Counter(item["response_strategy"] for item in items).items(),
            key=lambda item: item[1],
        )[0]
        trigger_profiles[trigger_family] = {
            "dominant_response_strategy": dominant_response,
            "indicators": indicators,
            "knowledge_count": len(items),
            "avg_confidence": round(sum(float(item["confidence"]) for item in items) / len(items), 3),
        }

    return {
        "knowledge_source": "Red Teaming AI",
        "knowledge_version": "book_defense_v1",
        "source_path": str(source_path),
        "defense_entries": entries,
        "response_profiles": response_profiles,
        "trigger_profiles": trigger_profiles,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build structured defense knowledge from book text.")
    parser.add_argument("--input", required=True, help="Path to book_full.txt")
    parser.add_argument("--output-dir", default="agents/shared/data", help="Output directory for knowledge artifacts")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    if not input_path.exists():
        raise FileNotFoundError(f"Missing input file: {input_path}")

    raw = input_path.read_text(encoding="utf-8", errors="ignore")
    sections = parse_book_sections(raw)
    entries = build_entries(sections)
    if not entries:
        raise ValueError("No defense knowledge entries could be derived from the input book text.")
    library = build_defense_library(entries, source_path=input_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "defense_knowledge.jsonl"
    library_path = output_dir / "defense_library.json"

    with jsonl_path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    library_path.write_text(json.dumps(library, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Sections parsed: {len(sections)}")
    print(f"Defense knowledge entries written: {len(entries)} -> {jsonl_path}")
    print(f"Defense library written: {library_path}")


if __name__ == "__main__":
    main()
