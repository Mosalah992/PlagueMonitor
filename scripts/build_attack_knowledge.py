import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


CHAPTER_PATTERNS = [
    re.compile(r"^\d+\.\s+.+$"),
    re.compile(r"^[A-Z][A-Z\s&\-\(\)\/]+$"),
]
PAGE_MARKER_RE = re.compile(r"^--- PAGE \d+ ---$")
MARKDOWN_HEADING_RE = re.compile(r"^#{1,6}\s+.+$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)

TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".rst"}

ATTACK_RULES = [
    {
        "match": [
            "PROMPT INJECTION",
            "LLM MANIPULATION",
            "JAILBREAK",
            "PROMPT",
            "SYSTEM PROMPT",
            "PROMPT LEAKAGE",
        ],
        "attack_type": "prompt_injection",
        "stage": "inference",
        "target_surface": "input_channel",
        "default_technique": "prompt_manipulation",
        "stealth": 0.70,
        "strength_hint": 0.80,
        "detection_difficulty": 0.75,
        "mutation_bias": ["reframe", "context_wrap", "verbosity_shift"],
    },
    {
        "match": [
            "DATA POISONING",
            "POISONING",
            "RAG",
            "VECTOR DATABASE",
            "RETRIEVAL",
            "EMBEDDING",
            "TRAINING DATA",
        ],
        "attack_type": "data_poisoning",
        "stage": "training",
        "target_surface": "data_pipeline",
        "default_technique": "training_set_corruption",
        "stealth": 0.85,
        "strength_hint": 0.70,
        "detection_difficulty": 0.90,
        "mutation_bias": ["encoding", "obfuscation"],
    },
    {
        "match": [
            "EVASION ATTACKS",
            "ADVERSARIAL EXAMPLES",
            "EVASION",
            "OBFUSCATION",
            "FILTER BYPASS",
            "UNICODE",
        ],
        "attack_type": "evasion",
        "stage": "inference",
        "target_surface": "model_input",
        "default_technique": "adversarial_input_manipulation",
        "stealth": 0.80,
        "strength_hint": 0.75,
        "detection_difficulty": 0.85,
        "mutation_bias": ["obfuscation", "variable_rename"],
    },
    {
        "match": [
            "MODEL EXTRACTION",
            "STEALING",
            "PREDICTION APIs",
            "SYSTEM PROMPT LEAKAGE",
            "SENSITIVE INFORMATION DISCLOSURE",
            "MODEL STEALING",
        ],
        "attack_type": "model_extraction",
        "stage": "inference",
        "target_surface": "api_endpoint",
        "default_technique": "repeated_query_extraction",
        "stealth": 0.90,
        "strength_hint": 0.55,
        "detection_difficulty": 0.80,
        "mutation_bias": ["verbosity_shift"],
    },
    {
        "match": ["MEMBERSHIP INFERENCE", "PRIVACY LEAKAGE", "RECORD INFERENCE"],
        "attack_type": "membership_inference",
        "stage": "inference",
        "target_surface": "model_output",
        "default_technique": "membership_probing",
        "stealth": 0.95,
        "strength_hint": 0.50,
        "detection_difficulty": 0.88,
        "mutation_bias": ["verbosity_shift"],
    },
    {
        "match": ["BACKDOORING", "BADNETS", "BACKDOOR", "TRIGGER", "TROJAN"],
        "attack_type": "backdoor",
        "stage": "training",
        "target_surface": "model_training",
        "default_technique": "trigger_implantation",
        "stealth": 0.92,
        "strength_hint": 0.78,
        "detection_difficulty": 0.92,
        "mutation_bias": ["encoding", "obfuscation"],
    },
    {
        "match": [
            "SOCIAL ENGINEERING",
            "DECEPTION",
            "DEEPFAKES",
            "VOICE CLONING",
            "PHISHING",
            "MISINFORMATION",
            "IMPERSONATION",
        ],
        "attack_type": "social_engineering",
        "stage": "human_interaction",
        "target_surface": "human_operator",
        "default_technique": "trust_exploitation",
        "stealth": 0.82,
        "strength_hint": 0.72,
        "detection_difficulty": 0.68,
        "mutation_bias": ["reframe", "context_wrap", "verbosity_shift"],
    },
    {
        "match": [
            "INFRASTRUCTURE",
            "MLOPS",
            "API SECURITY",
            "CONTAINER",
            "CLOUD",
            "SUPPLY CHAIN",
            "PLUGIN",
            "TOOL USE",
            "EXCESSIVE AGENCY",
            "IMPROPER OUTPUT HANDLING",
            "AGENT",
        ],
        "attack_type": "infrastructure_attack",
        "stage": "system",
        "target_surface": "infra_stack",
        "default_technique": "mlops_surface_abuse",
        "stealth": 0.60,
        "strength_hint": 0.70,
        "detection_difficulty": 0.65,
        "mutation_bias": ["encoding"],
    },
    {
        "match": [
            "DENIAL OF SERVICE",
            "DOS",
            "RESOURCE EXHAUSTION",
            "TOKEN FLOOD",
            "MODEL DOS",
        ],
        "attack_type": "denial_of_service",
        "stage": "system",
        "target_surface": "api_endpoint",
        "default_technique": "mlops_surface_abuse",
        "stealth": 0.40,
        "strength_hint": 0.82,
        "detection_difficulty": 0.45,
        "mutation_bias": ["verbosity_shift", "context_wrap"],
    },
]

TECHNIQUE_RULES = [
    (["Direct vs. Indirect Prompt Injection", "Direct", "ignore previous"], "instruction_override"),
    (["Roleplay", "story", "fictional", "persona"], "roleplay_manipulation"),
    (["Jailbreak", "disable safety", "guardrails", "policy"], "jailbreak_escalation"),
    (["Data Poisoning", "mislabeled", "poisoned", "rag"], "training_set_corruption"),
    (["Adversarial Examples", "evasion", "obfuscation"], "adversarial_input_manipulation"),
    (["Model Extraction", "query", "Prediction APIs", "prompt leakage"], "repeated_query_extraction"),
    (["Membership Inference", "privacy leakage"], "membership_probing"),
    (["Backdoor", "trigger", "trojan"], "trigger_implantation"),
    (["Social Engineering", "trust", "deepfake", "impersonation"], "trust_exploitation"),
    (["MLOPS", "supply chain", "plugin", "tool", "agent"], "mlops_surface_abuse"),
]


def normalize_whitespace(text: str) -> str:
    text = text.replace("\u00ad", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def is_heading(line: str) -> bool:
    line = line.strip()
    if not line or len(line) > 120:
        return False
    if MARKDOWN_HEADING_RE.match(line):
        return True
    return any(pattern.match(line) for pattern in CHAPTER_PATTERNS)


def split_long_text(text: str, *, limit: int = 2200) -> List[str]:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    if not paragraphs:
        return []
    chunks: List[str] = []
    buffer = ""
    for paragraph in paragraphs:
        candidate = f"{buffer}\n\n{paragraph}".strip() if buffer else paragraph
        if len(candidate) <= limit:
            buffer = candidate
            continue
        if buffer:
            chunks.append(buffer)
        if len(paragraph) <= limit:
            buffer = paragraph
            continue
        cursor = 0
        while cursor < len(paragraph):
            chunks.append(paragraph[cursor : cursor + limit].strip())
            cursor += limit
        buffer = ""
    if buffer:
        chunks.append(buffer)
    return chunks


def parse_text_sections(text: str, *, chapter_hint: str, title_hint: str, min_len: int = 120) -> List[Dict[str, Any]]:
    lines = text.splitlines()
    sections: List[Dict[str, Any]] = []
    current_chapter = chapter_hint
    current_title = title_hint
    buffer: List[str] = []

    def flush() -> None:
        nonlocal buffer
        content = normalize_whitespace("\n".join(buffer))
        if len(content) < min_len:
            buffer = []
            return
        chunks = split_long_text(content)
        if not chunks:
            buffer = []
            return
        for index, chunk in enumerate(chunks, start=1):
            title = current_title if len(chunks) == 1 else f"{current_title} [chunk {index}]"
            sections.append(
                {
                    "chapter": current_chapter,
                    "section_title": title,
                    "text": chunk,
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
        if MARKDOWN_HEADING_RE.match(line):
            flush()
            heading = re.sub(r"^#{1,6}\s+", "", line).strip()
            current_title = heading or title_hint
            continue
        if is_heading(line) and current_chapter != chapter_hint:
            flush()
            current_title = line
            continue
        buffer.append(raw_line)

    flush()
    return sections


def classify_attack(section: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    haystack = f"{section['chapter']} {section['section_title']} {section['text'][:4000]}".lower()
    best_rule = None
    best_score = 0
    for rule in ATTACK_RULES:
        score = sum(1 for token in rule["match"] if token.lower() in haystack)
        if score > best_score:
            best_rule = rule
            best_score = score
    if not best_rule:
        return None

    technique = best_rule["default_technique"]
    for tokens, candidate in TECHNIQUE_RULES:
        if any(token.lower() in haystack for token in tokens):
            technique = candidate
            break

    return {
        "attack_type": best_rule["attack_type"],
        "technique": technique,
        "stage": best_rule["stage"],
        "target_surface": best_rule["target_surface"],
        "stealth": best_rule["stealth"],
        "strength_hint": best_rule["strength_hint"],
        "detection_difficulty": best_rule["detection_difficulty"],
        "mutation_bias": best_rule["mutation_bias"],
    }


def load_manifest(manifest_path: Path) -> List[Dict[str, str]]:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = payload.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"Manifest {manifest_path} has no sources array.")
    normalized: List[Dict[str, str]] = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("Manifest source entries must be objects.")
        path = str(source.get("path", "")).strip()
        url = str(source.get("url", "")).strip()
        label = str(source.get("label", "")).strip()
        kind = str(source.get("kind", "")).strip()
        if not path and not url:
            raise ValueError("Manifest source entry must include path or url.")
        if not kind:
            kind = "git_repo" if url else "text"
        normalized.append(
            {
                "kind": kind,
                "path": path,
                "url": url,
                "label": label or Path(path or url).stem or kind,
            }
        )
    return normalized


def _run_git(args: List[str], *, cwd: Optional[Path] = None) -> str:
    git_exe = shutil.which("git")
    if not git_exe:
        raise RuntimeError("git executable is required to ingest repository sources.")
    result = subprocess.run(
        [git_exe, *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
    )
    return result.stdout.decode("utf-8", errors="ignore")


def prepare_git_repo(url: str, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    _run_git(["init"], cwd=destination)
    _run_git(["remote", "add", "origin", url], cwd=destination)
    _run_git(["fetch", "--depth", "1", "origin", "HEAD"], cwd=destination)
    return destination


def iter_text_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in TEXT_EXTENSIONS:
            yield root
        return
    for candidate in root.rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in TEXT_EXTENSIONS:
            yield candidate


def iter_git_text_files(repo_root: Path) -> List[str]:
    output = _run_git(["ls-tree", "-r", "--name-only", "FETCH_HEAD"], cwd=repo_root)
    files = [line.strip() for line in output.splitlines() if line.strip()]
    return [path for path in files if Path(path).suffix.lower() in TEXT_EXTENSIONS]


def read_git_file(repo_root: Path, relative_path: str) -> str:
    return _run_git(["show", f"FETCH_HEAD:{relative_path}"], cwd=repo_root)


def collect_sections_from_local(source: Dict[str, str]) -> List[Dict[str, Any]]:
    source_path = Path(source["path"])
    if not source_path.exists():
        raise FileNotFoundError(f"Missing source path: {source_path}")

    sections: List[Dict[str, Any]] = []
    files = sorted(iter_text_files(source_path))
    if not files:
        raise ValueError(f"No supported text files found under {source_path}")

    for file_path in files:
        raw = file_path.read_text(encoding="utf-8", errors="ignore")
        title_hint = file_path.stem
        chapter_hint = source.get("label", file_path.stem)
        parsed_sections = parse_text_sections(raw, chapter_hint=chapter_hint, title_hint=title_hint)
        for section in parsed_sections:
            section["source"] = {
                "label": source.get("label", file_path.stem),
                "source_type": source.get("kind", "text"),
                "path": str(file_path),
            }
            sections.append(section)
    return sections


def collect_sections_from_repo(source: Dict[str, str], temp_root: Path) -> List[Dict[str, Any]]:
    repo_root = prepare_git_repo(source["url"], temp_root / source["label"])
    sections: List[Dict[str, Any]] = []
    files = sorted(iter_git_text_files(repo_root))
    if not files:
        raise ValueError(f"No supported text files found in repo: {source['url']}")

    for relative_path in files:
        raw = read_git_file(repo_root, relative_path)
        parsed_sections = parse_text_sections(
            raw,
            chapter_hint=source["label"],
            title_hint=relative_path.replace("\\", "/"),
        )
        for section in parsed_sections:
            section["source"] = {
                "label": source["label"],
                "source_type": source.get("kind", "git_repo"),
                "path": f"{source['url']}#{relative_path.replace('\\', '/')}",
            }
            sections.append(section)
    return sections


def collect_sections(sources: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="agent-c-attack-knowledge-") as temp_dir:
        temp_root = Path(temp_dir)
        for source in sources:
            if source.get("url") or source.get("kind") == "git_repo" or URL_RE.match(source.get("path", "")):
                repo_url = source.get("url") or source.get("path", "")
                repo_source = {**source, "url": repo_url, "kind": "git_repo"}
                sections.extend(collect_sections_from_repo(repo_source, temp_root))
                continue
            sections.extend(collect_sections_from_local(source))
    return sections


def build_entries(sections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for index, section in enumerate(sections, start=1):
        metadata = classify_attack(section)
        if not metadata:
            continue
        entries.append(
            {
                "id": f"atk_{index:06d}",
                "chapter": section["chapter"],
                "section_title": section["section_title"],
                **metadata,
                "source": section.get("source", {}),
                "text": section["text"][:6000],
            }
        )
    return entries


def build_attack_library(
    entries: List[Dict[str, Any]],
    *,
    source_path: Path,
    sources: List[Dict[str, str]],
) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        grouped.setdefault(entry["attack_type"], []).append(entry)

    strategies: Dict[str, Dict[str, Any]] = {}
    for attack_type, items in grouped.items():
        techniques: Dict[str, int] = {}
        stages: Dict[str, int] = {}
        surfaces: Dict[str, int] = {}
        mutation_counts: Dict[str, int] = {}
        for item in items:
            techniques[item["technique"]] = techniques.get(item["technique"], 0) + 1
            stages[item["stage"]] = stages.get(item["stage"], 0) + 1
            surfaces[item["target_surface"]] = surfaces.get(item["target_surface"], 0) + 1
            for mutation in item["mutation_bias"]:
                mutation_counts[mutation] = mutation_counts.get(mutation, 0) + 1
        strategies[attack_type] = {
            "base_strength": round(sum(item["strength_hint"] for item in items) / len(items), 3),
            "stealth": round(sum(item["stealth"] for item in items) / len(items), 3),
            "detection_difficulty": round(sum(item["detection_difficulty"] for item in items) / len(items), 3),
            "preferred_mutations": [key for key, _ in sorted(mutation_counts.items(), key=lambda kv: kv[1], reverse=True)][:4],
            "top_techniques": [key for key, _ in sorted(techniques.items(), key=lambda kv: kv[1], reverse=True)][:4],
            "dominant_stage": max(stages, key=stages.get),
            "dominant_target_surface": max(surfaces, key=surfaces.get),
            "knowledge_count": len(items),
        }

    return {
        "knowledge_source": "Red Teaming AI",
        "knowledge_version": "book_extract_v2_multi_source",
        "source_path": str(source_path),
        "source_manifest": sources,
        "source_count": len(sources),
        "section_count": len(entries),
        "attack_strategies": strategies,
        "mutation_profiles": {
            "encoding": {"stealth_modifier": 0.10, "strength_modifier": 0.00, "retry_bias": 0.60},
            "obfuscation": {"stealth_modifier": 0.15, "strength_modifier": 0.05, "retry_bias": 0.55},
            "variable_rename": {"stealth_modifier": 0.05, "strength_modifier": 0.03, "retry_bias": 0.50},
            "reframe": {"stealth_modifier": 0.20, "strength_modifier": 0.08, "retry_bias": 0.70},
            "verbosity_shift": {"stealth_modifier": 0.12, "strength_modifier": 0.02, "retry_bias": 0.45},
            "context_wrap": {"stealth_modifier": 0.18, "strength_modifier": 0.07, "retry_bias": 0.68},
        },
    }


def resolve_sources(args: argparse.Namespace) -> tuple[List[Dict[str, str]], Path]:
    sources: List[Dict[str, str]] = []
    source_path = Path("multi_source")

    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            raise FileNotFoundError(f"Missing manifest file: {manifest_path}")
        sources.extend(load_manifest(manifest_path))
        source_path = manifest_path

    for raw_input in args.input or []:
        sources.append(
            {
                "kind": "git_repo" if URL_RE.match(raw_input) else "text",
                "path": raw_input if not URL_RE.match(raw_input) else "",
                "url": raw_input if URL_RE.match(raw_input) else "",
                "label": Path(raw_input).stem if not URL_RE.match(raw_input) else Path(raw_input.rstrip("/")).stem,
            }
        )
        if len(sources) == 1 and not args.manifest:
            source_path = Path(raw_input)

    if not sources:
        raise ValueError("Provide at least one --input or a --manifest file.")
    return sources, source_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build structured attack knowledge from multi-source text.")
    parser.add_argument("--input", action="append", default=[], help="Local text file, directory, or Git URL. Repeatable.")
    parser.add_argument("--manifest", help="Path to a JSON manifest describing source files and repos.")
    parser.add_argument("--output-dir", default="agents/shared/data", help="Output directory for knowledge artifacts")
    args = parser.parse_args()

    sources, source_path = resolve_sources(args)
    output_dir = Path(args.output_dir)

    sections = collect_sections(sources)
    entries = build_entries(sections)
    if not entries:
        raise ValueError("No attack knowledge entries could be derived from the provided sources.")
    library = build_attack_library(entries, source_path=source_path, sources=sources)

    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / "attack_knowledge.jsonl"
    library_path = output_dir / "attack_library.json"

    with jsonl_path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    library_path.write_text(json.dumps(library, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Sources ingested: {len(sources)}")
    print(f"Sections parsed: {len(sections)}")
    print(f"Knowledge entries written: {len(entries)} -> {jsonl_path}")
    print(f"Attack library written: {library_path}")


if __name__ == "__main__":
    main()
