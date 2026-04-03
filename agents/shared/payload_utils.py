import hashlib
import re
from typing import Any, Dict


PREVIEW_MAX_LEN = 200
DISPLAY_HASH_LEN = 12


def normalize_payload_text(payload: Any) -> str:
    if payload in (None, ""):
        return ""
    text = str(payload).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def hash_payload(payload: Any) -> str:
    text = normalize_payload_text(payload)
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def short_payload_hash(full_hash: str, length: int = DISPLAY_HASH_LEN) -> str:
    return str(full_hash or "")[:length]


def build_payload_preview(payload: Any, max_len: int = PREVIEW_MAX_LEN) -> str:
    text = normalize_payload_text(payload)
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    clipped = text[: max(0, max_len - 3)].rstrip()
    return f"{clipped}..."


def summarize_payload(
    payload: Any,
    *,
    parent_payload: Any = "",
    semantic_family: str = "",
    mutation_type: str = "",
    mutation_v: int | None = None,
    payload_source: str = "",
    preview_len: int = PREVIEW_MAX_LEN,
) -> Dict[str, Any]:
    text = normalize_payload_text(payload)
    parent_text = normalize_payload_text(parent_payload)
    full_hash = hash_payload(text)
    parent_full_hash = hash_payload(parent_text)
    summary = {
        "has_payload": bool(text),
        "payload_hash": short_payload_hash(full_hash),
        "payload_hash_full": full_hash,
        "parent_payload_hash": short_payload_hash(parent_full_hash),
        "parent_payload_hash_full": parent_full_hash,
        "payload_preview": build_payload_preview(text, max_len=preview_len),
        "payload_length": len(text),
        "semantic_family": str(semantic_family or ""),
        "mutation_type": str(mutation_type or ""),
        "payload_source": str(payload_source or ""),
    }
    if mutation_v is not None:
        summary["mutation_v"] = int(mutation_v)
    return summary
