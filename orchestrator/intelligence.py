import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


SUCCESS_EVENTS = {"INFECTION_SUCCESSFUL"}
BLOCK_EVENTS = {"INFECTION_BLOCKED", "PROPAGATION_SUPPRESSED", "STALE_EVENT_DROPPED"}
TERMINAL_EVENTS = SUCCESS_EVENTS | BLOCK_EVENTS
ATTEMPT_EVENTS = {"ATTACK_EXECUTED", "INFECTION_ATTEMPT"}
DECISION_EVENTS = {
    "ATTACKER_DECISION",
    "STRATEGY_SELECTED",
    "TECHNIQUE_SELECTED",
    "MUTATION_SELECTED",
    "ATTACK_EXECUTED",
    "ATTACK_RESULT_EVALUATED",
    "TARGET_SCORED",
    "CAMPAIGN_ADAPTED",
    "CAMPAIGN_OBJECTIVE_SET",
}
STRATEGY_TRANSITION_EVENTS = {"STRATEGY_SELECTED", "ATTACKER_DECISION", "ATTACK_EXECUTED"}


def parse_timestamp(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        except ValueError:
            return None


def iso_min(values: Iterable[Any]) -> str:
    parsed = [item for item in (parse_timestamp(value) for value in values) if item is not None]
    return min(parsed).isoformat() if parsed else ""


def iso_max(values: Iterable[Any]) -> str:
    parsed = [item for item in (parse_timestamp(value) for value in values) if item is not None]
    return max(parsed).isoformat() if parsed else ""


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, ""):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def stable_unique(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    output: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def first_nonempty(values: Iterable[Any]) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def most_common_nonempty(values: Iterable[Any], default: str = "") -> str:
    counter = Counter(str(value or "").strip() for value in values if str(value or "").strip())
    if not counter:
        return default
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[0][0]


def round_rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 4)


def bucket_timestamp(value: Any, *, bucket_minutes: int = 15) -> str:
    ts = parse_timestamp(value)
    if ts is None:
        return ""
    minute = (ts.minute // bucket_minutes) * bucket_minutes
    bucketed = ts.replace(minute=minute, second=0, microsecond=0)
    return bucketed.isoformat()


def normalized_payload_pattern(event: Dict[str, Any]) -> str:
    text = str(
        event.get("decoded_payload_preview")
        or event.get("payload_preview")
        or event.get("payload_text")
        or ""
    ).lower()
    if not text:
        return ""
    text = re.sub(r"[0-9a-f]{12,}", "<hex>", text)
    text = re.sub(r"\b\d+\b", "<num>", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"(objective|technique|mutation)=([^\]|> ]+)", r"\1=<value>", text)
    return text[:180].strip()


def lineage_depths(events: Sequence[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, str], Dict[str, List[str]], List[str]]:
    parent_by_child: Dict[str, str] = {}
    children_by_parent: Dict[str, List[str]] = defaultdict(list)
    warnings: List[str] = []

    for event in events:
        child = str(event.get("payload_hash") or "").strip()
        parent = str(event.get("parent_payload_hash") or "").strip()
        if not child:
            continue
        if parent and child not in parent_by_child:
            parent_by_child[child] = parent
            children_by_parent[parent].append(child)
        elif parent and parent_by_child.get(child) not in {None, "", parent}:
            warnings.append(
                f"Payload lineage ambiguity: payload {child} was observed with multiple parents."
            )

    depth_cache: Dict[str, int] = {}
    root_cache: Dict[str, str] = {}

    def compute_depth(payload_hash: str, trail: Optional[set[str]] = None) -> int:
        if not payload_hash:
            return 0
        if payload_hash in depth_cache:
            return depth_cache[payload_hash]
        seen = set(trail or set())
        if payload_hash in seen:
            warnings.append(f"Payload lineage cycle detected at {payload_hash}.")
            depth_cache[payload_hash] = 0
            root_cache[payload_hash] = payload_hash
            return 0
        seen.add(payload_hash)
        parent = parent_by_child.get(payload_hash, "")
        if not parent:
            depth_cache[payload_hash] = 0
            root_cache[payload_hash] = payload_hash
            return 0
        parent_depth = compute_depth(parent, seen)
        depth_cache[payload_hash] = parent_depth + 1
        root_cache[payload_hash] = root_cache.get(parent, parent or payload_hash)
        return depth_cache[payload_hash]

    all_hashes = stable_unique(
        [event.get("payload_hash") for event in events] + [event.get("parent_payload_hash") for event in events]
    )
    for payload_hash in all_hashes:
        compute_depth(payload_hash)
    return depth_cache, root_cache, dict(children_by_parent), stable_unique(warnings)


def build_attempt_records(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    attempts: Dict[str, Dict[str, Any]] = {}
    ordered = sorted(
        events,
        key=lambda item: (
            parse_timestamp(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc),
            str(item.get("event_id") or ""),
        ),
    )

    for event in ordered:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        attempt_id = str(
            metadata.get("attempt_id")
            or event.get("injection_id")
            or event.get("event_id")
            or ""
        ).strip()
        if not attempt_id:
            continue
        event_name = str(event.get("event") or "")
        if event_name in ATTEMPT_EVENTS:
            if attempt_id not in attempts:
                attempts[attempt_id] = {
                    "attempt_id": attempt_id,
                    "event_id": event.get("event_id"),
                    "ts": event.get("ts"),
                    "src": event.get("src"),
                    "dst": event.get("dst"),
                    "attack_type": event.get("attack_type") or metadata.get("attack_type") or "",
                    "strategy_family": metadata.get("strategy_family") or "",
                    "technique": metadata.get("technique") or "",
                    "mutation_type": event.get("mutation_type") or metadata.get("mutation_type") or "",
                    "payload_hash": event.get("payload_hash") or metadata.get("payload_hash") or "",
                    "parent_payload_hash": event.get("parent_payload_hash") or metadata.get("parent_payload_hash") or "",
                    "semantic_family": event.get("semantic_family") or metadata.get("semantic_family") or "",
                    "wrapper_type": event.get("payload_wrapper_type") or metadata.get("payload_wrapper_type") or "",
                    "decode_status": event.get("decode_status") or metadata.get("decode_status") or "",
                    "decode_complexity": len(event.get("decode_chain") or []),
                    "attack_strength": safe_float(event.get("attack_strength") or metadata.get("attack_strength")),
                    "hop_count": safe_int(event.get("hop_count") or metadata.get("hop_count")),
                    "mutation_v": safe_int(event.get("mutation_v") or metadata.get("mutation_v")),
                    "campaign_id": metadata.get("campaign_id") or "",
                    "objective": metadata.get("objective") or "",
                    "knowledge_source": metadata.get("knowledge_source") or "",
                    "knowledge_confidence": safe_float(metadata.get("knowledge_confidence")),
                    "prior_success_rate": safe_float(metadata.get("prior_success_rate")),
                    "inferred_target_resistance": safe_float(metadata.get("inferred_target_resistance")),
                    "outcome": "unknown",
                    "outcome_event": "",
                    "outcome_ts": "",
                    "event": dict(event),
                }
            continue

        if event_name in TERMINAL_EVENTS or event_name == "ATTACK_RESULT_EVALUATED":
            attempt = attempts.get(attempt_id)
            if not attempt:
                continue
            metadata_outcome = str(metadata.get("outcome") or "").strip().lower()
            if event_name in SUCCESS_EVENTS or metadata_outcome == "success":
                outcome = "success"
            elif event_name in BLOCK_EVENTS or metadata_outcome == "blocked":
                outcome = "blocked"
            else:
                outcome = attempt.get("outcome", "unknown")
            attempt["outcome"] = outcome
            attempt["outcome_event"] = event_name
            attempt["outcome_ts"] = event.get("ts")

    return list(attempts.values())


def compute_lineage_summary(events: Sequence[Dict[str, Any]], payload_hashes: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    relevant = [
        event for event in events
        if str(event.get("payload_hash") or "").strip()
        and (not payload_hashes or str(event.get("payload_hash") or "").strip() in payload_hashes)
    ]
    depths, roots, children_by_parent, warnings = lineage_depths(relevant)
    return {
        "depths": depths,
        "roots": roots,
        "children_by_parent": children_by_parent,
        "warnings": warnings,
    }


def build_mutation_analytics(
    events: Sequence[Dict[str, Any]],
    *,
    scope_label: str = "",
    truncated: bool = False,
) -> Dict[str, Any]:
    attempts = build_attempt_records(events)
    lineage = compute_lineage_summary(events)
    family_rows: List[Dict[str, Any]] = []
    by_family: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for attempt in attempts:
        family = str(attempt.get("mutation_type") or "unclassified")
        by_family[family].append(attempt)

    for family, items in sorted(by_family.items(), key=lambda item: item[0]):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        attempts_count = len(items)
        depth_values = [
            lineage["depths"].get(str(item.get("payload_hash") or ""), 0)
            for item in items
        ]
        family_rows.append(
            {
                "mutation_family": family,
                "total_attempts": attempts_count,
                "total_successes": successes,
                "total_blocks": blocks,
                "success_rate": round_rate(successes, attempts_count),
                "block_rate": round_rate(blocks, attempts_count),
                "avg_attack_strength": round(sum(safe_float(item.get("attack_strength")) for item in items) / max(attempts_count, 1), 4),
                "avg_hop_count": round(sum(safe_int(item.get("hop_count")) for item in items) / max(attempts_count, 1), 4),
                "avg_lineage_depth": round(sum(depth_values) / max(len(depth_values), 1), 4),
                "avg_decode_complexity": round(sum(safe_int(item.get("decode_complexity")) for item in items) / max(attempts_count, 1), 4),
                "first_seen": iso_min(item.get("ts") for item in items),
                "last_seen": iso_max(item.get("ts") for item in items),
                "affected_targets": stable_unique(item.get("dst") for item in items),
                "affected_campaigns": stable_unique(item.get("campaign_id") for item in items),
            }
        )

    by_target_rows: List[Dict[str, Any]] = []
    grouped_target: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for attempt in attempts:
        grouped_target[(str(attempt.get("mutation_type") or "unclassified"), str(attempt.get("dst") or ""))].append(attempt)
    for (family, target), items in sorted(grouped_target.items(), key=lambda item: (item[0][0], item[0][1])):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        by_target_rows.append(
            {
                "mutation_family": family,
                "target": target,
                "attempts": len(items),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(items)),
            }
        )

    by_strategy_rows: List[Dict[str, Any]] = []
    grouped_strategy: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for attempt in attempts:
        grouped_strategy[(str(attempt.get("mutation_type") or "unclassified"), str(attempt.get("strategy_family") or "unknown"))].append(attempt)
    for (family, strategy_family), items in sorted(grouped_strategy.items(), key=lambda item: (item[0][0], item[0][1])):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        by_strategy_rows.append(
            {
                "mutation_family": family,
                "strategy_family": strategy_family,
                "attempts": len(items),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(items)),
            }
        )

    over_time: Dict[Tuple[str, str], int] = defaultdict(int)
    for attempt in attempts:
        bucket = bucket_timestamp(attempt.get("ts"))
        family = str(attempt.get("mutation_type") or "unclassified")
        if bucket:
            over_time[(bucket, family)] += 1

    distribution = [
        {
            "mutation_family": row["mutation_family"],
            "count": row["total_attempts"],
            "share": round_rate(row["total_attempts"], len(attempts)),
        }
        for row in family_rows
    ]
    winning_families = sorted(
        family_rows,
        key=lambda item: (item["success_rate"], item["total_successes"], -item["block_rate"], item["mutation_family"]),
        reverse=True,
    )[:6]
    exploratory_families = sorted(
        family_rows,
        key=lambda item: (item["total_attempts"] - item["total_successes"], item["block_rate"], item["mutation_family"]),
        reverse=True,
    )[:6]

    warnings: List[str] = list(lineage.get("warnings") or [])
    if truncated:
        warnings.append("Mutation analytics scoped to the indexed query window limit.")

    return {
        "scope": {"label": scope_label, "attempt_count": len(attempts), "truncated": truncated},
        "mutation_families": sorted(
            family_rows,
            key=lambda item: (item["success_rate"], item["total_successes"], item["mutation_family"]),
            reverse=True,
        ),
        "leaderboard": sorted(
            family_rows,
            key=lambda item: (item["success_rate"], item["total_successes"], item["mutation_family"]),
            reverse=True,
        ),
        "by_target": by_target_rows,
        "by_strategy": by_strategy_rows,
        "over_time": [
            {"bucket": bucket, "mutation_family": family, "attempts": count}
            for (bucket, family), count in sorted(over_time.items(), key=lambda item: (item[0][0], item[0][1]))
        ],
        "distribution": distribution,
        "winning_families": winning_families,
        "exploratory_but_ineffective": exploratory_families,
        "warnings": stable_unique(warnings),
    }


def build_strategy_analytics(
    events: Sequence[Dict[str, Any]],
    *,
    scope_label: str = "",
    truncated: bool = False,
) -> Dict[str, Any]:
    attempts = build_attempt_records(events)
    grouped_strategy: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    grouped_technique: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    grouped_combo: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    for attempt in attempts:
        strategy_family = str(attempt.get("strategy_family") or "unknown")
        technique = str(attempt.get("technique") or "unknown")
        grouped_strategy[strategy_family].append(attempt)
        grouped_technique[technique].append(attempt)
        grouped_combo[(strategy_family, str(attempt.get("mutation_type") or "unclassified"))].append(attempt)

    strategy_rows: List[Dict[str, Any]] = []
    for family, items in sorted(grouped_strategy.items(), key=lambda item: item[0]):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        strategy_rows.append(
            {
                "strategy_family": family,
                "attempts": len(items),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(items)),
                "avg_target_resistance_when_used": round(sum(safe_float(item.get("inferred_target_resistance")) for item in items) / max(len(items), 1), 4),
                "avg_attack_strength": round(sum(safe_float(item.get("attack_strength")) for item in items) / max(len(items), 1), 4),
                "avg_mutation_diversity": round(len({str(item.get("mutation_type") or "unclassified") for item in items}) / max(len(items), 1), 4),
                "most_common_targets": [name for name, _count in Counter(str(item.get("dst") or "") for item in items if str(item.get("dst") or "")).most_common(3)],
                "campaign_count": len(stable_unique(item.get("campaign_id") for item in items)),
            }
        )

    technique_rows: List[Dict[str, Any]] = []
    for technique, items in sorted(grouped_technique.items(), key=lambda item: item[0]):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        mutation_synergy = Counter(str(item.get("mutation_type") or "unclassified") for item in items).most_common(3)
        target_breakdown = Counter(str(item.get("dst") or "") for item in items).most_common(4)
        technique_rows.append(
            {
                "technique": technique,
                "attempts": len(items),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(items)),
                "target_breakdown": [{"target": target, "count": count} for target, count in target_breakdown],
                "mutation_synergy": [{"mutation_family": family, "count": count} for family, count in mutation_synergy],
                "average_confidence": round(sum(safe_float(item.get("knowledge_confidence")) for item in items) / max(len(items), 1), 4),
            }
        )

    combo_rows: List[Dict[str, Any]] = []
    for (strategy_family, mutation_family), items in sorted(grouped_combo.items(), key=lambda item: (item[0][0], item[0][1])):
        successes = sum(1 for item in items if item.get("outcome") == "success")
        blocks = sum(1 for item in items if item.get("outcome") == "blocked")
        combo_rows.append(
            {
                "strategy_family": strategy_family,
                "mutation_family": mutation_family,
                "attempts": len(items),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(items)),
            }
        )

    recent_strategy_shifts: List[Dict[str, Any]] = []
    decision_events = [
        event for event in sorted(
            events,
            key=lambda item: (parse_timestamp(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc), str(item.get("event_id") or "")),
        )
        if str(event.get("event") or "") in STRATEGY_TRANSITION_EVENTS
    ]
    previous_family = ""
    for event in decision_events:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        family = str(metadata.get("strategy_family") or "").strip()
        if not family:
            continue
        if previous_family and previous_family != family:
            recent_strategy_shifts.append(
                {
                    "ts": event.get("ts"),
                    "from_strategy_family": previous_family,
                    "to_strategy_family": family,
                    "campaign_id": metadata.get("campaign_id") or "",
                    "reason": metadata.get("rationale") or "",
                }
            )
        previous_family = family

    failed_clusters = sorted(
        combo_rows,
        key=lambda item: (item["blocks"], item["attempts"], item["strategy_family"], item["mutation_family"]),
        reverse=True,
    )[:8]
    top_combos = sorted(
        combo_rows,
        key=lambda item: (item["success_rate"], item["successes"], item["strategy_family"], item["mutation_family"]),
        reverse=True,
    )[:8]
    warnings: List[str] = []
    if truncated:
        warnings.append("Strategy analytics scoped to the indexed query window limit.")

    return {
        "scope": {"label": scope_label, "attempt_count": len(attempts), "truncated": truncated},
        "strategy_families": sorted(
            strategy_rows,
            key=lambda item: (item["success_rate"], item["successes"], item["strategy_family"]),
            reverse=True,
        ),
        "leaderboard": sorted(
            strategy_rows,
            key=lambda item: (item["success_rate"], item["successes"], item["strategy_family"]),
            reverse=True,
        ),
        "techniques": sorted(
            technique_rows,
            key=lambda item: (item["success_rate"], item["successes"], item["technique"]),
            reverse=True,
        ),
        "strategy_mutation_combinations": sorted(
            combo_rows,
            key=lambda item: (item["success_rate"], item["successes"], item["strategy_family"], item["mutation_family"]),
            reverse=True,
        ),
        "top_successful_combinations": top_combos,
        "failed_tactic_clusters": failed_clusters,
        "recent_strategy_shifts": recent_strategy_shifts[-12:],
        "warnings": warnings,
    }


def build_reasoning_context(
    events: Sequence[Dict[str, Any]],
    focus_event: Dict[str, Any],
) -> Dict[str, Any]:
    metadata = focus_event.get("metadata") if isinstance(focus_event.get("metadata"), dict) else {}
    strategy_family = str(metadata.get("strategy_family") or "")
    technique = str(metadata.get("technique") or "")
    mutation_type = str(metadata.get("mutation_type") or focus_event.get("mutation_type") or "")
    objective = str(metadata.get("objective") or "")
    score_breakdown = metadata.get("score_breakdown") if isinstance(metadata.get("score_breakdown"), dict) else {}
    quick_explanation_parts = []
    if strategy_family:
        quick_explanation_parts.append(f"strategy={strategy_family}")
    if technique:
        quick_explanation_parts.append(f"technique={technique}")
    if mutation_type:
        quick_explanation_parts.append(f"mutation={mutation_type}")
    if objective:
        quick_explanation_parts.append(f"objective={objective}")

    focus_ts = parse_timestamp(focus_event.get("ts")) or datetime.max.replace(tzinfo=timezone.utc)
    focus_campaign = str(metadata.get("campaign_id") or "")
    focus_src = str(focus_event.get("src") or "")
    candidates: List[Dict[str, Any]] = []
    for event in events:
        if event.get("event_id") == focus_event.get("event_id"):
            continue
        event_name = str(event.get("event") or "")
        if event_name not in DECISION_EVENTS:
            continue
        event_metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        if focus_campaign and str(event_metadata.get("campaign_id") or "") != focus_campaign:
            continue
        if focus_src and str(event.get("src") or "") != focus_src:
            continue
        candidate_ts = parse_timestamp(event.get("ts"))
        if candidate_ts is None or candidate_ts >= focus_ts:
            continue
        candidates.append(event)
    candidates.sort(
        key=lambda item: (
            parse_timestamp(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc),
            str(item.get("event_id") or ""),
        )
    )
    previous = candidates[-1] if candidates else None
    previous_metadata = previous.get("metadata") if previous and isinstance(previous.get("metadata"), dict) else {}

    changes: List[Dict[str, Any]] = []
    change_messages: List[str] = []
    comparisons = [
        ("strategy_family", str(previous_metadata.get("strategy_family") or ""), strategy_family),
        ("mutation_type", str(previous_metadata.get("mutation_type") or ""), mutation_type),
        (
            "inferred_target_resistance",
            safe_float(previous_metadata.get("inferred_target_resistance"), default=-1.0),
            safe_float(metadata.get("inferred_target_resistance"), default=-1.0),
        ),
        (
            "prior_success_rate",
            safe_float(previous_metadata.get("prior_success_rate"), default=-1.0),
            safe_float(metadata.get("prior_success_rate"), default=-1.0),
        ),
    ]
    for field_name, before, after in comparisons:
        if before == after:
            continue
        changes.append({"field": field_name, "before": before, "after": after})
        if field_name == "strategy_family" and before and after:
            change_messages.append(f"Switched from {before} to {after}.")
        elif field_name == "mutation_type" and before and after:
            change_messages.append(f"Changed mutation from {before} to {after}.")
        elif field_name == "inferred_target_resistance" and before >= 0 and after >= 0:
            change_messages.append(
                f"Target resistance estimate moved from {before:.2f} to {after:.2f}."
            )
        elif field_name == "prior_success_rate" and before >= 0 and after >= 0:
            change_messages.append(
                f"Prior success rate changed from {before:.2f} to {after:.2f}."
            )

    quick_explanation = "; ".join(quick_explanation_parts) if quick_explanation_parts else "No attacker reasoning metadata on this event."
    rationale = str(metadata.get("rationale") or "")
    if rationale:
        quick_explanation = f"{quick_explanation}; rationale={rationale}"

    return {
        "decision_summary": {
            "strategy_family": strategy_family,
            "technique": technique,
            "mutation_type": mutation_type,
            "objective": objective,
            "rationale": rationale,
            "score_breakdown": score_breakdown,
            "inferred_target_resistance": metadata.get("inferred_target_resistance"),
            "prior_success_rate": metadata.get("prior_success_rate"),
            "knowledge_source": metadata.get("knowledge_source"),
            "knowledge_confidence": metadata.get("knowledge_confidence"),
            "runtime_override": metadata.get("runtime_override"),
            "adaptation_weight_deltas": {
                "strategy_weight_after": metadata.get("strategy_weight_after"),
                "mutation_weight_after": metadata.get("mutation_weight_after"),
            },
        },
        "previous_decision": {
            "event_id": previous.get("event_id") if previous else "",
            "ts": previous.get("ts") if previous else "",
            "strategy_family": previous_metadata.get("strategy_family") if previous else "",
            "technique": previous_metadata.get("technique") if previous else "",
            "mutation_type": previous_metadata.get("mutation_type") if previous else "",
            "objective": previous_metadata.get("objective") if previous else "",
            "inferred_target_resistance": previous_metadata.get("inferred_target_resistance") if previous else None,
            "prior_success_rate": previous_metadata.get("prior_success_rate") if previous else None,
        },
        "changes": changes,
        "change_messages": [message for message in change_messages if message],
        "quick_explanation": quick_explanation,
    }


def build_campaign_view(events: Sequence[Dict[str, Any]], campaign_id: str) -> Dict[str, Any]:
    campaign_events = [
        event for event in sorted(
            events,
            key=lambda item: (
                parse_timestamp(item.get("ts")) or datetime.min.replace(tzinfo=timezone.utc),
                str(item.get("event_id") or ""),
            ),
        )
        if str((event.get("metadata") or {}).get("campaign_id") if isinstance(event.get("metadata"), dict) else "") == campaign_id
    ]
    if not campaign_events:
        raise KeyError(campaign_id)

    attempts = build_attempt_records(campaign_events)
    lineage = compute_lineage_summary(campaign_events)
    mutation_analytics = build_mutation_analytics(campaign_events, scope_label=f"campaign:{campaign_id}")
    strategy_analytics = build_strategy_analytics(campaign_events, scope_label=f"campaign:{campaign_id}")
    objectives = stable_unique((event.get("metadata") or {}).get("objective") for event in campaign_events if isinstance(event.get("metadata"), dict))
    strategy_sequence = [
        {
            "ts": event.get("ts"),
            "strategy_family": str((event.get("metadata") or {}).get("strategy_family") or ""),
            "technique": str((event.get("metadata") or {}).get("technique") or ""),
            "reason": str((event.get("metadata") or {}).get("rationale") or ""),
        }
        for event in campaign_events
        if str(event.get("event") or "") in STRATEGY_TRANSITION_EVENTS
           and isinstance(event.get("metadata"), dict)
           and str((event.get("metadata") or {}).get("strategy_family") or "")
    ]
    mutation_sequence = [
        {
            "ts": attempt.get("ts"),
            "mutation_family": attempt.get("mutation_type"),
            "payload_hash": attempt.get("payload_hash"),
            "parent_payload_hash": attempt.get("parent_payload_hash"),
            "outcome": attempt.get("outcome"),
        }
        for attempt in attempts
    ]
    target_pressure_counter = Counter(str(attempt.get("dst") or "") for attempt in attempts if str(attempt.get("dst") or ""))
    target_blocks = Counter(str(attempt.get("dst") or "") for attempt in attempts if attempt.get("outcome") == "blocked")
    target_successes = Counter(str(attempt.get("dst") or "") for attempt in attempts if attempt.get("outcome") == "success")
    payload_reuse_counter = Counter(str(event.get("payload_hash") or "") for event in campaign_events if str(event.get("payload_hash") or ""))
    root_candidates = sorted(
        {lineage["roots"].get(str(event.get("payload_hash") or ""), str(event.get("payload_hash") or "")) for event in campaign_events if str(event.get("payload_hash") or "")}
    )
    final_outcome = "mixed"
    if attempts and all(item.get("outcome") == "blocked" for item in attempts):
        final_outcome = "blocked"
    elif any(item.get("outcome") == "success" for item in attempts):
        final_outcome = "successful_progression"
    timeline: List[Dict[str, Any]] = []
    for event in campaign_events:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        event_name = str(event.get("event") or "")
        if event_name in {"STRATEGY_SELECTED", "ATTACK_EXECUTED", "ATTACK_RESULT_EVALUATED", "CAMPAIGN_ADAPTED", "CAMPAIGN_OBJECTIVE_SET", "TARGET_SCORED", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}:
            timeline.append(
                {
                    "ts": event.get("ts"),
                    "event": event_name,
                    "strategy_family": metadata.get("strategy_family") or "",
                    "technique": metadata.get("technique") or "",
                    "mutation_type": metadata.get("mutation_type") or event.get("mutation_type") or "",
                    "target": event.get("dst") or metadata.get("target") or "",
                    "objective": metadata.get("objective") or "",
                    "reason": metadata.get("rationale") or "",
                    "payload_hash": event.get("payload_hash") or metadata.get("payload_hash") or "",
                }
            )
    findings: List[str] = []
    top_combo = strategy_analytics.get("top_successful_combinations", [])
    if top_combo:
        findings.append(
            f"Best observed tactic combination was {top_combo[0]['strategy_family']} + {top_combo[0]['mutation_family']} with success rate {top_combo[0]['success_rate']:.2f}."
        )
    top_failed = strategy_analytics.get("failed_tactic_clusters", [])
    if top_failed:
        findings.append(
            f"Most blocked tactic cluster was {top_failed[0]['strategy_family']} + {top_failed[0]['mutation_family']} ({top_failed[0]['blocks']} blocks)."
        )
    if objectives and len(objectives) > 1:
        findings.append(f"Campaign objective changed {len(objectives) - 1} times.")
    if root_candidates:
        findings.append(f"Campaign lineage roots: {', '.join(root_candidates[:4])}.")
    deepest_success = max(
        (item for item in attempts if item.get("outcome") == "success"),
        key=lambda item: (safe_int(item.get("hop_count")), str(item.get("dst") or "")),
        default={},
    )

    return {
        "campaign_id": campaign_id,
        "overview": {
            "campaign_id": campaign_id,
            "objective": objectives[-1] if objectives else "",
            "objectives_seen": objectives,
            "start_time": campaign_events[0].get("ts") or "",
            "end_time": campaign_events[-1].get("ts") or "",
            "ongoing": False,
            "participating_agents": stable_unique(
                [event.get("src") for event in campaign_events] + [event.get("dst") for event in campaign_events]
            ),
            "total_events": len(campaign_events),
            "total_attempts": len(attempts),
            "total_successes": sum(1 for item in attempts if item.get("outcome") == "success"),
            "total_blocks": sum(1 for item in attempts if item.get("outcome") == "blocked"),
            "final_outcome": final_outcome,
            "highest_hop_reached": max((safe_int(item.get("hop_count")) for item in attempts), default=0),
            "deepest_target_reached": str(deepest_success.get("dst") or ""),
            "deepest_target_depth": safe_int(deepest_success.get("hop_count")),
        },
        "timeline": timeline,
        "strategy_evolution": {
            "sequence": strategy_sequence,
            "transition_counts": [
                {"from_strategy_family": from_family, "to_strategy_family": to_family, "count": count}
                for (from_family, to_family), count in sorted(
                    Counter(
                        (strategy_sequence[index - 1]["strategy_family"], strategy_sequence[index]["strategy_family"])
                        for index in range(1, len(strategy_sequence))
                    ).items(),
                    key=lambda item: (-item[1], item[0][0], item[0][1]),
                )
            ],
            "reasons": [item for item in strategy_sequence if item.get("reason")],
        },
        "mutation_evolution": {
            "sequence": mutation_sequence,
            "branch_points": [
                {"parent_payload_hash": parent, "child_count": len(children)}
                for parent, children in sorted(lineage["children_by_parent"].items(), key=lambda item: (-len(item[1]), item[0]))
                if parent and len(children) > 1
            ],
            "successful_mutation_families": mutation_analytics.get("winning_families", []),
            "known_good_fallbacks": [
                item for item in mutation_sequence
                if item.get("outcome") == "success"
                and payload_reuse_counter.get(str(item.get("payload_hash") or ""), 0) > 1
            ][:8],
        },
        "payload_intelligence": {
            "root_payloads": root_candidates,
            "descendant_count": len(stable_unique(event.get("payload_hash") for event in campaign_events)),
            "most_successful_payload_hashes": [
                {"payload_hash": payload_hash, "successes": count}
                for payload_hash, count in Counter(
                    str(item.get("payload_hash") or "")
                    for item in attempts
                    if item.get("outcome") == "success" and str(item.get("payload_hash") or "")
                ).most_common(6)
            ],
            "most_reused_payloads": [
                {"payload_hash": payload_hash, "count": count}
                for payload_hash, count in payload_reuse_counter.most_common(6)
            ],
            "most_blocked_payloads": [
                {"payload_hash": payload_hash, "blocks": count}
                for payload_hash, count in Counter(
                    str(item.get("payload_hash") or "")
                    for item in attempts
                    if item.get("outcome") == "blocked" and str(item.get("payload_hash") or "")
                ).most_common(6)
            ],
        },
        "target_pressure": {
            "targets": [
                {
                    "target": target,
                    "attempts": target_pressure_counter.get(target, 0),
                    "successes": target_successes.get(target, 0),
                    "blocks": target_blocks.get(target, 0),
                }
                for target in sorted(target_pressure_counter)
            ],
            "most_resistant_target": max(target_blocks.items(), key=lambda item: (item[1], item[0]))[0] if target_blocks else "",
            "best_enabler_target": max(target_successes.items(), key=lambda item: (item[1], item[0]))[0] if target_successes else "",
        },
        "findings": findings,
        "warnings": stable_unique(lineage.get("warnings") or []),
    }


def list_campaigns(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        campaign_id = str(metadata.get("campaign_id") or "").strip()
        if campaign_id:
            grouped[campaign_id].append(event)
    campaigns = []
    for campaign_id, items in sorted(grouped.items(), key=lambda item: item[0]):
        attempts = build_attempt_records(items)
        campaigns.append(
            {
                "campaign_id": campaign_id,
                "objective": first_nonempty(((item.get("metadata") or {}).get("objective") for item in items if isinstance(item.get("metadata"), dict))),
                "start_time": iso_min(item.get("ts") for item in items),
                "end_time": iso_max(item.get("ts") for item in items),
                "participating_agents": stable_unique([item.get("src") for item in items] + [item.get("dst") for item in items]),
                "total_events": len(items),
                "attempts": len(attempts),
                "successes": sum(1 for item in attempts if item.get("outcome") == "success"),
                "blocks": sum(1 for item in attempts if item.get("outcome") == "blocked"),
            }
        )
    campaigns.sort(key=lambda item: (item["start_time"], item["campaign_id"]), reverse=True)
    return {"campaigns": campaigns}


def build_payload_families(events: Sequence[Dict[str, Any]], *, truncated: bool = False) -> Dict[str, Any]:
    lineage = compute_lineage_summary(events)
    family_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for event in events:
        payload_hash = str(event.get("payload_hash") or "").strip()
        if not payload_hash:
            continue
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        family_key = "|".join(
            [
                str(event.get("semantic_family") or metadata.get("semantic_family") or "unclassified"),
                str(lineage["roots"].get(payload_hash, payload_hash) or ""),
                str(event.get("payload_wrapper_type") or metadata.get("payload_wrapper_type") or "plain"),
                str(metadata.get("technique") or "unknown"),
                normalized_payload_pattern(event) or "patternless",
            ]
        )
        family_groups[family_key].append(event)

    families: List[Dict[str, Any]] = []
    for family_key, items in sorted(family_groups.items(), key=lambda item: item[0]):
        attempts = build_attempt_records(items)
        successes = sum(1 for item in attempts if item.get("outcome") == "success")
        blocks = sum(1 for item in attempts if item.get("outcome") == "blocked")
        payload_hashes = stable_unique(item.get("payload_hash") for item in items)
        family_name = most_common_nonempty((item.get("semantic_family") for item in items), default="unclassified")
        families.append(
            {
                "family_id": family_key,
                "semantic_family": family_name,
                "root_payload_hash": first_nonempty((lineage["roots"].get(item, "") for item in payload_hashes)) or first_nonempty(payload_hashes),
                "wrapper_type": most_common_nonempty((item.get("payload_wrapper_type") for item in items), default="plain"),
                "technique_signature": most_common_nonempty(
                    ((item.get("metadata") or {}).get("technique") for item in items if isinstance(item.get("metadata"), dict)),
                    default="unknown",
                ),
                "normalized_pattern": normalized_payload_pattern(items[0]) if items else "",
                "payload_hash_count": len(payload_hashes),
                "event_count": len(items),
                "attempts": len(attempts),
                "successes": successes,
                "blocks": blocks,
                "success_rate": round_rate(successes, len(attempts)),
                "target_distribution": [
                    {"target": target, "count": count}
                    for target, count in Counter(str(item.get("dst") or "") for item in items if str(item.get("dst") or "")).most_common(5)
                ],
                "avg_lineage_depth": round(
                    sum(lineage["depths"].get(payload_hash, 0) for payload_hash in payload_hashes) / max(len(payload_hashes), 1),
                    4,
                ),
                "mutation_diversity": len({str(item.get("mutation_type") or "unclassified") for item in items}),
                "confidence": "low" if len(payload_hashes) <= 1 else "medium",
            }
        )

    warnings: List[str] = []
    if truncated:
        warnings.append("Payload family grouping scoped to the indexed query window limit.")
    if any(item["confidence"] == "low" for item in families):
        warnings.append("Payload cluster heuristic low confidence for single-hash families.")

    families.sort(key=lambda item: (item["success_rate"], item["successes"], item["payload_hash_count"], item["family_id"]), reverse=True)
    return {"families": families, "warnings": stable_unique(warnings + list(lineage.get("warnings") or []))}


def build_decision_support(
    events: Sequence[Dict[str, Any]],
    *,
    focus_event: Optional[Dict[str, Any]] = None,
    query_label: str = "",
    truncated: bool = False,
) -> Dict[str, Any]:
    suggestions: List[Dict[str, Any]] = []
    lineage = compute_lineage_summary(events)
    mutation = build_mutation_analytics(events, scope_label=query_label, truncated=truncated)
    strategy = build_strategy_analytics(events, scope_label=query_label, truncated=truncated)
    families = build_payload_families(events, truncated=truncated)
    campaigns = list_campaigns(events)
    attempts = build_attempt_records(events)

    if focus_event:
        payload_hash = str(focus_event.get("payload_hash") or "").strip()
        campaign_id = str((focus_event.get("metadata") or {}).get("campaign_id") if isinstance(focus_event.get("metadata"), dict) else "").strip()
        injection_id = str(focus_event.get("injection_id") or "").strip()
        if payload_hash:
            child_count = len(lineage["children_by_parent"].get(payload_hash, []))
            if child_count:
                suggestions.append(
                    {
                        "title": "Inspect payload lineage",
                        "message": f"This payload hash has {child_count} descendants. Open lineage view.",
                        "action": {"type": "payload_lineage", "payload_hash": payload_hash},
                    }
                )
        if campaign_id:
            matching = [item for item in campaigns.get("campaigns", []) if item.get("campaign_id") == campaign_id]
            if matching:
                suggestions.append(
                    {
                        "title": "Review campaign intelligence",
                        "message": f"Campaign {campaign_id} has {matching[0]['total_events']} indexed events. Inspect campaign timeline.",
                        "action": {"type": "campaign", "campaign_id": campaign_id},
                    }
                )
        if injection_id:
            suggestions.append(
                {
                    "title": "Trace current injection",
                    "message": "This event belongs to a tracked injection chain. Load injection-scoped lineage and outcomes.",
                    "action": {"type": "query", "query": f"injection_id={injection_id}"},
                }
            )

    if mutation.get("winning_families"):
        winner = mutation["winning_families"][0]
        if winner.get("mutation_family"):
            target = first_nonempty(winner.get("affected_targets") or [])
            suggestions.append(
                {
                    "title": "Review winning mutation family",
                    "message": f"Mutation {winner['mutation_family']} shows the highest success rate{f' on {target}' if target else ''}. Open mutation analytics.",
                    "action": {"type": "mutation_analytics", "query": f"mutation_type={winner['mutation_family']}"},
                }
            )

    if strategy.get("recent_strategy_shifts"):
        latest_shift = strategy["recent_strategy_shifts"][-1]
        suggestions.append(
            {
                "title": "Inspect strategy shifts",
                "message": f"Recent shift from {latest_shift['from_strategy_family']} to {latest_shift['to_strategy_family']} detected. Review rationale changes.",
                "action": {"type": "query", "query": "event=STRATEGY_SELECTED OR event=ATTACK_RESULT_EVALUATED"},
            }
        )

    blocked_targets = Counter(str(item.get("dst") or "") for item in attempts if item.get("outcome") == "blocked")
    if blocked_targets:
        target, count = blocked_targets.most_common(1)[0]
        suggestions.append(
            {
                "title": "Compare tactics against resistant target",
                "message": f"Target {target} has the highest block ratio in scope ({count} blocked attempts). Compare tactics against that target.",
                "action": {"type": "query", "query": f"dst={target} AND (event=ATTACK_EXECUTED OR event=INFECTION_BLOCKED)"},
            }
        )

    risky_family = next((family for family in families.get("families", []) if family.get("payload_hash_count", 0) > 2 and family.get("blocks", 0) > family.get("successes", 0)), None)
    if risky_family:
        suggestions.append(
            {
                "title": "Inspect payload family cluster",
                "message": f"Repeated blocked payloads collapse into one family ({risky_family['semantic_family']}). Inspect payload family cluster.",
                "action": {"type": "payload_family", "family_id": risky_family["family_id"]},
            }
        )

    return {
        "suggestions": suggestions[:8],
        "warnings": stable_unique((mutation.get("warnings") or []) + (strategy.get("warnings") or []) + (families.get("warnings") or [])),
    }
