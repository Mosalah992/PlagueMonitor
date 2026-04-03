import json
import os
import shutil
import subprocess
import sys
import time
import http.client
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
LOGS_DIR = ROOT / "logs"
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
ARTIFACT_DIR = LOGS_DIR / f"research_validation_{RUN_TS}"
API_URL = "http://localhost:8000"
LOGICAL_MINUTES = 360
REAL_SECONDS_PER_MINUTE = 2.0
INJECT_EVERY_MINUTES = 5
ACCELERATED_HEARTBEAT_SECONDS = 2
LEVEL_PATTERN = ["easy", "medium", "difficult", "medium", "difficult", "easy"]
ARCHIVE_FILES = ("epidemic.db", "events.jsonl", "siem_index.db", "siem_actions.jsonl")
DECISION_EVENTS = {
    "ATTACKER_DECISION",
    "ATTACK_EXECUTED",
    "ATTACK_RESULT_EVALUATED",
    "STRATEGY_SELECTED",
    "DEFENSE_DECISION",
    "DEFENSE_RESULT_EVALUATED",
    "DEFENSE_ADAPTED",
}


def run_command(command: List[str], *, env: Dict[str, str] | None = None, output_path: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    if output_path is not None:
        output_path.write_text(
            completed.stdout + ("\n" + completed.stderr if completed.stderr else ""),
            encoding="utf-8",
        )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def api_json(method: str, path: str, payload: Dict[str, Any] | None = None, *, retries: int = 4, timeout: int = 30) -> Dict[str, Any]:
    body = None
    headers: Dict[str, str] = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, ConnectionError, TimeoutError, http.client.RemoteDisconnected) as exc:  # type: ignore[name-defined]
            last_error = exc
            time.sleep(min(2.0, 0.5 * (attempt + 1)))
    raise RuntimeError(f"API request failed after retries: {path} :: {last_error}")


def wait_for_status() -> None:
    deadline = time.time() + 120
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            payload = api_json("GET", "/status", timeout=10)
            if payload.get("status") == "running":
                return
        except Exception as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(f"API did not become ready: {last_error}")


def fetch_events(after_id: int = 0, *, order: str = "asc", limit: int = 1000) -> Dict[str, Any]:
    query = f"/events?after_id={after_id}&order={order}&limit={limit}"
    return api_json("GET", query, timeout=30)


def fetch_api(path: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if params:
        path = f"{path}?{urllib.parse.urlencode(params)}"
    return api_json("GET", path, timeout=30)


def archive_existing_logs() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ARCHIVE_FILES:
        source = LOGS_DIR / name
        if source.exists():
            target = ARTIFACT_DIR / f"pretest_{name}"
            shutil.move(str(source), str(target))


def event_id(event: Dict[str, Any]) -> int:
    return int(event.get("id", 0) or 0)


def metadata(event: Dict[str, Any]) -> Dict[str, Any]:
    value = event.get("metadata")
    return value if isinstance(value, dict) else {}


def fetch_new_events(last_seen_id: int) -> tuple[List[Dict[str, Any]], int]:
    collected: List[Dict[str, Any]] = []
    latest_seen = last_seen_id
    while True:
        payload = fetch_events(after_id=latest_seen, order="asc", limit=1000)
        rows = payload.get("events", [])
        if not rows:
            return collected, int(payload.get("latest_id", latest_seen) or latest_seen)
        collected.extend(rows)
        latest_seen = max(event_id(row) for row in rows)
        reported_latest = int(payload.get("latest_id", latest_seen) or latest_seen)
        if latest_seen >= reported_latest:
            return collected, latest_seen


def summarize_minute(
    minute_index: int,
    logical_ts: datetime,
    events: List[Dict[str, Any]],
    cumulative_events: List[Dict[str, Any]],
    *,
    injection: Dict[str, Any] | None,
) -> Dict[str, Any]:
    counts = Counter(str(event.get("event", "")) for event in events)
    attack_strategy = Counter(
        str(metadata(event).get("strategy_family") or metadata(event).get("attack_strategy") or "")
        for event in events
        if metadata(event).get("strategy_family") or metadata(event).get("attack_strategy")
    )
    defense_strategy = Counter(
        str(metadata(event).get("selected_strategy") or metadata(event).get("defense_strategy") or "")
        for event in events
        if metadata(event).get("selected_strategy") or metadata(event).get("defense_strategy")
    )
    mutation = Counter(
        str(metadata(event).get("mutation_type") or event.get("mutation_type") or "")
        for event in events
        if metadata(event).get("mutation_type") or event.get("mutation_type")
    )
    top_target = Counter(str(event.get("dst") or "") for event in events if event.get("dst"))
    defense_results = Counter(str(metadata(event).get("defense_result") or "") for event in events if metadata(event).get("defense_result"))
    cumulative_counts = Counter(str(event.get("event", "")) for event in cumulative_events)
    blocked = cumulative_counts["INFECTION_BLOCKED"]
    successful = cumulative_counts["INFECTION_SUCCESSFUL"]
    highlights: List[str] = []
    if counts["DEFENSE_ADAPTED"] > 0:
        highlights.append(f"defense adapted {counts['DEFENSE_ADAPTED']} times")
    if counts["ATTACK_RESULT_EVALUATED"] > 0:
        highlights.append(f"attacker evaluations {counts['ATTACK_RESULT_EVALUATED']}")
    if counts["INFECTION_SUCCESSFUL"] > 0 and counts["INFECTION_BLOCKED"] == 0:
        highlights.append("attacker pressure outpaced containment")
    if counts["INFECTION_BLOCKED"] > counts["INFECTION_SUCCESSFUL"]:
        highlights.append("containment pressure exceeded attacker gains")
    return {
        "minute": minute_index,
        "logical_ts_utc": logical_ts.isoformat(),
        "injection": injection or {},
        "event_count": len(events),
        "counts": dict(counts),
        "top_attack_strategy": attack_strategy.most_common(1)[0][0] if attack_strategy else "",
        "top_defense_strategy": defense_strategy.most_common(1)[0][0] if defense_strategy else "",
        "top_mutation": mutation.most_common(1)[0][0] if mutation else "",
        "top_target": top_target.most_common(1)[0][0] if top_target else "",
        "defense_results": dict(defense_results),
        "cumulative_successes": successful,
        "cumulative_blocks": blocked,
        "cumulative_block_ratio": round(blocked / max(blocked + successful, 1), 4),
        "highlights": highlights,
        "sample_event_ids": [str(event.get("event_id") or event.get("id") or "") for event in events[:5]],
    }


def choose_representative_event(all_events: List[Dict[str, Any]], *, event_name: str) -> Dict[str, Any] | None:
    matches = [event for event in all_events if str(event.get("event") or "") == event_name]
    return matches[-1] if matches else None


def build_report(
    minute_summaries: List[Dict[str, Any]],
    all_events: List[Dict[str, Any]],
    api_snapshots: Dict[str, Any],
    compose_ps: str,
    compose_logs: str,
) -> str:
    def event_ref(event: Dict[str, Any] | None) -> str:
        if not event:
            return "-"
        if event.get("event_id"):
            return str(event["event_id"])
        if event.get("id") is not None:
            return f"events:{event['id']}"
        return "-"

    total_counts = Counter(str(event.get("event", "")) for event in all_events)
    attack_routes = Counter(
        f"{event.get('src')} -> {event.get('dst')} [{event.get('attack_type') or metadata(event).get('strategy_family') or 'unknown'}]"
        for event in all_events
        if event.get("src") and event.get("dst") and str(event.get("event") or "") in {"ATTACK_EXECUTED", "INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
    )
    defense_types = Counter(str(metadata(event).get("defense_type") or "") for event in all_events if metadata(event).get("defense_type"))
    defense_strategies = Counter(
        str(metadata(event).get("selected_strategy") or metadata(event).get("defense_strategy") or "")
        for event in all_events
        if metadata(event).get("selected_strategy") or metadata(event).get("defense_strategy")
    )
    attack_strategies = Counter(
        str(metadata(event).get("strategy_family") or "")
        for event in all_events
        if metadata(event).get("strategy_family")
    )
    mutations = Counter(
        str(metadata(event).get("mutation_type") or event.get("mutation_type") or "")
        for event in all_events
        if metadata(event).get("mutation_type") or event.get("mutation_type")
    )
    payload_hashes = Counter(
        str(metadata(event).get("payload_hash") or event.get("payload_hash") or "")
        for event in all_events
        if metadata(event).get("payload_hash") or event.get("payload_hash")
    )
    defense_evaluations = [event for event in all_events if str(event.get("event") or "") == "DEFENSE_RESULT_EVALUATED"]
    defense_blocked = sum(1 for event in defense_evaluations if metadata(event).get("defense_result") == "blocked")
    defense_failed = sum(1 for event in defense_evaluations if metadata(event).get("defense_result") == "success")
    defense_effectiveness_values = [
        float(metadata(event).get("defense_effectiveness") or 0.0)
        for event in defense_evaluations
        if metadata(event).get("defense_effectiveness") is not None
    ]
    avg_defense_effectiveness = round(sum(defense_effectiveness_values) / max(len(defense_effectiveness_values), 1), 4)
    first_hour = minute_summaries[:60]
    last_hour = minute_summaries[-60:] if len(minute_summaries) >= 60 else minute_summaries
    first_hour_success = sum(item["counts"].get("INFECTION_SUCCESSFUL", 0) for item in first_hour)
    last_hour_success = sum(item["counts"].get("INFECTION_SUCCESSFUL", 0) for item in last_hour)
    first_hour_block = sum(item["counts"].get("INFECTION_BLOCKED", 0) for item in first_hour)
    last_hour_block = sum(item["counts"].get("INFECTION_BLOCKED", 0) for item in last_hour)
    defense_event = choose_representative_event(all_events, event_name="DEFENSE_RESULT_EVALUATED")
    attacker_event = choose_representative_event(all_events, event_name="ATTACK_RESULT_EVALUATED")
    lines: List[str] = []
    lines.append("Long-Horizon Adversarial Research Validation Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Artifact directory: {ARTIFACT_DIR.relative_to(ROOT)}")
    lines.append("")
    lines.append("Run Model")
    lines.append(f"- Logical horizon: {LOGICAL_MINUTES} minutes ({LOGICAL_MINUTES / 60:.1f} hours)")
    lines.append(f"- Real-time acceleration: 1 logical minute = {REAL_SECONDS_PER_MINUTE:.1f} seconds")
    lines.append(f"- Accelerated heartbeat interval: {ACCELERATED_HEARTBEAT_SECONDS} seconds")
    lines.append(f"- Injection cadence: every {INJECT_EVERY_MINUTES} logical minutes")
    lines.append("")
    lines.append("Infrastructure")
    lines.extend(f"- {line}" for line in compose_ps.splitlines() if line.strip())
    lines.append("")
    lines.append("Executive Findings")
    lines.append(f"- Total events observed: {len(all_events)}")
    lines.append(f"- HEARTBEAT events: {total_counts['HEARTBEAT']}")
    lines.append(f"- ATTACK_EXECUTED events: {total_counts['ATTACK_EXECUTED']}")
    lines.append(f"- INFECTION_SUCCESSFUL events: {total_counts['INFECTION_SUCCESSFUL']}")
    lines.append(f"- INFECTION_BLOCKED events: {total_counts['INFECTION_BLOCKED']}")
    lines.append(f"- DEFENSE_RESULT_EVALUATED events: {total_counts['DEFENSE_RESULT_EVALUATED']}")
    lines.append(f"- DEFENSE_ADAPTED events: {total_counts['DEFENSE_ADAPTED']}")
    lines.append(f"- Defense blocked outcomes: {defense_blocked}")
    lines.append(f"- Defense failed outcomes: {defense_failed}")
    lines.append(f"- Average defense effectiveness: {avg_defense_effectiveness}")
    lines.append(f"- First-hour attacker successes: {first_hour_success}; last-hour attacker successes: {last_hour_success}")
    lines.append(f"- First-hour attacker blocks: {first_hour_block}; last-hour attacker blocks: {last_hour_block}")
    lines.append("")
    lines.append("SOC Findings")
    if last_hour_success < first_hour_success:
        lines.append("- Attacker success volume decreased over the logical horizon, consistent with defender adaptation.")
    else:
        lines.append("- Attacker success volume did not decrease over the logical horizon; defender adaptation remains incomplete.")
    if last_hour_block > first_hour_block:
        lines.append("- Block volume increased over time, indicating Guardian learned stronger containment patterns.")
    else:
        lines.append("- Block volume did not increase materially over time; review defense weighting and quarantine thresholds.")
    if total_counts["DEFENSE_ADAPTED"] > 0:
        lines.append("- Guardian emitted explicit defense adaptation telemetry, confirming a live defense feedback loop.")
    if attack_routes:
        lines.append(f"- Most common attack route: {attack_routes.most_common(1)[0][0]}")
    if defense_strategies:
        lines.append(f"- Most common defense strategy: {defense_strategies.most_common(1)[0][0]}")
    if attack_strategies:
        lines.append(f"- Most common attacker strategy family: {attack_strategies.most_common(1)[0][0]}")
    if mutations:
        lines.append(f"- Most common mutation family: {mutations.most_common(1)[0][0]}")
    if payload_hashes:
        lines.append(f"- Most reused payload hash: {payload_hashes.most_common(1)[0][0]}")
    lines.append("")
    lines.append("Attack Patterns")
    for route, count in attack_routes.most_common(8):
        lines.append(f"- {route}: {count}")
    lines.append("")
    lines.append("Defense Patterns")
    for defense_type, count in defense_types.most_common(8):
        if defense_type:
            lines.append(f"- defense_type={defense_type}: {count}")
    for strategy, count in defense_strategies.most_common(8):
        if strategy:
            lines.append(f"- defense_strategy={strategy}: {count}")
    lines.append("")
    lines.append("API Intelligence Snapshots")
    mutation_top = (api_snapshots.get("mutation") or {}).get("leaderboard") or []
    strategy_top = (api_snapshots.get("strategy") or {}).get("leaderboard") or []
    families_top = (api_snapshots.get("payload_families") or {}).get("top_payload_families") or []
    campaigns_top = (api_snapshots.get("campaigns") or {}).get("campaigns") or []
    if mutation_top:
        row = mutation_top[0]
        lines.append(f"- Mutation leader: {row.get('mutation_type')} success_rate={row.get('success_rate')} attempts={row.get('total_attempts')}")
    if strategy_top:
        row = strategy_top[0]
        lines.append(f"- Strategy leader: {row.get('strategy_family')} success_rate={row.get('success_rate')} attempts={row.get('attempts')}")
    if families_top:
        row = families_top[0]
        lines.append(f"- Payload family leader: semantic_family={row.get('semantic_family')} hashes={row.get('payload_hash_count')} success_rate={row.get('success_rate')}")
    if campaigns_top:
        row = campaigns_top[0]
        lines.append(f"- Top campaign: campaign_id={row.get('campaign_id')} attempts={row.get('total_attempts')} successes={row.get('total_successes')} blocks={row.get('total_blocks')}")
    patterns = (api_snapshots.get("patterns") or {}).get("pattern_cards") or []
    for card in patterns[:8]:
        lines.append(f"- Pattern: {card.get('name')}: {card.get('explanation')}")
    lines.append("")
    lines.append("Representative Reasoning")
    if attacker_event:
        attack_detail = api_snapshots.get("attacker_decision_summary") or {}
        lines.append(f"- Attacker event: {event_ref(attacker_event)} -> {(attack_detail.get('summary') or {}).get('quick_explanation', '-')}")
        for message in (attack_detail.get("diff") or {}).get("messages", [])[:3]:
            lines.append(f"  attacker_change: {message}")
    if defense_event:
        defense_detail = api_snapshots.get("defense_decision_summary") or {}
        lines.append(f"- Defense event: {event_ref(defense_event)} -> {(defense_detail.get('summary') or {}).get('quick_explanation', '-')}")
        for message in (defense_detail.get("diff") or {}).get("messages", [])[:3]:
            lines.append(f"  defense_change: {message}")
    lines.append("")
    lines.append("Minute-by-Minute Timeline")
    for item in minute_summaries:
        lines.append(
            f"- M{item['minute']:03d} {item['logical_ts_utc']} "
            f"events={item['event_count']} attack_exec={item['counts'].get('ATTACK_EXECUTED', 0)} "
            f"success={item['counts'].get('INFECTION_SUCCESSFUL', 0)} blocked={item['counts'].get('INFECTION_BLOCKED', 0)} "
            f"defense_eval={item['counts'].get('DEFENSE_RESULT_EVALUATED', 0)} defense_adapt={item['counts'].get('DEFENSE_ADAPTED', 0)} "
            f"top_attack={item['top_attack_strategy'] or '-'} top_defense={item['top_defense_strategy'] or '-'} "
            f"top_mutation={item['top_mutation'] or '-'} top_target={item['top_target'] or '-'} "
            f"highlights={'; '.join(item['highlights']) if item['highlights'] else '-'}"
        )
    lines.append("")
    lines.append("Research Guidance")
    lines.append("- Compare first-hour versus last-hour attack success to quantify adaptation slope.")
    lines.append("- Review DEFENSE_ADAPTED chains for repeated failure streaks and quarantine escalations.")
    lines.append("- Pivot on defense_strategy=multi_layer_check versus mutation_type=context_wrap|reframe for defender effectiveness tuning.")
    lines.append("- Investigate campaigns where attacker success remained high despite defense adaptations; those are the highest research-value counterexamples.")
    lines.append("- Correlate payload lineage reuse with defense_result=success to find defender blind spots.")
    lines.append("")
    error_lines = [line for line in compose_logs.splitlines() if any(token in line for token in ("Traceback", "Exception", "ERROR", "Error"))]
    lines.append("Compose Log Review")
    if error_lines:
        for line in error_lines[:20]:
            lines.append(f"- {line}")
    else:
        lines.append("- No obvious error markers detected in compose logs.")
    return "\n".join(lines)


def main() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    archive_existing_logs()

    base_env = os.environ.copy()
    compose_env = dict(base_env)
    compose_env["HEARTBEAT_INTERVAL_S"] = str(ACCELERATED_HEARTBEAT_SECONDS)

    run_command(["docker", "compose", "down", "--remove-orphans"], env=compose_env, output_path=ARTIFACT_DIR / "compose_down.txt")
    run_command(["docker", "compose", "build", "orchestrator", "agent-a", "agent-b", "agent-c"], env=compose_env, output_path=ARTIFACT_DIR / "compose_build.txt")
    run_command(["docker", "compose", "up", "-d"], env=compose_env, output_path=ARTIFACT_DIR / "compose_up.txt")

    try:
        wait_for_status()
        reset_response = api_json("POST", "/reset", {})
        time.sleep(1.5)
        logical_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        baseline = fetch_events(order="desc", limit=1)
        last_seen_id = int(baseline.get("latest_id", 0) or 0)
        minute_summaries: List[Dict[str, Any]] = []
        all_events: List[Dict[str, Any]] = []
        injections: List[Dict[str, Any]] = []
        minute_jsonl = ARTIFACT_DIR / "minute_summaries.jsonl"
        with minute_jsonl.open("w", encoding="utf-8") as minute_handle:
            for minute_index in range(1, LOGICAL_MINUTES + 1):
                logical_ts = logical_start + timedelta(minutes=minute_index - 1)
                injection: Dict[str, Any] | None = None
                if minute_index == 1 or (minute_index - 1) % INJECT_EVERY_MINUTES == 0:
                    level = LEVEL_PATTERN[((minute_index - 1) // INJECT_EVERY_MINUTES) % len(LEVEL_PATTERN)]
                    injection = api_json("POST", "/inject/agent-c", {"worm_level": level})
                    injection["worm_level"] = level
                    injection["logical_minute"] = minute_index
                    injections.append(injection)
                time.sleep(REAL_SECONDS_PER_MINUTE)
                minute_events, latest_seen = fetch_new_events(last_seen_id)
                last_seen_id = latest_seen
                all_events.extend(minute_events)
                summary = summarize_minute(
                    minute_index,
                    logical_ts,
                    minute_events,
                    all_events,
                    injection=injection,
                )
                minute_summaries.append(summary)
                minute_handle.write(json.dumps(summary, ensure_ascii=False) + "\n")

        mutation = fetch_api("/api/mutation-analytics", {"time_range": "all"})
        strategy = fetch_api("/api/strategy-analytics", {"time_range": "all"})
        payload_families = fetch_api("/api/payload-families", {"time_range": "all"})
        campaigns = fetch_api("/api/campaigns", {"time_range": "all"})
        patterns = fetch_api("/api/patterns", {"q": "event!=HEARTBEAT", "time_range": "all"})
        defense_results = fetch_api("/api/search", {"q": "event=DEFENSE_RESULT_EVALUATED", "time_range": "all"})
        representative_defense = (defense_results.get("events") or [])[-1] if defense_results.get("events") else None
        representative_attack_results = fetch_api("/api/search", {"q": "event=ATTACK_RESULT_EVALUATED", "time_range": "all"})
        representative_attack = (representative_attack_results.get("events") or [])[-1] if representative_attack_results.get("events") else None
        defense_decision_summary = fetch_api(f"/api/decision-summary/{urllib.parse.quote(str(representative_defense['event_id']))}") if representative_defense else {}
        attacker_decision_summary = fetch_api(f"/api/decision-summary/{urllib.parse.quote(str(representative_attack['event_id']))}") if representative_attack else {}

        api_snapshots = {
            "mutation": mutation,
            "strategy": strategy,
            "payload_families": payload_families,
            "campaigns": campaigns,
            "patterns": patterns,
            "defense_decision_summary": defense_decision_summary,
            "attacker_decision_summary": attacker_decision_summary,
        }
        for name, payload in api_snapshots.items():
            (ARTIFACT_DIR / f"{name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

        compose_ps = run_command(["docker", "compose", "ps"], env=compose_env, output_path=ARTIFACT_DIR / "compose_ps.txt")
        compose_logs = run_command(["docker", "compose", "logs", "--no-color", "--timestamps"], env=compose_env, output_path=ARTIFACT_DIR / "compose_logs.txt")
        report = build_report(minute_summaries, all_events, api_snapshots, compose_ps, compose_logs)
        (ARTIFACT_DIR / "research_report.txt").write_text(report, encoding="utf-8")
        (ARTIFACT_DIR / "summary.json").write_text(
            json.dumps(
                {
                    "logical_minutes": LOGICAL_MINUTES,
                    "real_seconds_per_minute": REAL_SECONDS_PER_MINUTE,
                    "injections": injections,
                    "minute_summaries": minute_summaries,
                    "api_snapshot_paths": {name: f"{name}.json" for name in api_snapshots},
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        with (ARTIFACT_DIR / "all_events.jsonl").open("w", encoding="utf-8") as handle:
            for event in all_events:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        print(report)
    finally:
        run_command(["docker", "compose", "down", "--remove-orphans"], env=compose_env, output_path=ARTIFACT_DIR / "compose_down_final.txt")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Long research validation failed: {exc}", file=sys.stderr)
        raise
