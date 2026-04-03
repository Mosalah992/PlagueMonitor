import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOGS_DIR = ROOT / "logs"
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
ARTIFACT_DIR = LOGS_DIR / f"phase3_validation_{RUN_TS}"
API_URL = "http://localhost:8000"
RUN_LEVELS = ["easy", "medium", "difficult", "medium", "difficult", "easy"]
ACCELERATED_HEARTBEAT_SECONDS = 2
OBSERVATION_SECONDS = 4.0
RESET_WAIT_SECONDS = 1.2


def run_command(command, *, env=None, output_path=None):
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
        Path(output_path).write_text(
            completed.stdout + ("\n" + completed.stderr if completed.stderr else ""),
            encoding="utf-8",
        )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def api_json(path, *, method="GET", payload=None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"{API_URL}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_status():
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            payload = api_json("/status")
            if payload.get("status") == "running":
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError("API did not become ready in time")


def fetch_events(after_id=0, order="asc", limit=500):
    return api_json(f"/events?after_id={after_id}&order={order}&limit={limit}")


def archive_existing_logs():
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("epidemic.db", "events.jsonl", "siem_index.db", "siem_actions.jsonl"):
        source = LOGS_DIR / name
        if source.exists():
            shutil.copy2(source, ARTIFACT_DIR / f"pretest_{name}")


def event_id(event):
    return int(event.get("id", 0) or 0)


def pick_interesting_event(events):
    ranked = [
        event for event in events
        if event.get("payload_hash")
        and (
            event.get("event") in {"ATTACKER_DECISION", "ATTACK_EXECUTED", "ATTACK_RESULT_EVALUATED", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
            or event.get("metadata", {}).get("strategy_family")
        )
    ]
    return ranked[-1] if ranked else (events[-1] if events else None)


def summarize_run(index, level, reset_response, inject_response, events):
    counts = Counter(str(event.get("event", "")) for event in events)
    return {
        "run": index,
        "worm_level": level,
        "reset_id": reset_response.get("reset_id"),
        "epoch": reset_response.get("epoch"),
        "injection_id": inject_response.get("injection_id"),
        "event_count": len(events),
        "counts": dict(counts),
        "interesting_event_id": "",
        "interesting_payload_hash": "",
        "interesting_campaign_id": "",
    }


def safe_api_json(path):
    try:
        return api_json(path)
    except Exception as exc:
        return {"error": str(exc)}


def main():
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

        baseline = fetch_events(order="desc", limit=1)
        last_seen_id = int(baseline.get("latest_id", 0) or 0)
        run_summaries = []
        decoded_samples = []
        suggestion_samples = []

        for index, level in enumerate(RUN_LEVELS, start=1):
            reset_response = api_json("/reset", method="POST", payload={})
            time.sleep(RESET_WAIT_SECONDS)
            inject_response = api_json("/inject/agent-c", method="POST", payload={"worm_level": level})
            time.sleep(OBSERVATION_SECONDS)

            run_payload = fetch_events(after_id=last_seen_id, order="asc", limit=800)
            run_events = run_payload.get("events", [])
            if run_events:
                last_seen_id = max(event_id(event) for event in run_events)

            summary = summarize_run(index, level, reset_response, inject_response, run_events)
            if summary["injection_id"]:
                injection_query = f"injection_id={summary['injection_id']}"
                search_payload = safe_api_json(
                    f"/api/search?q={urllib.parse.quote(injection_query)}&time_range=all"
                )
                interesting_events = search_payload.get("events", [])
                interesting = pick_interesting_event(interesting_events)
                if interesting:
                    summary["interesting_event_id"] = interesting.get("event_id", "")
                    summary["interesting_payload_hash"] = interesting.get("payload_hash", "")
                    summary["interesting_campaign_id"] = interesting.get("metadata", {}).get("campaign_id", "")
            run_summaries.append(summary)
            (ARTIFACT_DIR / f"run_{index:02d}.json").write_text(
                json.dumps(
                    {
                        "summary": summary,
                        "reset_response": reset_response,
                        "inject_response": inject_response,
                        "events": run_events,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            interesting_event_id = summary.get("interesting_event_id") or ""
            campaign_id = summary.get("interesting_campaign_id") or ""
            injection_id = summary.get("injection_id") or ""

            if interesting_event_id:
                detail = safe_api_json(f"/api/event/{urllib.parse.quote(str(interesting_event_id))}?include_full_payload=true")
                decision = safe_api_json(f"/api/decision-summary/{urllib.parse.quote(str(interesting_event_id))}")
                support = safe_api_json(f"/api/decision-support?event_id={urllib.parse.quote(str(interesting_event_id))}")
                decoded_samples.append(
                    {
                        "run": index,
                        "event_id": interesting_event_id,
                        "payload_hash": summary.get("interesting_payload_hash"),
                        "raw_preview": detail.get("event", {}).get("payload_preview", ""),
                        "decoded_preview": detail.get("event", {}).get("decoded_payload_preview", ""),
                        "decoded_payload_text": detail.get("event", {}).get("decoded_payload_text", "")[:400],
                        "decision": decision,
                    }
                )
                suggestion_samples.append(
                    {
                        "run": index,
                        "event_id": interesting_event_id,
                        "suggestions": support.get("suggestions", []),
                    }
                )
                (ARTIFACT_DIR / f"event_detail_{index:02d}.json").write_text(json.dumps(detail, indent=2), encoding="utf-8")
                (ARTIFACT_DIR / f"decision_summary_{index:02d}.json").write_text(json.dumps(decision, indent=2), encoding="utf-8")
                (ARTIFACT_DIR / f"decision_support_{index:02d}.json").write_text(json.dumps(support, indent=2), encoding="utf-8")

            if injection_id:
                lineage = safe_api_json(f"/api/payload-lineage/by-injection/{urllib.parse.quote(str(injection_id))}")
                (ARTIFACT_DIR / f"lineage_injection_{index:02d}.json").write_text(json.dumps(lineage, indent=2), encoding="utf-8")

            if campaign_id:
                campaign = safe_api_json(f"/api/campaign/{urllib.parse.quote(str(campaign_id))}")
                (ARTIFACT_DIR / f"campaign_{index:02d}.json").write_text(json.dumps(campaign, indent=2), encoding="utf-8")

        scoped_query = urllib.parse.quote("event!=HEARTBEAT")
        mutation = safe_api_json(f"/api/mutation-analytics?q={scoped_query}&time_range=last_1h")
        strategy = safe_api_json(f"/api/strategy-analytics?q={scoped_query}&time_range=last_1h")
        families = safe_api_json(f"/api/payload-families?q={scoped_query}&time_range=last_1h")
        campaigns = safe_api_json("/api/campaigns")
        patterns = safe_api_json(f"/api/patterns?q={scoped_query}&time_range=last_1h")
        search = safe_api_json(f"/api/search?q={scoped_query}&time_range=last_1h")

        (ARTIFACT_DIR / "mutation_analytics.json").write_text(json.dumps(mutation, indent=2), encoding="utf-8")
        (ARTIFACT_DIR / "strategy_analytics.json").write_text(json.dumps(strategy, indent=2), encoding="utf-8")
        (ARTIFACT_DIR / "payload_families.json").write_text(json.dumps(families, indent=2), encoding="utf-8")
        (ARTIFACT_DIR / "campaigns.json").write_text(json.dumps(campaigns, indent=2), encoding="utf-8")
        (ARTIFACT_DIR / "patterns.json").write_text(json.dumps(patterns, indent=2), encoding="utf-8")
        (ARTIFACT_DIR / "search_snapshot.json").write_text(json.dumps(search, indent=2), encoding="utf-8")

        compose_ps = run_command(["docker", "compose", "ps"], env=compose_env, output_path=ARTIFACT_DIR / "compose_ps.txt")
        compose_logs = run_command(["docker", "compose", "logs", "--no-color", "--timestamps"], env=compose_env, output_path=ARTIFACT_DIR / "compose_logs.txt")

        total_counts = Counter()
        for summary in run_summaries:
            total_counts.update(summary["counts"])

        lines = []
        lines.append("Phase 3 Validation Report")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Artifact directory: {ARTIFACT_DIR.relative_to(ROOT)}")
        lines.append("")
        lines.append("Infrastructure")
        lines.extend(f"- {line}" for line in compose_ps.splitlines() if line.strip())
        lines.append("")
        lines.append("Heartbeat Model")
        lines.append(f"- Accelerated heartbeat interval: {ACCELERATED_HEARTBEAT_SECONDS} seconds")
        lines.append(f"- Injection windows executed: {len(RUN_LEVELS)}")
        lines.append(f"- Observation time per window: {OBSERVATION_SECONDS} seconds")
        lines.append("")
        lines.append("Executive Summary")
        lines.append(f"- Total HEARTBEAT events: {total_counts['HEARTBEAT']}")
        lines.append(f"- Total ATTACK_EXECUTED events: {total_counts['ATTACK_EXECUTED']}")
        lines.append(f"- Total INFECTION_SUCCESSFUL events: {total_counts['INFECTION_SUCCESSFUL']}")
        lines.append(f"- Total INFECTION_BLOCKED events: {total_counts['INFECTION_BLOCKED']}")
        lines.append(f"- Top mutation family: {mutation.get('summary', {}).get('top_family', '(empty)')}")
        lines.append(f"- Top strategy family: {strategy.get('summary', {}).get('top_strategy_family', '(empty)')}")
        lines.append(f"- Payload family count: {families.get('summary', {}).get('family_count', len(families.get('families', [])))}")
        lines.append(f"- Campaign count: {campaigns.get('summary', {}).get('campaign_count', len(campaigns.get('campaigns', [])))}")
        lines.append("")
        lines.append("Per-Window Breakdown")
        for summary in run_summaries:
            lines.append(
                f"- Run {summary['run']:02d} level={summary['worm_level']} events={summary['event_count']} "
                f"attempted={summary['counts'].get('ATTACK_EXECUTED', 0)} "
                f"successful={summary['counts'].get('INFECTION_SUCCESSFUL', 0)} "
                f"blocked={summary['counts'].get('INFECTION_BLOCKED', 0)} "
                f"heartbeats={summary['counts'].get('HEARTBEAT', 0)} "
                f"injection_id={summary['injection_id']}"
            )
        lines.append("")
        lines.append("Decoded Payload Samples")
        for sample in decoded_samples[:8]:
            lines.append(f"- Run {sample['run']:02d} event={sample['event_id']} hash={sample['payload_hash']}")
            lines.append(f"  raw_preview: {sample['raw_preview'][:220]}")
            lines.append(f"  decoded_preview: {sample['decoded_preview'][:220]}")
            decoded_text = sample.get("decoded_payload_text") or ""
            if decoded_text:
                lines.append(f"  decoded_payload_text: {decoded_text[:300]}")
            quick = sample.get("decision", {}).get("summary", {}).get("quick_explanation", "")
            if quick:
                lines.append(f"  why_this_attack: {quick}")
        lines.append("")
        lines.append("Mutation Analytics")
        for row in (mutation.get("leaderboard") or [])[:5]:
            lines.append(
                f"- {row['mutation_type']}: attempts={row['total_attempts']} success={row['total_successes']} "
                f"blocks={row['total_blocks']} rate={row['success_rate']:.1%} depth={row['avg_lineage_depth']}"
            )
        lines.append("")
        lines.append("Strategy Analytics")
        for row in (strategy.get("leaderboard") or [])[:5]:
            lines.append(
                f"- {row['strategy_family']}: attempts={row['attempts']} success={row['successes']} "
                f"blocks={row['blocks']} rate={row['success_rate']:.1%}"
            )
        lines.append("")
        lines.append("Payload Families")
        for row in (families.get("top_payload_families") or [])[:5]:
            lines.append(
                f"- {row.get('label') or row.get('semantic_family')}: hashes={row.get('payload_hash_count', row.get('hash_count', 0))} "
                f"attempts={row.get('attempts', 0)} success={row.get('success_rate', 0):.1%}"
            )
        lines.append("")
        lines.append("Observed Patterns")
        for card in (patterns.get("pattern_cards") or [])[:6]:
            lines.append(f"- {card.get('name')}: {card.get('explanation')}")
        lines.append("")
        lines.append("Suggested Next Runs")
        flattened_suggestions = []
        for sample in suggestion_samples:
            for item in sample.get("suggestions", [])[:3]:
                flattened_suggestions.append(item)
        seen = set()
        for item in flattened_suggestions:
            key = item.get("title") or item.get("message")
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"- {key}: {item.get('reason') or item.get('message', '')}")
        lines.append("")
        lines.append("Compose Log Errors")
        error_lines = [line for line in compose_logs.splitlines() if any(token in line for token in ("Traceback", "Exception", "ERROR", "Error"))]
        if error_lines:
            for line in error_lines[:20]:
                lines.append(f"- {line}")
        else:
            lines.append("- No obvious error markers detected in compose logs.")

        report_text = "\n".join(lines)
        (ARTIFACT_DIR / "phase3_report.txt").write_text(report_text, encoding="utf-8")
        (ARTIFACT_DIR / "summary.json").write_text(
            json.dumps(
                {
                    "runs": run_summaries,
                    "mutation_summary": mutation.get("summary", {}),
                    "strategy_summary": strategy.get("summary", {}),
                    "family_summary": families.get("summary", {}),
                    "campaign_summary": campaigns.get("summary", {}),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(report_text)
    finally:
        run_command(["docker", "compose", "down", "--remove-orphans"], env=compose_env, output_path=ARTIFACT_DIR / "compose_down_final.txt")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Phase 3 validation failed: {exc}", file=sys.stderr)
        raise
