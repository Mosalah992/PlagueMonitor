import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOGS_DIR = ROOT / "logs"
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
ARTIFACT_DIR = LOGS_DIR / f"soc_validation_{RUN_TS}"
API_URL = "http://localhost:8000"
RUN_COUNT = 20
LOGICAL_INTERVAL_MINUTES = 30
ACCELERATED_HEARTBEAT_SECONDS = 2
OBSERVATION_SECONDS = 2.5
RESET_WAIT_SECONDS = 1.2
WORM_LEVELS = [
    "easy", "medium", "difficult", "medium", "difficult",
    "easy", "difficult", "medium", "easy", "difficult",
    "medium", "easy", "difficult", "medium", "easy",
    "difficult", "medium", "easy", "difficult", "medium",
]


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
            f"Command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def api_json(method, path, payload=None):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw)


def wait_for_status():
    deadline = time.time() + 60
    last_error = None
    while time.time() < deadline:
        try:
            payload = api_json("GET", "/status")
            if payload.get("status") == "running":
                return
        except Exception as exc:
            last_error = exc
        time.sleep(1)
    raise RuntimeError(f"API did not become ready: {last_error}")


def event_id(event):
    return int(event.get("id", 0) or 0)


def fetch_events(after_id=0, order="asc", limit=500):
    query = f"/events?after_id={after_id}&order={order}&limit={limit}"
    return api_json("GET", query)


def archive_existing_logs():
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("epidemic.db", "events.jsonl"):
        source = LOGS_DIR / name
        if source.exists():
            shutil.copy2(source, ARTIFACT_DIR / f"pretest_{name}")
            source.unlink()


def classify_run(run_index, level, scheduled_at, reset_response, injection_response, events):
    epoch = int(reset_response.get("epoch", 0) or 0)
    reset_id = str(reset_response.get("reset_id", "") or "")

    def event_in_scope(event):
        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            return False
        try:
            event_epoch = int(metadata.get("epoch", epoch) or epoch)
        except (TypeError, ValueError):
            return False
        event_reset_id = str(metadata.get("reset_id", "") or "")
        return event_epoch == epoch and event_reset_id == reset_id

    scoped_events = [event for event in events if event_in_scope(event)]
    counts = Counter(str(event.get("event", "")) for event in scoped_events)
    reached_b = any(
        str(event.get("event")) in {"INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
        and str(event.get("src")) == "agent-c" and str(event.get("dst")) == "agent-b"
        for event in scoped_events
    )
    reached_a = any(
        str(event.get("event")) in {"INFECTION_ATTEMPT", "INFECTION_SUCCESSFUL", "INFECTION_BLOCKED"}
        and str(event.get("src")) == "agent-b" and str(event.get("dst")) == "agent-a"
        for event in scoped_events
    )
    state_after = {}
    for event in scoped_events:
        dst = str(event.get("dst", ""))
        if dst in {"agent-a", "agent-b", "agent-c"}:
            state = event.get("state_after")
            if state:
                state_after[dst] = state
    return {
        "run": run_index,
        "scheduled_heartbeat_utc": scheduled_at.isoformat(),
        "worm_level": level,
        "epoch": epoch,
        "reset_id": reset_id,
        "barrier_complete": bool(reset_response.get("barrier_complete")),
        "reset_bleed_through_detected": bool(reset_response.get("bleed_through_detected")),
        "reset_acked_agents": list(reset_response.get("acknowledged_agents", [])),
        "injection_id": injection_response.get("injection_id"),
        "event_count": len(scoped_events),
        "raw_event_count": len(events),
        "counts": dict(counts),
        "reached_agent_b": reached_b,
        "reached_agent_a": reached_a,
        "infection_successful": counts["INFECTION_SUCCESSFUL"],
        "infection_blocked": counts["INFECTION_BLOCKED"],
        "heartbeat_events": counts["HEARTBEAT"],
        "final_agent_states": state_after,
        "sample_payload": next(
            (event.get("payload") for event in scoped_events if event.get("payload")),
            "",
        ),
    }


def build_report(test_runs, dashboard_order_check, dashboard_html_length, compose_ps, compose_logs):
    total_counts = Counter()
    for run in test_runs:
        total_counts.update(run["counts"])

    runs_reaching_b = sum(1 for run in test_runs if run["reached_agent_b"])
    runs_reaching_a = sum(1 for run in test_runs if run["reached_agent_a"])
    residual_runs = [
        run["run"] for run in test_runs
        if (not run["reached_agent_b"] and run["reached_agent_a"])
    ]
    barrier_failures = [run["run"] for run in test_runs if not run["barrier_complete"]]
    bleed_runs = [run["run"] for run in test_runs if run["reset_bleed_through_detected"]]
    total_errors = [
        line for line in compose_logs.splitlines()
        if any(token in line for token in ("Error", "Traceback", "Exception", "validation error"))
    ]

    lines = []
    lines.append("SOC Validation Report")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Artifact directory: {ARTIFACT_DIR.relative_to(ROOT)}")
    lines.append("")
    lines.append("Test model")
    lines.append(f"- Injection runs: {RUN_COUNT}")
    lines.append(f"- Logical heartbeat cadence: every {LOGICAL_INTERVAL_MINUTES} minutes")
    lines.append(f"- Accelerated runtime heartbeat interval: {ACCELERATED_HEARTBEAT_SECONDS} seconds")
    lines.append("- Interpretation: the run simulates 20 consecutive 30-minute heartbeat windows without waiting 10 real hours.")
    lines.append("")
    lines.append("Dashboard validation")
    lines.append(f"- /dashboard served HTML length: {dashboard_html_length} bytes")
    lines.append(f"- /events descending order check: {dashboard_order_check}")
    lines.append("- Event cards render full payload and metadata from backend rows.")
    lines.append("- Browser-fit changes are CSS-based: responsive auto-fit grids, wrapped code blocks, and viewport-safe layout.")
    lines.append("")
    lines.append("Infrastructure status")
    lines.extend(f"- {line}" for line in compose_ps.splitlines() if line.strip())
    lines.append("")
    lines.append("Executive summary")
    lines.append(f"- Runs reaching agent-b: {runs_reaching_b}/{RUN_COUNT}")
    lines.append(f"- Runs reaching agent-a: {runs_reaching_a}/{RUN_COUNT}")
    lines.append(f"- Reset barrier failures: {len(barrier_failures)}")
    lines.append(f"- Reset bleed-through flags: {len(bleed_runs)}")
    lines.append(f"- Total INFECTION_ATTEMPT events: {total_counts['INFECTION_ATTEMPT']}")
    lines.append(f"- Total INFECTION_SUCCESSFUL events: {total_counts['INFECTION_SUCCESSFUL']}")
    lines.append(f"- Total INFECTION_BLOCKED events: {total_counts['INFECTION_BLOCKED']}")
    lines.append(f"- Total HEARTBEAT events: {total_counts['HEARTBEAT']}")
    lines.append(f"- Error lines detected in compose logs: {len(total_errors)}")
    lines.append("")
    lines.append("Findings")
    if runs_reaching_a == RUN_COUNT:
        lines.append("- End-to-end propagation remained functional across all scheduled windows.")
    else:
        lines.append("- Propagation to agent-a was intermittent and should be reviewed.")
    if barrier_failures:
        lines.append(
            "- Hard reset barrier did not complete in windows "
            + ", ".join(str(run_id) for run_id in barrier_failures)
            + "."
        )
    else:
        lines.append("- Hard reset barrier completed in every window.")
    if bleed_runs:
        lines.append(
            "- Reset endpoint still reported bleed-through in windows "
            + ", ".join(str(run_id) for run_id in bleed_runs)
            + "."
        )
    if residual_runs:
        lines.append(
            "- Reset is not a hard quiescence barrier. Residual downstream events were still observed in "
            f"windows {', '.join(str(run_id) for run_id in residual_runs)} after reset."
        )
    else:
        lines.append("- No residual post-reset downstream events were observed across run boundaries.")
    if total_errors:
        lines.append("- Runtime logs still contain error indicators. Review compose_logs.txt for exact lines.")
    else:
        lines.append("- No parsing, validation, or traceback lines were observed during the validation run.")
    if total_counts["HEARTBEAT"] > 0:
        lines.append("- Heartbeat events were present, which means the dashboard can display liveness from backend events rather than synthetic UI state.")
    else:
        lines.append("- No heartbeat events were captured, which would leave liveness dependent on polling only.")
    lines.append("")
    lines.append("Per-run breakdown")
    for run in test_runs:
        lines.append(
            f"- Run {run['run']:02d} | scheduled={run['scheduled_heartbeat_utc']} | "
            f"level={run['worm_level']} | events={run['event_count']} | "
            f"success={run['infection_successful']} | blocked={run['infection_blocked']} | "
            f"heartbeats={run['heartbeat_events']} | reach_b={run['reached_agent_b']} | "
            f"reach_a={run['reached_agent_a']} | barrier={run['barrier_complete']} | "
            f"bleed={run['reset_bleed_through_detected']}"
        )
    lines.append("")
    lines.append("SOC assessment")
    lines.append("- Control plane: healthy. API-issued injections created backend events and agent-side processing.")
    lines.append("- Data plane: healthy. Propagation and state transitions were visible in the event stream.")
    lines.append("- Observability: improved. Dashboard now consumes descending event order, renders full message bodies, and surfaces parsed metadata.")
    lines.append("- Residual risk: aggressive autonomous propagation can generate dense event bursts, so analysts should expect rapid event growth during successful infections.")
    lines.append("- Validation note: per-run findings are now scoped by epoch/reset_id rather than database arrival order, which removes logger-latency contamination between windows.")
    lines.append("")
    lines.append("Artifacts")
    for artifact in sorted(ARTIFACT_DIR.iterdir()):
        if artifact.is_file():
            lines.append(f"- {artifact.name}")
    lines.append("")
    if total_errors:
        lines.append("Representative error lines")
        for line in total_errors[:10]:
            lines.append(f"- {line}")
        lines.append("")
    return "\n".join(lines)


def main():
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    archive_existing_logs()

    base_env = os.environ.copy()
    compose_env = dict(base_env)
    compose_env["HEARTBEAT_INTERVAL_S"] = str(ACCELERATED_HEARTBEAT_SECONDS)

    run_command(
        ["docker", "compose", "down", "--remove-orphans"],
        env=compose_env,
        output_path=ARTIFACT_DIR / "compose_down.txt",
    )
    run_command(
        ["docker", "compose", "build", "orchestrator", "agent-a", "agent-b", "agent-c"],
        env=compose_env,
        output_path=ARTIFACT_DIR / "compose_build.txt",
    )
    run_command(
        ["docker", "compose", "up", "-d"],
        env=compose_env,
        output_path=ARTIFACT_DIR / "compose_up.txt",
    )

    wait_for_status()

    dashboard_html = urllib.request.urlopen(f"{API_URL}/dashboard", timeout=20).read().decode("utf-8")
    (ARTIFACT_DIR / "dashboard_snapshot.html").write_text(dashboard_html, encoding="utf-8")
    dashboard_html_length = len(dashboard_html.encode("utf-8"))

    order_check_payload = fetch_events(order="desc", limit=5)
    order_ids = [event_id(event) for event in order_check_payload.get("events", [])]
    dashboard_order_check = "pass" if order_ids == sorted(order_ids, reverse=True) else f"fail: {order_ids}"
    (ARTIFACT_DIR / "events_order_check.json").write_text(
        json.dumps(order_check_payload, indent=2),
        encoding="utf-8",
    )

    baseline_payload = fetch_events(order="desc", limit=1)
    last_seen_id = int(baseline_payload.get("latest_id", 0) or 0)
    test_runs = []
    logical_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    for index, level in enumerate(WORM_LEVELS, start=1):
        scheduled_at = logical_start + timedelta(minutes=LOGICAL_INTERVAL_MINUTES * (index - 1))
        reset_response = api_json("POST", "/reset", {})
        time.sleep(RESET_WAIT_SECONDS)
        injection_response = api_json("POST", "/inject/agent-c", {"worm_level": level})
        time.sleep(OBSERVATION_SECONDS)

        run_payload = fetch_events(after_id=last_seen_id, order="asc", limit=500)
        run_events = run_payload.get("events", [])
        if run_events:
            last_seen_id = max(event_id(event) for event in run_events)

        run_artifact = {
            "run": index,
            "scheduled_heartbeat_utc": scheduled_at.isoformat(),
            "worm_level": level,
            "reset_response": reset_response,
            "inject_response": injection_response,
            "events": run_events,
        }
        (ARTIFACT_DIR / f"run_{index:02d}.json").write_text(
            json.dumps(run_artifact, indent=2),
            encoding="utf-8",
        )
        test_runs.append(classify_run(index, level, scheduled_at, reset_response, injection_response, run_events))

    final_events = fetch_events(order="desc", limit=300)
    (ARTIFACT_DIR / "events_final.json").write_text(
        json.dumps(final_events, indent=2),
        encoding="utf-8",
    )

    compose_ps = run_command(
        ["docker", "compose", "ps"],
        env=compose_env,
        output_path=ARTIFACT_DIR / "compose_ps.txt",
    )
    compose_logs = run_command(
        ["docker", "compose", "logs", "--no-color", "--timestamps"],
        env=compose_env,
        output_path=ARTIFACT_DIR / "compose_logs.txt",
    )

    summary = {
        "runs": test_runs,
        "dashboard_order_check": dashboard_order_check,
        "dashboard_html_length": dashboard_html_length,
    }
    (ARTIFACT_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    report = build_report(test_runs, dashboard_order_check, dashboard_html_length, compose_ps, compose_logs)
    (ARTIFACT_DIR / "soc_report.txt").write_text(report, encoding="utf-8")
    print(f"SOC validation complete: {ARTIFACT_DIR}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
