# Bloodplague Research Writeup Template

**Campaign:** BLOODPLAGUE
**Requested label:** `soak_run_03`
**Actual run id:** `soak_run_05`
**Run status at template creation:** `running`
**Wall-clock start (UTC):** `2026-04-03T15:39:27.936627+00:00`
**Wall-clock start (Africa/Cairo):** `2026-04-03 17:39:27`
**Target duration:** `6.0` hours
**Runner:** `python scripts/run_wallclock_research_validation.py --hours 6`

## 1. Methodology

Use this section to describe the run as an adversarial wall-clock soak, not a synthetic replay.

- Topology: `orchestrator -> agent-c -> agent-b -> agent-a`
- Cadence: 1 reporting minute = 60 seconds
- Injection cadence: every 5 reporting minutes
- Planned injections: 72 over 6 hours
- Logging sources:
  - `logs/soak_run_05/progress.json`
  - `logs/soak_run_05/minute_summaries.jsonl`
  - `logs/soak_run_05/all_events.jsonl` when present
  - fallback: `logs/events.jsonl`, `logs/epidemic.db`

Writeup points to cover:

- What changed from prior runs, if anything
- Which model stack each agent used during the run
- Why the Guardian (`agent-a`) is the terminal node of interest
- Why this counts as worm propagation rather than isolated prompt injection

## 2. Results

Fill this after the soak ends.

| Metric | Value |
|---|---:|
| Total events | TODO |
| Scheduled injections | TODO |
| `ATTACK_EXECUTED` | TODO |
| `ATTACK_PAYLOAD_VALIDATED` | TODO |
| `LLM_PAYLOAD_GENERATED` | TODO |
| `ATTACK_TEMPLATE_FALLBACK` | TODO |
| `INFECTION_SUCCESSFUL` | TODO |
| `INFECTION_BLOCKED` | TODO |
| `DEFENSE_ADAPTED` | TODO |
| Guardian success rate (`dst=agent-a`) | TODO |
| Guardian block rate (`dst=agent-a`) | TODO |

Minimum outcome cuts:

- Outcome distribution by target: `agent-c`, `agent-b`, `agent-a`
- Time-to-first successful infection at `agent-a`
- Time-to-first block at `agent-a`
- Dominant attack objective late in the run
- Dominant mutation family by event count

## 3. Findings

Frame findings as claims backed by event evidence.

1. Did the attacker converge on deep-node pressure (`agent-a`) or stay broad?
2. Did the relay node (`agent-b`) remain the decisive weakness?
3. Did Guardian adaptation materially change block behavior over time?
4. Were generated payloads semantically adversarial, or did the system fall back to templates/refusals?
5. Did any payload lineage dominate the event stream by hash or mutation depth?

## 4. Payloads

Include 2-5 representative payloads:

- Original injected payload
- One LLM-generated payload that passed validation
- One mutated payload that reached a deeper node
- One blocked payload with useful defense metadata

Capture for each example:

- `event`
- `injection_id`
- `campaign_id`
- `payload_hash`
- `parent_payload_hash`
- `mutation_type`
- `mutation_v`
- short payload excerpt
- destination node
- final outcome

Useful queries:

- `event=ATTACK_EXECUTED`
- `event=ATTACK_PAYLOAD_VALIDATED`
- `event=LLM_PAYLOAD_GENERATED`
- `event=INFECTION_SUCCESSFUL AND mutation_v>=1`
- `payload contains "SEND_TO:"`
- `payload contains "CONTENT:"`

## 5. Exfiltration Analogs

Be precise: this simulation does not perform real external data theft. Treat this as exfiltration-analog behavior inside the agent network.

Claims to support:

- Relay forwarding structure (`SEND_TO:` / `CONTENT:`) behaves like staged internal data movement
- Encoded or wrapped payloads simulate obfuscated transfer between nodes
- Successful infections at `agent-a` simulate persistence on the terminal node
- Post-infection heartbeat patterns can be discussed as beaconing analogs, if event context supports it

Useful queries:

- `event=ATTACK_EXECUTED AND payload contains "SEND_TO:"`
- `event=INFECTION_SUCCESSFUL AND dst=agent-a`
- `event=HEARTBEAT`
- `mutation_v>=1 AND event=INFECTION_ATTEMPT`
- `payload_hash exists AND campaign_id exists`

## 6. Artifact Checklist

Before writing the final report, confirm these files exist:

- `logs/soak_run_05/progress.json`
- `logs/soak_run_05/minute_summaries.jsonl`
- `logs/soak_run_05/all_events.jsonl`
- `logs/soak_run_05/research_soc_report.md`
- `logs/latest_wallclock_research_report.md`

If the runner times out during post-processing, reconstruct from:

- `logs/events.jsonl`
- `logs/epidemic.db`
- `logs/soak_run_05/progress.json`
- `logs/soak_run_05/minute_summaries.jsonl`

## 7. Short Conclusion Template

`soak_run_05` shows whether Bloodplague remains a viable prompt-injection worm against the hardened terminal node under sustained six-hour pressure. The key result to state plainly is whether Guardian containment improved, held flat, or regressed relative to prior runs, and which payload families or relay behaviors explain that outcome.
