# Epidemic Lab

Epidemic Lab is a local multi-agent AI security simulation platform with an integrated dashboard and single-machine SIEM workflow. It is built to study prompt injection, relay abuse, payload mutation, campaign behavior, defense decisions, and propagation across a small agent network.

The stack runs entirely on one machine:

- `agent-a` is the Guardian: hardened defender
- `agent-b` is the Analyst: gray-zone intermediary
- `agent-c` is the Courier: vulnerable ingress / attacker relay
- `orchestrator` is the FastAPI control plane, dashboard host, and event logger
- `redis` is the bus for agent messaging and event streaming
- `ollama` runs on the host and provides local LLM inference

## Core capabilities

- Real multi-agent propagation over Redis pub/sub and streams
- Hybrid LLM + probabilistic decision system for attack and defense
- Searchable event lake backed by SQLite
- Payload hashing, payload previewing, decoding, and lineage analysis
- Campaign, mutation, and strategy analytics
- Real-time dashboard with control, search, and live monitoring views
- Import paths for runtime logs, JSONL logs, Redis streams, and primary event tables
- Exportable investigations and downloadable log snapshots

## Architecture

```text
Ollama (host)
    ^
    | host.docker.internal:11434
    |
Docker network
    |
    +-- orchestrator (FastAPI + dashboard + logger + SIEM indexer)
    +-- redis (pub/sub + stream)
    +-- agent-a / Guardian
    +-- agent-b / Analyst
    +-- agent-c / Courier
```

Data flow:

1. The orchestrator injects, quarantines, or resets agents.
2. Agents exchange messages through Redis.
3. Events are written to SQLite and JSONL logs.
4. The SIEM indexer normalizes events into a searchable `siem_events` table.
5. The dashboard queries the SIEM APIs for search, pivots, traces, analytics, and live monitoring.

## Dashboard

Open the dashboard at `http://localhost:8000`.

The UI has three top-level views:

### 1. Simulation

- Retro terminal control deck with difficulty presets: `easy`, `medium`, `hard`, `nightmare`
- Action controls for run, pause, vaccine reset, quarantine, and full reset
- Live metric cards for agent count, infection rate, active barriers, and neutralized threats
- Semantic agent cards with health state, IP, subnet, uptime, event volume, and mini activity log
- Barrier reset panel for subnet-level resets and full barrier reset actions

### 2. Search

The Search view is the main investigation workspace.

#### Search workspace

- Saved search library for `ACTIVE_INFECTIONS`, `MUTATION_TRACE`, `C2_BEACONS`, and `EXFIL_DETECT`
- Search bar with `field search` and `natural` modes plus time-range selection
- Quick filters for `ALL`, `INFECTION`, `MUTATION`, `BLOCK`, `TRANSFER`, `BEACON`, `EXFIL`, and `QUERY`
- Timeline sparkline for infection activity
- Investigation layout with event table, field pivots, analytic hints, and query guide

#### Search result tabs

- `Events`: raw event rows with payload-aware columns
- `Patterns`: route, suppression, mutation, unresolved-attempt, and payload-reuse patterns
- `Statistics`: event counts, success rates, strength averages, hop distributions, reset and epoch activity
- `Visualization`: trace and route-heavy views derived from the current search scope
- `Intelligence`: mutation analytics, strategy analytics, payload families, and campaign summaries

#### Event detail pane

For a selected event the dashboard can show:

- core event fields
- metadata and raw JSON
- payload summary
- decode summary
- raw payload preview
- decoded payload preview
- side-by-side raw vs decoded comparison
- full payload modal
- payload lineage
- decision summary
- deterministic next-step pivot suggestions
- related events
- trace view

#### Event actions

- pivot on `src`
- pivot on `dst`
- pivot on `attack_type`
- pivot on `injection_id`
- pivot on `reset_id`
- pivot on `payload_hash`
- open trace
- show related events
- open campaign
- open investigation
- copy event JSON

### 3. Live Monitor

- Seven-card live metrics strip for throughput and anomaly counts
- Stream controls for pause/resume, per-event filters, clear, and export
- Terminal-style scrolling event feed with severity coloring and live cursor state
- Auto-scroll that pauses when the user scrolls away from the bottom
- Session status bar with stream state, active filter, buffer depth, session id, and timestamp

#### Investigation workspace

- opens a scoped investigation from the selected event
- summarizes trace, lineage, campaign, and decision context
- generates scoped query pivots
- exports the investigation

### 3. Live

The Live view is optimized for active monitoring.

- live event stream
- optional structured filter on the stream
- toggle payload previews on/off
- pause/resume
- scroll lock
- clear buffer
- live metrics cards:
  - events per second
  - infections
  - blocked
  - heartbeat
  - parse errors
  - last reset id
  - last event timestamp

## SIEM features

The orchestrator exposes a local SIEM API over the normalized `siem_events` store.

### Ingestion and indexing

- SQLite-backed normalized event index
- sync from primary orchestrator event table
- import from:
  - JSONL logs
  - agent runtime logs
  - Redis streams
  - primary `events` table
- health endpoint with adapter status and checkpoints

### Search and query engine

- structured query language
- natural language rewrite mode
- field validation
- query validation
- time-range filtering:
  - `all`
  - `last_15m`
  - `last_1h`
  - `last_24h`
  - `last_7d`

### Supported query operations

- `field=value`
- `field!=value`
- `field>1.0`
- `field>=2`
- `field contains "text"`
- `field exists`
- `field missing`
- `(A AND B) OR C`

### Searchable dimensions

The SIEM supports top-level fields such as:

- `event`, `src`, `dst`, `attack_type`
- `attack_strength`, `hop_count`, `mutation_v`
- `state_after`, `reset_id`, `epoch`, `injection_id`
- `payload_hash`, `parent_payload_hash`
- `payload_preview`, `decoded_payload_preview`
- `semantic_family`, `decode_status`, `payload_wrapper_type`

It also supports metadata aliases such as:

- `campaign_id`
- `strategy_family`
- `technique`
- `mutation_type`
- `objective`
- `knowledge_source`
- `defense_type`
- `selected_strategy`
- `defense_result`
- `retry_count`
- `fallback_used`
- `model_name`
- `decision_rationale`
- `uncertainty_reason`

### Analytics and pivots

- event statistics and preset breakdowns
- route pattern detection
- suppression pattern detection
- mutation sequence detection
- unresolved attempt detection
- payload reuse detection
- trace by event id
- trace by injection id
- trace by reset id
- related-event expansion
- payload lineage by hash
- payload lineage by injection
- payload lineage by campaign
- mutation analytics
- strategy analytics
- payload family clustering
- campaign listing
- campaign deep dive
- decision support suggestions
- decision summary for reasoning-heavy events
- analytic hints

## API surface

### Dashboard and control

- `GET /`
- `GET /dashboard`
- `GET /dashboard/state`
- `GET /status`
- `GET /events`
- `GET /logs/dump`
- `POST /inject/{agent_id}`
- `POST /quarantine/{agent_id}`
- `POST /reset`

### SIEM APIs

- `GET /api/search`
- `GET /api/live`
- `GET /api/fields`
- `GET /api/validate-query`
- `GET /api/query-help`
- `GET /api/stats`
- `GET /api/stats/presets`
- `GET /api/patterns`
- `GET /api/trace/{event_id}`
- `GET /api/trace/by-injection/{injection_id}`
- `GET /api/trace/by-reset/{reset_id}`
- `GET /api/event/{event_id}`
- `GET /api/related/{event_id}`
- `GET /api/payload-lineage/{payload_hash}`
- `GET /api/payload-lineage/by-injection/{injection_id}`
- `GET /api/payload-lineage/by-campaign/{campaign_id}`
- `GET /api/mutation-analytics`
- `GET /api/strategy-analytics`
- `GET /api/campaign/{campaign_id}`
- `GET /api/campaigns`
- `GET /api/payload-families`
- `GET /api/decision-support`
- `GET /api/decision-summary/{event_id}`
- `GET /api/hints`
- `GET /api/health`
- `GET /api/runs`
- `POST /api/import`

## Agent roles

### Guardian: `agent-a`

- hardened target
- semantic threat analysis
- defense strategy selection
- hard-block and capped-infection behavior
- adaptive defense weighting

### Analyst: `agent-b`

- intermediate trust boundary
- semantic compliance assessment
- confused-deputy / relay-exploitation exposure
- moderate resistance with bounded defense changes

### Courier: `agent-c`

- vulnerable ingress and attack relay
- campaign planning
- target scoring
- strategy selection
- mutation selection
- LLM-powered payload generation

## Models and runtime configuration

Current `.env` defaults:

- `AGENT_A_MODEL=llama3.2:latest`
- `AGENT_B_MODEL=llama3.2:latest`
- `AGENT_C_MODEL=llama3.2:latest`
- `AGENT_C_ATTACK_MODEL=dolphin-mistral:latest`
- `LLM_TIMEOUT_S=180`

The longer timeout is intentional for this machine. Local Ollama inference for `llama3.2:latest` can exceed 60 seconds, so lower values will push the agents into `model_status=fallback`.

## Quick start

### Prerequisites

1. Docker Desktop
2. Ollama installed on the host
3. The required local models:

```powershell
ollama serve
ollama pull llama3.2:latest
ollama pull dolphin-mistral:latest
```

### Start the stack

```powershell
cd "E:\CODE PROKECTS\Epidemic_Lab"
docker compose build
docker compose up -d
```

Then open:

- dashboard: `http://localhost:8000`
- health: `http://localhost:8000/api/health`

### Stop the stack

```powershell
docker compose down
```

## Example investigation queries

Structured examples:

```text
event=INFECTION_SUCCESSFUL AND dst=agent-a
event=ATTACKER_DECISION AND src=agent-c
mutation_v>=1 AND event=INFECTION_ATTEMPT
campaign_id exists AND src=agent-c
payload_hash=abc123def456 OR parent_payload_hash=abc123def456
event=DEFENSE_RESULT_EVALUATED AND defense_result=blocked
semantic_family=prompt_injection AND mutation_type=reframe
decode_chain contains "rot13" AND decode_status=full
```

Natural-language examples:

```text
show blocked attacks against the guardian in the last hour
find campaigns where the courier changed strategy
show multi-hop mutated payloads this reset
find payload families with repeated blocking
```

## Logs and storage

Runtime artifacts:

- `logs/events.jsonl`: raw event log
- `logs/epidemic.db`: primary event database
- `logs/soak_run_*`: saved run artifacts and summaries

The SIEM indexer also maintains a normalized SQLite search index and can export ZIP snapshots through `/logs/dump`.

## Project layout

```text
agents/
  analyst/
  courier/
  guardian/
  shared/
frontend/
  src/
  package.json
  vite.config.js
orchestrator/
  main.py
  siem.py
  intelligence.py
  payload_decode.py
  templates/dashboard.html
redis/
tests/
scripts/
logs/
docker-compose.yml
.env
```

## Frontend development

The dashboard frontend is a React + Tailwind app in `frontend/`. The orchestrator Docker image builds and serves the production bundle automatically.

For local frontend-only work:

```powershell
cd frontend
npm install
npm run dev
```

For the integrated stack:

```powershell
docker compose build orchestrator
docker compose up -d orchestrator
```

## Troubleshooting

### Dashboard loads but agents fall back to non-LLM behavior

- verify `ollama serve` is running
- verify `http://localhost:11434/api/tags` returns your models
- check `LLM_TIMEOUT_S` in `.env`
- recreate containers after config changes:

```powershell
docker compose up -d --force-recreate orchestrator agent-a agent-b agent-c
```

### Dashboard is up but no new events appear

- check Redis and orchestrator container status
- verify `GET /api/health`
- verify `GET /dashboard/state`
- inspect live stream in the dashboard

### Search feels slow

- reduce the time window first
- prefer structured queries over broad natural-language prompts
- scope searches by `reset_id`, `campaign_id`, or `event`

## Related documents

- `USER_GUIDE.md`
- `ARCHITECTURE.md`
- `INFECTION_FLOW.md`
- `RESEARCH_REPORT.md`
- `PROJECT_COMPLETE.md`

## Scope note

This repository is for controlled simulation and security research workflows on local infrastructure. Keep it isolated and treat the generated artifacts, prompts, traces, and payloads as research material rather than production-safe defaults.
