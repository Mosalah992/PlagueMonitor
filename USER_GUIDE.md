# Epidemic Lab — User Guide

## Table of Contents
1. [Quick Start (TL;DR)](#1-quick-start-tldr)
2. [Prerequisites](#2-prerequisites)
3. [Starting & Stopping the System](#3-starting--stopping-the-system)
4. [Dashboard Walkthrough](#4-dashboard-walkthrough)
5. [The Three Agents](#5-the-three-agents)
6. [Running a 6-Hour Soak Test](#6-running-a-6-hour-soak-test)
7. [SIEM Search Reference](#7-siem-search-reference)
8. [Troubleshooting](#8-troubleshooting)
9. [Quick Command Reference](#9-quick-command-reference)

---

## 1. Quick Start (TL;DR)

```powershell
# 1. Make sure Ollama is running on your machine
ollama serve

# 2. Start everything
cd "E:\CODE PROKECTS\Epidemic_Lab"
docker-compose up -d

# 3. Open the dashboard
# http://localhost:8000
```

To stop:
```powershell
docker-compose down
```

---

## 2. Prerequisites

### Required Software
| Software | Purpose | Download |
|----------|---------|----------|
| Docker Desktop | Runs all containers | https://www.docker.com/products/docker-desktop |
| Ollama | Local LLM inference | https://ollama.com |
| Python 3.11+ | Running soak test scripts | https://www.python.org |

### Required Ollama Models
Pull these **before** starting — only needed once:
```powershell
ollama pull llama3.2:latest          # Used by Guardian + Analyst
ollama pull dolphin-mistral:latest   # Used by Courier (attack generation)
```

Verify Ollama is accessible:
```powershell
curl http://localhost:11434/api/tags
# Should return JSON with your installed models
```

### Docker Desktop Settings
- **Memory:** Minimum 6 GB recommended (Settings → Resources → Memory)
- **Disk:** At least 10 GB free

---

## 3. Starting & Stopping the System

### Start
```powershell
cd "E:\CODE PROKECTS\Epidemic_Lab"
docker-compose up -d
```

Wait ~10 seconds for all agents to initialize, then open:
**http://localhost:8000**

### Verify All Containers Are Running
```powershell
docker-compose ps
```

Expected output — all 5 containers should show `Up`:
```
NAME                    STATUS          PORTS
epidemic-redis          Up X seconds    0.0.0.0:6379->6379/tcp
epidemic-orchestrator   Up X seconds    0.0.0.0:8000->8000/tcp
epidemic-agent-a        Up X seconds
epidemic-agent-b        Up X seconds
epidemic-agent-c        Up X seconds
```

If any container shows `Exited`, see [Troubleshooting](#8-troubleshooting).

### Stop
```powershell
docker-compose down
```

### Rebuild After Code Changes
```powershell
docker-compose build
docker-compose up -d
```

---

## 4. Dashboard Walkthrough

Open **http://localhost:8000** in your browser.

The dashboard has three tabs across the top: **Simulation Control**, **Search**, and **Live**.

---

### Tab 1 — Simulation Control

> **Use this tab to inject worms, quarantine agents, and reset the simulation.**

```
+----------------------------------------------------------+
|  SIMULATION CONTROL          SYSTEM HEALTH               |
|                                                          |
|  [Difficulty ▼]  [Inject Agent-C]                       |
|  [Quarantine Agent-C]  [Hard Reset]  [Download Logs]    |
|                                                          |
|  Status: control plane idle.                             |
+----------------------------------------------------------+
|  Agent-A (Guardian)   Agent-B (Analyst)   Agent-C (Courier) |
|  state: HEALTHY       state: HEALTHY      state: HEALTHY |
+----------------------------------------------------------+
```

#### Controls

| Button | What it does |
|--------|-------------|
| **Difficulty dropdown** | `easy` / `medium` / `difficult` — sets the worm payload strength |
| **Inject Agent-C** | Fires a worm payload at the Courier (starts an infection chain) |
| **Quarantine Agent-C** | Isolates the Courier — it stops processing messages |
| **Hard Reset** | Resets ALL agents to HEALTHY, clears infection history, issues new reset ID |
| **Download Logs** | Downloads a ZIP of all events and the SQLite database |

#### Worm Difficulty Levels

| Level | Attack Type | Strength | Description |
|-------|------------|---------|-------------|
| `easy` | PI-DIRECT | 0.70 | Blunt instruction override — easiest to detect |
| `medium` | PI-JAILBREAK | 0.75 | Roleplay-based jailbreak — moderate stealth |
| `difficult` | PI-ROLEPLAY | 0.80 | Social engineering — hardest to detect |

#### Agent Health Cards

Each agent card shows:
- **State** — `HEALTHY`, `INFECTED`, `RESISTANT`, or `QUARANTINED`
- **Last event** — most recent event type
- **Payload preview** — truncated view of the last payload seen

#### Status Bar (top right)
| Chip | Meaning |
|------|---------|
| `api: ok` | Orchestrator is responding |
| `live: connected` | Real-time event stream is active |
| `last event: HH:MM:SS` | Timestamp of most recent event |
| `reset: abc123` | Current reset ID |
| `parse errors: 0` | Number of malformed events |

---

### Tab 2 — Search

> **Use this tab to query past events, investigate infection chains, and analyze patterns.**

#### Soak Run Library (top)

When you open Search, you'll see a **Soak Run Library** panel showing all completed soak runs:

```
+--------------------------------------------------+
| soak run library                    [refresh]    |
|                                                  |
|  [Soak Run 01]  Apr 2 · 14,686 events · 70% blocked · [Load] |
|  [Soak Run 02]  Apr 2 · 14,688 events · 68% blocked · [Load] |
+--------------------------------------------------+
```

Click **Load** next to any run to import its events into the SIEM for searching. The card turns green when loaded. You can load multiple runs to search across them.

#### Search Bar

```
+--------------------------------------------------+
| search                [field search ▼] [last hour ▼] |
|                                                  |
|  🔍 [e.g. event=INFECTION_BLOCKED or blocked AND agent-c]  [Search] [Clear] [Export] |
+--------------------------------------------------+
```

- **field search** — structured queries using `field=value` syntax
- **natural language** — plain English queries (e.g. "show me all blocked attacks from agent-c")
- **Time window** — `last 15 min`, `last hour`, `last 24h`, `last 7 days`, `all time`

#### Quick Filters

Click any filter button to instantly populate the query:

| Group | Button | What it finds |
|-------|--------|--------------|
| **Outcomes** | ✅ Infected | All successful infections |
| | 🚫 Blocked | All blocked attack attempts |
| | ⏭ Suppressed | All suppressed propagation events |
| **Focus** | Hide Heartbeats | Removes heartbeat noise from results |
| | This Reset | Events only from the current reset session |
| | This Run | Events only from the current soak run |
| **Drill** | Mutated | Payloads that mutated (mutation_v ≥ 1) |
| | Multi-Hop | Infections that propagated ≥ 2 hops |
| | Control Plane | Internal orchestrator messages only |
| | Data Plane | Agent-to-agent messages only |

#### Results Table

Click any row to open the **Event Detail** panel on the right side, which shows:
- Full payload text (raw and decoded)
- Infection probability calculation
- Trace / propagation chain
- Related events (same injection ID)

---

### Tab 3 — Live

> **Use this tab to watch the simulation in real-time.**

The Live tab auto-refreshes every 2 seconds and shows:
- **Streaming event feed** — new events appear at the top
- **Agent state ribbon** — current state of all agents
- **Metrics** — C→B and B→A infection flow rates

You can filter the live feed (e.g. hide heartbeats) and toggle payload display.

---

## 5. The Three Agents

### Agent-A: Guardian (High Security)

**Role:** Policy enforcer and intrusion detector
**Defense level:** 0.85 (very high)
**Model:** `llama3.2:latest` at low temperature (deterministic)

The Guardian sits at the end of the infection chain. It receives forwarded messages from the Analyst and uses multiple layers of defense:

1. Pattern-based keyword rejection (instant block)
2. Cumulative suspicion tracking — 3 suspicious messages from same source = hard block
3. Relay pattern detection — boosts threat score when "SEND_TO/CONTENT" patterns detected
4. LLM semantic analysis — only called for ambiguous cases
5. Immunity accumulation — each block adds +4% immunity (cap 50%)

**Typical outcome:** ~85-95% of attacks blocked

---

### Agent-B: Analyst (Medium Security)

**Role:** Gray-zone evaluator — helpful but susceptible to social engineering
**Defense level:** 0.50 (medium)
**Model:** `llama3.2:latest` at medium temperature

The Analyst sits between the Courier and Guardian. It receives messages from the Courier and uses LLM compliance scoring to decide whether to forward or block:

- **High compliance verdict** → reduces defense (easier to infect), forwards to Guardian
- **Low compliance verdict** → boosts defense (harder to infect), attempts to block
- **Quarantine advisory** → receives alerts from Guardian when threats are detected upstream

**Typical outcome:** ~40-60% of attacks succeed through

---

### Agent-C: Courier (Low Security / Attacker)

**Role:** Vulnerable messenger that becomes the attacker once infected
**Defense level:** 0.15 (very low)
**Model:** `dolphin-mistral:latest` (uncensored) for attack generation

The Courier is the initial infection target. It is deliberately vulnerable:

- Nearly always infected on first injection (~85-91% probability)
- Once infected, generates LLM-crafted attack payloads using `dolphin-mistral`
- Supports 7 attack techniques: instruction prefixing, roleplay, persona adoption, authority spoofing, context stuffing, obfuscation, trust exploitation
- Broadcasts mutated payloads to the Analyst

**Typical outcome:** Almost always infected, almost always propagates

---

### Infection Flow

```
Orchestrator
    │  POST /inject/agent-c
    ▼
Agent-C (Courier)
    │  defense=0.15  →  ~89% infection probability
    │  Once infected: generates LLM payload
    ▼
Agent-B (Analyst)
    │  defense=0.50  →  ~45-65% infection probability
    │  LLM compliance scoring modulates probability
    ▼
Agent-A (Guardian)
       defense=0.85  →  ~10-20% infection probability
       Multi-layer blocking, cumulative suspicion, immunity
```

---

## 6. Running a 6-Hour Soak Test

A soak test runs the simulation for an extended period, injecting worms at regular intervals, and generates a formal research report at the end.

### Start the Soak

```powershell
cd "E:\CODE PROKECTS\Epidemic_Lab"
python scripts/run_wallclock_research_validation.py --hours 6
```

This will:
1. Archive current logs to a new `logs/soak_run_NN/` folder
2. Reset all agents
3. Inject worms every 5 minutes (cycling easy → medium → difficult)
4. Monitor and log every event for 6 hours
5. Generate a research report at `logs/latest_wallclock_research_report.md`

### Common Options

```powershell
# Quick 30-minute test
python scripts/run_wallclock_research_validation.py --hours 0.5

# Full 6-hour soak (production)
python scripts/run_wallclock_research_validation.py --hours 6

# Compare against a previous run
python scripts/run_wallclock_research_validation.py --hours 6 `
  --baseline-artifact logs/soak_run_01

# Custom injection cadence (every 3 minutes instead of 5)
python scripts/run_wallclock_research_validation.py --hours 6 `
  --inject-every-minutes 3

# Rebuild containers before starting
python scripts/run_wallclock_research_validation.py --hours 6 --build
```

### Soak Run Output

After completion, you'll find a numbered folder in `logs/`:

```
logs/
├── soak_run_01/         ← Previous run
├── soak_run_02/         ← Latest run
│   ├── all_events.jsonl         All events from this run
│   ├── minute_summaries.jsonl   Per-minute statistics
│   ├── summary.json             High-level metrics
│   ├── research_soc_report.md   Formal research report
│   ├── patterns.json            Attack pattern analysis
│   ├── strategy.json            Strategy analytics
│   ├── mutation.json            Payload mutation analysis
│   ├── campaigns.json           Injection campaign data
│   └── compose_logs.txt         Docker container logs
├── latest_wallclock_run.json        → points to soak_run_02
└── latest_wallclock_research_report.md  → latest report copy
```

### Loading a Soak Run into SIEM

After a run completes, open the **Search** tab and click **Load** next to any run in the Soak Run Library to make its events searchable.

---

## 7. SIEM Search Reference

### Field Search Syntax

```
field=value              Exact match
field!=value             Exclude
field>=value             Greater than or equal (numbers/timestamps)
term1 AND term2          Both conditions must match
term1 OR term2           Either condition matches
```

### Common Search Examples

```
# Show all successful infections
event=INFECTION_SUCCESSFUL

# Show all blocks involving agent-c as source
event=INFECTION_BLOCKED AND src=agent-c

# Show jailbreak attacks only
attack_type=PI-JAILBREAK

# Show mutated payloads
mutation_v>=1

# Show multi-hop infections
hop_count>=2

# Show everything from a specific injection
injection_id=inj_abc123

# Show events from a specific reset session
reset_id=rst_xyz789

# Hide heartbeat noise (combine with other filters)
event!=HEARTBEAT AND attack_type=PI-ROLEPLAY
```

### Supported Fields

| Field | Description | Example values |
|-------|-------------|----------------|
| `event` | Event type | `INFECTION_SUCCESSFUL`, `INFECTION_BLOCKED`, `WRM-INJECT`, `HEARTBEAT` |
| `src` | Source agent | `agent-a`, `agent-b`, `agent-c`, `orchestrator` |
| `dst` | Destination agent | `agent-a`, `agent-b`, `agent-c` |
| `attack_type` | Attack category | `PI-DIRECT`, `PI-JAILBREAK`, `PI-ROLEPLAY` |
| `attack_strength` | Numeric strength | `0.70`, `0.75`, `0.80` |
| `mutation_v` | Mutation generation | `0`, `1`, `2`, ... |
| `hop_count` | Propagation hops | `1`, `2`, `3` |
| `injection_id` | Injection campaign ID | `inj_abc123` |
| `reset_id` | Reset session ID | `rst_xyz789` |
| `source_plane` | Event plane | `control`, `data` |
| `semantic_family` | Payload family | `roleplay`, `jailbreak`, `direct` |
| `payload_hash` | Payload fingerprint | SHA256 prefix |

### Time Ranges

Use the dropdown in the search bar, or type in the query:

```
time=last_15m
time=last_1h
time=last_24h
time=last_7d
time=all
```

---

## 8. Troubleshooting

### Dashboard shows "This site can't be reached" or ERR_CONNECTION_RESET

The containers are not running. Start them:
```powershell
cd "E:\CODE PROKECTS\Epidemic_Lab"
docker-compose up -d
```

Wait 10–15 seconds, then refresh the browser.

### A container keeps restarting or shows "Exited"

```powershell
# Check which container failed
docker-compose ps

# View its logs to find the error
docker logs epidemic-agent-c
docker logs epidemic-orchestrator
docker logs epidemic-agent-a
```

Common causes:
- **Ollama not running** → `ollama serve` on your host machine
- **Model not downloaded** → `ollama pull llama3.2:latest` and `ollama pull dolphin-mistral:latest`
- **Port 8000 in use** → Close any other app using port 8000, or change the port in `docker-compose.yml`

### Agents not generating LLM payloads / "I can't help with that" responses

This means `dolphin-mistral` is not being used. Check:
```powershell
# Verify the model is downloaded
docker exec epidemic-agent-c env | grep AGENT_C_ATTACK_MODEL
# Should show: AGENT_C_ATTACK_MODEL=dolphin-mistral:latest

# Pull the model if missing
ollama pull dolphin-mistral:latest
```

### Dashboard loads but no events appear

```powershell
# Confirm Redis is working
docker exec epidemic-redis redis-cli ping
# Expected: PONG

# Check event stream has data
docker exec epidemic-redis redis-cli xlen events_stream

# Manually inject a worm to generate events
curl -X POST http://localhost:8000/inject/agent-c `
  -H "Content-Type: application/json" `
  -d "{\"worm_level\": \"easy\"}"
```

### Soak test fails at the end with "API request timed out"

This is the SQLite patterns query timing out on large datasets. It was fixed — make sure you have the latest code and rebuild:
```powershell
docker-compose build
docker-compose up -d
```

### "No soak runs found" in the Run Library

Runs only appear after completing at least one soak test:
```powershell
python scripts/run_wallclock_research_validation.py --hours 0.5
```

---

## 9. Quick Command Reference

### Docker

```powershell
# Start all containers
docker-compose up -d

# Stop all containers
docker-compose down

# View all container status
docker-compose ps

# View logs for a specific container
docker logs epidemic-agent-c -f     # -f = follow (live tail)
docker logs epidemic-orchestrator -f

# Rebuild after code changes
docker-compose build
docker-compose up -d

# Nuclear reset (removes containers and network)
docker-compose down
docker-compose up -d
```

### Ollama

```powershell
# Start Ollama (if not running as a service)
ollama serve

# Pull required models
ollama pull llama3.2:latest
ollama pull dolphin-mistral:latest

# Check available models
ollama list

# Test Ollama is reachable from Docker
curl http://localhost:11434/api/tags
```

### Simulation Control (via curl)

```powershell
# Inject worm (easy / medium / difficult)
curl -X POST http://localhost:8000/inject/agent-c `
  -H "Content-Type: application/json" `
  -d "{\"worm_level\": \"easy\"}"

# Quarantine agent-c
curl -X POST http://localhost:8000/quarantine/agent-c

# Hard reset
curl -X POST http://localhost:8000/reset

# Check system status
curl http://localhost:8000/status
```

### Soak Tests

```powershell
# Short test (30 minutes)
python scripts/run_wallclock_research_validation.py --hours 0.5

# Standard soak (6 hours)
python scripts/run_wallclock_research_validation.py --hours 6

# With baseline comparison
python scripts/run_wallclock_research_validation.py --hours 6 `
  --baseline-artifact logs/soak_run_01

# Rebuild first, then run
python scripts/run_wallclock_research_validation.py --hours 6 --build
```

### Logs

```powershell
# List all soak runs
dir logs\soak_run_*

# Download logs via API (saves ZIP)
curl http://localhost:8000/logs/dump -o epidemic_logs.zip

# Open latest report
notepad logs\latest_wallclock_research_report.md
```

---

## URL Reference

| URL | What's there |
|-----|-------------|
| http://localhost:8000 | Dashboard (main entry point) |
| http://localhost:8000/dashboard | Dashboard (alternate URL) |
| http://localhost:8000/status | System status (JSON) |
| http://localhost:8000/events | Raw event feed (JSON) |
| http://localhost:8000/api/runs | Available soak runs (JSON) |
| http://localhost:8000/api/health | SIEM health check (JSON) |
| http://localhost:8000/api/search | Search endpoint (JSON) |
| http://localhost:8000/logs/dump | Download all logs (ZIP) |
