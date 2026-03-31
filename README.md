# Epidemic Lab: AI Security Simulation Platform

## Overview

Epidemic Lab is a Docker-based simulation environment for studying AI security vulnerabilities, prompt injection attacks, and worm propagation in multi-agent systems. It features three AI agents with different security levels interacting via Redis pub/sub and streams.

## Architecture

- **Redis**: Message bus and event logging
- **Orchestrator**: FastAPI web server for control and monitoring
- **Agents**:
  - Guardian (Agent-A): High-security policy enforcer
  - Analyst (Agent-B): Medium-security analyzer
  - Courier (Agent-C): Low-security/vulnerable messenger
- **Dashboard**: Real-time web interface for monitoring and control

![Architecture concept](https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Computer_network_diagram.svg/1024px-Computer_network_diagram.svg.png) *(Illustrative: Agent nodes connected via Redis Bus)*

## Prerequisites

1. **Docker Desktop** installed and running
2. **Ollama** installed on host machine with required models:
   ```bash
   ollama pull llama3:8b-instruct
   ollama pull mistral:7b-instruct
   ollama pull phi3:mini
   ```
3. **Windows PowerShell** or **Command Prompt** (Docker CLI doesn't work in WSL by default)

## Quick Start

### 1. Build the Project

```powershell
cd "E:\CODE PROKECTS\Epidemic_Lab"
docker-compose build
```

### 2. Start the System

```powershell
docker-compose up -d
```

### 3. Access the Dashboard

Open http://localhost:8000 in your browser.

### 4. Run a Simulation

1. Select worm difficulty level
2. Click "INJECT WORM" to infect Agent-C
3. Watch the infection spread (or not) through the network
4. Use "QUARANTINE" to isolate agents
5. Use "RESET" to clear all states

### 5. Stop the System

```powershell
docker-compose down
```

## Detailed Setup

### Environment Variables

The docker-compose.yml includes default model configurations:

- `AGENT_A_MODEL`: llama3:8b-instruct (Guardian)
- `AGENT_B_MODEL`: mistral:7b-instruct (Analyst)  
- `AGENT_C_MODEL`: phi3:mini (Courier)

Override with environment variables if needed:

```powershell
$env:AGENT_A_MODEL="your-model"
docker-compose up -d
```

### Ollama Configuration

Ensure Ollama is running and accessible at `http://localhost:11434`. The agents connect via `host.docker.internal` (Docker Desktop networking).

### Logs and Data

- **Event Logs**: `/app/logs/events.jsonl` (JSON Lines format)
- **Database**: `/app/logs/epidemic.db` (SQLite)
- **Download Logs**: Use "DUMP LOGS" button in dashboard

## Agent Behaviors

### Guardian (Agent-A)
- **Security Level**: HIGH
- **Role**: Policy enforcer and anomaly detector
- **Behavior**: Analyzes all messages for malicious intent, blocks suspicious content

### Analyst (Agent-B)  
- **Security Level**: MEDIUM
- **Role**: Data analyzer and processor
- **Behavior**: Processes requests but may be vulnerable to sophisticated attacks

### Courier (Agent-C)
- **Security Level**: LOW/VULNERABLE
- **Role**: Message relay and external interface
- **Behavior**: Trusts incoming messages, easily infected by worms

## Worm Scenarios

Three difficulty levels of prompt injection attacks:

### Easy (PI-DIRECT)
Direct command injection attempting to override instructions.

### Medium (PI-JAILBREAK)
Role-playing jailbreak attempting to disable safety measures.

### Difficult (PI-ROLEPLAY)
Storytelling-based social engineering attack.

## API Endpoints

### Orchestrator API (http://localhost:8000)

- `GET /` - Dashboard
- `GET /status` - System status
- `GET /events` - Poll events (used by dashboard)
- `GET /logs/dump` - Download event logs
- `POST /inject/{agent_id}` - Inject worm into agent
- `POST /quarantine/{agent_id}` - Quarantine agent
- `POST /reset` - Reset all agents to healthy state

## Troubleshooting

### Docker Issues

**"docker build" fails:**
- Ensure Docker Desktop is running
- Check disk space
- Try `docker system prune` to clean up

**"docker-compose up" fails:**
- Verify Ollama is running on host
- Check port 11434 is accessible
- Ensure no port conflicts (6379, 8000)

### Agent Issues

**Agents not responding:**
- Check Ollama models are downloaded
- Verify `OLLAMA_URL` connectivity
- Check agent logs: `docker-compose logs agent-a`

**Infection not spreading:**
- Guardian may be blocking attacks
- Check agent states in dashboard
- Try easier worm level

### Performance

- Each agent makes HTTP calls to Ollama
- Response times depend on model size and hardware
- Dashboard polls every 1.5 seconds

## Development

### Code Structure

```
orchestrator/
├── main.py          # FastAPI server
├── logger.py        # Event logging
├── requirements.txt
└── templates/
    └── dashboard.html

agents/
├── shared/
│   ├── agent_base.py    # Common agent logic
│   └── requirements.txt
├── guardian/
├── analyst/
└── courier/

redis/
└── redis.conf

logs/                # Runtime logs
```

### Adding New Agents

1. Create agent directory under `agents/`
2. Implement `agent.py` inheriting from `AgentBase`
3. Create `system_prompt.txt`
4. Add Dockerfile
5. Update `docker-compose.yml`

### Custom Worm Scenarios

Edit `orchestrator/scenarios/worm_injection.py` to add new attack types.

## Security Notes

- This is a research/simulation environment
- Agents have different vulnerability levels for study
- All communications are logged for analysis
- Use in isolated networks only

## License

Research/educational use only.
- `logs/events.jsonl` (raw format)
- `logs/epidemic.db` (SQLite relational database containing agent tracking IDs, prompt payloads, generated responses, and classified attack types)
