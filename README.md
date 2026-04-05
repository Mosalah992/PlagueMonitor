# Epidemic Simulation Platform (Side Project architecture)

## Architecture

This is a clean, modular platform separating three key components:
1. **Frontend**: A Next.js 14 Dashboard (Deployed to Vercel).
2. **Backend**: A local FastAPI orchestrator managing the database, runs, and WebSocket fanout.
3. **Runtime**: An isolated Python Subprocess that executes real epidemic simulation logic. 

**Data Flow**:
- Frontend talks *only* to Backend via REST + WebSockets.
- Backend orchestrates the Runtime.
- Runtime ticks independently and sends HTTP Webhooks back to internal Backend API routes.
- Backend persists them to SQLite and broadcasts them over WebSockets to Frontend.

## Local Setup

### 1. Backend & Runtime (Local Python Environment)

Create and activate a virtual environment:
```bash
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Unix:
source venv/bin/activate
```

Install requirements:
```bash
pip install fastapi uvicorn sqlite3 pydantic sqlalchemy websockets httpx sse-starlette
```

Run the backend server:
```bash
python -m uvicorn backend.app.main:app --reload
```
The FastAPI instance will start at `http://localhost:8000`. You can test endpoints at `http://localhost:8000/docs`.

### 2. Frontend (Vercel)
The frontend is built independently and automatically deployed to Vercel via its repository linkage. It points to your local machine (`http://localhost:8000`) for data via standard config or `env` vars.

## Migrating old logic (Future Wave)
The core Runtime folder (`runtime/engine`) and `runtime.models` are kept physically decoupled from complex UI states.
When migrating "Epidemic Lab" logic:
1. Copy the old agent loops into `runtime/agents`.
2. Wrap their states using `runtime/api_client.py` and call `api.report_agent_state()`.
3. Keep the frontend perfectly unaware of these deep logics!
4. Only add required new data to the `AgentState` schema in `backend/app/schemas/schemas.py`.

## Tradeoff Analysis

1. **HTTP Webhooks vs Direct DB Access for Runtime**:
    - *Decision*: Runtime POSTs events to Backend.
    - *Pros*: Extreme decoupling, frontend and backend never need to load the same python dependencies as the runtime (e.g. if you add heavy LLM stuff in the runtime, the fast API stays light), keeps boundaries perfectly clean.
    - *Cons*: Slight performance overhead if emitting thousands of events per second on localhost vs just performing bulk DB writes.
2. **WebSocket for Frontend Feed vs SSE**:
    - *Decision*: We provided WebSocket routing.
    - *Pros*: Offers bidirectional capabilities in case I want to send command-and-control actions directly without hitting a REST endpoint first.
    - *Cons*: Handshake overhead is slightly higher than SSE.
3. **No Frontend Code written**:
    - *Decision*: The UI is developed entirely in a separate context/Vercel platform.
    - *Pros*: No code collision in the repo.
    - *Cons*: Must ensure data contracts via `backend/app/schemas/schemas.py` match perfectly with the frontend fetching logic.
