import asyncio
import os
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Deque, Dict

import httpx
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Footer, Header, Log, Static

API_URL = os.environ.get("API_URL", "http://localhost:8000")
APP_ROOT = Path(__file__).resolve().parents[1]
AGENT_ROLES = {
    "agent-a": "Guardian",
    "agent-b": "Analyst",
    "agent-c": "Courier",
}


class EpidemicDashboard(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 4;
        grid-columns: 1fr 1fr;
        grid-rows: auto 1fr 1fr 1fr;
    }
    #controls {
        column-span: 2;
        height: 3;
        padding: 0 1;
        border: solid $accent;
    }
    .panel {
        padding: 1;
        border: solid $primary;
        background: $surface;
    }
    #error-log, #event-log {
        height: 100%;
    }
    """

    BINDINGS = [
        ("e", "inject_easy", "Inject Easy"),
        ("i", "inject_medium", "Inject Medium"),
        ("q", "quarantine", "Quarantine C"),
        ("r", "reset", "Reset"),
        ("d", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Button("Inject Easy", id="inject-easy")
            yield Button("Inject Medium", id="inject-medium")
            yield Button("Quarantine C", id="quarantine")
            yield Button("Reset", id="reset")
            yield Static("API: unknown", id="api-status")
        yield Static(id="agents-panel", classes="panel")
        yield Static(id="metrics-panel", classes="panel")
        yield Log(id="event-log", classes="panel")
        yield Log(id="error-log", classes="panel")
        yield Footer()

    async def on_mount(self) -> None:
        self.http = httpx.AsyncClient(timeout=5.0)
        self.api_ok = False
        self.api_status_text = "API: unknown"
        self.last_event_id = 0
        self.last_log_poll = datetime.now(timezone.utc) - timedelta(seconds=2)
        self.agent_states: Dict[str, str] = {agent_id: "HEALTHY" for agent_id in AGENT_ROLES}
        self.agent_last_event: Dict[str, str] = {agent_id: "Waiting..." for agent_id in AGENT_ROLES}
        self.event_counts: Counter = Counter()
        self.recent_events: Deque[str] = deque(maxlen=10)
        self.recent_errors: Deque[str] = deque(maxlen=50)

        self.api_status_widget = self.query_one("#api-status", Static)
        self.agents_panel = self.query_one("#agents-panel", Static)
        self.metrics_panel = self.query_one("#metrics-panel", Static)
        self.event_log = self.query_one("#event-log", Log)
        self.error_log = self.query_one("#error-log", Log)

        self.set_interval(1.0, self.poll_events)
        self.set_interval(2.0, self.poll_logs)
        self.set_interval(2.0, self.poll_status)
        self.set_interval(1.0, self.refresh_panels)
        self.refresh_panels()

    async def on_unmount(self) -> None:
        await self.http.aclose()

    def add_error(self, message: str) -> None:
        self.recent_errors.append(message)
        self.error_log.write_line(message)

    def add_event_line(self, message: str) -> None:
        self.recent_events.append(message)
        self.event_log.clear()
        for line in self.recent_events:
            self.event_log.write_line(line)

    async def poll_status(self) -> None:
        try:
            response = await self.http.get(f"{API_URL}/status")
            response.raise_for_status()
            self.api_ok = True
            self.api_status_text = f"API: OK {response.text.strip()}"
        except Exception as exc:
            self.api_ok = False
            self.api_status_text = f"API: ERROR {exc}"
            self.add_error(f"[dashboard] status poll failed: {exc}")
        self.api_status_widget.update(self.api_status_text)

    async def poll_events(self) -> None:
        try:
            response = await self.http.get(
                f"{API_URL}/events",
                params={"after_id": self.last_event_id, "limit": 100},
            )
            response.raise_for_status()
            payload = response.json()
            for event in payload.get("events", []):
                self.last_event_id = max(self.last_event_id, int(event.get("id", 0)))
                self.process_event(event)
        except Exception as exc:
            self.add_error(f"[dashboard] event poll failed: {exc}")

    async def poll_logs(self) -> None:
        since = self.last_log_poll.isoformat()
        command = [
            "docker",
            "compose",
            "logs",
            "--timestamps",
            "--since",
            since,
            "--no-color",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(APP_ROOT),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            self.last_log_poll = datetime.now(timezone.utc)
            if proc.returncode != 0:
                self.add_error(f"[docker] {stderr.decode().strip() or f'exit {proc.returncode}'}")
                return
            for raw_line in stdout.decode(errors="replace").splitlines():
                if any(token in raw_line for token in ("Error", "Exception", "Traceback", "validation error")):
                    self.add_error(raw_line)
        except Exception as exc:
            self.add_error(f"[dashboard] log poll failed: {exc}")

    def process_event(self, event: Dict[str, str]) -> None:
        event_name = str(event.get("event", "UNKNOWN"))
        src = str(event.get("src", ""))
        dst = str(event.get("dst", ""))
        attack_type = str(event.get("attack_type", ""))
        line = f"[{event.get('ts')}] {event_name} | {src} -> {dst}"
        if attack_type:
            line += f" | {attack_type}"
        self.add_event_line(line)
        self.event_counts[event_name] += 1

        if event_name == "RESET_ISSUED":
            for agent_id in self.agent_states:
                self.agent_states[agent_id] = "HEALTHY"
                self.agent_last_event[agent_id] = "RESET_ISSUED"
        elif dst in self.agent_states:
            self.agent_last_event[dst] = event_name
            if event_name == "QUARANTINE_ISSUED":
                self.agent_states[dst] = "QUARANTINED"
            elif event_name == "INFECTION_SUCCESSFUL":
                self.agent_states[dst] = "INFECTED"
            elif event_name == "INFECTION_BLOCKED":
                self.agent_states[dst] = str(event.get("state_after") or event.get("state") or self.agent_states[dst])

    def refresh_panels(self) -> None:
        agent_lines = ["Agent States"]
        for agent_id, role in AGENT_ROLES.items():
            agent_lines.append(
                f"{agent_id} {role} | state={self.agent_states[agent_id]} | last={self.agent_last_event[agent_id]}"
            )
        self.agents_panel.update("\n".join(agent_lines))

        metrics_lines = [
            "Simulation Metrics",
            self.api_status_text,
            f"infection_attempt: {self.event_counts['INFECTION_ATTEMPT']}",
            f"infection_successful: {self.event_counts['INFECTION_SUCCESSFUL']}",
            f"infection_blocked: {self.event_counts['INFECTION_BLOCKED']}",
            f"mutation_created: {self.event_counts['MUTATION_CREATED']}",
            f"errors visible: {len(self.recent_errors)}",
        ]
        self.metrics_panel.update("\n".join(metrics_lines))

    async def post_control(self, endpoint: str, payload: Dict[str, str] | None = None) -> None:
        try:
            response = await self.http.post(f"{API_URL}{endpoint}", json=payload or {})
            response.raise_for_status()
            self.add_event_line(f"[control] POST {endpoint} -> {response.text}")
        except Exception as exc:
            self.add_error(f"[dashboard] control request failed for {endpoint}: {exc}")

    async def action_inject_easy(self) -> None:
        await self.post_control("/inject/agent-c", {"worm_level": "easy"})

    async def action_inject_medium(self) -> None:
        await self.post_control("/inject/agent-c", {"worm_level": "medium"})

    async def action_quarantine(self) -> None:
        await self.post_control("/quarantine/agent-c")

    async def action_reset(self) -> None:
        await self.post_control("/reset")

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "inject-easy":
            await self.action_inject_easy()
        elif event.button.id == "inject-medium":
            await self.action_inject_medium()
        elif event.button.id == "quarantine":
            await self.action_quarantine()
        elif event.button.id == "reset":
            await self.action_reset()


if __name__ == "__main__":
    EpidemicDashboard().run()
