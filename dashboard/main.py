import os
from typing import Dict

import httpx
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, Footer, Header, Static

API_URL = os.environ.get("API_URL", "http://localhost:8000")


class SimulationControl(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-columns: 1fr 1fr;
        grid-rows: auto 1fr 1fr;
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
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Button("Inject Easy", id="inject-easy")
            yield Button("Inject Medium", id="inject-medium")
            yield Button("Quarantine C", id="quarantine")
            yield Button("Reset", id="reset")
            yield Static("API: pending", id="api-status")
        yield Static(id="health-panel", classes="panel")
        yield Static(id="agents-panel", classes="panel")
        yield Static(id="status-panel", classes="panel")
        yield Footer()

    async def on_mount(self) -> None:
        self.http = httpx.AsyncClient(timeout=5.0)
        self.api_status = self.query_one("#api-status", Static)
        self.health_panel = self.query_one("#health-panel", Static)
        self.agents_panel = self.query_one("#agents-panel", Static)
        self.status_panel = self.query_one("#status-panel", Static)
        self.last_control_status = "control plane idle."
        self.set_interval(2.0, self.refresh_state)
        await self.refresh_state()

    async def on_unmount(self) -> None:
        await self.http.aclose()

    async def refresh_state(self) -> None:
        try:
            control, health = await self._fetch_state()
            self.api_status.update("API: connected")
            self.health_panel.update(
                "\n".join(
                    [
                        "Simulation Control",
                        f"indexed_events={health.get('indexed_events', 0)}",
                        f"parse_errors={health.get('parse_errors', 0)}",
                        f"last_event_ts={health.get('last_event_ts', '-')}",
                    ]
                )
            )
            self.agents_panel.update(
                "\n".join(
                    ["Agent States"]
                    + [
                        f"{agent['id']} role={agent['role']} state={agent['state']} last={agent['last_event']}"
                        for agent in control.get("agents", {}).values()
                    ]
                )
            )
            self.status_panel.update(self.last_control_status)
        except Exception as exc:
            self.api_status.update(f"API: error {exc}")
            self.status_panel.update(f"control/status error: {exc}")

    async def _fetch_state(self) -> tuple[Dict, Dict]:
        control_response = await self.http.get(f"{API_URL}/dashboard/state")
        control_response.raise_for_status()
        health_response = await self.http.get(f"{API_URL}/api/health")
        health_response.raise_for_status()
        return control_response.json(), health_response.json()

    async def _post_control(self, endpoint: str, payload: Dict | None = None) -> None:
        response = await self.http.post(f"{API_URL}{endpoint}", json=payload or {})
        response.raise_for_status()
        self.last_control_status = f"{endpoint} -> {response.text}"
        await self.refresh_state()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "inject-easy":
            await self._post_control("/inject/agent-c", {"worm_level": "easy"})
        elif event.button.id == "inject-medium":
            await self._post_control("/inject/agent-c", {"worm_level": "medium"})
        elif event.button.id == "quarantine":
            await self._post_control("/quarantine/agent-c")
        elif event.button.id == "reset":
            await self._post_control("/reset")


if __name__ == "__main__":
    SimulationControl().run()
