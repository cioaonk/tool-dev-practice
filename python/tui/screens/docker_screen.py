"""
Docker Management Screen

A screen for managing Docker containers, viewing logs, executing commands,
and launching attack scenarios against Docker-based targets.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Dict, Optional, Any

from textual.app import ComposeResult
from textual.screen import Screen, ModalScreen
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    Input,
    Label,
    RichLog,
)
from textual.binding import Binding
from textual.reactive import reactive

from ..widgets.docker_widgets import (
    ContainerList,
    ContainerControls,
    ContainerLogs,
    ContainerStats,
    AttackScenarioSelector,
    DockerCommandRunner,
    ContainerInfo,
)


class ExecCommandModal(ModalScreen[Optional[str]]):
    """Modal dialog for entering a command to execute in a container."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
        Binding("enter", "submit", "Submit", show=False),
    ]

    DEFAULT_CSS = """
    ExecCommandModal {
        align: center middle;
        background: $surface 60%;
    }

    ExecCommandModal #exec-container {
        width: 60;
        height: auto;
        max-height: 50%;
        background: $surface;
        border: double $primary;
        padding: 1 2;
    }

    ExecCommandModal #exec-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding: 1 0;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ExecCommandModal #exec-label {
        padding: 1 0 0 0;
    }

    ExecCommandModal Input {
        margin: 1 0;
        border: round $secondary;
    }

    ExecCommandModal Input:focus {
        border: round $primary;
    }

    ExecCommandModal #button-row {
        layout: horizontal;
        align: center middle;
        padding-top: 1;
        border-top: solid $secondary;
        margin-top: 1;
        height: 4;
    }

    ExecCommandModal Button {
        margin: 0 1;
        min-width: 12;
    }

    ExecCommandModal #exec-submit-btn {
        background: $success;
    }

    ExecCommandModal #exec-cancel-btn {
        background: $error;
    }
    """

    def __init__(self, container_name: str, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.container_name = container_name

    def compose(self) -> ComposeResult:
        """Compose the modal dialog."""
        with Container(id="exec-container"):
            yield Static(f"[b]Execute in: {self.container_name}[/b]", id="exec-title")
            yield Label("Enter command to execute:", id="exec-label")
            yield Input(
                placeholder="e.g., /bin/bash -c 'ls -la'",
                id="exec-input"
            )
            with Horizontal(id="button-row"):
                yield Button("Cancel", id="exec-cancel-btn", variant="error")
                yield Button("Execute", id="exec-submit-btn", variant="success")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "exec-submit-btn":
            self.action_submit()
        elif event.button.id == "exec-cancel-btn":
            self.action_cancel()

    def action_submit(self) -> None:
        """Submit the command."""
        input_widget = self.query_one("#exec-input", Input)
        command = input_widget.value.strip()
        if command:
            self.dismiss(command)
        else:
            self.notify("Please enter a command", severity="warning")

    def action_cancel(self) -> None:
        """Cancel and close."""
        self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input."""
        self.action_submit()


class DockerScreen(Screen):
    """Main Docker management screen."""

    BINDINGS = [
        Binding("escape", "go_back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("u", "compose_up", "Up All", show=True),
        Binding("d", "compose_down", "Down All", show=True),
        Binding("l", "view_logs", "Logs", show=True),
        Binding("e", "exec_command", "Exec", show=True),
        Binding("s", "start_container", "Start", show=False),
        Binding("x", "stop_container", "Stop", show=False),
    ]

    DEFAULT_CSS = """
    DockerScreen {
        background: $surface;
    }

    DockerScreen #docker-container {
        layout: grid;
        grid-size: 3 2;
        grid-columns: 1fr 2fr 1fr;
        grid-rows: 2fr 1fr;
        padding: 1;
    }

    DockerScreen #container-list-panel {
        column-span: 1;
        row-span: 2;
    }

    DockerScreen #main-panel {
        column-span: 1;
        row-span: 2;
    }

    DockerScreen #right-panel {
        column-span: 1;
        row-span: 2;
    }

    DockerScreen #logs-panel {
        height: 100%;
    }

    DockerScreen #output-area {
        height: 100%;
        border: solid $secondary;
        background: $surface-darken-2;
    }

    DockerScreen #output-title {
        dock: top;
        height: 2;
        text-style: bold;
        color: $secondary;
        text-align: center;
        padding: 0 1;
        border-bottom: solid $secondary;
        background: $surface-darken-1;
    }

    DockerScreen #output-log {
        height: 100%;
        padding: 1;
    }

    DockerScreen #status-bar {
        dock: bottom;
        height: 2;
        background: $primary-darken-2;
        padding: 0 2;
        border-top: solid $primary;
    }

    DockerScreen #status-content {
        layout: horizontal;
        width: 100%;
        height: 100%;
        align: center middle;
    }

    DockerScreen .status-item {
        padding: 0 2;
    }
    """

    # Reactive attributes
    selected_container: reactive[Optional[ContainerInfo]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._operation_in_progress = False

    def compose(self) -> ComposeResult:
        """Compose the Docker screen layout."""
        yield Header(show_clock=True)

        with Container(id="docker-container"):
            # Left panel - Container list
            with Vertical(id="container-list-panel"):
                yield ContainerList(id="container-list")

            # Main panel - Logs and output
            with Vertical(id="main-panel"):
                yield ContainerLogs(id="logs-panel")

            # Right panel - Controls, Stats, Attack scenarios
            with Vertical(id="right-panel"):
                yield ContainerControls(id="container-controls")
                yield ContainerStats(id="container-stats")
                yield AttackScenarioSelector(id="attack-scenarios")

        # Status bar
        with Container(id="status-bar"):
            with Horizontal(id="status-content"):
                yield Static("[green]Ready[/green]", id="status-state", classes="status-item")
                yield Static("|", classes="separator")
                yield Static("Container: None", id="status-container", classes="status-item")
                yield Static("|", classes="separator")
                yield Static(datetime.now().strftime("%H:%M:%S"), id="status-clock", classes="status-item")

        yield Footer()

    def on_mount(self) -> None:
        """Set up the screen when mounted."""
        self.log_output("Docker Management Screen initialized", level="info")
        self.log_output("Press 'r' to refresh container list", level="info")
        self.set_interval(1, self._update_clock)

    def _update_clock(self) -> None:
        """Update the clock in status bar."""
        clock = self.query_one("#status-clock", Static)
        clock.update(datetime.now().strftime("%H:%M:%S"))

    def log_output(self, message: str, level: str = "info") -> None:
        """Log a message to the logs panel."""
        logs_panel = self.query_one("#logs-panel", ContainerLogs)
        logs_widget = logs_panel.query_one("#logs-content", RichLog)

        # Format with timestamp and level
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_styles = {
            "info": "cyan",
            "success": "green",
            "warning": "yellow",
            "error": "red",
            "debug": "dim",
        }
        style = level_styles.get(level, "white")

        logs_widget.write(f"[dim]{timestamp}[/dim] [{style}]{message}[/{style}]")

    def update_status(self, status: str, style: str = "green") -> None:
        """Update the status indicator."""
        status_widget = self.query_one("#status-state", Static)
        status_widget.update(f"[{style}]{status}[/{style}]")

    # Event handlers for container list
    async def on_container_list_container_selected(
        self,
        message: ContainerList.ContainerSelected
    ) -> None:
        """Handle container selection."""
        self.selected_container = message.container

        # Update controls
        controls = self.query_one("#container-controls", ContainerControls)
        controls.selected_container = message.container.name

        # Update status bar
        status_container = self.query_one("#status-container", Static)
        status_container.update(f"Container: {message.container.name}")

        # Load stats
        stats_widget = self.query_one("#container-stats", ContainerStats)
        await stats_widget.update_stats(message.container.id, message.container.name)

        self.log_output(
            f"Selected container: {message.container.name} ({message.container.status})",
            level="info"
        )

    # Event handlers for container controls
    async def on_container_controls_start_container(
        self,
        message: ContainerControls.StartContainer
    ) -> None:
        """Handle start container request."""
        await self._start_container(message.container_name)

    async def on_container_controls_stop_container(
        self,
        message: ContainerControls.StopContainer
    ) -> None:
        """Handle stop container request."""
        await self._stop_container(message.container_name)

    async def on_container_controls_restart_container(
        self,
        message: ContainerControls.RestartContainer
    ) -> None:
        """Handle restart container request."""
        await self._restart_container(message.container_name)

    async def on_container_controls_view_logs(
        self,
        message: ContainerControls.ViewLogs
    ) -> None:
        """Handle view logs request."""
        if self.selected_container:
            await self._view_logs(self.selected_container.id, message.container_name)

    async def on_container_controls_exec_command(
        self,
        message: ContainerControls.ExecCommand
    ) -> None:
        """Handle exec command request."""
        await self.action_exec_command()

    async def on_container_controls_compose_up(
        self,
        message: ContainerControls.ComposeUp
    ) -> None:
        """Handle compose up request."""
        await self.action_compose_up()

    async def on_container_controls_compose_down(
        self,
        message: ContainerControls.ComposeDown
    ) -> None:
        """Handle compose down request."""
        await self.action_compose_down()

    # Event handlers for attack scenarios
    async def on_attack_scenario_selector_launch_scenario(
        self,
        message: AttackScenarioSelector.LaunchScenario
    ) -> None:
        """Handle attack scenario launch."""
        scenario = message.scenario
        self.log_output(
            f"Launching attack scenario: {scenario['name']}",
            level="warning"
        )
        self.log_output(
            f"Target: {scenario['target']} at {scenario['ip']}:{scenario['port']}",
            level="info"
        )

        # Here you would integrate with the actual attack tools
        # For now, we just log the scenario details
        self.notify(
            f"Scenario '{scenario['name']}' ready - configure in Tools panel",
            title="Attack Scenario",
            severity="warning"
        )

    # Container operations
    async def _start_container(self, container_name: str) -> None:
        """Start a container."""
        if self._operation_in_progress:
            self.notify("Operation in progress", severity="warning")
            return

        self._operation_in_progress = True
        self.update_status("Starting...", "yellow")
        self.log_output(f"Starting container: {container_name}", level="info")

        code, stdout, stderr = await DockerCommandRunner.start_container(container_name)

        if code == 0:
            self.log_output(f"Container {container_name} started successfully", level="success")
            self.update_status("Ready", "green")
            await self._refresh_containers()
        else:
            self.log_output(f"Failed to start container: {stderr}", level="error")
            self.update_status("Error", "red")

        self._operation_in_progress = False

    async def _stop_container(self, container_name: str) -> None:
        """Stop a container."""
        if self._operation_in_progress:
            self.notify("Operation in progress", severity="warning")
            return

        self._operation_in_progress = True
        self.update_status("Stopping...", "yellow")
        self.log_output(f"Stopping container: {container_name}", level="info")

        code, stdout, stderr = await DockerCommandRunner.stop_container(container_name)

        if code == 0:
            self.log_output(f"Container {container_name} stopped successfully", level="success")
            self.update_status("Ready", "green")
            await self._refresh_containers()
        else:
            self.log_output(f"Failed to stop container: {stderr}", level="error")
            self.update_status("Error", "red")

        self._operation_in_progress = False

    async def _restart_container(self, container_name: str) -> None:
        """Restart a container."""
        if self._operation_in_progress:
            self.notify("Operation in progress", severity="warning")
            return

        self._operation_in_progress = True
        self.update_status("Restarting...", "yellow")
        self.log_output(f"Restarting container: {container_name}", level="info")

        code, stdout, stderr = await DockerCommandRunner.restart_container(container_name)

        if code == 0:
            self.log_output(f"Container {container_name} restarted successfully", level="success")
            self.update_status("Ready", "green")
            await self._refresh_containers()
        else:
            self.log_output(f"Failed to restart container: {stderr}", level="error")
            self.update_status("Error", "red")

        self._operation_in_progress = False

    async def _view_logs(self, container_id: str, container_name: str) -> None:
        """View container logs."""
        logs_panel = self.query_one("#logs-panel", ContainerLogs)
        await logs_panel.load_logs(container_id, container_name)

    async def _exec_in_container(self, container_name: str, command: str) -> None:
        """Execute a command in a container."""
        self.log_output(f"Executing in {container_name}: {command}", level="info")

        # Parse command string into list
        import shlex
        try:
            cmd_list = shlex.split(command)
        except ValueError as e:
            self.log_output(f"Invalid command format: {e}", level="error")
            return

        code, stdout, stderr = await DockerCommandRunner.exec_command(
            container_name,
            cmd_list
        )

        if code == 0:
            self.log_output("Command output:", level="success")
            for line in stdout.split("\n"):
                if line.strip():
                    self.log_output(f"  {line}", level="info")
        else:
            self.log_output(f"Command failed: {stderr}", level="error")

    async def _refresh_containers(self) -> None:
        """Refresh the container list."""
        container_list = self.query_one("#container-list", ContainerList)
        await container_list.refresh_containers()

    # Action handlers (keyboard shortcuts)
    def action_go_back(self) -> None:
        """Go back to the main dashboard."""
        self.app.pop_screen()

    async def action_refresh(self) -> None:
        """Refresh container list."""
        self.log_output("Refreshing container list...", level="info")
        await self._refresh_containers()
        self.log_output("Container list refreshed", level="success")

    async def action_compose_up(self) -> None:
        """Start all compose services."""
        if self._operation_in_progress:
            self.notify("Operation in progress", severity="warning")
            return

        self._operation_in_progress = True
        self.update_status("Starting All...", "yellow")
        self.log_output("Starting all compose services...", level="info")

        code, stdout, stderr = await DockerCommandRunner.compose_up()

        if code == 0:
            self.log_output("All services started successfully", level="success")
            if stdout:
                for line in stdout.split("\n")[-5:]:  # Last 5 lines
                    if line.strip():
                        self.log_output(f"  {line}", level="info")
            self.update_status("Ready", "green")
            await self._refresh_containers()
        else:
            self.log_output(f"Failed to start services: {stderr}", level="error")
            self.update_status("Error", "red")

        self._operation_in_progress = False

    async def action_compose_down(self) -> None:
        """Stop all compose services."""
        if self._operation_in_progress:
            self.notify("Operation in progress", severity="warning")
            return

        self._operation_in_progress = True
        self.update_status("Stopping All...", "yellow")
        self.log_output("Stopping all compose services...", level="info")

        code, stdout, stderr = await DockerCommandRunner.compose_down()

        if code == 0:
            self.log_output("All services stopped successfully", level="success")
            self.update_status("Ready", "green")
            await self._refresh_containers()
        else:
            self.log_output(f"Failed to stop services: {stderr}", level="error")
            self.update_status("Error", "red")

        self._operation_in_progress = False

    async def action_view_logs(self) -> None:
        """View logs for selected container."""
        if self.selected_container:
            await self._view_logs(
                self.selected_container.id,
                self.selected_container.name
            )
        else:
            self.notify("No container selected", severity="warning")

    async def action_exec_command(self) -> None:
        """Open exec command modal."""
        if not self.selected_container:
            self.notify("No container selected", severity="warning")
            return

        if self.selected_container.status != "running":
            self.notify("Container must be running to exec", severity="warning")
            return

        modal = ExecCommandModal(self.selected_container.name)
        command = await self.app.push_screen_wait(modal)

        if command:
            await self._exec_in_container(self.selected_container.name, command)

    async def action_start_container(self) -> None:
        """Start the selected container."""
        if self.selected_container:
            await self._start_container(self.selected_container.name)
        else:
            self.notify("No container selected", severity="warning")

    async def action_stop_container(self) -> None:
        """Stop the selected container."""
        if self.selected_container:
            await self._stop_container(self.selected_container.name)
        else:
            self.notify("No container selected", severity="warning")
