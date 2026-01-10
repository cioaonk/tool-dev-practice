"""
Docker Widgets

Reusable widget components for Docker container management and monitoring.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Literal, Any
from dataclasses import dataclass, field

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input, Select, Label
from textual.widget import Widget
from textual.reactive import reactive
from textual.message import Message
from textual.binding import Binding
from rich.text import Text


# Type aliases
ContainerStatus = Literal["running", "stopped", "paused", "restarting", "exited", "dead"]


@dataclass
class ContainerInfo:
    """Information about a Docker container."""

    id: str
    name: str
    image: str
    status: ContainerStatus
    ports: str
    created: str
    networks: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    cpu_percent: float = 0.0
    memory_usage: str = "0B"
    memory_percent: float = 0.0

    def __hash__(self) -> int:
        return hash(self.id)


class DockerCommandRunner:
    """Utility class to run Docker commands."""

    DOCKER_COMPOSE_DIR = Path("/Users/ic/cptc11/docker")

    @classmethod
    async def run_command(
        cls,
        command: List[str],
        cwd: Optional[Path] = None,
        timeout: float = 30.0
    ) -> tuple[int, str, str]:
        """
        Run a command asynchronously.

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd or cls.DOCKER_COMPOSE_DIR
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                return (
                    process.returncode or 0,
                    stdout.decode("utf-8", errors="replace"),
                    stderr.decode("utf-8", errors="replace")
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return (-1, "", "Command timed out")

        except FileNotFoundError:
            return (-1, "", f"Command not found: {command[0]}")
        except Exception as e:
            return (-1, "", str(e))

    @classmethod
    async def get_containers(cls) -> List[ContainerInfo]:
        """Get list of all containers in the compose project."""
        # Use docker-compose ps to get project containers
        code, stdout, stderr = await cls.run_command([
            "docker-compose", "ps", "--all", "--format", "json"
        ])

        if code != 0:
            # Try alternative: docker ps with label filter
            code, stdout, stderr = await cls.run_command([
                "docker", "ps", "-a",
                "--filter", "label=com.docker.compose.project",
                "--format", '{{json .}}'
            ])
            if code != 0:
                return []

        containers = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                # Handle both docker-compose and docker ps formats
                container = ContainerInfo(
                    id=data.get("ID", data.get("id", ""))[:12],
                    name=data.get("Name", data.get("name", data.get("Names", ""))),
                    image=data.get("Image", data.get("image", "")),
                    status=cls._parse_status(data.get("State", data.get("Status", "unknown"))),
                    ports=data.get("Ports", data.get("ports", "")),
                    created=data.get("CreatedAt", data.get("created_at", "")),
                    networks=data.get("Networks", "").split(",") if data.get("Networks") else [],
                    labels=data.get("Labels", {}) if isinstance(data.get("Labels"), dict) else {}
                )
                containers.append(container)
            except json.JSONDecodeError:
                continue

        return containers

    @classmethod
    def _parse_status(cls, status: str) -> ContainerStatus:
        """Parse container status string to ContainerStatus type."""
        status_lower = status.lower()
        if "running" in status_lower or "up" in status_lower:
            return "running"
        elif "paused" in status_lower:
            return "paused"
        elif "restarting" in status_lower:
            return "restarting"
        elif "exited" in status_lower:
            return "exited"
        elif "dead" in status_lower:
            return "dead"
        else:
            return "stopped"

    @classmethod
    async def get_container_stats(cls, container_id: str) -> Dict[str, Any]:
        """Get resource usage stats for a container."""
        code, stdout, stderr = await cls.run_command([
            "docker", "stats", container_id,
            "--no-stream", "--format", "{{json .}}"
        ])

        if code != 0 or not stdout.strip():
            return {}

        try:
            return json.loads(stdout.strip())
        except json.JSONDecodeError:
            return {}

    @classmethod
    async def get_container_logs(
        cls,
        container_id: str,
        tail: int = 100,
        follow: bool = False
    ) -> tuple[int, str, str]:
        """Get container logs."""
        cmd = ["docker", "logs", "--tail", str(tail)]
        if not follow:
            cmd.append(container_id)
            return await cls.run_command(cmd)
        return (-1, "", "Follow mode not supported in async context")

    @classmethod
    async def start_container(cls, container_name: str) -> tuple[int, str, str]:
        """Start a container."""
        return await cls.run_command([
            "docker-compose", "start", container_name
        ])

    @classmethod
    async def stop_container(cls, container_name: str) -> tuple[int, str, str]:
        """Stop a container."""
        return await cls.run_command([
            "docker-compose", "stop", container_name
        ])

    @classmethod
    async def restart_container(cls, container_name: str) -> tuple[int, str, str]:
        """Restart a container."""
        return await cls.run_command([
            "docker-compose", "restart", container_name
        ])

    @classmethod
    async def compose_up(cls) -> tuple[int, str, str]:
        """Start all compose services."""
        return await cls.run_command([
            "docker-compose", "up", "-d"
        ], timeout=120.0)

    @classmethod
    async def compose_down(cls) -> tuple[int, str, str]:
        """Stop all compose services."""
        return await cls.run_command([
            "docker-compose", "down"
        ], timeout=60.0)

    @classmethod
    async def exec_command(
        cls,
        container_name: str,
        command: List[str]
    ) -> tuple[int, str, str]:
        """Execute a command in a container."""
        full_cmd = ["docker", "exec", container_name] + command
        return await cls.run_command(full_cmd, timeout=60.0)


class ContainerStatusIndicator(Static):
    """A visual status indicator for container state."""

    STATUS_ICONS = {
        "running": ("[green]", "[/green]", "running"),
        "stopped": ("[dim]", "[/dim]", "stopped"),
        "paused": ("[yellow]", "[/yellow]", "paused"),
        "restarting": ("[cyan]", "[/cyan]", "restarting"),
        "exited": ("[red]", "[/red]", "exited"),
        "dead": ("[red bold]", "[/red bold]", "dead"),
    }

    DEFAULT_CSS = """
    ContainerStatusIndicator {
        width: auto;
        height: 1;
    }
    """

    def __init__(self, status: ContainerStatus, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._status = status

    def on_mount(self) -> None:
        """Render the status indicator."""
        self._update_display()

    def _update_display(self) -> None:
        """Update the displayed status."""
        prefix, suffix, label = self.STATUS_ICONS.get(
            self._status,
            ("[dim]", "[/dim]", "unknown")
        )
        self.update(f"{prefix}{label}{suffix}")

    def set_status(self, status: ContainerStatus) -> None:
        """Update the status."""
        self._status = status
        self._update_display()


class ContainerListItem(Horizontal):
    """A single container item in the container list."""

    DEFAULT_CSS = """
    ContainerListItem {
        height: 3;
        padding: 0 1;
        margin-bottom: 1;
        border: round $secondary;
        background: $surface;
    }

    ContainerListItem:hover {
        background: $primary-darken-1;
    }

    ContainerListItem:focus {
        background: $primary;
        border: round $accent;
    }

    ContainerListItem.--selected {
        background: $primary;
        border: double $accent;
    }

    ContainerListItem.--running {
        border-left: thick $success;
    }

    ContainerListItem.--stopped {
        border-left: thick $error;
    }

    ContainerListItem .container-name {
        width: 25;
        text-style: bold;
    }

    ContainerListItem .container-image {
        width: 20;
        color: $text-muted;
    }

    ContainerListItem .container-status {
        width: 12;
    }

    ContainerListItem .container-ports {
        width: 1fr;
        color: $text-muted;
    }
    """

    class Selected(Message):
        """Message sent when a container is selected."""

        def __init__(self, container: ContainerInfo) -> None:
            self.container = container
            super().__init__()

    def __init__(self, container: ContainerInfo, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.container = container
        self.can_focus = True

    def compose(self) -> ComposeResult:
        """Compose the container item display."""
        yield Static(self.container.name, classes="container-name")
        yield Static(self.container.image[:18], classes="container-image")
        yield ContainerStatusIndicator(self.container.status, classes="container-status")
        yield Static(self.container.ports[:30] if self.container.ports else "-", classes="container-ports")

    def on_mount(self) -> None:
        """Apply status-based styling."""
        if self.container.status == "running":
            self.add_class("--running")
        else:
            self.add_class("--stopped")

    def on_click(self) -> None:
        """Handle click events."""
        self.add_class("--selected")
        self.post_message(self.Selected(self.container))

    def deselect(self) -> None:
        """Deselect this container."""
        self.remove_class("--selected")

    def update_container(self, container: ContainerInfo) -> None:
        """Update the container info."""
        self.container = container
        # Update status classes
        self.remove_class("--running")
        self.remove_class("--stopped")
        if container.status == "running":
            self.add_class("--running")
        else:
            self.add_class("--stopped")


class ContainerList(Widget):
    """Widget displaying a list of Docker containers."""

    DEFAULT_CSS = """
    ContainerList {
        height: 100%;
        border: solid $primary;
        background: $surface-darken-1;
        padding: 1;
    }

    ContainerList #container-list-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ContainerList #container-list-scroll {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $primary;
    }

    ContainerList #container-count {
        dock: bottom;
        height: 1;
        text-align: center;
        color: $text-muted;
        padding-top: 1;
        border-top: solid $secondary;
    }

    ContainerList #loading-message {
        text-align: center;
        color: $text-muted;
        padding: 2;
    }
    """

    class ContainerSelected(Message):
        """Message sent when a container is selected."""

        def __init__(self, container: ContainerInfo) -> None:
            self.container = container
            super().__init__()

    # Reactive attributes
    selected_container: reactive[Optional[ContainerInfo]] = reactive(None)
    container_count: reactive[int] = reactive(0)
    loading: reactive[bool] = reactive(False)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._containers: List[ContainerInfo] = []
        self._container_items: Dict[str, ContainerListItem] = {}

    def compose(self) -> ComposeResult:
        """Compose the container list layout."""
        yield Label("[b]DOCKER CONTAINERS[/b]", id="container-list-title")

        with ScrollableContainer(id="container-list-scroll"):
            yield Static("[dim]Loading containers...[/dim]", id="loading-message")

        yield Static("0 containers", id="container-count")

    async def on_mount(self) -> None:
        """Load containers when mounted."""
        await self.refresh_containers()

    async def refresh_containers(self) -> None:
        """Refresh the container list."""
        self.loading = True

        try:
            self._containers = await DockerCommandRunner.get_containers()
            self.container_count = len(self._containers)

            # Rebuild the list
            scroll = self.query_one("#container-list-scroll", ScrollableContainer)

            # Remove loading message
            try:
                loading_msg = self.query_one("#loading-message", Static)
                loading_msg.remove()
            except Exception:
                pass

            # Clear existing items
            for item in list(self._container_items.values()):
                item.remove()
            self._container_items.clear()

            # Add container items
            for container in self._containers:
                item = ContainerListItem(
                    container,
                    id=f"container-{container.id}"
                )
                self._container_items[container.id] = item
                await scroll.mount(item)

            # Update count
            count_widget = self.query_one("#container-count", Static)
            running = sum(1 for c in self._containers if c.status == "running")
            count_widget.update(f"{len(self._containers)} containers ({running} running)")

        finally:
            self.loading = False

    def on_container_list_item_selected(self, message: ContainerListItem.Selected) -> None:
        """Handle container item selection."""
        # Deselect all other items
        for item in self._container_items.values():
            if item.container != message.container:
                item.deselect()

        self.selected_container = message.container
        self.post_message(self.ContainerSelected(message.container))

    def get_container_by_name(self, name: str) -> Optional[ContainerInfo]:
        """Get a container by name."""
        for container in self._containers:
            if container.name == name:
                return container
        return None


class ContainerControls(Widget):
    """Control buttons for container operations."""

    DEFAULT_CSS = """
    ContainerControls {
        height: auto;
        padding: 1;
        border: solid $secondary;
        background: $surface-darken-1;
    }

    ContainerControls #controls-title {
        text-style: bold;
        color: $secondary;
        text-align: center;
        padding-bottom: 1;
    }

    ContainerControls .control-row {
        layout: horizontal;
        height: 3;
        align: center middle;
        margin-bottom: 1;
    }

    ContainerControls Button {
        margin: 0 1;
        min-width: 10;
    }

    ContainerControls #start-btn {
        background: $success;
    }

    ContainerControls #stop-btn {
        background: $error;
    }

    ContainerControls #restart-btn {
        background: $warning;
    }

    ContainerControls #logs-btn {
        background: $primary;
    }

    ContainerControls #exec-btn {
        background: $secondary;
    }

    ContainerControls #run-tool-btn {
        background: $warning;
    }

    ContainerControls .compose-controls {
        border-top: solid $secondary;
        padding-top: 1;
        margin-top: 1;
    }

    ContainerControls #compose-up-btn {
        background: $success-darken-1;
    }

    ContainerControls #compose-down-btn {
        background: $error-darken-1;
    }
    """

    class StartContainer(Message):
        """Request to start a container."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    class StopContainer(Message):
        """Request to stop a container."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    class RestartContainer(Message):
        """Request to restart a container."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    class ViewLogs(Message):
        """Request to view container logs."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    class ExecCommand(Message):
        """Request to execute command in container."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    class ComposeUp(Message):
        """Request to start all compose services."""
        pass

    class ComposeDown(Message):
        """Request to stop all compose services."""
        pass

    class RunTool(Message):
        """Request to run a tool against the selected container."""
        def __init__(self, container_name: str) -> None:
            self.container_name = container_name
            super().__init__()

    # Reactive attributes
    selected_container: reactive[Optional[str]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        """Compose the control buttons."""
        yield Static("[b]Container Controls[/b]", id="controls-title")

        # Individual container controls
        with Horizontal(classes="control-row"):
            yield Button("Start", id="start-btn", disabled=True)
            yield Button("Stop", id="stop-btn", disabled=True)
            yield Button("Restart", id="restart-btn", disabled=True)

        with Horizontal(classes="control-row"):
            yield Button("Logs", id="logs-btn", disabled=True)
            yield Button("Exec", id="exec-btn", disabled=True)

        with Horizontal(classes="control-row"):
            yield Button("Run Tool", id="run-tool-btn", disabled=True)

        # Compose-wide controls
        with Vertical(classes="compose-controls"):
            yield Static("[dim]Compose Environment[/dim]", id="compose-title")
            with Horizontal(classes="control-row"):
                yield Button("Up All", id="compose-up-btn")
                yield Button("Down All", id="compose-down-btn")

    def watch_selected_container(self, container_name: Optional[str]) -> None:
        """Enable/disable buttons based on selection."""
        has_selection = container_name is not None

        for btn_id in ["start-btn", "stop-btn", "restart-btn", "logs-btn", "exec-btn", "run-tool-btn"]:
            btn = self.query_one(f"#{btn_id}", Button)
            btn.disabled = not has_selection

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "start-btn" and self.selected_container:
            self.post_message(self.StartContainer(self.selected_container))
        elif event.button.id == "stop-btn" and self.selected_container:
            self.post_message(self.StopContainer(self.selected_container))
        elif event.button.id == "restart-btn" and self.selected_container:
            self.post_message(self.RestartContainer(self.selected_container))
        elif event.button.id == "logs-btn" and self.selected_container:
            self.post_message(self.ViewLogs(self.selected_container))
        elif event.button.id == "exec-btn" and self.selected_container:
            self.post_message(self.ExecCommand(self.selected_container))
        elif event.button.id == "run-tool-btn" and self.selected_container:
            self.post_message(self.RunTool(self.selected_container))
        elif event.button.id == "compose-up-btn":
            self.post_message(self.ComposeUp())
        elif event.button.id == "compose-down-btn":
            self.post_message(self.ComposeDown())


class ContainerLogs(Widget):
    """Widget for displaying container logs."""

    DEFAULT_CSS = """
    ContainerLogs {
        height: 100%;
        border: solid $secondary;
        background: $surface-darken-2;
    }

    ContainerLogs #logs-title {
        dock: top;
        height: 2;
        text-style: bold;
        color: $secondary;
        text-align: center;
        padding: 0 1;
        border-bottom: solid $secondary;
        background: $surface-darken-1;
    }

    ContainerLogs #logs-content {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $secondary;
        padding: 1;
    }
    """

    container_name: reactive[Optional[str]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        """Compose the logs viewer."""
        yield Static("[b]Container Logs[/b]", id="logs-title")
        yield RichLog(
            id="logs-content",
            highlight=True,
            markup=True,
            auto_scroll=True,
            max_lines=5000
        )

    def watch_container_name(self, name: Optional[str]) -> None:
        """Update title when container changes."""
        title = self.query_one("#logs-title", Static)
        if name:
            title.update(f"[b]Logs: {name}[/b]")
        else:
            title.update("[b]Container Logs[/b]")

    async def load_logs(self, container_id: str, container_name: str) -> None:
        """Load logs for a container."""
        self.container_name = container_name

        logs_widget = self.query_one("#logs-content", RichLog)
        logs_widget.clear()
        logs_widget.write(f"[dim]Loading logs for {container_name}...[/dim]")

        code, stdout, stderr = await DockerCommandRunner.get_container_logs(
            container_id,
            tail=200
        )

        logs_widget.clear()

        if code != 0:
            logs_widget.write(f"[red]Error loading logs: {stderr}[/red]")
            return

        if not stdout.strip():
            logs_widget.write("[dim]No logs available[/dim]")
            return

        for line in stdout.split("\n"):
            # Color code log lines based on content
            if "error" in line.lower() or "err" in line.lower():
                logs_widget.write(f"[red]{line}[/red]")
            elif "warn" in line.lower():
                logs_widget.write(f"[yellow]{line}[/yellow]")
            elif "info" in line.lower():
                logs_widget.write(f"[cyan]{line}[/cyan]")
            else:
                logs_widget.write(line)

    def clear_logs(self) -> None:
        """Clear the logs display."""
        self.container_name = None
        logs_widget = self.query_one("#logs-content", RichLog)
        logs_widget.clear()


class ContainerStats(Widget):
    """Widget displaying container resource usage statistics."""

    DEFAULT_CSS = """
    ContainerStats {
        height: auto;
        min-height: 8;
        border: solid $warning;
        background: $surface-darken-1;
        padding: 1;
    }

    ContainerStats #stats-title {
        text-style: bold;
        color: $warning;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ContainerStats .stat-row {
        height: 1;
        padding: 0 1;
    }

    ContainerStats .stat-label {
        width: 12;
        color: $text-muted;
    }

    ContainerStats .stat-value {
        width: 1fr;
        color: $text;
    }

    ContainerStats .stat-bar {
        width: 20;
    }
    """

    container_name: reactive[Optional[str]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._stats: Dict[str, Any] = {}

    def compose(self) -> ComposeResult:
        """Compose the stats display."""
        yield Static("[b]Resource Usage[/b]", id="stats-title")

        with Vertical(id="stats-content"):
            with Horizontal(classes="stat-row"):
                yield Static("CPU:", classes="stat-label")
                yield Static("-", id="cpu-value", classes="stat-value")

            with Horizontal(classes="stat-row"):
                yield Static("Memory:", classes="stat-label")
                yield Static("-", id="memory-value", classes="stat-value")

            with Horizontal(classes="stat-row"):
                yield Static("Net I/O:", classes="stat-label")
                yield Static("-", id="net-value", classes="stat-value")

            with Horizontal(classes="stat-row"):
                yield Static("Block I/O:", classes="stat-label")
                yield Static("-", id="block-value", classes="stat-value")

    async def update_stats(self, container_id: str, container_name: str) -> None:
        """Update stats for a container."""
        self.container_name = container_name

        stats = await DockerCommandRunner.get_container_stats(container_id)

        if not stats:
            self._clear_stats()
            return

        self._stats = stats

        # Update display
        self.query_one("#cpu-value", Static).update(
            stats.get("CPUPerc", "-")
        )
        self.query_one("#memory-value", Static).update(
            f"{stats.get('MemUsage', '-')} ({stats.get('MemPerc', '-')})"
        )
        self.query_one("#net-value", Static).update(
            stats.get("NetIO", "-")
        )
        self.query_one("#block-value", Static).update(
            stats.get("BlockIO", "-")
        )

    def _clear_stats(self) -> None:
        """Clear the stats display."""
        self._stats = {}
        self.query_one("#cpu-value", Static).update("-")
        self.query_one("#memory-value", Static).update("-")
        self.query_one("#net-value", Static).update("-")
        self.query_one("#block-value", Static).update("-")


class AttackScenarioSelector(Widget):
    """Widget for selecting and launching attack scenarios against Docker targets."""

    DEFAULT_CSS = """
    AttackScenarioSelector {
        height: auto;
        min-height: 12;
        border: solid $error;
        background: $surface-darken-1;
        padding: 1;
    }

    AttackScenarioSelector #scenario-title {
        text-style: bold;
        color: $error;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    AttackScenarioSelector .scenario-item {
        height: 2;
        padding: 0 1;
        margin-bottom: 1;
        border: round $secondary;
        background: $surface;
    }

    AttackScenarioSelector .scenario-item:hover {
        background: $error-darken-2;
        border: round $error;
    }

    AttackScenarioSelector .scenario-item:focus {
        background: $error-darken-1;
        border: round $error;
    }

    AttackScenarioSelector #launch-btn {
        margin-top: 1;
        background: $error;
    }
    """

    # Predefined attack scenarios based on docker-compose services
    SCENARIOS = [
        {
            "name": "Web App Scan",
            "target": "vulnerable-web",
            "description": "Scan vulnerable web application",
            "ip": "10.10.10.10",
            "port": "8080"
        },
        {
            "name": "FTP Brute Force",
            "target": "ftp-server",
            "description": "Test FTP credentials",
            "ip": "10.10.10.20",
            "port": "2121"
        },
        {
            "name": "SMTP Enumeration",
            "target": "smtp-server",
            "description": "Enumerate SMTP users",
            "ip": "10.10.10.30",
            "port": "2525"
        },
        {
            "name": "DNS Zone Transfer",
            "target": "dns-server",
            "description": "Attempt DNS zone transfer",
            "ip": "10.10.10.40",
            "port": "5353"
        },
        {
            "name": "SMB Share Enum",
            "target": "smb-server",
            "description": "Enumerate SMB shares",
            "ip": "10.10.20.50",
            "port": "4445"
        },
        {
            "name": "MySQL Audit",
            "target": "mysql-server",
            "description": "Audit MySQL database",
            "ip": "10.10.20.60",
            "port": "3307"
        },
    ]

    class LaunchScenario(Message):
        """Message sent when launching an attack scenario."""

        def __init__(self, scenario: Dict[str, str]) -> None:
            self.scenario = scenario
            super().__init__()

    selected_scenario: reactive[Optional[Dict[str, str]]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def compose(self) -> ComposeResult:
        """Compose the scenario selector."""
        yield Static("[b]ATTACK SCENARIOS[/b]", id="scenario-title")

        with ScrollableContainer(id="scenario-list"):
            for scenario in self.SCENARIOS:
                yield Static(
                    f"[b]{scenario['name']}[/b] - {scenario['description']}\n"
                    f"[dim]Target: {scenario['ip']}:{scenario['port']}[/dim]",
                    classes="scenario-item",
                    id=f"scenario-{scenario['target']}"
                )

        yield Button("Launch Selected", id="launch-btn", disabled=True)

    def on_mount(self) -> None:
        """Set up click handlers for scenarios."""
        for scenario in self.SCENARIOS:
            item = self.query_one(f"#scenario-{scenario['target']}", Static)
            item.can_focus = True

    def on_static_focus(self, event) -> None:
        """Handle scenario focus."""
        widget_id = event.widget.id
        if widget_id and widget_id.startswith("scenario-"):
            target = widget_id.replace("scenario-", "")
            for scenario in self.SCENARIOS:
                if scenario["target"] == target:
                    self.selected_scenario = scenario
                    self.query_one("#launch-btn", Button).disabled = False
                    break

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle launch button press."""
        if event.button.id == "launch-btn" and self.selected_scenario:
            self.post_message(self.LaunchScenario(self.selected_scenario))
