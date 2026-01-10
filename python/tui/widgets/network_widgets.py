"""
Network Widgets for CORE Network Emulator Integration

Widgets for displaying and interacting with CORE network topologies,
nodes, and traffic monitoring.
"""

from __future__ import annotations

import asyncio
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, List, Dict, Optional, Any, Literal
from dataclasses import dataclass, field

from textual.app import ComposeResult
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Label, Input, Select
from textual.widget import Widget
from textual.message import Message
from textual.reactive import reactive
from textual.binding import Binding
from rich.text import Text
from rich.table import Table


NodeStatus = Literal["running", "stopped", "unknown"]


@dataclass
class NetworkTopology:
    """Represents a CORE network topology file."""

    name: str
    path: Path
    description: str = ""
    node_count: int = 0
    segments: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.path)


@dataclass
class NetworkNode:
    """Represents a node in a CORE network."""

    name: str
    node_id: str
    ip_addresses: List[str] = field(default_factory=list)
    node_type: str = "host"  # router, host, switch, etc.
    status: NodeStatus = "unknown"
    services: List[str] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.node_id)


@dataclass
class NetworkSession:
    """Represents an active CORE session."""

    session_id: str
    name: str
    state: str
    nodes: List[NetworkNode] = field(default_factory=list)


class TopologyItem(Static):
    """A clickable topology item in the topology list."""

    DEFAULT_CSS = """
    TopologyItem {
        height: 4;
        padding: 0 1;
        margin-bottom: 1;
        border: round $secondary;
        background: $surface;
    }

    TopologyItem:hover {
        background: $primary-darken-1;
    }

    TopologyItem:focus {
        background: $primary;
        border: round $accent;
    }

    TopologyItem.--selected {
        background: $primary;
        border: double $accent;
    }

    TopologyItem .topology-name {
        text-style: bold;
        color: $text;
    }

    TopologyItem .topology-path {
        color: $text-muted;
        text-style: italic;
    }

    TopologyItem .topology-info {
        color: $success;
    }
    """

    class Selected(Message):
        """Message sent when a topology is selected."""

        def __init__(self, topology: NetworkTopology) -> None:
            self.topology = topology
            super().__init__()

    def __init__(self, topology: NetworkTopology, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.topology = topology
        self.can_focus = True

    def compose(self) -> ComposeResult:
        """Compose the topology item display."""
        yield Static(f"[b]{self.topology.name}[/b]", classes="topology-name")
        yield Static(f"[i]{self.topology.path.name}[/i]", classes="topology-path")
        if self.topology.node_count > 0:
            yield Static(
                f"[green]{self.topology.node_count} nodes[/green]",
                classes="topology-info"
            )

    def on_click(self) -> None:
        """Handle click events."""
        self.add_class("--selected")
        self.post_message(self.Selected(self.topology))


class TopologyList(Widget):
    """Widget for listing available network topologies."""

    DEFAULT_CSS = """
    TopologyList {
        height: 100%;
        border: solid $primary;
        background: $surface-darken-1;
        padding: 1;
    }

    TopologyList #topology-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    TopologyList #topology-scroll {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $primary;
    }

    TopologyList #topology-count {
        dock: bottom;
        height: 1;
        text-align: center;
        color: $text-muted;
        padding-top: 1;
        border-top: solid $secondary;
    }
    """

    class TopologySelected(Message):
        """Message sent when a topology is selected."""

        def __init__(self, topology: NetworkTopology) -> None:
            self.topology = topology
            super().__init__()

    selected_topology: reactive[Optional[NetworkTopology]] = reactive(None)

    def __init__(self, networks_dir: Path, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.networks_dir = networks_dir
        self._topologies: List[NetworkTopology] = []
        self._topology_items: Dict[str, TopologyItem] = {}

    def compose(self) -> ComposeResult:
        """Compose the topology list layout."""
        yield Label("[b]NETWORK TOPOLOGIES[/b]", id="topology-title")

        with ScrollableContainer(id="topology-scroll"):
            # Load and display topologies
            pass

        yield Static("0 topologies", id="topology-count")

    def on_mount(self) -> None:
        """Load topologies when mounted."""
        self.load_topologies()

    def load_topologies(self) -> None:
        """Load available .imn topology files."""
        self._topologies.clear()
        container = self.query_one("#topology-scroll", ScrollableContainer)

        # Remove old items
        for item in self._topology_items.values():
            item.remove()
        self._topology_items.clear()

        if self.networks_dir.exists():
            imn_files = list(self.networks_dir.glob("*.imn"))

            for imn_file in sorted(imn_files):
                topology = self._parse_topology(imn_file)
                self._topologies.append(topology)

                item = TopologyItem(
                    topology,
                    id=f"topology-{imn_file.stem}"
                )
                self._topology_items[imn_file.stem] = item
                container.mount(item)

        # Update count
        count_widget = self.query_one("#topology-count", Static)
        count_widget.update(f"{len(self._topologies)} topologies")

    def _parse_topology(self, imn_file: Path) -> NetworkTopology:
        """Parse a .imn file to extract topology info."""
        name = imn_file.stem.replace("-", " ").replace("_", " ").title()
        node_count = 0
        segments: List[str] = []

        try:
            content = imn_file.read_text()

            # Count nodes
            node_matches = re.findall(r'^node\s+n\d+\s*\{', content, re.MULTILINE)
            node_count = len(node_matches)

            # Find network segments from annotations or hostnames
            segment_matches = re.findall(
                r'label\s*\{([^}]*(?:Network|Segment|DMZ)[^}]*)\}',
                content,
                re.IGNORECASE
            )
            segments = [s.strip() for s in segment_matches if s.strip()]

        except Exception:
            pass

        return NetworkTopology(
            name=name,
            path=imn_file,
            node_count=node_count,
            segments=segments
        )

    def on_topology_item_selected(self, message: TopologyItem.Selected) -> None:
        """Handle topology selection."""
        # Deselect all other items
        for item in self._topology_items.values():
            if item.topology != message.topology:
                item.remove_class("--selected")

        self.selected_topology = message.topology
        self.post_message(self.TopologySelected(message.topology))


class NodeTable(Widget):
    """Widget for displaying network nodes in a table."""

    DEFAULT_CSS = """
    NodeTable {
        height: 100%;
        border: solid $secondary;
        background: $surface-darken-1;
        padding: 1;
    }

    NodeTable #node-table-title {
        text-style: bold;
        color: $secondary;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    NodeTable DataTable {
        height: 100%;
    }
    """

    class NodeSelected(Message):
        """Message sent when a node is selected."""

        def __init__(self, node: NetworkNode) -> None:
            self.node = node
            super().__init__()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._nodes: List[NetworkNode] = []

    def compose(self) -> ComposeResult:
        """Compose the node table layout."""
        yield Label("[b]NETWORK NODES[/b]", id="node-table-title")
        yield DataTable(id="node-data-table")

    def on_mount(self) -> None:
        """Initialize the data table."""
        table = self.query_one("#node-data-table", DataTable)
        table.add_columns("Name", "IP Address", "Type", "Status", "Services")
        table.cursor_type = "row"

    def update_nodes(self, nodes: List[NetworkNode]) -> None:
        """Update the table with new nodes."""
        self._nodes = nodes
        table = self.query_one("#node-data-table", DataTable)
        table.clear()

        for node in nodes:
            # Format status with color
            if node.status == "running":
                status_display = "[green]Running[/green]"
            elif node.status == "stopped":
                status_display = "[red]Stopped[/red]"
            else:
                status_display = "[dim]Unknown[/dim]"

            # Format IP addresses
            ip_display = ", ".join(node.ip_addresses) if node.ip_addresses else "[dim]N/A[/dim]"

            # Format services
            services_display = ", ".join(node.services[:3]) if node.services else "[dim]None[/dim]"
            if len(node.services) > 3:
                services_display += "..."

            table.add_row(
                node.name,
                ip_display,
                node.node_type,
                status_display,
                services_display,
                key=node.node_id
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        if event.row_key and event.row_key.value:
            node_id = str(event.row_key.value)
            for node in self._nodes:
                if node.node_id == node_id:
                    self.post_message(self.NodeSelected(node))
                    break

    def clear_nodes(self) -> None:
        """Clear all nodes from the table."""
        self._nodes.clear()
        table = self.query_one("#node-data-table", DataTable)
        table.clear()


class TopologyVisualizer(Widget):
    """Widget for displaying ASCII network topology visualization."""

    DEFAULT_CSS = """
    TopologyVisualizer {
        height: 100%;
        border: solid $warning;
        background: $surface-darken-2;
        padding: 1;
    }

    TopologyVisualizer #topo-vis-title {
        text-style: bold;
        color: $warning;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    TopologyVisualizer #topo-vis-content {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $warning;
    }
    """

    # ASCII symbols for different node types
    NODE_SYMBOLS = {
        "router": "[cyan][@][/cyan]",
        "host": "[green][H][/green]",
        "server": "[yellow][S][/yellow]",
        "switch": "[blue][=][/blue]",
        "lanswitch": "[blue][=][/blue]",
        "hub": "[magenta][+][/magenta]",
        "pc": "[green][P][/green]",
        "firewall": "[red][#][/red]",
        "unknown": "[dim][?][/dim]",
    }

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._topology: Optional[NetworkTopology] = None
        self._nodes: List[NetworkNode] = []

    def compose(self) -> ComposeResult:
        """Compose the visualizer layout."""
        yield Label("[b]TOPOLOGY VISUALIZATION[/b]", id="topo-vis-title")
        yield Static(
            "[dim]Select a topology to view its network diagram[/dim]",
            id="topo-vis-content"
        )

    def render_topology(
        self,
        topology: NetworkTopology,
        nodes: List[NetworkNode]
    ) -> None:
        """Render a network topology as ASCII art."""
        self._topology = topology
        self._nodes = nodes

        content = self.query_one("#topo-vis-content", Static)

        if not nodes:
            content.update("[dim]No nodes to display[/dim]")
            return

        # Build ASCII representation
        lines = [
            f"[b]{topology.name}[/b]",
            f"[dim]File: {topology.path.name}[/dim]",
            "",
        ]

        # Group nodes by type
        routers = [n for n in nodes if n.node_type in ("router", "firewall")]
        switches = [n for n in nodes if n.node_type in ("switch", "lanswitch")]
        hosts = [n for n in nodes if n.node_type in ("host", "pc", "server")]

        # Draw routers at top
        if routers:
            lines.append("[b]-- Routers/Firewalls --[/b]")
            router_line = "    ".join(
                f"{self._get_node_symbol(r.node_type)} {r.name}"
                for r in routers[:4]
            )
            lines.append(f"  {router_line}")
            if len(routers) > 4:
                lines.append(f"  [dim]... and {len(routers) - 4} more[/dim]")
            lines.append("         |")
            lines.append("    +----+----+")
            lines.append("    |         |")

        # Draw switches in middle
        if switches:
            lines.append("[b]-- Switches --[/b]")
            switch_line = "    ".join(
                f"{self._get_node_symbol(s.node_type)} {s.name}"
                for s in switches[:4]
            )
            lines.append(f"  {switch_line}")
            if len(switches) > 4:
                lines.append(f"  [dim]... and {len(switches) - 4} more[/dim]")
            lines.append("    |    |    |")

        # Draw hosts at bottom
        if hosts:
            lines.append("[b]-- Hosts/Servers --[/b]")
            for i in range(0, min(len(hosts), 8), 4):
                host_group = hosts[i:i+4]
                host_line = "  ".join(
                    f"{self._get_node_symbol(h.node_type)} {h.name[:12]}"
                    for h in host_group
                )
                lines.append(f"  {host_line}")

            if len(hosts) > 8:
                lines.append(f"  [dim]... and {len(hosts) - 8} more hosts[/dim]")

        # Add legend
        lines.extend([
            "",
            "[dim]Legend:[/dim]",
            f"  {self.NODE_SYMBOLS['router']} Router  "
            f"{self.NODE_SYMBOLS['switch']} Switch  "
            f"{self.NODE_SYMBOLS['host']} Host  "
            f"{self.NODE_SYMBOLS['server']} Server  "
            f"{self.NODE_SYMBOLS['firewall']} Firewall",
        ])

        content.update("\n".join(lines))

    def _get_node_symbol(self, node_type: str) -> str:
        """Get the ASCII symbol for a node type."""
        return self.NODE_SYMBOLS.get(
            node_type.lower(),
            self.NODE_SYMBOLS["unknown"]
        )

    def clear(self) -> None:
        """Clear the visualization."""
        self._topology = None
        self._nodes.clear()
        content = self.query_one("#topo-vis-content", Static)
        content.update("[dim]Select a topology to view its network diagram[/dim]")


class NetworkControlPanel(Widget):
    """Widget with controls for CORE network operations."""

    DEFAULT_CSS = """
    NetworkControlPanel {
        height: auto;
        border: solid $success;
        background: $surface-darken-1;
        padding: 1;
    }

    NetworkControlPanel #control-title {
        text-style: bold;
        color: $success;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    NetworkControlPanel #control-buttons {
        layout: horizontal;
        height: auto;
        align: center middle;
        padding: 1 0;
    }

    NetworkControlPanel Button {
        margin: 0 1;
        min-width: 16;
    }

    NetworkControlPanel #session-info {
        text-align: center;
        color: $text-muted;
        padding-top: 1;
        border-top: solid $secondary;
        margin-top: 1;
    }
    """

    class StartNetwork(Message):
        """Message to start a network."""
        pass

    class StopNetwork(Message):
        """Message to stop a network."""
        pass

    class OpenGUI(Message):
        """Message to open CORE GUI."""
        pass

    class RefreshStatus(Message):
        """Message to refresh network status."""
        pass

    # Reactive attributes
    session_active: reactive[bool] = reactive(False)
    session_id: reactive[Optional[str]] = reactive(None)

    def compose(self) -> ComposeResult:
        """Compose the control panel layout."""
        yield Label("[b]NETWORK CONTROLS[/b]", id="control-title")

        with Horizontal(id="control-buttons"):
            yield Button("Start Network", variant="success", id="btn-start")
            yield Button("Stop Network", variant="error", id="btn-stop")
            yield Button("Open GUI", variant="primary", id="btn-gui")
            yield Button("Refresh", variant="default", id="btn-refresh")

        yield Static("Session: [dim]None[/dim]", id="session-info")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-start":
            self.post_message(self.StartNetwork())
        elif event.button.id == "btn-stop":
            self.post_message(self.StopNetwork())
        elif event.button.id == "btn-gui":
            self.post_message(self.OpenGUI())
        elif event.button.id == "btn-refresh":
            self.post_message(self.RefreshStatus())

    def update_session(self, session_id: Optional[str], active: bool) -> None:
        """Update the session display."""
        self.session_id = session_id
        self.session_active = active

        session_info = self.query_one("#session-info", Static)
        if active and session_id:
            session_info.update(f"Session: [green]{session_id}[/green] (Active)")
        else:
            session_info.update("Session: [dim]None[/dim]")

        # Update button states
        start_btn = self.query_one("#btn-start", Button)
        stop_btn = self.query_one("#btn-stop", Button)

        start_btn.disabled = active
        stop_btn.disabled = not active


class NetworkLog(Widget):
    """Widget for displaying network operation logs."""

    DEFAULT_CSS = """
    NetworkLog {
        height: 100%;
        border: solid $secondary;
        background: $surface-darken-2;
        padding: 0;
    }

    NetworkLog #netlog-title {
        text-style: bold;
        color: $secondary;
        text-align: center;
        padding: 0 1;
        height: 1;
        border-bottom: solid $secondary;
        background: $surface-darken-1;
    }

    NetworkLog #netlog-content {
        height: 100%;
        padding: 1;
        scrollbar-background: $surface;
        scrollbar-color: $secondary;
    }
    """

    def compose(self) -> ComposeResult:
        """Compose the log layout."""
        yield Static("[b]NETWORK LOG[/b]", id="netlog-title")
        yield RichLog(
            id="netlog-content",
            highlight=True,
            markup=True,
            auto_scroll=True,
            max_lines=1000,
        )

    def log(self, message: str, level: str = "info") -> None:
        """Add a log entry."""
        log_widget = self.query_one("#netlog-content", RichLog)

        # Color mapping
        colors = {
            "debug": "dim",
            "info": "white",
            "success": "green",
            "warning": "yellow",
            "error": "red bold",
        }

        prefixes = {
            "debug": "[DBG]",
            "info": "[INF]",
            "success": "[OK ]",
            "warning": "[WRN]",
            "error": "[ERR]",
        }

        color = colors.get(level, "white")
        prefix = prefixes.get(level, "[???]")
        time_str = datetime.now().strftime("%H:%M:%S")

        text = Text()
        text.append(f"{time_str} ", style="dim")
        text.append(f"{prefix} ", style=color)
        text.append(message, style=color if level in ("error", "warning", "success") else "white")

        log_widget.write(text)

    def clear(self) -> None:
        """Clear the log."""
        log_widget = self.query_one("#netlog-content", RichLog)
        log_widget.clear()


class NodeActionPanel(Widget):
    """Widget for node-specific actions."""

    DEFAULT_CSS = """
    NodeActionPanel {
        height: auto;
        border: solid $accent;
        background: $surface-darken-1;
        padding: 1;
    }

    NodeActionPanel #node-action-title {
        text-style: bold;
        color: $accent;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    NodeActionPanel #selected-node {
        text-align: center;
        padding: 1 0;
    }

    NodeActionPanel #node-action-buttons {
        layout: horizontal;
        height: auto;
        align: center middle;
        padding: 1 0;
    }

    NodeActionPanel Button {
        margin: 0 1;
    }
    """

    class OpenTerminal(Message):
        """Message to open a terminal to a node."""

        def __init__(self, node: NetworkNode) -> None:
            self.node = node
            super().__init__()

    class StartNode(Message):
        """Message to start a node."""

        def __init__(self, node: NetworkNode) -> None:
            self.node = node
            super().__init__()

    class StopNode(Message):
        """Message to stop a node."""

        def __init__(self, node: NetworkNode) -> None:
            self.node = node
            super().__init__()

    class RunTool(Message):
        """Message to run a tool against a node."""

        def __init__(self, node: NetworkNode) -> None:
            self.node = node
            super().__init__()

    selected_node: reactive[Optional[NetworkNode]] = reactive(None)

    def compose(self) -> ComposeResult:
        """Compose the action panel layout."""
        yield Label("[b]NODE ACTIONS[/b]", id="node-action-title")
        yield Static("[dim]Select a node from the table[/dim]", id="selected-node")

        with Horizontal(id="node-action-buttons"):
            yield Button("Terminal", variant="primary", id="btn-terminal", disabled=True)
            yield Button("Start", variant="success", id="btn-start-node", disabled=True)
            yield Button("Stop", variant="error", id="btn-stop-node", disabled=True)
            yield Button("Run Tool", variant="warning", id="btn-run-tool", disabled=True)

    def set_selected_node(self, node: Optional[NetworkNode]) -> None:
        """Set the currently selected node."""
        self.selected_node = node

        selected_display = self.query_one("#selected-node", Static)
        btn_terminal = self.query_one("#btn-terminal", Button)
        btn_start = self.query_one("#btn-start-node", Button)
        btn_stop = self.query_one("#btn-stop-node", Button)
        btn_tool = self.query_one("#btn-run-tool", Button)

        if node:
            ip_display = ", ".join(node.ip_addresses) if node.ip_addresses else "N/A"
            selected_display.update(
                f"[b]{node.name}[/b] ({node.node_type})\n"
                f"[dim]IP: {ip_display}[/dim]"
            )

            # Enable buttons based on node status
            btn_terminal.disabled = node.status != "running"
            btn_start.disabled = node.status == "running"
            btn_stop.disabled = node.status != "running"
            btn_tool.disabled = node.status != "running"
        else:
            selected_display.update("[dim]Select a node from the table[/dim]")
            btn_terminal.disabled = True
            btn_start.disabled = True
            btn_stop.disabled = True
            btn_tool.disabled = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if not self.selected_node:
            return

        if event.button.id == "btn-terminal":
            self.post_message(self.OpenTerminal(self.selected_node))
        elif event.button.id == "btn-start-node":
            self.post_message(self.StartNode(self.selected_node))
        elif event.button.id == "btn-stop-node":
            self.post_message(self.StopNode(self.selected_node))
        elif event.button.id == "btn-run-tool":
            self.post_message(self.RunTool(self.selected_node))


class TrafficMonitor(Widget):
    """Widget for monitoring network traffic summary."""

    DEFAULT_CSS = """
    TrafficMonitor {
        height: auto;
        min-height: 10;
        border: solid $warning;
        background: $surface-darken-1;
        padding: 1;
    }

    TrafficMonitor #traffic-title {
        text-style: bold;
        color: $warning;
        text-align: center;
        padding-bottom: 1;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    TrafficMonitor #traffic-stats {
        height: auto;
        padding: 1;
    }

    TrafficMonitor .traffic-row {
        height: 1;
    }
    """

    # Reactive attributes
    packets_sent: reactive[int] = reactive(0)
    packets_received: reactive[int] = reactive(0)
    bytes_sent: reactive[int] = reactive(0)
    bytes_received: reactive[int] = reactive(0)

    def compose(self) -> ComposeResult:
        """Compose the traffic monitor layout."""
        yield Label("[b]TRAFFIC MONITOR[/b]", id="traffic-title")
        yield Static(self._render_stats(), id="traffic-stats")

    def _render_stats(self) -> str:
        """Render traffic statistics."""
        lines = [
            "[b]Network Statistics[/b]",
            "",
            f"Packets Sent:     [cyan]{self.packets_sent:>10,}[/cyan]",
            f"Packets Received: [cyan]{self.packets_received:>10,}[/cyan]",
            f"Bytes Sent:       [green]{self._format_bytes(self.bytes_sent):>10}[/green]",
            f"Bytes Received:   [green]{self._format_bytes(self.bytes_received):>10}[/green]",
            "",
            "[dim]Statistics update when network is active[/dim]",
        ]
        return "\n".join(lines)

    def _format_bytes(self, num_bytes: int) -> str:
        """Format bytes in human-readable form."""
        for unit in ["B", "KB", "MB", "GB"]:
            if abs(num_bytes) < 1024:
                return f"{num_bytes:,.1f} {unit}"
            num_bytes /= 1024
        return f"{num_bytes:,.1f} TB"

    def update_stats(
        self,
        packets_sent: int = 0,
        packets_received: int = 0,
        bytes_sent: int = 0,
        bytes_received: int = 0
    ) -> None:
        """Update traffic statistics."""
        self.packets_sent = packets_sent
        self.packets_received = packets_received
        self.bytes_sent = bytes_sent
        self.bytes_received = bytes_received

        stats_widget = self.query_one("#traffic-stats", Static)
        stats_widget.update(self._render_stats())

    def reset_stats(self) -> None:
        """Reset all statistics."""
        self.update_stats(0, 0, 0, 0)
