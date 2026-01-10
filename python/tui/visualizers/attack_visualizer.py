"""
Attack Visualizer Widget

A widget for visualizing attack patterns, network topology,
and security events in ASCII/Unicode art.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional, Literal, Dict, Any
from dataclasses import dataclass, field

from textual.app import ComposeResult
from textual.containers import Vertical, ScrollableContainer
from textual.widgets import Static, RichLog
from textual.widget import Widget
from textual.reactive import reactive
from textual.message import Message
from rich.text import Text
from rich.panel import Panel
from rich.table import Table


SeverityLevel = Literal["low", "medium", "high", "critical"]


@dataclass
class AttackEvent:
    """Represents a single attack event."""

    timestamp: datetime
    source: str
    target: str
    attack_type: str
    severity: SeverityLevel
    details: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.timestamp, self.source, self.target, self.attack_type))


@dataclass
class NetworkNode:
    """Represents a node in the network topology."""

    name: str
    ip: str
    node_type: str  # attacker, target, gateway, server, etc.
    status: str  # active, inactive, compromised

    def __hash__(self) -> int:
        return hash(self.name)


class AttackVisualizer(Widget):
    """
    Attack pattern visualization widget.

    Features:
    - ASCII network topology display
    - Attack event timeline
    - Severity-based coloring
    - Real-time updates
    - Interactive exploration
    """

    DEFAULT_CSS = """
    AttackVisualizer {
        height: 100%;
        border: solid $warning;
        background: $surface-darken-1;
        padding: 0;
    }

    AttackVisualizer #visualizer-title {
        text-style: bold;
        color: $warning;
        text-align: center;
        padding: 0 1;
        height: 1;
        border-bottom: solid $secondary;
        background: $surface-darken-2;
    }

    AttackVisualizer #attack-content {
        height: 100%;
        padding: 1;
    }

    AttackVisualizer #topology-view {
        height: auto;
        min-height: 8;
        padding: 1;
        background: $surface-darken-2;
        border: round $secondary;
        margin-bottom: 1;
    }

    AttackVisualizer #event-log {
        height: auto;
        max-height: 100%;
        padding: 0;
        scrollbar-background: $surface;
        scrollbar-color: $warning;
    }

    AttackVisualizer .severity-low {
        color: $success;
    }

    AttackVisualizer .severity-medium {
        color: $warning;
    }

    AttackVisualizer .severity-high {
        color: $error;
    }

    AttackVisualizer .severity-critical {
        color: $error;
        text-style: bold blink;
    }
    """

    # Severity colors and icons
    SEVERITY_STYLES = {
        "low": ("green", "○"),
        "medium": ("yellow", "◐"),
        "high": ("red", "●"),
        "critical": ("red bold", "◉"),
    }

    # Node type symbols
    NODE_SYMBOLS = {
        "attacker": "☠",
        "target": "◎",
        "gateway": "⬡",
        "server": "▣",
        "workstation": "▢",
        "unknown": "?",
    }

    class AttackDetected(Message):
        """Message sent when an attack event is detected."""

        def __init__(self, event: AttackEvent) -> None:
            self.event = event
            super().__init__()

    # Reactive attributes
    event_count: reactive[int] = reactive(0)
    active_attacks: reactive[int] = reactive(0)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._events: List[AttackEvent] = []
        self._nodes: Dict[str, NetworkNode] = {}

    def compose(self) -> ComposeResult:
        """Compose the visualizer layout."""
        yield Static("[b]ATTACK PATTERN VISUALIZER[/b]", id="visualizer-title")

        with Vertical(id="attack-content"):
            yield Static(self._render_topology(), id="topology-view")
            yield RichLog(
                id="event-log",
                highlight=True,
                markup=True,
                auto_scroll=True,
                max_lines=1000,
            )

    def on_mount(self) -> None:
        """Initialize with sample topology."""
        self._init_sample_topology()
        self._update_topology_display()

    def _init_sample_topology(self) -> None:
        """Initialize sample network topology."""
        self._nodes = {
            "attacker": NetworkNode(
                name="Attacker",
                ip="???",
                node_type="attacker",
                status="active"
            ),
            "gateway": NetworkNode(
                name="Gateway",
                ip="192.168.1.1",
                node_type="gateway",
                status="active"
            ),
            "server1": NetworkNode(
                name="Web Server",
                ip="192.168.1.10",
                node_type="server",
                status="active"
            ),
            "server2": NetworkNode(
                name="DB Server",
                ip="192.168.1.20",
                node_type="server",
                status="active"
            ),
            "workstation": NetworkNode(
                name="Workstation",
                ip="192.168.1.100",
                node_type="workstation",
                status="active"
            ),
        }

    def _render_topology(self) -> str:
        """Render ASCII network topology."""
        if not self._nodes:
            return "[dim]No network topology loaded[/dim]"

        # Build ASCII art representation
        lines = [
            "[b]Network Topology[/b]",
            "",
            "    [red]" + self.NODE_SYMBOLS["attacker"] + " Attacker[/red]",
            "         |",
            "         v",
            "    [cyan]" + self.NODE_SYMBOLS["gateway"] + " Gateway (192.168.1.1)[/cyan]",
            "         |",
            "    +----+----+",
            "    |         |",
            "    v         v",
            "[green]" + self.NODE_SYMBOLS["server"] + " Web[/green]    [yellow]" + self.NODE_SYMBOLS["server"] + " DB[/yellow]",
            "[dim](10)[/dim]      [dim](20)[/dim]",
            "",
        ]

        # Add status legend
        lines.extend([
            "[dim]Legend: " + self.NODE_SYMBOLS["attacker"] + "=Attacker  " +
            self.NODE_SYMBOLS["gateway"] + "=Gateway  " +
            self.NODE_SYMBOLS["server"] + "=Server  " +
            self.NODE_SYMBOLS["workstation"] + "=Workstation[/dim]"
        ])

        return "\n".join(lines)

    def _update_topology_display(self) -> None:
        """Update the topology display."""
        topology_view = self.query_one("#topology-view", Static)
        topology_view.update(self._render_topology())

    def add_attack_event(
        self,
        source: str,
        target: str,
        attack_type: str,
        severity: SeverityLevel = "medium",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Add an attack event to the visualizer.

        Args:
            source: Attack source
            target: Attack target
            attack_type: Type of attack
            severity: Severity level
            details: Additional details
        """
        event = AttackEvent(
            timestamp=datetime.now(),
            source=source,
            target=target,
            attack_type=attack_type,
            severity=severity,
            details=details or {}
        )

        self._events.append(event)
        self.event_count = len(self._events)

        # Render event to log
        self._render_event(event)

        # Post message
        self.post_message(self.AttackDetected(event))

    def _render_event(self, event: AttackEvent) -> None:
        """Render an attack event to the log."""
        style, icon = self.SEVERITY_STYLES.get(event.severity, ("white", "?"))

        event_log = self.query_one("#event-log", RichLog)

        # Create formatted event text
        text = Text()
        text.append(event.timestamp.strftime("%H:%M:%S"), style="dim")
        text.append(" ")
        text.append(f"{icon} ", style=style)
        text.append(f"[{event.severity.upper()}] ", style=style)
        text.append(f"{event.attack_type}: ", style="bold")
        text.append(f"{event.source} -> {event.target}", style="white")

        event_log.write(text)

    def add_node(
        self,
        name: str,
        ip: str,
        node_type: str,
        status: str = "active"
    ) -> None:
        """
        Add a node to the topology.

        Args:
            name: Node name
            ip: IP address
            node_type: Type of node
            status: Node status
        """
        self._nodes[name.lower()] = NetworkNode(
            name=name,
            ip=ip,
            node_type=node_type,
            status=status
        )
        self._update_topology_display()

    def update_node_status(self, name: str, status: str) -> None:
        """Update a node's status."""
        key = name.lower()
        if key in self._nodes:
            self._nodes[key].status = status
            self._update_topology_display()

    def clear_events(self) -> None:
        """Clear all attack events."""
        self._events.clear()
        self.event_count = 0

        event_log = self.query_one("#event-log", RichLog)
        event_log.clear()

    def get_events_by_severity(
        self,
        severity: SeverityLevel
    ) -> List[AttackEvent]:
        """Get events filtered by severity."""
        return [e for e in self._events if e.severity == severity]

    def get_timeline_summary(self) -> str:
        """Generate a timeline summary of events."""
        if not self._events:
            return "No events recorded"

        lines = ["Attack Timeline Summary", "=" * 40, ""]

        for event in self._events[-10:]:  # Last 10 events
            time_str = event.timestamp.strftime("%H:%M:%S")
            lines.append(
                f"{time_str} | {event.severity:8} | {event.attack_type}"
            )

        lines.append("")
        lines.append(f"Total events: {len(self._events)}")

        return "\n".join(lines)

    def render_attack_graph(self) -> str:
        """
        Render an ASCII attack graph showing relationships.

        Returns a string representation of attack patterns.
        """
        if not self._events:
            return "[dim]No attack patterns to display[/dim]"

        # Build attack graph
        sources: Dict[str, List[str]] = {}
        for event in self._events:
            if event.source not in sources:
                sources[event.source] = []
            if event.target not in sources[event.source]:
                sources[event.source].append(event.target)

        lines = ["[b]Attack Graph[/b]", ""]

        for source, targets in sources.items():
            lines.append(f"[red]{source}[/red]")
            for i, target in enumerate(targets):
                connector = "└──>" if i == len(targets) - 1 else "├──>"
                lines.append(f"   {connector} [yellow]{target}[/yellow]")
            lines.append("")

        return "\n".join(lines)
