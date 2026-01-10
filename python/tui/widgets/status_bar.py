"""
Status Bar Widget

A status bar that displays active operations, system status, and key metrics.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional, List, Literal
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Static
from textual.widget import Widget
from textual.reactive import reactive
from textual.timer import Timer


StatusType = Literal["ready", "running", "complete", "error", "cancelled", "warning"]


@dataclass
class ActiveOperation:
    """Represents an active operation."""

    name: str
    start_time: datetime
    status: StatusType


class StatusItem(Static):
    """A single item in the status bar."""

    DEFAULT_CSS = """
    StatusItem {
        width: auto;
        height: 1;
        padding: 0 2;
    }

    StatusItem .status-label {
        color: $text-muted;
    }

    StatusItem .status-value {
        color: $text;
        text-style: bold;
    }
    """

    def __init__(
        self,
        label: str,
        value: str = "",
        *args,
        **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.label = label
        self._value = value

    def compose(self) -> ComposeResult:
        """Compose the status item."""
        yield Static(f"{self.label}: ", classes="status-label")
        yield Static(self._value, classes="status-value", id=f"value-{self.id or 'default'}")

    def update_value(self, value: str, style: Optional[str] = None) -> None:
        """Update the displayed value."""
        self._value = value
        value_widget = self.query_one(f"#value-{self.id or 'default'}", Static)
        if style:
            value_widget.update(f"[{style}]{value}[/{style}]")
        else:
            value_widget.update(value)


class ToolsmithStatusBar(Widget):
    """
    Status bar widget for the Security Toolsmith application.

    Displays:
    - Current status (ready, running, error, etc.)
    - Active tool name
    - Operation duration
    - System metrics
    """

    DEFAULT_CSS = """
    ToolsmithStatusBar {
        dock: bottom;
        height: 3;
        background: $primary-darken-2;
        padding: 0 2;
        border-top: solid $primary;
    }

    ToolsmithStatusBar #status-content {
        layout: horizontal;
        width: 100%;
        height: 100%;
        align: center middle;
    }

    ToolsmithStatusBar .status-section {
        width: auto;
        height: 1;
        padding: 0 2;
    }

    ToolsmithStatusBar #status-indicator {
        width: auto;
        padding: 0 1;
    }

    ToolsmithStatusBar #status-indicator.--ready {
        color: $success;
    }

    ToolsmithStatusBar #status-indicator.--running {
        color: $warning;
    }

    ToolsmithStatusBar #status-indicator.--complete {
        color: $success;
    }

    ToolsmithStatusBar #status-indicator.--error {
        color: $error;
    }

    ToolsmithStatusBar #status-indicator.--cancelled {
        color: $text-muted;
    }

    ToolsmithStatusBar #active-tool {
        color: $primary-lighten-2;
        text-style: bold;
    }

    ToolsmithStatusBar #duration {
        color: $text-muted;
    }

    ToolsmithStatusBar #clock {
        dock: right;
        width: auto;
        padding: 0 1;
        color: $text;
    }

    ToolsmithStatusBar .separator {
        width: 1;
        color: $primary;
    }
    """

    # Status indicators with Unicode symbols
    STATUS_ICONS = {
        "ready": "[green]●[/green] READY",
        "running": "[yellow]◐[/yellow] RUNNING",
        "complete": "[green]✓[/green] COMPLETE",
        "error": "[red]✗[/red] ERROR",
        "cancelled": "[dim]○[/dim] CANCELLED",
        "warning": "[yellow]⚠[/yellow] WARNING",
    }

    # Reactive attributes
    status: reactive[StatusType] = reactive("ready")
    active_tool: reactive[Optional[str]] = reactive(None)
    operation_count: reactive[int] = reactive(0)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._start_time: Optional[datetime] = None
        self._operations: List[ActiveOperation] = []
        self._timer: Optional[Timer] = None

    def compose(self) -> ComposeResult:
        """Compose the status bar layout."""
        with Horizontal(id="status-content"):
            yield Static(self.STATUS_ICONS["ready"], id="status-indicator", classes="--ready")
            yield Static("|", classes="separator")
            yield Static("Tool: None", id="active-tool", classes="status-section")
            yield Static("|", classes="separator")
            yield Static("Duration: --:--", id="duration", classes="status-section")
            yield Static("|", classes="separator")
            yield Static("Ops: 0", id="op-count", classes="status-section")
            yield Static(datetime.now().strftime("%H:%M:%S"), id="clock")

    def on_mount(self) -> None:
        """Start the clock timer when mounted."""
        self._timer = self.set_interval(1, self._update_clock)

    def _update_clock(self) -> None:
        """Update the clock display."""
        clock = self.query_one("#clock", Static)
        clock.update(datetime.now().strftime("%H:%M:%S"))

        # Update duration if an operation is running
        if self._start_time and self.status == "running":
            self._update_duration()

    def _update_duration(self) -> None:
        """Update the duration display."""
        if self._start_time is None:
            return

        duration = datetime.now() - self._start_time
        minutes = int(duration.total_seconds() // 60)
        seconds = int(duration.total_seconds() % 60)

        duration_widget = self.query_one("#duration", Static)
        duration_widget.update(f"Duration: {minutes:02d}:{seconds:02d}")

    def update_status(
        self,
        status: StatusType,
        tool: Optional[str] = None
    ) -> None:
        """
        Update the status bar.

        Args:
            status: New status
            tool: Optional tool name
        """
        self.status = status

        # Update status indicator
        indicator = self.query_one("#status-indicator", Static)
        indicator.update(self.STATUS_ICONS.get(status, self.STATUS_ICONS["ready"]))

        # Update CSS class for styling
        for cls in ["--ready", "--running", "--complete", "--error", "--cancelled"]:
            indicator.remove_class(cls)
        indicator.add_class(f"--{status}")

        # Update active tool
        if tool is not None:
            self.active_tool = tool
            tool_widget = self.query_one("#active-tool", Static)
            tool_widget.update(f"Tool: {tool}")
        elif status == "ready":
            self.active_tool = None
            tool_widget = self.query_one("#active-tool", Static)
            tool_widget.update("Tool: None")

        # Handle timing
        if status == "running":
            self._start_time = datetime.now()
            self.operation_count += 1
            self._update_op_count()
        elif status in ("complete", "error", "cancelled"):
            self._update_duration()

    def _update_op_count(self) -> None:
        """Update the operation count display."""
        op_widget = self.query_one("#op-count", Static)
        op_widget.update(f"Ops: {self.operation_count}")

    def watch_status(self, status: StatusType) -> None:
        """React to status changes."""
        pass  # Handled in update_status

    def get_active_operation(self) -> Optional[ActiveOperation]:
        """Get the currently active operation."""
        if self.status == "running" and self.active_tool and self._start_time:
            return ActiveOperation(
                name=self.active_tool,
                start_time=self._start_time,
                status=self.status
            )
        return None

    def reset(self) -> None:
        """Reset the status bar to initial state."""
        self.update_status("ready")
        self._start_time = None

        duration_widget = self.query_one("#duration", Static)
        duration_widget.update("Duration: --:--")
