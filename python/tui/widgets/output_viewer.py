"""
Output Viewer Widget

A scrollable log viewer that displays tool output with syntax highlighting
and severity-based coloring.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional, Literal
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import ScrollableContainer
from textual.widgets import Static, RichLog, Log
from textual.widget import Widget
from textual.reactive import reactive
from textual.message import Message
from rich.text import Text
from rich.console import RenderableType


LogLevel = Literal["debug", "info", "success", "warning", "error"]


@dataclass
class LogEntry:
    """A single log entry."""

    timestamp: datetime
    message: str
    level: LogLevel

    def to_rich(self) -> Text:
        """Convert to Rich Text for rendering."""
        # Color mapping for log levels
        colors = {
            "debug": "dim",
            "info": "white",
            "success": "green",
            "warning": "yellow",
            "error": "red bold",
        }

        # Level prefixes
        prefixes = {
            "debug": "[DBG]",
            "info": "[INF]",
            "success": "[OK ]",
            "warning": "[WRN]",
            "error": "[ERR]",
        }

        color = colors.get(self.level, "white")
        prefix = prefixes.get(self.level, "[???]")
        time_str = self.timestamp.strftime("%H:%M:%S")

        text = Text()
        text.append(f"{time_str} ", style="dim")
        text.append(f"{prefix} ", style=color)
        text.append(self.message, style=color if self.level in ("error", "warning", "success") else "white")

        return text


class OutputViewer(Widget):
    """
    Output viewer widget for displaying tool execution logs.

    Features:
    - Scrollable log display
    - Color-coded log levels
    - Timestamp for each entry
    - Auto-scroll to latest
    - Search functionality (planned)
    - Export capabilities (planned)
    """

    DEFAULT_CSS = """
    OutputViewer {
        height: 100%;
        background: $surface-darken-2;
        padding: 0;
    }

    OutputViewer #output-log {
        height: 100%;
        scrollbar-background: $surface;
        scrollbar-color: $primary;
        background: $surface-darken-2;
        padding: 1;
    }

    OutputViewer #output-header {
        dock: top;
        height: 1;
        background: $surface-darken-1;
        padding: 0 1;
        border-bottom: solid $secondary;
    }

    OutputViewer #output-footer {
        dock: bottom;
        height: 1;
        background: $surface-darken-1;
        padding: 0 1;
        border-top: solid $secondary;
        color: $text-muted;
    }
    """

    class LogAdded(Message):
        """Message sent when a new log entry is added."""

        def __init__(self, entry: LogEntry) -> None:
            self.entry = entry
            super().__init__()

    # Reactive attributes
    auto_scroll: reactive[bool] = reactive(True)
    log_count: reactive[int] = reactive(0)
    filter_level: reactive[Optional[LogLevel]] = reactive(None)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._entries: List[LogEntry] = []

    def compose(self) -> ComposeResult:
        """Compose the output viewer layout."""
        yield Static("Output Log", id="output-header")
        yield RichLog(
            id="output-log",
            highlight=True,
            markup=True,
            auto_scroll=True,
            max_lines=10000,
        )
        yield Static("0 entries | Auto-scroll: ON", id="output-footer")

    def log(
        self,
        message: str,
        level: LogLevel = "info",
        timestamp: Optional[datetime] = None
    ) -> None:
        """
        Add a log entry.

        Args:
            message: The log message
            level: Log level (debug, info, success, warning, error)
            timestamp: Optional timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()

        entry = LogEntry(timestamp=timestamp, message=message, level=level)
        self._entries.append(entry)
        self.log_count = len(self._entries)

        # Check filter
        if self.filter_level is not None and entry.level != self.filter_level:
            return

        # Add to the Rich log widget
        log_widget = self.query_one("#output-log", RichLog)
        log_widget.write(entry.to_rich())

        # Update footer
        self._update_footer()

        # Post message
        self.post_message(self.LogAdded(entry))

    def clear(self) -> None:
        """Clear all log entries."""
        self._entries.clear()
        self.log_count = 0

        log_widget = self.query_one("#output-log", RichLog)
        log_widget.clear()

        self._update_footer()

    def _update_footer(self) -> None:
        """Update the footer with current stats."""
        footer = self.query_one("#output-footer", Static)
        scroll_status = "ON" if self.auto_scroll else "OFF"
        footer.update(f"{self.log_count} entries | Auto-scroll: {scroll_status}")

    def watch_auto_scroll(self, auto_scroll: bool) -> None:
        """React to auto-scroll changes."""
        log_widget = self.query_one("#output-log", RichLog)
        log_widget.auto_scroll = auto_scroll
        self._update_footer()

    def watch_filter_level(self, level: Optional[LogLevel]) -> None:
        """React to filter level changes."""
        # Refresh display with filter
        log_widget = self.query_one("#output-log", RichLog)
        log_widget.clear()

        for entry in self._entries:
            if level is None or entry.level == level:
                log_widget.write(entry.to_rich())

    def toggle_auto_scroll(self) -> None:
        """Toggle auto-scroll."""
        self.auto_scroll = not self.auto_scroll

    def set_filter(self, level: Optional[LogLevel]) -> None:
        """Set the log level filter."""
        self.filter_level = level

    def get_entries(
        self,
        level: Optional[LogLevel] = None,
        limit: Optional[int] = None
    ) -> List[LogEntry]:
        """
        Get log entries with optional filtering.

        Args:
            level: Optional level filter
            limit: Maximum number of entries to return

        Returns:
            List of log entries
        """
        entries = self._entries
        if level is not None:
            entries = [e for e in entries if e.level == level]
        if limit is not None:
            entries = entries[-limit:]
        return entries

    def export_text(self) -> str:
        """Export log entries as plain text."""
        lines = []
        for entry in self._entries:
            time_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"[{time_str}] [{entry.level.upper()}] {entry.message}")
        return "\n".join(lines)
