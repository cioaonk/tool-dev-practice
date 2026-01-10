"""
Security Toolsmith TUI - Main Application

The main Textual application for the security toolsmith TUI.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Header,
    Footer,
    Static,
    Button,
    Label,
    ListView,
    ListItem,
    Log,
    LoadingIndicator,
    DataTable,
    Input,
    ProgressBar,
)
from textual.screen import Screen, ModalScreen
from textual.reactive import reactive
from textual.message import Message
from textual.worker import Worker, WorkerState

# Import local components
from .widgets.tool_panel import ToolPanel
from .widgets.output_viewer import OutputViewer
from .widgets.status_bar import ToolsmithStatusBar
from .visualizers.attack_visualizer import AttackVisualizer
from .screens.tool_config import ToolConfigScreen
from .screens.docker_screen import DockerScreen
from .screens.network_screen import NetworkScreen


@dataclass
class SecurityTool:
    """Represents a security tool available in the application."""

    name: str
    description: str
    command: str
    category: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    is_running: bool = False

    def __hash__(self) -> int:
        return hash(self.name)


# Default tools available in the application
DEFAULT_TOOLS: List[SecurityTool] = [
    SecurityTool(
        name="File Info",
        description="Get file information including hash and type",
        command="file_info.py",
        category="Recon",
        parameters=[
            {"name": "filename", "type": "str", "required": True, "description": "File to analyze"}
        ]
    ),
    SecurityTool(
        name="Port Scanner",
        description="Scan target for open ports",
        command="port_scanner.py",
        category="Recon",
        parameters=[
            {"name": "target", "type": "str", "required": True, "description": "Target IP or hostname"},
            {"name": "ports", "type": "str", "required": False, "description": "Port range (e.g., 1-1000)"}
        ]
    ),
    SecurityTool(
        name="Network Mapper",
        description="Map network topology and discover hosts",
        command="network_mapper.py",
        category="Recon",
        parameters=[
            {"name": "subnet", "type": "str", "required": True, "description": "Subnet to scan (CIDR)"}
        ]
    ),
    SecurityTool(
        name="Vuln Scanner",
        description="Scan for known vulnerabilities",
        command="vuln_scanner.py",
        category="Vulnerability",
        parameters=[
            {"name": "target", "type": "str", "required": True, "description": "Target to scan"},
            {"name": "profile", "type": "str", "required": False, "description": "Scan profile"}
        ]
    ),
    SecurityTool(
        name="Password Auditor",
        description="Audit password strength and policies",
        command="password_auditor.py",
        category="Audit",
        parameters=[
            {"name": "hash_file", "type": "str", "required": True, "description": "File containing hashes"}
        ]
    ),
    SecurityTool(
        name="Log Analyzer",
        description="Analyze logs for suspicious patterns",
        command="log_analyzer.py",
        category="Analysis",
        parameters=[
            {"name": "log_path", "type": "str", "required": True, "description": "Path to log file"},
            {"name": "pattern", "type": "str", "required": False, "description": "Search pattern"}
        ]
    ),
    SecurityTool(
        name="Traffic Analyzer",
        description="Analyze network traffic captures",
        command="traffic_analyzer.py",
        category="Analysis",
        parameters=[
            {"name": "pcap_file", "type": "str", "required": True, "description": "PCAP file to analyze"}
        ]
    ),
    SecurityTool(
        name="Attack Simulator",
        description="Simulate attack patterns for testing",
        command="attack_simulator.py",
        category="Simulation",
        parameters=[
            {"name": "scenario", "type": "str", "required": True, "description": "Attack scenario name"},
            {"name": "target", "type": "str", "required": True, "description": "Target system"}
        ]
    ),
]


class DashboardScreen(Screen):
    """Main dashboard screen for the application."""

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("h", "toggle_help", "Help", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("c", "clear_output", "Clear", show=True),
        Binding("D", "open_docker", "Docker", show=True),
        Binding("N", "open_network", "Network", show=True),
        Binding("escape", "cancel_operation", "Cancel", show=False),
    ]

    CSS_PATH = None  # We load CSS from the app

    def __init__(self) -> None:
        super().__init__()
        self.help_visible = False

    def compose(self) -> ComposeResult:
        """Compose the dashboard layout."""
        yield Header(show_clock=True)

        with Container(id="dashboard-container"):
            # Left sidebar - Tool Panel
            yield ToolPanel(id="tool-panel", tools=DEFAULT_TOOLS)

            # Main content area
            with Vertical(id="main-content"):
                with Container(id="content-header"):
                    yield Label("Tool Output", id="content-header-title")
                yield OutputViewer(id="output-viewer")

            # Attack visualizer panel
            yield AttackVisualizer(id="attack-visualizer")

        yield ToolsmithStatusBar(id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Handle mount event."""
        self.log_message("Security Toolsmith TUI initialized", level="info")
        self.log_message("Select a tool from the left panel to begin", level="info")
        self.update_status("ready")

    def log_message(self, message: str, level: str = "info") -> None:
        """Log a message to the output viewer."""
        output_viewer = self.query_one("#output-viewer", OutputViewer)
        output_viewer.log(message, level=level)

    def update_status(self, status: str, tool: Optional[str] = None) -> None:
        """Update the status bar."""
        status_bar = self.query_one("#status-bar", ToolsmithStatusBar)
        status_bar.update_status(status, tool)

    def action_toggle_help(self) -> None:
        """Toggle help panel visibility."""
        self.log_message("Help: Press 'q' to quit, 'r' to refresh, 'c' to clear output", level="info")

    def action_refresh(self) -> None:
        """Refresh the display."""
        self.log_message("Refreshing display...", level="info")

    def action_clear_output(self) -> None:
        """Clear the output log."""
        output_viewer = self.query_one("#output-viewer", OutputViewer)
        output_viewer.clear()
        self.log_message("Output cleared", level="info")

    def action_cancel_operation(self) -> None:
        """Cancel the current operation."""
        self.log_message("Operation cancelled", level="warning")
        self.update_status("cancelled")

    def action_open_docker(self) -> None:
        """Open the Docker management screen."""
        self.log_message("Opening Docker management screen...", level="info")
        self.app.push_screen(DockerScreen())

    def action_open_network(self) -> None:
        """Open the CORE Network management screen."""
        self.log_message("Opening CORE Network management screen...", level="info")
        self.app.push_screen(NetworkScreen())

    async def on_tool_panel_tool_selected(self, message: ToolPanel.ToolSelected) -> None:
        """Handle tool selection from the tool panel."""
        tool = message.tool
        self.log_message(f"Selected tool: {tool.name}", level="info")
        self.log_message(f"  Category: {tool.category}", level="debug")
        self.log_message(f"  Description: {tool.description}", level="debug")

        # Show tool configuration screen
        config_screen = ToolConfigScreen(tool)
        result = await self.app.push_screen_wait(config_screen)

        if result:
            # User confirmed - run the tool
            await self.run_tool(tool, result)

    async def run_tool(self, tool: SecurityTool, params: Dict[str, str]) -> None:
        """Run a tool with the given parameters."""
        self.log_message(f"Running {tool.name}...", level="info")
        self.update_status("running", tool.name)

        # Log parameters (sanitized)
        for key, value in params.items():
            if value:
                self.log_message(f"  {key}: {value}", level="debug")

        # Simulate tool execution with async worker
        self.run_tool_async(tool, params)

    def run_tool_async(self, tool: SecurityTool, params: Dict[str, str]) -> None:
        """Run tool execution in a worker."""
        async def execute_tool() -> str:
            """Simulate tool execution."""
            # Simulate some processing time
            await asyncio.sleep(2)

            # Generate sample output based on tool
            output_lines = [
                f"=== {tool.name} Output ===",
                f"Timestamp: {datetime.now().isoformat()}",
                "",
            ]

            if tool.name == "File Info":
                filename = params.get("filename", "unknown")
                output_lines.extend([
                    f"Analyzing file: {filename}",
                    "---",
                    f"  File size: 1234 bytes",
                    f"  MD5: a1b2c3d4e5f6...",
                    f"  Type: ASCII text",
                ])
            elif tool.name == "Port Scanner":
                target = params.get("target", "unknown")
                output_lines.extend([
                    f"Scanning target: {target}",
                    "---",
                    "  Port 22: OPEN (SSH)",
                    "  Port 80: OPEN (HTTP)",
                    "  Port 443: OPEN (HTTPS)",
                    "  Port 3306: CLOSED",
                ])
            elif tool.name == "Network Mapper":
                subnet = params.get("subnet", "unknown")
                output_lines.extend([
                    f"Mapping subnet: {subnet}",
                    "---",
                    "  Host 192.168.1.1: Gateway (ACTIVE)",
                    "  Host 192.168.1.10: Workstation (ACTIVE)",
                    "  Host 192.168.1.20: Server (ACTIVE)",
                    "  Host 192.168.1.50: Unknown (INACTIVE)",
                ])
            else:
                output_lines.extend([
                    f"Tool execution simulated",
                    "Parameters received:",
                ])
                for key, value in params.items():
                    output_lines.append(f"  {key}: {value}")

            output_lines.append("")
            output_lines.append("=== Execution Complete ===")

            return "\n".join(output_lines)

        def on_complete(result: str) -> None:
            """Handle tool completion."""
            for line in result.split("\n"):
                if line.startswith("==="):
                    self.log_message(line, level="success")
                elif line.startswith("  Port") and "OPEN" in line:
                    self.log_message(line, level="warning")
                elif line.startswith("  Host") and "ACTIVE" in line:
                    self.log_message(line, level="success")
                else:
                    self.log_message(line, level="info")

            self.update_status("complete", tool.name)

            # Update attack visualizer with sample data
            visualizer = self.query_one("#attack-visualizer", AttackVisualizer)
            visualizer.add_attack_event(
                source="Toolsmith",
                target=params.get("target", params.get("filename", "unknown")),
                attack_type=tool.name,
                severity="medium"
            )

        # Use Textual's worker system
        self.app.call_later(lambda: asyncio.create_task(self._execute_and_callback(execute_tool, on_complete)))

    async def _execute_and_callback(self, coro_func, callback) -> None:
        """Execute coroutine and call callback with result."""
        try:
            result = await coro_func()
            callback(result)
        except Exception as e:
            self.log_message(f"Error: {str(e)}", level="error")
            self.update_status("error")


class ToolsmithApp(App):
    """Main Textual application for Security Toolsmith."""

    TITLE = "Security Toolsmith"
    SUB_TITLE = "Terminal Security Tool Suite"

    CSS_PATH = Path(__file__).parent / "styles" / "main.tcss"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode", show=True),
    ]

    # Reactive attributes
    dark_mode: reactive[bool] = reactive(True)
    active_tool: reactive[Optional[str]] = reactive(None)

    def __init__(self) -> None:
        super().__init__()
        self.tools = DEFAULT_TOOLS

    def on_mount(self) -> None:
        """Handle application mount."""
        self.push_screen(DashboardScreen())

    def action_toggle_dark(self) -> None:
        """Toggle dark mode."""
        self.dark = not self.dark

    def watch_dark_mode(self, dark_mode: bool) -> None:
        """React to dark mode changes."""
        self.dark = dark_mode


def main() -> None:
    """Entry point for the TUI application."""
    app = ToolsmithApp()
    app.run()


if __name__ == "__main__":
    main()
