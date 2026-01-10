"""
Security Toolsmith TUI - Main Application

The main Textual application for the security toolsmith TUI.
Integrates real security tool execution via subprocess with streaming output.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Optional, List, Dict, Any, Union
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

# Import tool discovery and execution
from .utils.tool_discovery import (
    DiscoveredTool,
    ToolRegistry,
    get_registry,
)
from .utils.tool_executor import (
    ToolExecutor,
    ExecutionConfig,
    ExecutionResult,
    ExecutionStatus,
    get_executor,
)


@dataclass
class SecurityTool:
    """
    Represents a security tool available in the application.

    This class adapts DiscoveredTool for compatibility with existing widgets.
    """

    name: str
    description: str
    command: str
    category: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    is_running: bool = False
    # Reference to the discovered tool for execution
    _discovered_tool: Optional[DiscoveredTool] = field(default=None, repr=False)

    def __hash__(self) -> int:
        return hash(self.name)

    @classmethod
    def from_discovered(cls, discovered: DiscoveredTool) -> "SecurityTool":
        """Create a SecurityTool from a DiscoveredTool."""
        # Convert parameters to the format expected by ToolConfigScreen
        parameters = []
        for param in discovered.parameters:
            param_dict = {
                "name": param.name,
                "type": param.param_type,
                "required": param.required,
                "description": param.description,
            }
            if param.default is not None:
                param_dict["default"] = str(param.default)
            if param.choices:
                param_dict["choices"] = param.choices
            parameters.append(param_dict)

        return cls(
            name=discovered.display_name,
            description=discovered.description,
            command=str(discovered.tool_path),
            category=discovered.category,
            parameters=parameters,
            _discovered_tool=discovered,
        )


def discover_tools() -> List[SecurityTool]:
    """
    Discover all available security tools from the tools directory.

    Returns:
        List of SecurityTool instances
    """
    registry = get_registry()
    registry.discover()

    tools = []
    for discovered in registry.tools:
        tool = SecurityTool.from_discovered(discovered)
        tools.append(tool)

    return tools


# Try to discover tools, fall back to empty list if discovery fails
try:
    DEFAULT_TOOLS: List[SecurityTool] = discover_tools()
except Exception as e:
    print(f"Warning: Tool discovery failed: {e}")
    DEFAULT_TOOLS = []


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
        self._current_tool: Optional[SecurityTool] = None
        self._executor = get_executor()

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

        # Report discovered tools
        if DEFAULT_TOOLS:
            self.log_message(
                f"Discovered {len(DEFAULT_TOOLS)} security tools",
                level="success"
            )
            categories = set(t.category for t in DEFAULT_TOOLS)
            self.log_message(
                f"Categories: {', '.join(sorted(categories))}",
                level="debug"
            )
        else:
            self.log_message(
                "No tools discovered - check tools directory",
                level="warning"
            )

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
        self.log_message("Press 'D' for Docker screen, 'N' for Network screen", level="info")
        self.log_message("Press 'Escape' to cancel a running tool", level="info")

    def action_refresh(self) -> None:
        """Refresh the display."""
        self.log_message("Refreshing display...", level="info")

    def action_clear_output(self) -> None:
        """Clear the output log."""
        output_viewer = self.query_one("#output-viewer", OutputViewer)
        output_viewer.clear()
        self.log_message("Output cleared", level="info")

    async def action_cancel_operation(self) -> None:
        """Cancel the current operation."""
        if self._current_tool and self._current_tool._discovered_tool:
            tool_name = self._current_tool._discovered_tool.name
            cancelled = await self._executor.cancel(tool_name)
            if cancelled:
                self.log_message(
                    f"Cancelled execution of {self._current_tool.name}",
                    level="warning"
                )
        else:
            self.log_message("No operation to cancel", level="info")
        self.update_status("cancelled")
        self._current_tool = None

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
        self._current_tool = tool
        self.log_message(f"Running {tool.name}...", level="info")
        self.update_status("running", tool.name)

        # Log parameters (sanitized)
        for key, value in params.items():
            if value:
                # Don't log sensitive parameter values in full
                display_value = value if len(value) < 50 else f"{value[:47]}..."
                self.log_message(f"  {key}: {display_value}", level="debug")

        # Execute real tool
        if tool._discovered_tool:
            await self._execute_real_tool(tool, params)
        else:
            # Fallback for tools without discovered metadata
            self.log_message(
                f"Warning: {tool.name} has no executable - simulating",
                level="warning"
            )
            await self._simulate_tool_execution(tool, params)

    async def _execute_real_tool(
        self,
        tool: SecurityTool,
        params: Dict[str, str]
    ) -> None:
        """Execute a real tool via subprocess with streaming output."""
        discovered = tool._discovered_tool
        if not discovered:
            return

        self.log_message(f"Executing: {discovered.tool_path}", level="debug")

        # Check for plan mode
        plan_mode = params.pop("plan", "false").lower() in ("true", "yes", "1")
        if plan_mode:
            self.log_message("[PLAN MODE] Showing execution plan only", level="warning")

        config = ExecutionConfig(
            plan_mode=plan_mode,
            verbose=True,
        )

        try:
            # Stream output in real-time
            async for stream_type, line in self._executor.execute_streaming(
                discovered,
                params,
                config
            ):
                # Determine log level based on content and stream type
                if stream_type == "stderr":
                    level = "error"
                elif stream_type == "status":
                    level = "info"
                elif stream_type == "error":
                    level = "error"
                else:
                    # Parse stdout for visual cues
                    level = self._determine_log_level(line)

                self.log_message(line, level=level)

            # Execution complete
            self.update_status("complete", tool.name)
            self.log_message(f"=== {tool.name} Execution Complete ===", level="success")

            # Update attack visualizer with execution data
            self._update_visualizer(tool, params)

        except Exception as e:
            self.log_message(f"Execution error: {str(e)}", level="error")
            self.update_status("error", tool.name)

        finally:
            self._current_tool = None

    def _determine_log_level(self, line: str) -> str:
        """Determine appropriate log level based on line content."""
        line_lower = line.lower()

        # Error indicators
        if any(x in line_lower for x in ["error", "fail", "[!]", "exception"]):
            return "error"

        # Warning indicators
        if any(x in line_lower for x in ["warning", "warn", "[w]", "caution"]):
            return "warning"

        # Success indicators
        if any(x in line_lower for x in [
            "[+]", "success", "found", "open", "alive",
            "completed", "===", "discovered"
        ]):
            return "success"

        # Debug/info indicators
        if any(x in line_lower for x in ["[*]", "[i]", "info", "scanning", "checking"]):
            return "info"

        # Default
        return "info"

    def _update_visualizer(self, tool: SecurityTool, params: Dict[str, str]) -> None:
        """Update attack visualizer with tool execution data."""
        try:
            visualizer = self.query_one("#attack-visualizer", AttackVisualizer)

            # Determine target from parameters
            target = (
                params.get("target") or
                params.get("targets") or
                params.get("domain") or
                params.get("host") or
                params.get("filename") or
                "unknown"
            )

            # Determine severity based on tool category
            category_severity = {
                "Reconnaissance": "low",
                "Web Testing": "medium",
                "Credential Testing": "medium",
                "Network Services": "medium",
                "Evasion/Payload": "high",
                "Exploitation": "high",
            }
            severity = category_severity.get(tool.category, "medium")

            visualizer.add_attack_event(
                source="Toolsmith",
                target=target,
                attack_type=tool.name,
                severity=severity
            )
        except Exception:
            pass  # Visualizer update is non-critical

    async def _simulate_tool_execution(
        self,
        tool: SecurityTool,
        params: Dict[str, str]
    ) -> None:
        """Fallback simulation for tools without real executables."""
        self.log_message("=== Simulated Execution ===", level="warning")

        await asyncio.sleep(1)

        self.log_message(f"Tool: {tool.name}", level="info")
        self.log_message("Parameters received:", level="info")

        for key, value in params.items():
            self.log_message(f"  {key}: {value}", level="info")

        await asyncio.sleep(0.5)

        self.log_message(
            "Note: This tool does not have a real executable configured.",
            level="warning"
        )
        self.log_message(
            "Please ensure the tool exists in the tools directory.",
            level="warning"
        )

        self.update_status("complete", tool.name)
        self._current_tool = None


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
