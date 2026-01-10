"""
Network Screen for CORE Network Emulator Management

A screen for managing CORE network topologies, viewing network diagrams,
and interacting with network nodes.
"""

from __future__ import annotations

import asyncio
import subprocess
import re
import os
from pathlib import Path
from typing import TYPE_CHECKING, Optional, List, Dict, Any
from dataclasses import dataclass

from textual.app import ComposeResult
from textual.screen import Screen
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Header, Footer, Static, Button, Label, Input
from textual.reactive import reactive
from textual.message import Message
from textual.timer import Timer

from ..widgets.network_widgets import (
    NetworkTopology,
    NetworkNode,
    NetworkSession,
    TopologyList,
    NodeTable,
    TopologyVisualizer,
    NetworkControlPanel,
    NetworkLog,
    NodeActionPanel,
    TrafficMonitor,
)
from ..utils.network_targets import CoreTargetManager, NetworkTarget, NetworkSegment


class CoreNetworkManager:
    """
    Manager class for CORE network operations.

    Handles communication with CORE via subprocess calls to core-cli
    or direct API interaction.
    """

    def __init__(self, networks_dir: Path) -> None:
        self.networks_dir = networks_dir
        self._session_id: Optional[str] = None
        self._nodes: List[NetworkNode] = []

    @property
    def session_id(self) -> Optional[str]:
        """Get the current session ID."""
        return self._session_id

    @property
    def is_session_active(self) -> bool:
        """Check if a session is active."""
        return self._session_id is not None

    async def check_core_available(self) -> bool:
        """Check if CORE is available on the system."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "which", "core-cli",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            return proc.returncode == 0 and bool(stdout.strip())
        except Exception:
            return False

    async def get_sessions(self) -> List[NetworkSession]:
        """Get list of active CORE sessions."""
        sessions: List[NetworkSession] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "session", "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                # Parse session list output
                for line in output.strip().split("\n"):
                    if line.strip() and not line.startswith("Session"):
                        parts = line.split()
                        if len(parts) >= 2:
                            sessions.append(NetworkSession(
                                session_id=parts[0],
                                name=parts[1] if len(parts) > 1 else "Unknown",
                                state=parts[2] if len(parts) > 2 else "Unknown"
                            ))
        except FileNotFoundError:
            pass
        except Exception:
            pass

        return sessions

    async def start_network(self, topology: NetworkTopology) -> tuple[bool, str]:
        """
        Start a network from a topology file.

        Returns tuple of (success, message).
        """
        if not topology.path.exists():
            return False, f"Topology file not found: {topology.path}"

        try:
            # Try using core-cli to load the session
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "session", "open",
                "--file", str(topology.path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                # Try to extract session ID from output
                match = re.search(r'session\s*(\d+)', output, re.IGNORECASE)
                if match:
                    self._session_id = match.group(1)
                else:
                    # Assign a default session ID
                    self._session_id = "1"

                return True, f"Network started successfully (Session: {self._session_id})"
            else:
                error = stderr.decode() if stderr else "Unknown error"
                return False, f"Failed to start network: {error}"

        except FileNotFoundError:
            return False, "CORE CLI not found. Please install CORE network emulator."
        except Exception as e:
            return False, f"Error starting network: {str(e)}"

    async def stop_network(self) -> tuple[bool, str]:
        """
        Stop the current network session.

        Returns tuple of (success, message).
        """
        if not self._session_id:
            return False, "No active session to stop"

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "session", "delete",
                "--id", self._session_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                old_session = self._session_id
                self._session_id = None
                self._nodes.clear()
                return True, f"Session {old_session} stopped successfully"
            else:
                error = stderr.decode() if stderr else "Unknown error"
                return False, f"Failed to stop session: {error}"

        except FileNotFoundError:
            return False, "CORE CLI not found"
        except Exception as e:
            return False, f"Error stopping session: {str(e)}"

    async def get_nodes(self, session_id: Optional[str] = None) -> List[NetworkNode]:
        """Get nodes from the current or specified session."""
        sid = session_id or self._session_id
        if not sid:
            return []

        nodes: List[NetworkNode] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "list",
                "--id", sid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                # Parse node list output
                for line in output.strip().split("\n"):
                    if line.strip() and not line.startswith("Node"):
                        parts = line.split()
                        if len(parts) >= 2:
                            node = NetworkNode(
                                name=parts[1] if len(parts) > 1 else f"node{parts[0]}",
                                node_id=parts[0],
                                node_type=parts[2] if len(parts) > 2 else "host",
                                status="running"
                            )
                            nodes.append(node)

        except FileNotFoundError:
            pass
        except Exception:
            pass

        self._nodes = nodes
        return nodes

    async def parse_topology_nodes(self, topology: NetworkTopology) -> List[NetworkNode]:
        """Parse nodes directly from a topology .imn file."""
        nodes: List[NetworkNode] = []

        if not topology.path.exists():
            return nodes

        try:
            content = topology.path.read_text()

            # Find all node definitions
            node_pattern = re.compile(
                r'node\s+(n\d+)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}',
                re.MULTILINE | re.DOTALL
            )

            for match in node_pattern.finditer(content):
                node_id = match.group(1)
                node_content = match.group(2)

                # Extract hostname
                hostname_match = re.search(r'hostname\s+(\S+)', node_content)
                hostname = hostname_match.group(1) if hostname_match else node_id

                # Extract node type
                type_match = re.search(r'type\s+(\S+)', node_content)
                model_match = re.search(r'model\s+(\S+)', node_content)
                node_type = model_match.group(1) if model_match else (
                    type_match.group(1) if type_match else "host"
                )

                # Extract IP addresses
                ip_addresses: List[str] = []
                ip_pattern = re.compile(r'ip\s+address\s+(\d+\.\d+\.\d+\.\d+/?\d*)')
                for ip_match in ip_pattern.finditer(node_content):
                    ip_addr = ip_match.group(1).split("/")[0]  # Remove CIDR notation
                    ip_addresses.append(ip_addr)

                # Extract services
                services: List[str] = []
                services_match = re.search(r'services\s*\{([^}]+)\}', node_content)
                if services_match:
                    services = services_match.group(1).strip().split()

                node = NetworkNode(
                    name=hostname,
                    node_id=node_id,
                    ip_addresses=ip_addresses,
                    node_type=node_type,
                    status="stopped",
                    services=services
                )
                nodes.append(node)

        except Exception:
            pass

        return nodes

    async def open_terminal(self, node: NetworkNode) -> tuple[bool, str]:
        """Open a terminal session to a node."""
        if not self._session_id:
            return False, "No active session"

        try:
            # Use core-cli to open a terminal
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "terminal",
                "--id", self._session_id,
                "--node", node.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Don't wait for completion - terminal is interactive
            return True, f"Opening terminal to {node.name}"

        except FileNotFoundError:
            return False, "CORE CLI not found"
        except Exception as e:
            return False, f"Error opening terminal: {str(e)}"

    async def start_node(self, node: NetworkNode) -> tuple[bool, str]:
        """Start a specific node."""
        if not self._session_id:
            return False, "No active session"

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "start",
                "--id", self._session_id,
                "--node", node.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                return True, f"Node {node.name} started"
            else:
                return False, f"Failed to start node: {stderr.decode()}"

        except FileNotFoundError:
            return False, "CORE CLI not found"
        except Exception as e:
            return False, f"Error: {str(e)}"

    async def stop_node(self, node: NetworkNode) -> tuple[bool, str]:
        """Stop a specific node."""
        if not self._session_id:
            return False, "No active session"

        try:
            proc = await asyncio.create_subprocess_exec(
                "core-cli", "node", "stop",
                "--id", self._session_id,
                "--node", node.node_id,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                return True, f"Node {node.name} stopped"
            else:
                return False, f"Failed to stop node: {stderr.decode()}"

        except FileNotFoundError:
            return False, "CORE CLI not found"
        except Exception as e:
            return False, f"Error: {str(e)}"

    async def open_gui(self) -> tuple[bool, str]:
        """Open the CORE GUI application."""
        try:
            # Launch core-gui in background
            proc = await asyncio.create_subprocess_exec(
                "core-gui",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True
            )
            return True, "CORE GUI launched"

        except FileNotFoundError:
            return False, "CORE GUI not found. Please install CORE network emulator."
        except Exception as e:
            return False, f"Error launching GUI: {str(e)}"


# Import for tool selection - use lazy import to avoid circular dependency
from textual.screen import ModalScreen
from textual.widgets import OptionList
from textual.widgets.option_list import Option

if TYPE_CHECKING:
    from ..app import SecurityTool


def _get_default_tools():
    """Lazy import of DEFAULT_TOOLS to avoid circular import."""
    from ..app import DEFAULT_TOOLS
    return DEFAULT_TOOLS


def _get_tool_config_screen():
    """Lazy import of ToolConfigScreen to avoid circular import."""
    from ..screens.tool_config import ToolConfigScreen
    return ToolConfigScreen


class ToolSelectorModal(ModalScreen[Optional["SecurityTool"]]):
    """
    Modal screen for selecting a security tool to run against a network node.

    Filters to show only tools that accept a target parameter.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=True),
    ]

    DEFAULT_CSS = """
    ToolSelectorModal {
        align: center middle;
        background: $surface 60%;
    }

    ToolSelectorModal #selector-container {
        width: 60;
        height: auto;
        max-height: 80%;
        background: $surface;
        border: double $primary;
        padding: 1 2;
    }

    ToolSelectorModal #selector-title {
        text-style: bold;
        color: $primary;
        text-align: center;
        padding: 1 0;
        border-bottom: solid $secondary;
        margin-bottom: 1;
    }

    ToolSelectorModal #target-info {
        color: $success;
        text-align: center;
        padding: 0 1;
        border: round $success;
        margin-bottom: 1;
        height: auto;
    }

    ToolSelectorModal #tool-list {
        height: auto;
        max-height: 20;
        border: round $secondary;
        margin: 1 0;
    }

    ToolSelectorModal #scan-network-btn {
        margin-top: 1;
        width: 100%;
        background: $warning;
    }

    ToolSelectorModal #cancel-btn {
        margin-top: 1;
        width: 100%;
    }
    """

    # Tools that can target a specific IP
    TARGET_TOOLS = ["Port Scanner", "Vuln Scanner", "Attack Simulator"]
    # Tools that scan entire networks
    NETWORK_TOOLS = ["Network Mapper"]

    def __init__(
        self,
        node: NetworkNode,
        network_cidr: Optional[str] = None,
        *args,
        **kwargs
    ) -> None:
        """
        Initialize the tool selector.

        Args:
            node: The network node to run tools against
            network_cidr: Optional CIDR range for network-wide scans
        """
        super().__init__(*args, **kwargs)
        self.node = node
        self.network_cidr = network_cidr
        self._available_tools: List[SecurityTool] = []

    def compose(self) -> ComposeResult:
        """Compose the tool selector."""
        with Container(id="selector-container"):
            yield Static("[b]Select Tool to Run[/b]", id="selector-title")

            # Show target info
            ip_display = self.node.ip_addresses[0] if self.node.ip_addresses else "N/A"
            yield Static(
                f"[b]Target:[/b] {self.node.name} ({ip_display})",
                id="target-info"
            )

            # Filter tools that accept targets
            self._available_tools = [
                tool for tool in _get_default_tools()
                if tool.name in self.TARGET_TOOLS
            ]

            # Create option list
            yield OptionList(
                *[Option(f"{tool.name} - {tool.description}", id=tool.name)
                  for tool in self._available_tools],
                id="tool-list"
            )

            # Add network scan button if CIDR available
            if self.network_cidr:
                yield Button(
                    f"Scan Entire Network ({self.network_cidr})",
                    variant="warning",
                    id="scan-network-btn"
                )

            yield Button("Cancel", variant="error", id="cancel-btn")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        """Handle tool selection."""
        tool_name = event.option.id
        if tool_name:
            for tool in self._available_tools:
                if tool.name == tool_name:
                    self.dismiss(tool)
                    return

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "cancel-btn":
            self.dismiss(None)
        elif event.button.id == "scan-network-btn":
            # Find Network Mapper tool
            for tool in _get_default_tools():
                if tool.name == "Network Mapper":
                    self.dismiss(tool)
                    return

    def action_cancel(self) -> None:
        """Cancel selection."""
        self.dismiss(None)


class NetworkScreen(Screen):
    """
    Network management screen for CORE integration.

    Provides interface for:
    - Listing available network topologies
    - Starting/stopping networks
    - Viewing network topology visualizations
    - Managing individual nodes
    - Monitoring network traffic
    """

    BINDINGS = [
        Binding("q", "go_back", "Back", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("s", "start_network", "Start", show=True),
        Binding("x", "stop_network", "Stop", show=True),
        Binding("g", "open_gui", "GUI", show=True),
        Binding("t", "open_terminal", "Terminal", show=False),
        Binding("escape", "go_back", "Back", show=False),
    ]

    CSS = """
    NetworkScreen {
        background: $surface;
    }

    NetworkScreen #network-container {
        layout: grid;
        grid-size: 3 3;
        grid-columns: 1fr 2fr 1fr;
        grid-rows: 2fr 1fr 1fr;
        padding: 1;
        height: 100%;
    }

    NetworkScreen #topology-list {
        column-span: 1;
        row-span: 2;
    }

    NetworkScreen #topology-visualizer {
        column-span: 1;
        row-span: 1;
    }

    NetworkScreen #node-table {
        column-span: 1;
        row-span: 1;
    }

    NetworkScreen #control-panel {
        column-span: 1;
        row-span: 1;
    }

    NetworkScreen #network-log {
        column-span: 2;
        row-span: 1;
    }

    NetworkScreen #node-actions {
        column-span: 1;
        row-span: 1;
    }

    NetworkScreen #traffic-monitor {
        column-span: 1;
        row-span: 1;
    }
    """

    # Reactive attributes
    selected_topology: reactive[Optional[NetworkTopology]] = reactive(None)
    selected_node: reactive[Optional[NetworkNode]] = reactive(None)
    session_active: reactive[bool] = reactive(False)

    def __init__(self, networks_dir: Optional[Path] = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Default to networks directory relative to project root
        if networks_dir is None:
            # Navigate up from tui directory to find networks
            tui_dir = Path(__file__).parent.parent
            project_root = tui_dir.parent.parent
            networks_dir = project_root / "networks"

        self.networks_dir = networks_dir
        self.core_manager = CoreNetworkManager(networks_dir)
        self._refresh_timer: Optional[Timer] = None
        self._parsed_nodes: List[NetworkNode] = []

    def compose(self) -> ComposeResult:
        """Compose the network screen layout."""
        yield Header(show_clock=True)

        with Container(id="network-container"):
            yield TopologyList(self.networks_dir, id="topology-list")
            yield TopologyVisualizer(id="topology-visualizer")
            yield NetworkControlPanel(id="control-panel")
            yield NodeTable(id="node-table")
            yield NodeActionPanel(id="node-actions")
            yield TrafficMonitor(id="traffic-monitor")
            yield NetworkLog(id="network-log")

        yield Footer()

    def on_mount(self) -> None:
        """Handle screen mount."""
        self.log_message("Network screen initialized", level="info")
        self.log_message(f"Networks directory: {self.networks_dir}", level="debug")

        # Check if CORE is available
        self.check_core_availability()

    async def check_core_availability(self) -> None:
        """Check if CORE is available and log status."""
        available = await self.core_manager.check_core_available()
        if available:
            self.log_message("CORE network emulator detected", level="success")
        else:
            self.log_message(
                "CORE not found - some features may be unavailable",
                level="warning"
            )
            self.log_message(
                "Install CORE with: sudo apt-get install core-network",
                level="info"
            )

    def log_message(self, message: str, level: str = "info") -> None:
        """Log a message to the network log."""
        try:
            log_widget = self.query_one("#network-log", NetworkLog)
            log_widget.log(message, level=level)
        except Exception:
            pass

    # ----- Topology Selection Handling -----

    async def on_topology_list_topology_selected(
        self,
        message: TopologyList.TopologySelected
    ) -> None:
        """Handle topology selection from the list."""
        self.selected_topology = message.topology
        self.log_message(f"Selected topology: {message.topology.name}", level="info")

        # Parse nodes from the topology file
        self._parsed_nodes = await self.core_manager.parse_topology_nodes(
            message.topology
        )

        # Update the visualizer
        visualizer = self.query_one("#topology-visualizer", TopologyVisualizer)
        visualizer.render_topology(message.topology, self._parsed_nodes)

        # Update the node table
        node_table = self.query_one("#node-table", NodeTable)
        node_table.update_nodes(self._parsed_nodes)

        self.log_message(
            f"Loaded {len(self._parsed_nodes)} nodes from topology",
            level="success"
        )

    # ----- Node Selection Handling -----

    def on_node_table_node_selected(self, message: NodeTable.NodeSelected) -> None:
        """Handle node selection from the table."""
        self.selected_node = message.node

        # Update node action panel
        action_panel = self.query_one("#node-actions", NodeActionPanel)
        action_panel.set_selected_node(message.node)

        self.log_message(
            f"Selected node: {message.node.name} ({message.node.node_type})",
            level="info"
        )

    # ----- Network Control Panel Handling -----

    async def on_network_control_panel_start_network(
        self,
        message: NetworkControlPanel.StartNetwork
    ) -> None:
        """Handle start network request."""
        await self.action_start_network()

    async def on_network_control_panel_stop_network(
        self,
        message: NetworkControlPanel.StopNetwork
    ) -> None:
        """Handle stop network request."""
        await self.action_stop_network()

    async def on_network_control_panel_open_gui(
        self,
        message: NetworkControlPanel.OpenGUI
    ) -> None:
        """Handle open GUI request."""
        await self.action_open_gui()

    async def on_network_control_panel_refresh_status(
        self,
        message: NetworkControlPanel.RefreshStatus
    ) -> None:
        """Handle refresh status request."""
        await self.action_refresh()

    # ----- Node Action Panel Handling -----

    async def on_node_action_panel_open_terminal(
        self,
        message: NodeActionPanel.OpenTerminal
    ) -> None:
        """Handle open terminal request."""
        self.log_message(f"Opening terminal to {message.node.name}...", level="info")
        success, msg = await self.core_manager.open_terminal(message.node)
        level = "success" if success else "error"
        self.log_message(msg, level=level)

    async def on_node_action_panel_start_node(
        self,
        message: NodeActionPanel.StartNode
    ) -> None:
        """Handle start node request."""
        self.log_message(f"Starting node {message.node.name}...", level="info")
        success, msg = await self.core_manager.start_node(message.node)
        level = "success" if success else "error"
        self.log_message(msg, level=level)

        if success:
            # Update node status
            message.node.status = "running"
            await self._refresh_nodes()

    async def on_node_action_panel_stop_node(
        self,
        message: NodeActionPanel.StopNode
    ) -> None:
        """Handle stop node request."""
        self.log_message(f"Stopping node {message.node.name}...", level="info")
        success, msg = await self.core_manager.stop_node(message.node)
        level = "success" if success else "error"
        self.log_message(msg, level=level)

        if success:
            # Update node status
            message.node.status = "stopped"
            await self._refresh_nodes()

    async def on_node_action_panel_run_tool(
        self,
        message: NodeActionPanel.RunTool
    ) -> None:
        """Handle run tool request - show tool selector and run selected tool."""
        node = message.node

        if not node.ip_addresses:
            self.log_message(
                f"Node {node.name} has no IP address to target",
                level="error"
            )
            return

        target_ip = node.ip_addresses[0]

        # Determine network CIDR if available from the topology
        network_cidr: Optional[str] = None
        if self.selected_topology:
            target_manager = CoreTargetManager(self.networks_dir)
            segments = target_manager.get_network_ranges(self.selected_topology.path)
            # Find the segment containing this node's IP
            for segment in segments:
                if segment.contains(target_ip):
                    network_cidr = segment.cidr
                    break
            # If no match, use first available segment
            if not network_cidr and segments:
                network_cidr = segments[0].cidr

        self.log_message(
            f"Selecting tool for {node.name} ({target_ip})...",
            level="info"
        )

        # Show tool selector modal
        tool_selector = ToolSelectorModal(node, network_cidr=network_cidr)
        selected_tool = await self.app.push_screen_wait(tool_selector)

        if not selected_tool:
            self.log_message("Tool selection cancelled", level="info")
            return

        self.log_message(
            f"Selected tool: {selected_tool.name}",
            level="info"
        )

        # Prepare prefill values based on the tool
        prefill_values: Dict[str, str] = {}
        target_info = f"{node.name} ({target_ip})"

        if selected_tool.name == "Network Mapper":
            # Use the network CIDR for Network Mapper
            if network_cidr:
                prefill_values["subnet"] = network_cidr
                target_info = f"Network: {network_cidr}"
        elif selected_tool.name in ("Port Scanner", "Vuln Scanner"):
            prefill_values["target"] = target_ip
        elif selected_tool.name == "Attack Simulator":
            prefill_values["target"] = target_ip

        # Show tool configuration with pre-filled values
        ToolConfigScreen = _get_tool_config_screen()
        config_screen = ToolConfigScreen(
            tool=selected_tool,
            prefill_target=prefill_values,
            target_info=target_info
        )
        result = await self.app.push_screen_wait(config_screen)

        if result:
            # User confirmed - log the action (actual execution would happen in dashboard)
            self.log_message(
                f"Running {selected_tool.name} against {target_info}...",
                level="success"
            )
            for key, value in result.items():
                if value:
                    self.log_message(f"  {key}: {value}", level="debug")
            self.log_message(
                "Tool execution initiated. Check Dashboard for results.",
                level="info"
            )
        else:
            self.log_message("Tool configuration cancelled", level="info")

    # ----- Actions -----

    async def action_start_network(self) -> None:
        """Start the selected network topology."""
        if not self.selected_topology:
            self.log_message("No topology selected", level="warning")
            return

        self.log_message(
            f"Starting network: {self.selected_topology.name}...",
            level="info"
        )

        success, msg = await self.core_manager.start_network(self.selected_topology)
        level = "success" if success else "error"
        self.log_message(msg, level=level)

        if success:
            self.session_active = True

            # Update control panel
            control_panel = self.query_one("#control-panel", NetworkControlPanel)
            control_panel.update_session(
                self.core_manager.session_id,
                self.core_manager.is_session_active
            )

            # Refresh nodes
            await self._refresh_nodes()

            # Update node status to running
            for node in self._parsed_nodes:
                node.status = "running"

            node_table = self.query_one("#node-table", NodeTable)
            node_table.update_nodes(self._parsed_nodes)

    async def action_stop_network(self) -> None:
        """Stop the current network session."""
        if not self.core_manager.is_session_active:
            self.log_message("No active session to stop", level="warning")
            return

        self.log_message("Stopping network...", level="info")
        success, msg = await self.core_manager.stop_network()
        level = "success" if success else "error"
        self.log_message(msg, level=level)

        if success:
            self.session_active = False

            # Update control panel
            control_panel = self.query_one("#control-panel", NetworkControlPanel)
            control_panel.update_session(None, False)

            # Update node status to stopped
            for node in self._parsed_nodes:
                node.status = "stopped"

            node_table = self.query_one("#node-table", NodeTable)
            node_table.update_nodes(self._parsed_nodes)

            # Clear node selection
            action_panel = self.query_one("#node-actions", NodeActionPanel)
            action_panel.set_selected_node(None)

    async def action_open_gui(self) -> None:
        """Open the CORE GUI application."""
        self.log_message("Launching CORE GUI...", level="info")
        success, msg = await self.core_manager.open_gui()
        level = "success" if success else "error"
        self.log_message(msg, level=level)

    async def action_refresh(self) -> None:
        """Refresh network status and nodes."""
        self.log_message("Refreshing network status...", level="info")

        # Refresh topology list
        topology_list = self.query_one("#topology-list", TopologyList)
        topology_list.load_topologies()

        # Refresh nodes if a topology is selected
        if self.selected_topology:
            self._parsed_nodes = await self.core_manager.parse_topology_nodes(
                self.selected_topology
            )

            # If session is active, get live node status
            if self.core_manager.is_session_active:
                live_nodes = await self.core_manager.get_nodes()
                live_ids = {n.node_id for n in live_nodes}

                for node in self._parsed_nodes:
                    if node.node_id in live_ids:
                        node.status = "running"
                    else:
                        node.status = "stopped"

            node_table = self.query_one("#node-table", NodeTable)
            node_table.update_nodes(self._parsed_nodes)

        self.log_message("Refresh complete", level="success")

    async def action_open_terminal(self) -> None:
        """Open terminal to selected node."""
        if self.selected_node and self.session_active:
            success, msg = await self.core_manager.open_terminal(self.selected_node)
            level = "success" if success else "error"
            self.log_message(msg, level=level)
        else:
            self.log_message(
                "Select a running node to open terminal",
                level="warning"
            )

    def action_go_back(self) -> None:
        """Return to the previous screen."""
        self.app.pop_screen()

    async def _refresh_nodes(self) -> None:
        """Internal method to refresh node list."""
        if self.selected_topology:
            node_table = self.query_one("#node-table", NodeTable)
            node_table.update_nodes(self._parsed_nodes)

    # ----- Lifecycle -----

    def on_unmount(self) -> None:
        """Clean up when screen is unmounted."""
        if self._refresh_timer:
            self._refresh_timer.stop()
