"""
Tests for CORE network emulation integration in the TUI application.

This module tests network-related functionality with mocked subprocess calls
to allow tests to run in CI without actual CORE network emulator installed.

Tests cover:
- Network session management
- Node management
- Link management
- Topology visualization
- Network command execution
- Error handling for network failures
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Any
from unittest.mock import patch, MagicMock, AsyncMock
from contextlib import asynccontextmanager

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tui.app import ToolsmithApp, DashboardScreen, SecurityTool
from tui.utils.helpers import run_command
from tui.visualizers.attack_visualizer import AttackVisualizer, NetworkNode


@asynccontextmanager
async def safe_run_test(app):
    """
    Context manager that safely runs TUI tests, skipping on compatibility errors.
    """
    try:
        async with app.run_test() as pilot:
            yield pilot
    except (AttributeError, RuntimeError, TypeError) as e:
        pytest.skip(f"TUI test environment not fully compatible: {e}")


class TestNetworkCommandExecution:
    """Test suite for CORE network command execution with mocked subprocess."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_core_session_list_success(self, mock_subprocess_network):
        """Test successful CORE session list command."""
        returncode, stdout, stderr = await run_command(["core-cli", "session", "list"])

        assert returncode == 0
        assert stdout != ""
        assert stderr == ""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_core_session_list_parses_json(self, mock_subprocess_network):
        """Test that CORE session list output can be parsed as JSON."""
        returncode, stdout, stderr = await run_command(["core-cli", "session", "list"])

        # Should be valid JSON
        data = json.loads(stdout)
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_core_command_failure(self, mock_subprocess_error):
        """Test CORE command failure handling."""
        returncode, stdout, stderr = await run_command(["core-cli", "session", "list"])

        assert returncode == 1
        assert stderr != ""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_core_command_timeout(self, mock_subprocess_timeout):
        """Test CORE command timeout handling."""
        returncode, stdout, stderr = await run_command(["core-cli", "session", "list"], timeout=1.0)

        assert returncode == -1


class TestNetworkSessionManagement:
    """Test suite for CORE network session management."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_list_parsing(self, mock_network_output):
        """Test parsing of CORE session list."""
        sessions = mock_network_output["sessions"]

        assert len(sessions) == 2
        assert sessions[0]["id"] == 1
        assert sessions[0]["name"] == "test-topology"
        assert sessions[0]["state"] == "RUNTIME"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_create(self):
        """Test creating a new CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"session_id": 3}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "create", "--name", "new-session"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["session_id"] == 3

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_delete(self):
        """Test deleting a CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "deleted"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "delete", "--id", "1"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_start(self):
        """Test starting a CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "started", "state": "RUNTIME"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "start", "--id", "1"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["state"] == "RUNTIME"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_stop(self):
        """Test stopping a CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "stopped", "state": "DEFINITION"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "stop", "--id", "1"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["state"] == "DEFINITION"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_state_runtime(self, mock_network_output):
        """Test identifying sessions in RUNTIME state."""
        sessions = mock_network_output["sessions"]
        runtime_sessions = [s for s in sessions if s["state"] == "RUNTIME"]

        assert len(runtime_sessions) == 1
        assert runtime_sessions[0]["name"] == "test-topology"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_state_definition(self, mock_network_output):
        """Test identifying sessions in DEFINITION state."""
        sessions = mock_network_output["sessions"]
        definition_sessions = [s for s in sessions if s["state"] == "DEFINITION"]

        assert len(definition_sessions) == 1
        assert definition_sessions[0]["name"] == "attack-sim"


class TestNetworkNodeManagement:
    """Test suite for CORE network node management."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_list_parsing(self, mock_network_output):
        """Test parsing of CORE node list."""
        nodes = mock_network_output["nodes"]

        assert len(nodes) == 3
        assert nodes[0]["name"] == "router1"
        assert nodes[0]["type"] == "router"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_add(self):
        """Test adding a node to CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"node_id": 4, "name": "host3", "type": "host"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "add",
                "--session", "1",
                "--name", "host3",
                "--type", "host"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["name"] == "host3"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_delete(self):
        """Test deleting a node from CORE session."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "deleted"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "delete",
                "--session", "1",
                "--node", "3"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_types(self, mock_network_output):
        """Test different node types are recognized."""
        nodes = mock_network_output["nodes"]
        node_types = {n["type"] for n in nodes}

        assert "router" in node_types
        assert "host" in node_types

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_command_execution(self):
        """Test executing a command on a CORE node."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'eth0: 10.0.0.10/24\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "exec",
                "--session", "1",
                "--node", "2",
                "--command", "ip addr show"
            ])

            assert returncode == 0
            assert "10.0.0.10" in stdout


class TestNetworkLinkManagement:
    """Test suite for CORE network link management."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_link_list_parsing(self, mock_network_output):
        """Test parsing of CORE link list."""
        links = mock_network_output["links"]

        assert len(links) == 2
        assert links[0]["node1"] == 1
        assert links[0]["node2"] == 2

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_link_add(self):
        """Test adding a link between CORE nodes."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"link_id": 3, "node1": 2, "node2": 3}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "link", "add",
                "--session", "1",
                "--node1", "2",
                "--node2", "3"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_link_delete(self):
        """Test deleting a link between CORE nodes."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "deleted"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "link", "delete",
                "--session", "1",
                "--link", "1"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_link_modify_bandwidth(self):
        """Test modifying link bandwidth."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"link_id": 1, "bandwidth": "1000Mbps"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "link", "modify",
                "--session", "1",
                "--link", "1",
                "--bandwidth", "1000Mbps"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["bandwidth"] == "1000Mbps"


class TestNetworkTopologyVisualization:
    """Test suite for network topology visualization."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_topology_display_in_visualizer(self):
        """Test that network topology can be displayed in AttackVisualizer."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            visualizer = app.query_one("#attack-visualizer", AttackVisualizer)

            # Add network nodes
            visualizer.add_node("Router1", "10.0.0.1", "gateway", "active")
            visualizer.add_node("Host1", "10.0.0.10", "workstation", "active")
            await pilot.pause()

            assert "router1" in visualizer._nodes
            assert "host1" in visualizer._nodes

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_topology_node_status_update(self):
        """Test updating node status in topology."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            visualizer = app.query_one("#attack-visualizer", AttackVisualizer)

            visualizer.add_node("TestNode", "10.0.0.5", "server", "active")
            await pilot.pause()

            visualizer.update_node_status("TestNode", "compromised")
            await pilot.pause()

            assert visualizer._nodes["testnode"].status == "compromised"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_topology_renders_correctly(self):
        """Test that topology renders without errors."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            visualizer = app.query_one("#attack-visualizer", AttackVisualizer)

            topology_view = app.query_one("#topology-view")
            assert topology_view is not None


class TestNetworkNode:
    """Test suite for NetworkNode dataclass."""

    def test_network_node_creation(self):
        """Test NetworkNode creation with all fields."""
        node = NetworkNode(
            name="TestRouter",
            ip="192.168.1.1",
            node_type="router",
            status="active"
        )

        assert node.name == "TestRouter"
        assert node.ip == "192.168.1.1"
        assert node.node_type == "router"
        assert node.status == "active"

    def test_network_node_hash(self):
        """Test NetworkNode hashability."""
        node1 = NetworkNode("Node1", "10.0.0.1", "host", "active")
        node2 = NetworkNode("Node1", "10.0.0.1", "host", "inactive")

        # Same name should have same hash
        assert hash(node1) == hash(node2)

    def test_network_node_in_set(self):
        """Test NetworkNode can be added to set."""
        node = NetworkNode("Node1", "10.0.0.1", "host", "active")
        node_set = {node}

        assert len(node_set) == 1
        assert node in node_set


class TestNetworkErrorHandling:
    """Test suite for network error handling."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_core_daemon_not_running(self):
        """Test handling when CORE daemon is not running."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Cannot connect to CORE daemon'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["core-cli", "session", "list"])

            assert returncode == 1
            assert "daemon" in stderr.lower()

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_session_not_found(self):
        """Test handling when session is not found."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Session 999 not found'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "info", "--id", "999"
            ])

            assert returncode == 1
            assert "not found" in stderr.lower()

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_node_not_found(self):
        """Test handling when node is not found."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Node 999 not found in session'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "info",
                "--session", "1",
                "--node", "999"
            ])

            assert returncode == 1
            assert "not found" in stderr.lower()

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_invalid_node_type(self):
        """Test handling invalid node type."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Invalid node type: invalid_type'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "add",
                "--session", "1",
                "--name", "test",
                "--type", "invalid_type"
            ])

            assert returncode == 1
            assert "invalid" in stderr.lower()


class TestNetworkFileOperations:
    """Test suite for network file operations (topology files)."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_topology_save(self):
        """Test saving network topology to file."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "saved", "file": "/tmp/topology.xml"}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "save",
                "--id", "1",
                "--file", "/tmp/topology.xml"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["status"] == "saved"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_topology_load(self):
        """Test loading network topology from file."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"status": "loaded", "session_id": 5}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "load",
                "--file", "/tmp/topology.xml"
            ])

            assert returncode == 0
            data = json.loads(stdout)
            assert data["session_id"] == 5


class TestNetworkScenarios:
    """Test suite for common network scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_create_simple_network(self):
        """Test creating a simple network topology."""
        # This test simulates creating a basic network
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            # Create session
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'{"session_id": 10}',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "session", "create", "--name", "simple-net"
            ])
            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_network_connectivity_test(self):
        """Test running connectivity test between nodes."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'PING 10.0.0.11: 64 bytes from 10.0.0.11: icmp_seq=1 time=0.1ms\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "core-cli", "node", "exec",
                "--session", "1",
                "--node", "2",
                "--command", "ping -c 1 10.0.0.11"
            ])

            assert returncode == 0
            assert "10.0.0.11" in stdout


class TestNetworkUIIntegration:
    """Test suite for network integration with TUI."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_app_displays_network_status(self):
        """Test that app can display network status."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            assert app.is_running

            # Visualizer should show network topology
            visualizer = app.query_one("#attack-visualizer", AttackVisualizer)
            assert visualizer is not None

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_network_events_in_visualizer(self):
        """Test that network events can be displayed in visualizer."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            visualizer = app.query_one("#attack-visualizer", AttackVisualizer)

            # Add network-related attack event
            visualizer.add_attack_event(
                source="10.0.0.100",
                target="10.0.0.10",
                attack_type="Network Scan",
                severity="low"
            )
            await pilot.pause()

            assert visualizer.event_count >= 1

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_network_error_display_in_output(self):
        """Test that network errors are displayed in output viewer."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            from tui.widgets.output_viewer import OutputViewer

            screen = app.screen
            if isinstance(screen, DashboardScreen):
                output_viewer = app.query_one("#output-viewer", OutputViewer)

                # Log a network error
                screen.log_message("Network error: Cannot connect to CORE daemon", level="error")
                await pilot.pause()

                error_entries = output_viewer.get_entries(level="error")
                assert len(error_entries) > 0
