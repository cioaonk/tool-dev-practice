"""
Pytest configuration and shared fixtures for TUI tests.

This module provides common fixtures and configuration for testing
the Security Toolsmith TUI application.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING, List, Dict, Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from textual.pilot import Pilot
from textual.widgets import Static, Button, Input, Label

# Import TUI components
from tui.app import ToolsmithApp, DashboardScreen, SecurityTool, DEFAULT_TOOLS
from tui.widgets.tool_panel import ToolPanel, ToolItem, CategoryHeader
from tui.widgets.output_viewer import OutputViewer, LogEntry
from tui.widgets.status_bar import ToolsmithStatusBar
from tui.visualizers.attack_visualizer import AttackVisualizer, AttackEvent, NetworkNode
from tui.screens.tool_config import ToolConfigScreen, ParameterInput


@pytest.fixture
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_tool() -> SecurityTool:
    """Create a sample security tool for testing."""
    return SecurityTool(
        name="Test Tool",
        description="A test tool for unit testing",
        command="test_tool.py",
        category="Testing",
        parameters=[
            {"name": "target", "type": "str", "required": True, "description": "Target to test"},
            {"name": "verbose", "type": "bool", "required": False, "description": "Enable verbose output"},
        ]
    )


@pytest.fixture
def sample_tool_no_params() -> SecurityTool:
    """Create a sample security tool with no parameters."""
    return SecurityTool(
        name="Simple Tool",
        description="A simple tool with no parameters",
        command="simple_tool.py",
        category="Testing",
        parameters=[]
    )


@pytest.fixture
def sample_tools() -> List[SecurityTool]:
    """Create a list of sample security tools for testing."""
    return [
        SecurityTool(
            name="Recon Tool 1",
            description="First recon tool",
            command="recon1.py",
            category="Recon",
            parameters=[{"name": "target", "type": "str", "required": True, "description": "Target"}]
        ),
        SecurityTool(
            name="Recon Tool 2",
            description="Second recon tool",
            command="recon2.py",
            category="Recon",
            parameters=[]
        ),
        SecurityTool(
            name="Vuln Scanner",
            description="Vulnerability scanner",
            command="vuln.py",
            category="Vulnerability",
            parameters=[
                {"name": "target", "type": "str", "required": True, "description": "Target"},
                {"name": "port", "type": "int", "required": False, "description": "Port"}
            ]
        ),
    ]


@pytest.fixture
def mock_docker_output() -> Dict[str, Any]:
    """Create mock Docker command output."""
    return {
        "containers": [
            {
                "ID": "abc123",
                "Image": "security-tool:latest",
                "Command": "python tool.py",
                "Created": "2 hours ago",
                "Status": "Up 2 hours",
                "Ports": "8080->8080/tcp",
                "Names": "security-scanner"
            },
            {
                "ID": "def456",
                "Image": "network-mapper:1.0",
                "Command": "mapper --scan",
                "Created": "1 day ago",
                "Status": "Exited (0) 1 day ago",
                "Ports": "",
                "Names": "network-mapper"
            },
        ],
        "images": [
            {"Repository": "security-tool", "Tag": "latest", "ImageID": "sha256:abc"},
            {"Repository": "network-mapper", "Tag": "1.0", "ImageID": "sha256:def"},
        ]
    }


@pytest.fixture
def mock_network_output() -> Dict[str, Any]:
    """Create mock CORE network command output."""
    return {
        "sessions": [
            {"id": 1, "name": "test-topology", "state": "RUNTIME", "nodes": 5},
            {"id": 2, "name": "attack-sim", "state": "DEFINITION", "nodes": 3},
        ],
        "nodes": [
            {"id": 1, "name": "router1", "type": "router", "ip": "10.0.0.1"},
            {"id": 2, "name": "host1", "type": "host", "ip": "10.0.0.10"},
            {"id": 3, "name": "host2", "type": "host", "ip": "10.0.0.11"},
        ],
        "links": [
            {"node1": 1, "node2": 2, "bandwidth": "100Mbps"},
            {"node1": 1, "node2": 3, "bandwidth": "100Mbps"},
        ]
    }


@pytest.fixture
def mock_subprocess_docker():
    """Mock subprocess calls for Docker commands."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        # Configure mock process
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(
            b'[{"ID":"abc123","Image":"security-tool:latest","Status":"Up"}]',
            b''
        ))
        mock_exec.return_value = mock_process
        yield mock_exec


@pytest.fixture
def mock_subprocess_network():
    """Mock subprocess calls for CORE network commands."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.returncode = 0
        mock_process.communicate = AsyncMock(return_value=(
            b'{"sessions":[{"id":1,"name":"test-topology","state":"RUNTIME"}]}',
            b''
        ))
        mock_exec.return_value = mock_process
        yield mock_exec


@pytest.fixture
def mock_subprocess_error():
    """Mock subprocess calls that return errors."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.returncode = 1
        mock_process.communicate = AsyncMock(return_value=(
            b'',
            b'Error: Command failed'
        ))
        mock_exec.return_value = mock_process
        yield mock_exec


@pytest.fixture
def mock_subprocess_timeout():
    """Mock subprocess calls that timeout."""
    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_process = AsyncMock()
        mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_process.kill = MagicMock()
        mock_exec.return_value = mock_process
        yield mock_exec


class MockApp:
    """A lightweight mock app for testing widgets in isolation."""

    def __init__(self):
        self.dark = True
        self._notifications: List[str] = []

    def notify(self, message: str, severity: str = "information"):
        self._notifications.append((message, severity))

    def call_later(self, callback):
        pass


@pytest.fixture
def mock_app() -> MockApp:
    """Create a mock app for testing."""
    return MockApp()


# Helper functions for tests

def create_test_log_entries(count: int = 5) -> List[LogEntry]:
    """Create test log entries."""
    from datetime import datetime, timedelta

    levels = ["debug", "info", "success", "warning", "error"]
    entries = []

    base_time = datetime.now()
    for i in range(count):
        entries.append(LogEntry(
            timestamp=base_time + timedelta(seconds=i),
            message=f"Test message {i}",
            level=levels[i % len(levels)]
        ))

    return entries


def create_test_attack_events(count: int = 3) -> List[AttackEvent]:
    """Create test attack events."""
    from datetime import datetime, timedelta

    severities = ["low", "medium", "high", "critical"]
    events = []

    base_time = datetime.now()
    for i in range(count):
        events.append(AttackEvent(
            timestamp=base_time + timedelta(seconds=i),
            source=f"Attacker{i}",
            target=f"Target{i}",
            attack_type=f"Attack Type {i}",
            severity=severities[i % len(severities)],
            details={"test": f"value{i}"}
        ))

    return events


# Pytest configuration

def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "docker: marks tests that mock Docker interactions"
    )
    config.addinivalue_line(
        "markers", "network: marks tests that mock network interactions"
    )
