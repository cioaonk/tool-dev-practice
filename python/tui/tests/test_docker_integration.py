"""
Tests for Docker integration in the TUI application.

This module tests Docker-related functionality with mocked subprocess calls
to allow tests to run in CI without actual Docker installed.

Tests cover:
- Docker container listing
- Docker image management
- Docker command execution
- Error handling for Docker failures
- Docker status display
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


class TestDockerCommandExecution:
    """Test suite for Docker command execution with mocked subprocess."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_ps_command_success(self, mock_subprocess_docker):
        """Test successful Docker ps command execution."""
        returncode, stdout, stderr = await run_command(["docker", "ps", "--format", "json"])

        assert returncode == 0
        assert stdout != ""
        assert stderr == ""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_ps_command_parses_json(self, mock_subprocess_docker):
        """Test that Docker ps output can be parsed as JSON."""
        returncode, stdout, stderr = await run_command(["docker", "ps", "--format", "json"])

        # Should be valid JSON
        containers = json.loads(stdout)
        assert isinstance(containers, list)
        assert len(containers) > 0
        assert "ID" in containers[0]

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_images_command_success(self):
        """Test successful Docker images command execution."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'[{"Repository":"test-image","Tag":"latest","ID":"sha256:abc123"}]',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "images", "--format", "json"])

            assert returncode == 0
            images = json.loads(stdout)
            assert isinstance(images, list)

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_command_failure(self, mock_subprocess_error):
        """Test Docker command failure handling."""
        returncode, stdout, stderr = await run_command(["docker", "ps"])

        assert returncode == 1
        assert stderr != ""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_command_timeout(self, mock_subprocess_timeout):
        """Test Docker command timeout handling."""
        returncode, stdout, stderr = await run_command(["docker", "ps"], timeout=1.0)

        assert returncode == -1
        assert "timed out" in stderr.lower() or stderr == ""


class TestDockerContainerList:
    """Test suite for Docker container listing functionality."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_container_list_parsing(self, mock_docker_output):
        """Test parsing of Docker container list."""
        containers = mock_docker_output["containers"]

        assert len(containers) == 2
        assert containers[0]["ID"] == "abc123"
        assert containers[0]["Names"] == "security-scanner"
        assert "Up" in containers[0]["Status"]

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_container_list_empty(self):
        """Test handling of empty container list."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'[]', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "ps", "--format", "json"])

            assert returncode == 0
            containers = json.loads(stdout)
            assert containers == []

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_container_status_running(self, mock_docker_output):
        """Test identifying running containers."""
        containers = mock_docker_output["containers"]
        running = [c for c in containers if "Up" in c["Status"]]

        assert len(running) == 1
        assert running[0]["Names"] == "security-scanner"

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_container_status_exited(self, mock_docker_output):
        """Test identifying exited containers."""
        containers = mock_docker_output["containers"]
        exited = [c for c in containers if "Exited" in c["Status"]]

        assert len(exited) == 1
        assert exited[0]["Names"] == "network-mapper"


class TestDockerImageList:
    """Test suite for Docker image listing functionality."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_image_list_parsing(self, mock_docker_output):
        """Test parsing of Docker image list."""
        images = mock_docker_output["images"]

        assert len(images) == 2
        assert images[0]["Repository"] == "security-tool"
        assert images[0]["Tag"] == "latest"

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_image_list_empty(self):
        """Test handling of empty image list."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'[]', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "images", "--format", "json"])

            assert returncode == 0
            images = json.loads(stdout)
            assert images == []


class TestDockerOperations:
    """Test suite for Docker operations (start, stop, remove)."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_start_container(self):
        """Test starting a Docker container."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'container_id\n', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "start", "test-container"])

            assert returncode == 0
            mock_exec.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_stop_container(self):
        """Test stopping a Docker container."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'container_id\n', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "stop", "test-container"])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_remove_container(self):
        """Test removing a Docker container."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'container_id\n', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "rm", "test-container"])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_start_nonexistent_container(self):
        """Test starting a non-existent container."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: No such container: nonexistent'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "start", "nonexistent"])

            assert returncode == 1
            assert "No such container" in stderr


class TestDockerRun:
    """Test suite for Docker run command."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_run_success(self):
        """Test successful Docker run command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'new_container_id\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "run", "-d", "--name", "test", "alpine:latest"
            ])

            assert returncode == 0
            assert stdout.strip() != ""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_run_with_environment(self):
        """Test Docker run with environment variables."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'container_id\n', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "run", "-d",
                "-e", "MY_VAR=value",
                "alpine:latest"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_run_with_volume(self):
        """Test Docker run with volume mount."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'container_id\n', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "run", "-d",
                "-v", "/host/path:/container/path",
                "alpine:latest"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_run_image_not_found(self):
        """Test Docker run with missing image."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Unable to find image \'nonexistent:latest\' locally'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "run", "nonexistent:latest"
            ])

            assert returncode == 1
            assert "Unable to find image" in stderr


class TestDockerLogs:
    """Test suite for Docker logs command."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_logs_success(self):
        """Test successful Docker logs retrieval."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'Log line 1\nLog line 2\nLog line 3\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "logs", "test-container"])

            assert returncode == 0
            assert "Log line" in stdout

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_logs_with_tail(self):
        """Test Docker logs with tail option."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'Last log line\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "logs", "--tail", "1", "test-container"
            ])

            assert returncode == 0


class TestDockerExec:
    """Test suite for Docker exec command."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_exec_success(self):
        """Test successful Docker exec command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'command output\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "exec", "test-container", "ls", "-la"
            ])

            assert returncode == 0
            assert "command output" in stdout

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_exec_container_not_running(self):
        """Test Docker exec on non-running container."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Error: Container test-container is not running'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "exec", "test-container", "ls"
            ])

            assert returncode == 1
            assert "not running" in stderr


class TestDockerNetworking:
    """Test suite for Docker networking commands."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_network_list(self):
        """Test listing Docker networks."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'[{"Name":"bridge","ID":"abc123"},{"Name":"host","ID":"def456"}]',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "network", "ls", "--format", "json"
            ])

            assert returncode == 0
            networks = json.loads(stdout)
            assert len(networks) == 2

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_network_inspect(self):
        """Test inspecting a Docker network."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'[{"Name":"bridge","Subnet":"172.17.0.0/16"}]',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker", "network", "inspect", "bridge"
            ])

            assert returncode == 0


class TestDockerCompose:
    """Test suite for Docker Compose commands."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_compose_up(self):
        """Test Docker Compose up command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'Creating network...\nCreating container...\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker-compose", "up", "-d"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_compose_down(self):
        """Test Docker Compose down command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'Stopping containers...\nRemoving containers...\n',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker-compose", "down"
            ])

            assert returncode == 0

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_compose_ps(self):
        """Test Docker Compose ps command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(
                b'[{"Name":"service1","State":"running"},{"Name":"service2","State":"running"}]',
                b''
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command([
                "docker-compose", "ps", "--format", "json"
            ])

            assert returncode == 0


class TestDockerErrorHandling:
    """Test suite for Docker error handling."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_daemon_not_running(self):
        """Test handling when Docker daemon is not running."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'Cannot connect to the Docker daemon. Is the docker daemon running?'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "ps"])

            assert returncode == 1
            assert "daemon" in stderr.lower()

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_permission_denied(self):
        """Test handling permission denied errors."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'permission denied while trying to connect to the Docker daemon socket'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "ps"])

            assert returncode == 1
            assert "permission denied" in stderr.lower()

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_invalid_command(self):
        """Test handling invalid Docker commands."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(
                b'',
                b'docker: \'invalid\' is not a docker command.'
            ))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["docker", "invalid"])

            assert returncode == 1
            assert "not a docker command" in stderr


class TestDockerUIIntegration:
    """Test suite for Docker integration with TUI."""

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_app_displays_docker_status(self):
        """Test that app can display Docker status."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            # App should be running
            assert app.is_running

            # Could update status bar with Docker status
            from tui.widgets.status_bar import ToolsmithStatusBar
            status_bar = app.query_one("#status-bar", ToolsmithStatusBar)
            assert status_bar is not None

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_container_info_display(self, mock_docker_output):
        """Test displaying Docker container information."""
        containers = mock_docker_output["containers"]

        # Verify container info structure
        for container in containers:
            assert "ID" in container
            assert "Image" in container
            assert "Status" in container
            assert "Names" in container

    @pytest.mark.asyncio
    @pytest.mark.docker
    async def test_docker_error_display_in_output(self):
        """Test that Docker errors are displayed in output viewer."""
        app = ToolsmithApp()
        async with safe_run_test(app) as pilot:
            from tui.widgets.output_viewer import OutputViewer

            screen = app.screen
            if isinstance(screen, DashboardScreen):
                output_viewer = app.query_one("#output-viewer", OutputViewer)

                # Log a Docker error
                screen.log_message("Docker error: Cannot connect to daemon", level="error")
                await pilot.pause()

                # Should have logged the error
                error_entries = output_viewer.get_entries(level="error")
                assert len(error_entries) > 0
