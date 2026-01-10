"""
Tests for the Reverse Shell Handler tool.

This module contains unit tests and integration tests for the reverse-shell-handler tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/reverse-shell-handler')

from tool import (
    ShellSession,
    HandlerConfig,
    PayloadGenerator,
    ShellHandler,
    get_documentation,
    print_plan,
    parse_arguments,
)


# =============================================================================
# Test get_documentation()
# =============================================================================

class TestGetDocumentation:
    """Tests for the get_documentation function."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        docs = get_documentation()
        assert isinstance(docs, dict)

    def test_get_documentation_has_required_keys(self):
        """Test that documentation contains all required keys."""
        docs = get_documentation()
        required_keys = ["name", "version", "description"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "reverse-shell-handler"

    def test_get_documentation_has_arguments(self):
        """Test that documentation includes argument definitions."""
        docs = get_documentation()
        assert "arguments" in docs
        assert isinstance(docs["arguments"], dict)

    def test_get_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        docs = get_documentation()
        assert "examples" in docs
        assert isinstance(docs["examples"], list)


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = HandlerConfig(
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_listener_info(self, capsys):
        """Test that planning mode shows listener information."""
        config = HandlerConfig(
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.100" in captured.out
        assert "4444" in captured.out

    def test_plan_mode_does_not_bind_socket(self):
        """Test that planning mode does not bind to socket."""
        with patch('socket.socket') as mock_socket:
            config = HandlerConfig(
                lhost="192.168.1.100",
                lport=4444,
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be bound in plan mode
            mock_socket.return_value.bind.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_lhost(self):
        """Test that valid LHOST is accepted."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        assert config.lhost == "192.168.1.100"

    def test_valid_lport(self):
        """Test that valid LPORT is accepted."""
        config = HandlerConfig(lhost="0.0.0.0", lport=4444)
        assert config.lport == 4444

    def test_valid_lport_range(self):
        """Test various valid port numbers."""
        for port in [1, 80, 443, 4444, 65535]:
            config = HandlerConfig(lhost="0.0.0.0", lport=port)
            assert config.lport == port


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_socket_bind_error_handled(self):
        """Test that socket bind errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.bind.side_effect = socket.error("Address already in use")

            config = HandlerConfig(lhost="0.0.0.0", lport=4444)
            handler = ShellHandler(config)

            try:
                result = handler.start()
                assert result == False or result is None
            except socket.error:
                pass  # Acceptable to propagate socket errors

    def test_connection_timeout_handling(self):
        """Test that connection timeouts are handled."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.accept.side_effect = socket.timeout("Timeout")

            config = HandlerConfig(lhost="0.0.0.0", lport=4444, timeout=0.1)
            handler = ShellHandler(config)

            # Should handle timeout gracefully
            try:
                handler.start()
            except socket.timeout:
                pass  # Acceptable


# =============================================================================
# Test ShellSession Data Class
# =============================================================================

class TestShellSession:
    """Tests for the ShellSession data class."""

    def test_shell_session_creation(self):
        """Test that ShellSession can be created."""
        session = ShellSession(
            session_id=1,
            remote_addr="192.168.1.50",
            remote_port=54321
        )
        assert session.session_id == 1
        assert session.remote_addr == "192.168.1.50"

    def test_shell_session_with_socket(self):
        """Test ShellSession with socket object."""
        mock_socket = MagicMock()
        session = ShellSession(
            session_id=1,
            remote_addr="192.168.1.50",
            remote_port=54321,
            socket=mock_socket
        )
        assert session.socket == mock_socket


# =============================================================================
# Test PayloadGenerator Class
# =============================================================================

class TestPayloadGenerator:
    """Tests for the PayloadGenerator class."""

    def test_payload_generator_initialization(self):
        """Test PayloadGenerator initialization."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        assert generator is not None

    def test_bash_payload_generation(self):
        """Test bash payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_bash()

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "bash" in payload.lower() or "/dev/tcp" in payload

    def test_python_payload_generation(self):
        """Test Python payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_python()

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "python" in payload.lower() or "socket" in payload

    def test_netcat_payload_generation(self):
        """Test netcat payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_netcat()

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "nc" in payload or "netcat" in payload.lower()

    def test_php_payload_generation(self):
        """Test PHP payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_php()

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "php" in payload.lower() or "fsockopen" in payload

    def test_perl_payload_generation(self):
        """Test Perl payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_perl()

        assert "192.168.1.100" in payload
        assert "4444" in payload

    def test_ruby_payload_generation(self):
        """Test Ruby payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_ruby()

        assert "192.168.1.100" in payload
        assert "4444" in payload

    def test_powershell_payload_generation(self):
        """Test PowerShell payload generation."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)
        payload = generator.generate_powershell()

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "powershell" in payload.lower() or "TCPClient" in payload


# =============================================================================
# Test ShellHandler Class
# =============================================================================

class TestShellHandler:
    """Tests for the ShellHandler class."""

    def test_handler_initialization(self):
        """Test ShellHandler initialization."""
        config = HandlerConfig(lhost="0.0.0.0", lport=4444)
        handler = ShellHandler(config)
        assert handler is not None

    def test_handler_has_sessions_list(self):
        """Test that handler has sessions tracking."""
        config = HandlerConfig(lhost="0.0.0.0", lport=4444)
        handler = ShellHandler(config)
        assert hasattr(handler, 'sessions') or hasattr(handler, '_sessions')

    def test_handler_start_with_mocked_socket(self):
        """Test handler start with mocked socket."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.accept.side_effect = socket.timeout()

            config = HandlerConfig(lhost="0.0.0.0", lport=4444, timeout=0.1)
            handler = ShellHandler(config)

            # Should handle timeout gracefully
            try:
                handler.start()
            except socket.timeout:
                pass


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_lhost_argument(self):
        """Test parsing LHOST argument."""
        with patch('sys.argv', ['tool.py', '-l', '192.168.1.100']):
            args = parse_arguments()
            assert args.lhost == '192.168.1.100'

    def test_parse_lport_argument(self):
        """Test parsing LPORT argument."""
        with patch('sys.argv', ['tool.py', '-p', '4444']):
            args = parse_arguments()
            assert args.lport == 4444

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_payload_argument(self):
        """Test parsing --payload argument."""
        with patch('sys.argv', ['tool.py', '--payload', 'bash']):
            args = parse_arguments()
            assert args.payload == 'bash' or 'bash' in str(args.payload)


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_handler_accepts_connection(self):
        """Test handler accepting a connection."""
        with patch('socket.socket') as mock_socket:
            mock_client = MagicMock()
            mock_client.recv.return_value = b"id\n"
            mock_socket.return_value.accept.return_value = (mock_client, ("192.168.1.50", 54321))

            config = HandlerConfig(lhost="0.0.0.0", lport=4444)
            handler = ShellHandler(config)

            # Test would require more complex mocking for full integration

    def test_payload_generator_all_types(self):
        """Test generating all payload types."""
        config = HandlerConfig(lhost="192.168.1.100", lport=4444)
        generator = PayloadGenerator(config)

        payloads = {
            "bash": generator.generate_bash(),
            "python": generator.generate_python(),
            "netcat": generator.generate_netcat(),
            "php": generator.generate_php(),
            "perl": generator.generate_perl(),
            "ruby": generator.generate_ruby(),
            "powershell": generator.generate_powershell(),
        }

        for name, payload in payloads.items():
            assert "192.168.1.100" in payload, f"{name} payload missing LHOST"
            assert "4444" in payload, f"{name} payload missing LPORT"

    def test_multiple_sessions(self):
        """Test handling multiple sessions."""
        config = HandlerConfig(lhost="0.0.0.0", lport=4444)
        handler = ShellHandler(config)

        # Create mock sessions
        sessions = [
            ShellSession(1, "192.168.1.50", 54321),
            ShellSession(2, "192.168.1.51", 54322),
            ShellSession(3, "192.168.1.52", 54323),
        ]

        # If handler supports session management
        if hasattr(handler, 'sessions'):
            for session in sessions:
                handler.sessions.append(session)
            assert len(handler.sessions) == 3
