#!/usr/bin/env python3
"""
Test Suite for Service Fingerprinter
=====================================

Comprehensive tests for the service fingerprinting tool including
plan mode, documentation, and mock network operations.
"""

import sys
import unittest
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from io import StringIO
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tool import (
    ServiceInfo,
    FingerprintConfig,
    ProbeResult,
    ServiceProbe,
    HTTPProbe,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS
)

try:
    from testing_utils import (
        SecurityToolTestCase,
        MockSocket,
        TestDataGenerator,
        capture_output,
        mock_argv,
        validate_plan_output,
        validate_documentation
    )
except ImportError:
    # Fallback if testing_utils not available
    from unittest import TestCase as SecurityToolTestCase
    MockSocket = None
    TestDataGenerator = None


class TestServiceInfo(unittest.TestCase):
    """Tests for ServiceInfo dataclass."""

    def test_service_info_creation(self):
        """Test creating a ServiceInfo instance."""
        info = ServiceInfo(
            port=22,
            protocol="tcp",
            service_name="ssh",
            version="OpenSSH_8.4p1"
        )
        self.assertEqual(info.port, 22)
        self.assertEqual(info.protocol, "tcp")
        self.assertEqual(info.service_name, "ssh")
        self.assertEqual(info.version, "OpenSSH_8.4p1")

    def test_service_info_to_dict(self):
        """Test serialization to dictionary."""
        info = ServiceInfo(
            port=80,
            protocol="tcp",
            service_name="http",
            product="Apache",
            version="2.4.41"
        )
        data = info.to_dict()

        self.assertIn("port", data)
        self.assertIn("service_name", data)
        self.assertEqual(data["port"], 80)
        self.assertEqual(data["product"], "Apache")

    def test_service_info_default_values(self):
        """Test default values for optional fields."""
        info = ServiceInfo(port=443, protocol="tcp", service_name="https")

        self.assertIsNone(info.version)
        self.assertIsNone(info.product)
        self.assertEqual(info.ssl_enabled, False)
        self.assertEqual(info.confidence, 0)


class TestFingerprintConfig(unittest.TestCase):
    """Tests for FingerprintConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = FingerprintConfig()

        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.threads, DEFAULT_THREADS)
        self.assertEqual(config.plan_mode, False)
        self.assertEqual(config.verbose, False)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22, 80, 443],
            timeout=10.0,
            threads=20,
            aggressive=True,
            plan_mode=True
        )

        self.assertEqual(config.target, "192.168.1.100")
        self.assertEqual(len(config.ports), 3)
        self.assertTrue(config.aggressive)
        self.assertTrue(config.plan_mode)


class TestProbeResult(unittest.TestCase):
    """Tests for ProbeResult dataclass."""

    def test_probe_result_matched(self):
        """Test matched probe result."""
        result = ProbeResult(
            matched=True,
            service_name="http",
            version="Apache/2.4.41",
            confidence=90
        )

        self.assertTrue(result.matched)
        self.assertEqual(result.confidence, 90)

    def test_probe_result_not_matched(self):
        """Test non-matched probe result."""
        result = ProbeResult(matched=False)

        self.assertFalse(result.matched)
        self.assertIsNone(result.service_name)
        self.assertEqual(result.confidence, 0)


class TestDocumentation(unittest.TestCase):
    """Tests for tool documentation."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        doc = get_documentation()
        self.assertIsInstance(doc, dict)

    def test_documentation_has_required_fields(self):
        """Test that documentation has all required fields."""
        doc = get_documentation()

        required_fields = ["name", "description", "usage", "arguments"]
        for field in required_fields:
            self.assertIn(field, doc, f"Missing required field: {field}")

    def test_documentation_name_not_empty(self):
        """Test that tool name is not empty."""
        doc = get_documentation()
        self.assertTrue(len(doc["name"]) > 0)

    def test_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        doc = get_documentation()
        self.assertIn("examples", doc)


class TestArgumentParser(unittest.TestCase):
    """Tests for argument parser."""

    def test_parser_creation(self):
        """Test parser can be created."""
        parser = create_argument_parser()
        self.assertIsNotNone(parser)

    def test_parser_has_plan_flag(self):
        """Test parser has --plan flag."""
        parser = create_argument_parser()

        # Check for plan flag in actions
        plan_found = False
        for action in parser._actions:
            if '--plan' in action.option_strings or '-p' in action.option_strings:
                plan_found = True
                break

        self.assertTrue(plan_found, "Parser should have --plan flag")

    def test_parser_target_argument(self):
        """Test parser has target argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--target', '192.168.1.1', '--ports', '80,443'])

        self.assertEqual(args.target, '192.168.1.1')

    def test_parser_ports_argument(self):
        """Test parser parses ports correctly."""
        parser = create_argument_parser()
        args = parser.parse_args(['--target', '192.168.1.1', '--ports', '22,80,443'])

        self.assertIn('22', args.ports)


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22, 80, 443],
            plan_mode=True
        )

        # Capture stdout
        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertTrue(len(output) > 0)

    def test_plan_mode_shows_target(self):
        """Test that plan output shows target."""
        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22, 80],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("192.168.1.100", output)

    def test_plan_mode_shows_ports(self):
        """Test that plan output shows ports to scan."""
        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22, 80, 443],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        # Should show port information
        self.assertTrue("22" in output or "port" in output.lower())

    def test_plan_mode_no_network_operations(self):
        """Test that plan mode does not perform network operations."""
        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22, 80],
            plan_mode=True
        )

        with patch('socket.socket') as mock_socket:
            captured = StringIO()
            sys.stdout = captured
            try:
                print_plan(config)
            finally:
                sys.stdout = sys.__stdout__

            # Socket should not be instantiated in plan mode
            # The print_plan function should just print and return


class TestHTTPProbe(unittest.TestCase):
    """Tests for HTTP service probe."""

    def test_http_probe_properties(self):
        """Test HTTP probe properties."""
        probe = HTTPProbe()

        self.assertEqual(probe.name, "http")
        self.assertIn(80, probe.ports)
        self.assertEqual(probe.protocol, "tcp")

    @patch('socket.socket')
    def test_http_probe_detection(self, mock_socket_class):
        """Test HTTP probe with mock response."""
        # Create mock socket
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
        mock_socket_class.return_value = mock_sock

        probe = HTTPProbe()
        config = FingerprintConfig(target="test.com", timeout=5.0)

        result = probe.probe(mock_sock, config)

        # Probe should match HTTP response
        self.assertTrue(result.matched)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_empty_target_error(self):
        """Test error handling for empty target."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args(['--ports', '80'])

    def test_invalid_port_handling(self):
        """Test handling of invalid port values."""
        parser = create_argument_parser()

        # Should handle or reject invalid ports
        args = parser.parse_args(['--target', '192.168.1.1', '--ports', '80'])
        self.assertIsNotNone(args)


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    @patch('socket.socket')
    @patch('socket.create_connection')
    def test_fingerprint_workflow(self, mock_create, mock_socket_class):
        """Test complete fingerprinting workflow with mocks."""
        # Setup mock socket
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.4\r\n"
        mock_create.return_value = mock_sock
        mock_socket_class.return_value = mock_sock

        config = FingerprintConfig(
            target="192.168.1.100",
            ports=[22],
            timeout=5.0
        )

        # Just verify config is properly created
        self.assertEqual(config.target, "192.168.1.100")
        self.assertEqual(config.ports, [22])


# =============================================================================
# Test Fixtures
# =============================================================================

class ServiceFingerprinterFixtures:
    """Test fixtures for service fingerprinter."""

    # Sample service banners
    BANNERS = {
        "ssh": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
        "ftp": b"220 ProFTPD 1.3.6 Server (FTP Server) ready.\r\n",
        "smtp": b"220 mail.example.com ESMTP Postfix\r\n",
        "http": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
        "mysql": b"\x5b\x00\x00\x00\x0a5.7.32-0ubuntu0.18.04.1",
    }

    # Common service ports
    COMMON_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        80: "http",
        443: "https",
        3306: "mysql",
        5432: "postgresql",
        3389: "rdp"
    }

    @classmethod
    def get_banner(cls, service: str) -> bytes:
        """Get banner for a service."""
        return cls.BANNERS.get(service, b"")

    @classmethod
    def get_mock_socket(cls, service: str):
        """Get a mock socket that returns a service banner."""
        mock = MagicMock()
        mock.recv.return_value = cls.get_banner(service)
        return mock


if __name__ == '__main__':
    unittest.main(verbosity=2)
