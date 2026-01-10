#!/usr/bin/env python3
"""
Unit tests for Port Scanner tool.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    PortScanner,
    ScanConfig,
    PortResult,
    ScanReport,
    PortState,
    ScanType,
    TCPConnectScan,
    UDPScan,
    parse_port_specification,
    get_service_name,
    get_documentation
)


class TestPortSpecification(unittest.TestCase):
    """Tests for port specification parsing."""

    def test_single_port(self):
        """Test parsing single port."""
        ports = parse_port_specification("80")
        self.assertEqual(ports, [80])

    def test_port_range(self):
        """Test parsing port range."""
        ports = parse_port_specification("80-83")
        self.assertEqual(ports, [80, 81, 82, 83])

    def test_port_list(self):
        """Test parsing comma-separated list."""
        ports = parse_port_specification("22,80,443")
        self.assertEqual(ports, [22, 80, 443])

    def test_combined_specification(self):
        """Test combined port specification."""
        ports = parse_port_specification("22,80-82,443")
        self.assertEqual(ports, [22, 80, 81, 82, 443])

    def test_top20_keyword(self):
        """Test top20 keyword."""
        ports = parse_port_specification("top20")
        self.assertEqual(len(ports), 20)
        self.assertIn(80, ports)
        self.assertIn(443, ports)

    def test_top100_keyword(self):
        """Test top100 keyword."""
        ports = parse_port_specification("top100")
        self.assertEqual(len(ports), 100)

    def test_invalid_port(self):
        """Test invalid port handling."""
        ports = parse_port_specification("99999")
        self.assertEqual(ports, [])

    def test_invalid_range(self):
        """Test invalid range handling."""
        ports = parse_port_specification("abc-def")
        self.assertEqual(ports, [])


class TestPortResult(unittest.TestCase):
    """Tests for PortResult dataclass."""

    def test_result_creation(self):
        """Test creating port result."""
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            protocol="tcp",
            service="http"
        )
        self.assertEqual(result.port, 80)
        self.assertEqual(result.state, PortState.OPEN)
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.service, "http")

    def test_to_dict(self):
        """Test serialization."""
        result = PortResult(
            port=443,
            state=PortState.OPEN,
            protocol="tcp",
            service="https",
            banner="nginx/1.18.0"
        )
        data = result.to_dict()
        self.assertEqual(data["port"], 443)
        self.assertEqual(data["state"], "open")
        self.assertEqual(data["banner"], "nginx/1.18.0")


class TestScanReport(unittest.TestCase):
    """Tests for ScanReport dataclass."""

    def test_get_open_ports(self):
        """Test filtering open ports."""
        report = ScanReport(target="192.168.1.1")
        report.results = [
            PortResult(port=22, state=PortState.OPEN, protocol="tcp"),
            PortResult(port=23, state=PortState.CLOSED, protocol="tcp"),
            PortResult(port=80, state=PortState.OPEN, protocol="tcp"),
            PortResult(port=443, state=PortState.FILTERED, protocol="tcp"),
        ]
        open_ports = report.get_open_ports()
        self.assertEqual(len(open_ports), 2)
        self.assertEqual(open_ports[0].port, 22)
        self.assertEqual(open_ports[1].port, 80)

    def test_get_filtered_ports(self):
        """Test filtering filtered ports."""
        report = ScanReport(target="192.168.1.1")
        report.results = [
            PortResult(port=22, state=PortState.OPEN, protocol="tcp"),
            PortResult(port=443, state=PortState.FILTERED, protocol="tcp"),
            PortResult(port=8080, state=PortState.FILTERED, protocol="tcp"),
        ]
        filtered = report.get_filtered_ports()
        self.assertEqual(len(filtered), 2)


class TestScanConfig(unittest.TestCase):
    """Tests for ScanConfig dataclass."""

    def test_default_config(self):
        """Test default configuration."""
        config = ScanConfig()
        self.assertEqual(config.timeout, 1.0)
        self.assertEqual(config.threads, 50)
        self.assertEqual(config.scan_type, ScanType.TCP_CONNECT)
        self.assertTrue(config.randomize_ports)
        self.assertFalse(config.banner_grab)

    def test_custom_config(self):
        """Test custom configuration."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=[22, 80, 443],
            scan_type=ScanType.UDP,
            threads=10,
            banner_grab=True
        )
        self.assertEqual(config.target, "192.168.1.1")
        self.assertEqual(config.ports, [22, 80, 443])
        self.assertEqual(config.scan_type, ScanType.UDP)
        self.assertTrue(config.banner_grab)


class TestTCPConnectScan(unittest.TestCase):
    """Tests for TCP Connect scan technique."""

    def test_technique_properties(self):
        """Test technique name and privileges."""
        technique = TCPConnectScan()
        self.assertEqual(technique.name, "TCP Connect")
        self.assertFalse(technique.requires_root)

    @patch('socket.socket')
    def test_open_port(self, mock_socket):
        """Test detecting open port."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock

        config = ScanConfig()
        technique = TCPConnectScan()
        result = technique.scan_port("192.168.1.1", 80, config)

        self.assertEqual(result.state, PortState.OPEN)
        self.assertEqual(result.port, 80)

    @patch('socket.socket')
    def test_closed_port(self, mock_socket):
        """Test detecting closed port."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket.return_value = mock_sock

        config = ScanConfig()
        technique = TCPConnectScan()
        result = technique.scan_port("192.168.1.1", 80, config)

        self.assertEqual(result.state, PortState.CLOSED)


class TestUDPScan(unittest.TestCase):
    """Tests for UDP scan technique."""

    def test_technique_properties(self):
        """Test technique name and privileges."""
        technique = UDPScan()
        self.assertEqual(technique.name, "UDP")
        self.assertFalse(technique.requires_root)


class TestServiceName(unittest.TestCase):
    """Tests for service name lookup."""

    def test_known_services(self):
        """Test known service lookups."""
        self.assertEqual(get_service_name(22), "ssh")
        self.assertEqual(get_service_name(80), "http")
        self.assertEqual(get_service_name(443), "https")
        self.assertEqual(get_service_name(3389), "rdp")

    def test_unknown_service(self):
        """Test unknown port."""
        self.assertIsNone(get_service_name(12345))


class TestPortScanner(unittest.TestCase):
    """Tests for PortScanner class."""

    @patch('socket.gethostbyname')
    def test_resolve_target(self, mock_resolve):
        """Test target resolution."""
        mock_resolve.return_value = "192.168.1.1"

        config = ScanConfig(target="example.com", ports=[80])
        scanner = PortScanner(config)
        resolved = scanner._resolve_target()

        self.assertEqual(resolved, "192.168.1.1")

    def test_stop_event(self):
        """Test scanner stop functionality."""
        config = ScanConfig(target="192.168.1.1", ports=[80])
        scanner = PortScanner(config)
        scanner.stop()
        self.assertTrue(scanner._stop_event.is_set())


class TestDocumentation(unittest.TestCase):
    """Tests for documentation hooks."""

    def test_get_documentation(self):
        """Test documentation structure."""
        docs = get_documentation()
        self.assertIn("name", docs)
        self.assertIn("version", docs)
        self.assertIn("category", docs)
        self.assertIn("scan_types", docs)
        self.assertIn("arguments", docs)
        self.assertEqual(docs["name"], "port-scanner")

    def test_scan_types_documented(self):
        """Test scan types are documented."""
        docs = get_documentation()
        scan_types = docs["scan_types"]
        self.assertIn("connect", scan_types)
        self.assertIn("syn", scan_types)
        self.assertIn("udp", scan_types)


if __name__ == "__main__":
    unittest.main()
