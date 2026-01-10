#!/usr/bin/env python3
"""
Unit tests for Network Scanner tool.
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    NetworkScanner,
    ScanConfig,
    ScanResult,
    TCPConnectScan,
    DNSResolutionScan,
    get_documentation,
    print_plan
)


class TestScanConfig(unittest.TestCase):
    """Tests for ScanConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ScanConfig()
        self.assertEqual(config.timeout, 2.0)
        self.assertEqual(config.threads, 10)
        self.assertEqual(config.delay_min, 0.0)
        self.assertEqual(config.delay_max, 0.1)
        self.assertFalse(config.resolve_hostnames)
        self.assertFalse(config.plan_mode)

    def test_custom_config(self):
        """Test custom configuration values."""
        config = ScanConfig(
            targets=["192.168.1.0/24"],
            timeout=5.0,
            threads=20,
            scan_methods=["tcp", "dns"]
        )
        self.assertEqual(config.targets, ["192.168.1.0/24"])
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.threads, 20)
        self.assertEqual(config.scan_methods, ["tcp", "dns"])


class TestScanResult(unittest.TestCase):
    """Tests for ScanResult dataclass."""

    def test_result_creation(self):
        """Test creating a scan result."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=0.05,
            method="tcp_connect:80"
        )
        self.assertEqual(result.ip, "192.168.1.1")
        self.assertTrue(result.is_alive)
        self.assertEqual(result.response_time, 0.05)
        self.assertEqual(result.method, "tcp_connect:80")

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            method="tcp_connect:80",
            hostname="router.local"
        )
        data = result.to_dict()
        self.assertEqual(data["ip"], "192.168.1.1")
        self.assertTrue(data["is_alive"])
        self.assertEqual(data["hostname"], "router.local")
        self.assertIn("timestamp", data)


class TestNetworkScanner(unittest.TestCase):
    """Tests for NetworkScanner class."""

    def test_expand_single_ip(self):
        """Test expanding a single IP address."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        self.assertEqual(targets, ["192.168.1.1"])

    def test_expand_cidr(self):
        """Test expanding CIDR notation."""
        config = ScanConfig(targets=["192.168.1.0/30"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # /30 network has 2 usable hosts
        self.assertEqual(len(targets), 2)
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)

    def test_expand_range(self):
        """Test expanding IP range notation."""
        config = ScanConfig(targets=["192.168.1.1-3"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        self.assertEqual(len(targets), 3)
        self.assertIn("192.168.1.1", targets)
        self.assertIn("192.168.1.2", targets)
        self.assertIn("192.168.1.3", targets)

    def test_get_live_hosts(self):
        """Test filtering live hosts."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        scanner.results = [
            ScanResult(ip="192.168.1.1", is_alive=True, method="tcp"),
            ScanResult(ip="192.168.1.2", is_alive=False, method="tcp"),
            ScanResult(ip="192.168.1.3", is_alive=True, method="tcp"),
        ]
        live = scanner.get_live_hosts()
        self.assertEqual(len(live), 2)
        self.assertEqual(live[0].ip, "192.168.1.1")
        self.assertEqual(live[1].ip, "192.168.1.3")

    def test_stop_event(self):
        """Test scanner stop functionality."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        scanner.stop()
        self.assertTrue(scanner._stop_event.is_set())


class TestTCPConnectScan(unittest.TestCase):
    """Tests for TCP Connect scan technique."""

    def test_technique_properties(self):
        """Test technique name and description."""
        technique = TCPConnectScan()
        self.assertEqual(technique.name, "tcp_connect")
        self.assertIn("TCP", technique.description)

    @patch('socket.socket')
    def test_successful_scan(self, mock_socket):
        """Test successful TCP connection."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock

        config = ScanConfig(tcp_ports=[80])
        technique = TCPConnectScan()
        result = technique.scan("192.168.1.1", config)

        self.assertTrue(result.is_alive)
        self.assertIn("tcp_connect", result.method)

    @patch('socket.socket')
    def test_failed_scan(self, mock_socket):
        """Test failed TCP connection."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused
        mock_socket.return_value = mock_sock

        config = ScanConfig(tcp_ports=[80])
        technique = TCPConnectScan()
        result = technique.scan("192.168.1.1", config)

        self.assertFalse(result.is_alive)


class TestDNSResolutionScan(unittest.TestCase):
    """Tests for DNS resolution scan technique."""

    def test_technique_properties(self):
        """Test technique name and description."""
        technique = DNSResolutionScan()
        self.assertEqual(technique.name, "dns")
        self.assertIn("DNS", technique.description)

    @patch('socket.gethostbyaddr')
    def test_successful_lookup(self, mock_lookup):
        """Test successful DNS reverse lookup."""
        mock_lookup.return_value = ("host.example.com", [], ["192.168.1.1"])

        config = ScanConfig()
        technique = DNSResolutionScan()
        result = technique.scan("192.168.1.1", config)

        self.assertTrue(result.is_alive)
        self.assertEqual(result.hostname, "host.example.com")

    @patch('socket.gethostbyaddr')
    def test_failed_lookup(self, mock_lookup):
        """Test failed DNS reverse lookup."""
        import socket
        mock_lookup.side_effect = socket.herror("Host not found")

        config = ScanConfig()
        technique = DNSResolutionScan()
        result = technique.scan("192.168.1.1", config)

        self.assertFalse(result.is_alive)


class TestDocumentation(unittest.TestCase):
    """Tests for documentation hooks."""

    def test_get_documentation(self):
        """Test documentation structure."""
        docs = get_documentation()
        self.assertIn("name", docs)
        self.assertIn("version", docs)
        self.assertIn("category", docs)
        self.assertIn("description", docs)
        self.assertIn("arguments", docs)
        self.assertIn("examples", docs)
        self.assertEqual(docs["name"], "network-scanner")
        self.assertEqual(docs["category"], "reconnaissance")

    def test_documentation_arguments(self):
        """Test that all arguments are documented."""
        docs = get_documentation()
        args = docs["arguments"]
        self.assertIn("targets", args)
        self.assertIn("--timeout", args)
        self.assertIn("--threads", args)
        self.assertIn("--plan", args)


class TestPlanMode(unittest.TestCase):
    """Tests for planning mode."""

    def test_plan_mode_no_execution(self):
        """Verify plan mode doesn't execute scans."""
        config = ScanConfig(
            targets=["192.168.1.0/24"],
            plan_mode=True
        )

        # Plan mode should only print, not scan
        import io
        from contextlib import redirect_stdout

        f = io.StringIO()
        with redirect_stdout(f):
            print_plan(config)

        output = f.getvalue()
        self.assertIn("PLAN MODE", output)
        self.assertIn("No actions will be taken", output)


if __name__ == "__main__":
    unittest.main()
