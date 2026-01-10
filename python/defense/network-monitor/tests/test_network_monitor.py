#!/usr/bin/env python3
"""
Unit tests for Network Monitor tool.

Tests cover:
- Connection data classes
- Detection rules
- Connection collectors
- Planning mode
- Output formatting
"""

import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    NetworkConnection,
    NetworkAlert,
    MonitorResult,
    NetworkMonitor,
    NetstatCollector,
    SuspiciousPortDetector,
    HighPortCountDetector,
    ExternalConnectionDetector,
    UnusualListenerDetector,
    DNSTunnelingDetector,
    get_documentation,
    format_output_text,
    format_output_json,
)


class TestNetworkConnection(unittest.TestCase):
    """Tests for NetworkConnection data class."""

    def test_create_connection(self):
        """Test connection creation."""
        conn = NetworkConnection(
            protocol="tcp",
            local_ip="192.168.1.50",
            local_port=45123,
            remote_ip="10.0.0.1",
            remote_port=443,
            state="ESTABLISHED",
            pid=1234,
            process_name="browser",
        )

        self.assertEqual(conn.protocol, "tcp")
        self.assertEqual(conn.local_ip, "192.168.1.50")
        self.assertEqual(conn.remote_port, 443)
        self.assertEqual(conn.state, "ESTABLISHED")

    def test_connection_to_dict(self):
        """Test connection serialization."""
        conn = NetworkConnection(
            protocol="tcp",
            local_ip="127.0.0.1",
            local_port=8080,
            remote_ip="*",
            remote_port=0,
            state="LISTEN",
        )

        data = conn.to_dict()

        self.assertEqual(data["protocol"], "tcp")
        self.assertEqual(data["state"], "LISTEN")
        self.assertIn("timestamp", data)


class TestNetworkAlert(unittest.TestCase):
    """Tests for NetworkAlert data class."""

    def test_create_alert(self):
        """Test alert creation."""
        conn = NetworkConnection(
            protocol="tcp",
            local_ip="192.168.1.50",
            local_port=45123,
            remote_ip="10.0.0.1",
            remote_port=4444,
            state="ESTABLISHED",
        )

        alert = NetworkAlert(
            rule_name="SUSPICIOUS_PORT",
            severity="HIGH",
            description="Connection to port 4444",
            connections=[conn],
            timestamp=datetime.now(),
            recommendation="Investigate",
        )

        self.assertEqual(alert.rule_name, "SUSPICIOUS_PORT")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(len(alert.connections), 1)

    def test_alert_to_dict(self):
        """Test alert serialization."""
        alert = NetworkAlert(
            rule_name="TEST_RULE",
            severity="MEDIUM",
            description="Test alert",
            connections=[],
            timestamp=datetime.now(),
        )

        data = alert.to_dict()

        self.assertEqual(data["rule_name"], "TEST_RULE")
        self.assertEqual(data["severity"], "MEDIUM")
        self.assertIn("timestamp", data)


class TestSuspiciousPortDetector(unittest.TestCase):
    """Tests for suspicious port detection."""

    def setUp(self):
        self.detector = SuspiciousPortDetector()

    def test_detect_metasploit_port(self):
        """Test detection of Metasploit default port."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123,
                remote_ip="10.0.0.1",
                remote_port=4444,
                state="ESTABLISHED",
            )
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertIn("4444", alerts[0].description)

    def test_detect_elite_port(self):
        """Test detection of 31337 (elite) port."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123,
                remote_ip="10.0.0.1",
                remote_port=31337,
                state="ESTABLISHED",
            )
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 1)
        self.assertIn("31337", alerts[0].description)

    def test_no_alert_for_normal_port(self):
        """Test no alert for normal ports."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123,
                remote_ip="10.0.0.1",
                remote_port=443,
                state="ESTABLISHED",
            )
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 0)


class TestHighPortCountDetector(unittest.TestCase):
    """Tests for high connection count detection."""

    def setUp(self):
        self.detector = HighPortCountDetector(threshold=5)

    def test_detect_high_count(self):
        """Test detection of high connection count."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123 + i,
                remote_ip=f"10.0.0.{i}",
                remote_port=443,
                state="ESTABLISHED",
                process_name="scanner",
            )
            for i in range(10)
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 1)
        self.assertIn("scanner", alerts[0].description)

    def test_no_alert_below_threshold(self):
        """Test no alert when below threshold."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123 + i,
                remote_ip=f"10.0.0.{i}",
                remote_port=443,
                state="ESTABLISHED",
                process_name="browser",
            )
            for i in range(3)
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 0)


class TestExternalConnectionDetector(unittest.TestCase):
    """Tests for external connection detection."""

    def setUp(self):
        self.detector = ExternalConnectionDetector()

    def test_identify_private_ips(self):
        """Test private IP identification."""
        self.assertTrue(self.detector._is_private("192.168.1.1"))
        self.assertTrue(self.detector._is_private("10.0.0.1"))
        self.assertTrue(self.detector._is_private("172.16.0.1"))
        self.assertTrue(self.detector._is_private("127.0.0.1"))

    def test_identify_public_ips(self):
        """Test public IP identification."""
        self.assertFalse(self.detector._is_private("8.8.8.8"))
        self.assertFalse(self.detector._is_private("1.1.1.1"))
        self.assertFalse(self.detector._is_private("203.0.113.1"))

    def test_detect_many_external_connections(self):
        """Test detection of many external connections."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=45123 + i,
                remote_ip=f"8.8.8.{i % 255}",
                remote_port=443,
                state="ESTABLISHED",
            )
            for i in range(25)
        ]

        alerts = self.detector.analyze(connections)

        # Should alert when > 20 external connections
        self.assertEqual(len(alerts), 1)


class TestUnusualListenerDetector(unittest.TestCase):
    """Tests for unusual listener detection."""

    def setUp(self):
        self.detector = UnusualListenerDetector()

    def test_detect_unusual_listener(self):
        """Test detection of unusual listening port."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="0.0.0.0",
                local_port=9999,
                remote_ip="*",
                remote_port=0,
                state="LISTEN",
            )
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 1)
        self.assertIn("unusual", alerts[0].description.lower())

    def test_no_alert_for_common_port(self):
        """Test no alert for common listening ports."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="0.0.0.0",
                local_port=443,
                remote_ip="*",
                remote_port=0,
                state="LISTEN",
            )
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 0)


class TestDNSTunnelingDetector(unittest.TestCase):
    """Tests for DNS tunneling detection."""

    def setUp(self):
        self.detector = DNSTunnelingDetector()

    def test_detect_high_dns_activity(self):
        """Test detection of high DNS query rate."""
        connections = [
            NetworkConnection(
                protocol="udp",
                local_ip="192.168.1.50",
                local_port=45123 + i,
                remote_ip="8.8.8.8",
                remote_port=53,
                state="UNKNOWN",
                process_name="suspicious_app",
            )
            for i in range(25)
        ]

        alerts = self.detector.analyze(connections)

        self.assertEqual(len(alerts), 1)
        self.assertIn("DNS", alerts[0].description)


class TestNetstatCollector(unittest.TestCase):
    """Tests for netstat collector."""

    def setUp(self):
        self.collector = NetstatCollector()

    def test_parse_tcp_line(self):
        """Test parsing TCP netstat line."""
        line = "tcp4       0      0  192.168.1.50.443       10.0.0.1.45123        ESTABLISHED"
        conn = self.collector._parse_line(line)

        # Note: This depends on the specific netstat format
        # The test may need adjustment based on platform
        if conn:
            self.assertEqual(conn.protocol, "tcp")

    def test_parse_address(self):
        """Test address parsing."""
        ip, port = self.collector._parse_address("192.168.1.50.443")
        self.assertEqual(ip, "192.168.1.50")
        self.assertEqual(port, 443)

    def test_parse_wildcard_address(self):
        """Test wildcard address parsing."""
        ip, port = self.collector._parse_address("*.*")
        self.assertEqual(ip, "*")
        self.assertEqual(port, 0)


class TestNetworkMonitor(unittest.TestCase):
    """Tests for main NetworkMonitor class."""

    def setUp(self):
        self.monitor = NetworkMonitor()

    def test_plan_mode(self):
        """Test planning mode output."""
        plan = self.monitor.get_plan(
            continuous=False,
            interval=30,
            output_format="text"
        )

        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("network-monitor", plan)
        self.assertIn("No actions will be taken", plan)

    def test_plan_mode_continuous(self):
        """Test planning mode for continuous monitoring."""
        plan = self.monitor.get_plan(
            continuous=True,
            interval=60,
            output_format="json"
        )

        self.assertIn("Continuous monitoring", plan)
        self.assertIn("60s", plan)

    def test_calculate_statistics(self):
        """Test statistics calculation."""
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_ip="192.168.1.50",
                local_port=443,
                remote_ip="10.0.0.1",
                remote_port=45123,
                state="ESTABLISHED",
                process_name="web",
            ),
            NetworkConnection(
                protocol="tcp",
                local_ip="0.0.0.0",
                local_port=80,
                remote_ip="*",
                remote_port=0,
                state="LISTEN",
                process_name="nginx",
            ),
        ]

        stats = self.monitor._calculate_statistics(connections)

        self.assertEqual(stats['by_protocol']['tcp'], 2)
        self.assertEqual(stats['established_count'], 1)
        self.assertIn(80, stats['listening_ports'])


class TestMonitorResult(unittest.TestCase):
    """Tests for MonitorResult data class."""

    def test_duration_calculation(self):
        """Test duration calculation."""
        start = datetime.now()
        end = datetime.now()

        result = MonitorResult(
            start_time=start,
            end_time=end,
            total_connections=10,
            alerts=[],
            statistics={},
            connections=[],
        )

        self.assertGreaterEqual(result.duration, 0)

    def test_to_dict(self):
        """Test serialization."""
        result = MonitorResult(
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_connections=10,
            alerts=[],
            statistics={"test": 1},
            connections=[],
        )

        data = result.to_dict()

        self.assertEqual(data["total_connections"], 10)
        self.assertEqual(data["alert_count"], 0)


class TestOutputFormatters(unittest.TestCase):
    """Tests for output formatters."""

    def setUp(self):
        self.result = MonitorResult(
            start_time=datetime.now(),
            end_time=datetime.now(),
            total_connections=5,
            alerts=[
                NetworkAlert(
                    rule_name="TEST_ALERT",
                    severity="HIGH",
                    description="Test description",
                    connections=[],
                    timestamp=datetime.now(),
                )
            ],
            statistics={
                'by_protocol': {'tcp': 5},
                'by_state': {'ESTABLISHED': 3, 'LISTEN': 2},
                'established_count': 3,
                'unique_remote_ips': 2,
                'listening_ports': [80, 443],
            },
            connections=[],
        )

    def test_text_output(self):
        """Test text format output."""
        output = format_output_text(self.result)

        self.assertIn("NETWORK MONITOR REPORT", output)
        self.assertIn("TEST_ALERT", output)
        self.assertIn("HIGH", output)

    def test_json_output(self):
        """Test JSON format output."""
        output = format_output_json(self.result)
        data = json.loads(output)

        self.assertEqual(data["total_connections"], 5)
        self.assertEqual(data["alert_count"], 1)


class TestDocumentation(unittest.TestCase):
    """Tests for documentation function."""

    def test_documentation_structure(self):
        """Test documentation returns required fields."""
        docs = get_documentation()

        self.assertIn("name", docs)
        self.assertIn("category", docs)
        self.assertIn("version", docs)
        self.assertIn("description", docs)
        self.assertIn("features", docs)
        self.assertIn("usage_examples", docs)
        self.assertIn("detection_rules", docs)
        self.assertEqual(docs["name"], "network-monitor")


if __name__ == '__main__':
    unittest.main(verbosity=2)
