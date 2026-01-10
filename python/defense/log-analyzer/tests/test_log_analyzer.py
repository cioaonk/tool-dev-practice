#!/usr/bin/env python3
"""
Unit tests for Log Analyzer tool.
"""

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    LogAnalyzer,
    LogEntry,
    SyslogParser,
    AuthLogParser,
    ApacheLogParser,
    NginxLogParser,
    BruteForceDetector,
    PasswordSprayDetector,
    SQLInjectionDetector,
    PathTraversalDetector,
    get_documentation,
)


class TestSyslogParser(unittest.TestCase):
    """Tests for syslog format parsing."""

    def setUp(self):
        self.parser = SyslogParser()

    def test_basic_syslog_line(self):
        """Test parsing a basic syslog entry."""
        line = "Jan 15 10:23:45 server1 sshd[12345]: Connection from 192.168.1.100"
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.log_format, "syslog")
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.action, "sshd")
        self.assertEqual(entry.line_number, 1)

    def test_syslog_without_pid(self):
        """Test parsing syslog entry without PID."""
        line = "Jan 15 10:23:45 server1 kernel: Device eth0 entered promiscuous mode"
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "kernel")

    def test_invalid_line(self):
        """Test that invalid lines return None."""
        line = "This is not a valid syslog line"
        entry = self.parser.parse_line(line, 1)
        self.assertIsNone(entry)


class TestAuthLogParser(unittest.TestCase):
    """Tests for auth.log format parsing."""

    def setUp(self):
        self.parser = AuthLogParser()

    def test_failed_login(self):
        """Test parsing failed login attempts."""
        line = "Jan 15 10:23:45 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2"
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "failed_login")
        self.assertEqual(entry.user, "admin")
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.severity, "WARNING")

    def test_successful_login(self):
        """Test parsing successful login."""
        line = "Jan 15 10:23:45 server1 sshd[12345]: Accepted publickey for root from 192.168.1.50 port 22 ssh2"
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "successful_login")
        self.assertEqual(entry.user, "root")
        self.assertEqual(entry.source_ip, "192.168.1.50")

    def test_session_opened(self):
        """Test parsing session opened."""
        line = "Jan 15 10:23:45 server1 sshd[12345]: pam_unix(sshd:session): session opened for user john"
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "session_opened")
        self.assertEqual(entry.user, "john")


class TestApacheLogParser(unittest.TestCase):
    """Tests for Apache log format parsing."""

    def setUp(self):
        self.parser = ApacheLogParser()

    def test_combined_log_format(self):
        """Test parsing Apache combined log format."""
        line = '192.168.1.100 - john [15/Jan/2024:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.source_ip, "192.168.1.100")
        self.assertEqual(entry.user, "john")
        self.assertEqual(entry.action, "HTTP_200")
        self.assertIn("GET /index.html", entry.message)
        self.assertEqual(entry.severity, "INFO")

    def test_404_status(self):
        """Test parsing 404 response."""
        line = '192.168.1.100 - - [15/Jan/2024:10:23:45 +0000] "GET /notfound HTTP/1.1" 404 0 "-" "curl"'
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "HTTP_404")
        self.assertEqual(entry.severity, "WARNING")
        self.assertIsNone(entry.user)

    def test_500_status(self):
        """Test parsing 500 response."""
        line = '192.168.1.100 - - [15/Jan/2024:10:23:45 +0000] "POST /api HTTP/1.1" 500 0 "-" "curl"'
        entry = self.parser.parse_line(line, 1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.action, "HTTP_500")
        self.assertEqual(entry.severity, "ERROR")


class TestBruteForceDetector(unittest.TestCase):
    """Tests for brute force detection rule."""

    def setUp(self):
        self.detector = BruteForceDetector(threshold=3, window_minutes=5)

    def test_detect_brute_force(self):
        """Test detection of brute force attack."""
        now = datetime.now()
        entries = [
            LogEntry(
                timestamp=now + timedelta(seconds=i*10),
                source_ip="192.168.1.100",
                user="admin",
                action="failed_login",
                message=f"Failed password for admin",
                raw_line=f"Failed login attempt {i}"
            )
            for i in range(5)
        ]

        alerts = self.detector.analyze(entries)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertIn("192.168.1.100", alerts[0].source_ips)

    def test_no_alert_under_threshold(self):
        """Test no alert when under threshold."""
        now = datetime.now()
        entries = [
            LogEntry(
                timestamp=now + timedelta(seconds=i*10),
                source_ip="192.168.1.100",
                user="admin",
                action="failed_login",
                message="Failed password",
                raw_line="Failed login"
            )
            for i in range(2)  # Under threshold
        ]

        alerts = self.detector.analyze(entries)
        self.assertEqual(len(alerts), 0)


class TestPasswordSprayDetector(unittest.TestCase):
    """Tests for password spray detection rule."""

    def setUp(self):
        self.detector = PasswordSprayDetector(threshold=3, window_minutes=10)

    def test_detect_password_spray(self):
        """Test detection of password spray attack."""
        now = datetime.now()
        users = ["alice", "bob", "charlie", "david", "eve"]
        entries = [
            LogEntry(
                timestamp=now + timedelta(seconds=i*10),
                source_ip="192.168.1.100",
                user=users[i],
                action="failed_login",
                message=f"Failed password for {users[i]}",
                raw_line=f"Failed login for {users[i]}"
            )
            for i in range(5)
        ]

        alerts = self.detector.analyze(entries)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "CRITICAL")


class TestSQLInjectionDetector(unittest.TestCase):
    """Tests for SQL injection detection rule."""

    def setUp(self):
        self.detector = SQLInjectionDetector()

    def test_detect_union_select(self):
        """Test detection of UNION SELECT injection."""
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                user=None,
                action="HTTP_200",
                message="GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1",
                raw_line="SQL injection attempt",
                log_format="apache"
            )
        ]

        alerts = self.detector.analyze(entries)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_detect_or_1_equals_1(self):
        """Test detection of OR 1=1 injection."""
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                user=None,
                action="HTTP_200",
                message="GET /login?user=admin' OR 1=1-- HTTP/1.1",
                raw_line="SQL injection attempt",
                log_format="apache"
            )
        ]

        alerts = self.detector.analyze(entries)
        self.assertEqual(len(alerts), 1)


class TestPathTraversalDetector(unittest.TestCase):
    """Tests for path traversal detection rule."""

    def setUp(self):
        self.detector = PathTraversalDetector()

    def test_detect_dot_dot_slash(self):
        """Test detection of ../ traversal."""
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                user=None,
                action="HTTP_200",
                message="GET /files/../../../etc/passwd HTTP/1.1",
                raw_line="Path traversal attempt",
                log_format="apache"
            )
        ]

        alerts = self.detector.analyze(entries)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_detect_encoded_traversal(self):
        """Test detection of URL-encoded traversal."""
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                source_ip="192.168.1.100",
                user=None,
                action="HTTP_200",
                message="GET /files/%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1",
                raw_line="Encoded path traversal",
                log_format="apache"
            )
        ]

        alerts = self.detector.analyze(entries)
        self.assertEqual(len(alerts), 1)


class TestLogAnalyzer(unittest.TestCase):
    """Integration tests for LogAnalyzer."""

    def setUp(self):
        self.analyzer = LogAnalyzer()

    def test_format_detection_auth(self):
        """Test auto-detection of auth log format."""
        sample = [
            "Jan 15 10:23:45 server1 sshd[12345]: Failed password for admin from 192.168.1.100 port 22"
        ]
        detected = self.analyzer.detect_format(sample)
        self.assertIn(detected, ['auth', 'syslog'])

    def test_format_detection_apache(self):
        """Test auto-detection of Apache log format."""
        sample = [
            '192.168.1.100 - - [15/Jan/2024:10:23:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla"'
        ]
        detected = self.analyzer.detect_format(sample)
        self.assertEqual(detected, 'apache')

    def test_plan_mode(self):
        """Test planning mode output."""
        plan = self.analyzer.get_plan(
            log_files=['/var/log/auth.log'],
            log_format='auth',
            output_format='text',
            rules_enabled=[]
        )

        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("BRUTE_FORCE_DETECTION", plan)
        self.assertIn("No actions will be taken", plan)


class TestDocumentation(unittest.TestCase):
    """Tests for documentation function."""

    def test_documentation_structure(self):
        """Test that documentation returns required fields."""
        docs = get_documentation()

        self.assertIn("name", docs)
        self.assertIn("description", docs)
        self.assertIn("features", docs)
        self.assertIn("usage_examples", docs)
        self.assertIn("arguments", docs)
        self.assertEqual(docs["name"], "log-analyzer")


if __name__ == '__main__':
    unittest.main(verbosity=2)
