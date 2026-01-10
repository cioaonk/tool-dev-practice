#!/usr/bin/env python3
"""
Test Suite for DNS Enumerator
==============================

Comprehensive tests for the DNS enumeration tool including
plan mode, documentation, and mock DNS operations.
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
    DNSRecord,
    EnumConfig,
    RecordType,
    DNSResolver,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_SUBDOMAINS
)


class TestDNSRecord(unittest.TestCase):
    """Tests for DNSRecord dataclass."""

    def test_record_creation(self):
        """Test creating a DNSRecord instance."""
        record = DNSRecord(
            name="www.example.com",
            record_type="A",
            value="93.184.216.34"
        )

        self.assertEqual(record.name, "www.example.com")
        self.assertEqual(record.record_type, "A")
        self.assertEqual(record.value, "93.184.216.34")

    def test_record_with_ttl(self):
        """Test record with TTL."""
        record = DNSRecord(
            name="example.com",
            record_type="MX",
            value="mail.example.com",
            ttl=3600,
            priority=10
        )

        self.assertEqual(record.ttl, 3600)
        self.assertEqual(record.priority, 10)

    def test_record_to_dict(self):
        """Test serialization to dictionary."""
        record = DNSRecord(
            name="ns1.example.com",
            record_type="NS",
            value="dns1.example.com",
            ttl=86400
        )

        data = record.to_dict()

        self.assertIn("name", data)
        self.assertIn("type", data)
        self.assertEqual(data["ttl"], 86400)


class TestEnumConfig(unittest.TestCase):
    """Tests for EnumConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = EnumConfig()

        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.threads, DEFAULT_THREADS)
        self.assertEqual(config.plan_mode, False)
        self.assertTrue(config.brute_force)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = EnumConfig(
            domain="example.com",
            nameserver="8.8.8.8",
            wordlist=["www", "mail", "ftp"],
            zone_transfer=True,
            plan_mode=True
        )

        self.assertEqual(config.domain, "example.com")
        self.assertEqual(config.nameserver, "8.8.8.8")
        self.assertTrue(config.zone_transfer)
        self.assertTrue(config.plan_mode)

    def test_config_record_types(self):
        """Test default record types."""
        config = EnumConfig()

        self.assertIn("A", config.record_types)
        self.assertIn("AAAA", config.record_types)


class TestRecordType(unittest.TestCase):
    """Tests for RecordType enum."""

    def test_record_type_values(self):
        """Test record type values."""
        self.assertEqual(RecordType.A.value, 1)
        self.assertEqual(RecordType.NS.value, 2)
        self.assertEqual(RecordType.MX.value, 15)
        self.assertEqual(RecordType.TXT.value, 16)
        self.assertEqual(RecordType.AAAA.value, 28)

    def test_all_common_types(self):
        """Test common record types are defined."""
        expected_types = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"]

        defined_types = [t.name for t in RecordType]

        for exp in expected_types:
            self.assertIn(exp, defined_types)


class TestDNSResolver(unittest.TestCase):
    """Tests for DNSResolver class."""

    def test_resolver_creation(self):
        """Test DNS resolver can be created."""
        resolver = DNSResolver(nameserver="8.8.8.8", timeout=5.0)

        self.assertEqual(resolver.nameserver, "8.8.8.8")
        self.assertEqual(resolver.timeout, 5.0)

    def test_resolver_default_nameserver(self):
        """Test resolver default nameserver."""
        resolver = DNSResolver()

        self.assertEqual(resolver.nameserver, "8.8.8.8")

    @patch('socket.socket')
    def test_resolver_query_building(self, mock_socket_class):
        """Test DNS query packet building."""
        resolver = DNSResolver()

        # Build query for A record
        query = resolver._build_query("example.com", RecordType.A)

        # Should produce a bytes object
        self.assertIsInstance(query, bytes)
        self.assertTrue(len(query) > 0)

        # Should contain the domain name
        self.assertIn(b"example", query)


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
        self.assertIn("dns", doc["name"].lower())


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

    def test_parser_domain_argument(self):
        """Test parser has domain argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--domain', 'example.com'])

        self.assertEqual(args.domain, 'example.com')

    def test_parser_nameserver_argument(self):
        """Test parser accepts nameserver."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--domain', 'example.com',
            '--nameserver', '1.1.1.1'
        ])

        self.assertEqual(args.nameserver, '1.1.1.1')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = EnumConfig(
            domain="example.com",
            wordlist=["www", "mail", "ftp"],
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

    def test_plan_mode_shows_domain(self):
        """Test that plan output shows domain."""
        config = EnumConfig(
            domain="example.com",
            wordlist=["www"],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("example.com", output)

    def test_plan_mode_shows_subdomain_count(self):
        """Test that plan shows number of subdomains."""
        config = EnumConfig(
            domain="example.com",
            wordlist=["www", "mail", "ftp", "api", "dev"],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        # Should show subdomain count
        self.assertTrue("5" in output or "subdomain" in output.lower())


class TestDefaultSubdomains(unittest.TestCase):
    """Tests for default subdomain list."""

    def test_default_subdomains_not_empty(self):
        """Test default subdomain list has entries."""
        self.assertTrue(len(DEFAULT_SUBDOMAINS) > 0)

    def test_default_subdomains_has_common(self):
        """Test default list has common subdomains."""
        common = ["www", "mail", "ftp", "admin", "api"]

        for subdomain in common:
            self.assertIn(subdomain, DEFAULT_SUBDOMAINS)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_domain_error(self):
        """Test error handling for missing domain."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])


# =============================================================================
# Test Fixtures
# =============================================================================

class DNSEnumeratorFixtures:
    """Test fixtures for DNS enumerator."""

    # Sample DNS records
    RECORDS = {
        "example.com": [
            DNSRecord("example.com", "A", "93.184.216.34", ttl=3600),
            DNSRecord("example.com", "NS", "ns1.example.com", ttl=86400),
            DNSRecord("example.com", "MX", "mail.example.com", ttl=3600, priority=10)
        ],
        "www.example.com": [
            DNSRecord("www.example.com", "A", "93.184.216.34", ttl=3600),
            DNSRecord("www.example.com", "CNAME", "example.com", ttl=3600)
        ]
    }

    # Common subdomains
    SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "imap",
        "admin", "ns1", "ns2", "api", "dev", "staging"
    ]

    @classmethod
    def get_records(cls, domain: str):
        """Get records for a domain."""
        return cls.RECORDS.get(domain, [])

    @classmethod
    def get_mock_dns_response(cls, domain: str):
        """Get a mock DNS response."""
        records = cls.get_records(domain)

        if records:
            return {
                "status": "success",
                "records": [r.to_dict() for r in records]
            }
        return {"status": "nxdomain", "records": []}


if __name__ == '__main__':
    unittest.main(verbosity=2)
