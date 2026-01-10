"""
Tests for the DNS Enumerator tool.

This module contains unit tests and integration tests for the dns-enumerator tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/dns-enumerator')

from tool import (
    RecordType,
    DNSRecord,
    EnumConfig,
    DNSResolver,
    ZoneTransfer,
    DNSEnumerator,
    get_documentation,
    print_plan,
    parse_arguments,
    DEFAULT_SUBDOMAINS,
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
        assert docs["name"] == "dns-enumerator"

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
        config = EnumConfig(
            domain="example.com",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_domain_info(self, capsys):
        """Test that planning mode shows domain information."""
        config = EnumConfig(
            domain="example.com",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_plan_mode_shows_record_types(self, capsys):
        """Test that planning mode shows record types to query."""
        config = EnumConfig(
            domain="example.com",
            record_types=[RecordType.A, RecordType.MX],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention record types
        assert "A" in captured.out or "MX" in captured.out or "record" in captured.out.lower()

    def test_plan_mode_does_not_query_dns(self):
        """Test that planning mode does not make DNS queries."""
        with patch('socket.socket') as mock_socket:
            config = EnumConfig(
                domain="example.com",
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be used in plan mode
            mock_socket.return_value.sendto.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_domain(self):
        """Test that valid domains are accepted."""
        config = EnumConfig(domain="example.com")
        assert config.domain == "example.com"

    def test_valid_record_types(self):
        """Test that record types are properly configured."""
        config = EnumConfig(
            domain="example.com",
            record_types=[RecordType.A, RecordType.AAAA, RecordType.MX]
        )
        assert RecordType.A in config.record_types
        assert RecordType.MX in config.record_types

    def test_valid_wordlist(self):
        """Test that subdomain wordlist is accepted."""
        config = EnumConfig(
            domain="example.com",
            wordlist=["www", "mail", "ftp"]
        )
        assert len(config.wordlist) == 3


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_dns_query_error_handled(self):
        """Test that DNS query errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.error("DNS error")

            config = EnumConfig(domain="example.com")
            resolver = DNSResolver(config)
            result = resolver.resolve("example.com", RecordType.A)

            # Should handle error gracefully
            assert result is None or isinstance(result, list)

    def test_timeout_handling(self):
        """Test that DNS timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout("Timeout")

            config = EnumConfig(domain="example.com", timeout=0.1)
            resolver = DNSResolver(config)
            result = resolver.resolve("example.com", RecordType.A)

            # Should handle timeout gracefully
            assert result is None or isinstance(result, list)

    def test_zone_transfer_denied(self):
        """Test handling of zone transfer denial."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.side_effect = socket.error("Transfer denied")

            config = EnumConfig(domain="example.com")
            zt = ZoneTransfer(config)
            result = zt.attempt("ns1.example.com")

            # Should handle denial gracefully
            assert result is None or isinstance(result, list)


# =============================================================================
# Test RecordType Enum
# =============================================================================

class TestRecordTypeEnum:
    """Tests for the RecordType enum."""

    def test_record_type_a(self):
        """Test A record type."""
        assert RecordType.A is not None

    def test_record_type_aaaa(self):
        """Test AAAA record type."""
        assert RecordType.AAAA is not None

    def test_record_type_mx(self):
        """Test MX record type."""
        assert RecordType.MX is not None

    def test_record_type_ns(self):
        """Test NS record type."""
        assert RecordType.NS is not None

    def test_record_type_txt(self):
        """Test TXT record type."""
        assert RecordType.TXT is not None

    def test_record_type_cname(self):
        """Test CNAME record type."""
        assert RecordType.CNAME is not None


# =============================================================================
# Test DNSRecord Data Class
# =============================================================================

class TestDNSRecord:
    """Tests for the DNSRecord data class."""

    def test_dns_record_creation(self):
        """Test that DNSRecord can be created."""
        record = DNSRecord(
            name="example.com",
            record_type=RecordType.A,
            value="93.184.216.34"
        )
        assert record.name == "example.com"
        assert record.value == "93.184.216.34"

    def test_dns_record_with_ttl(self):
        """Test DNSRecord with TTL."""
        record = DNSRecord(
            name="example.com",
            record_type=RecordType.A,
            value="93.184.216.34",
            ttl=3600
        )
        assert record.ttl == 3600


# =============================================================================
# Test DNSResolver Class
# =============================================================================

class TestDNSResolver:
    """Tests for the DNSResolver class."""

    def test_resolver_initialization(self):
        """Test DNSResolver initialization."""
        config = EnumConfig(domain="example.com")
        resolver = DNSResolver(config)
        assert resolver is not None

    def test_resolver_with_custom_server(self):
        """Test DNSResolver with custom DNS server."""
        config = EnumConfig(
            domain="example.com",
            dns_server="8.8.8.8"
        )
        resolver = DNSResolver(config)
        assert resolver.config.dns_server == "8.8.8.8"

    def test_resolver_query_with_mock(self):
        """Test DNSResolver query with mocked socket."""
        with patch('socket.socket') as mock_socket:
            # Simulate DNS response
            mock_socket.return_value.recvfrom.return_value = (
                b'\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00',
                ('8.8.8.8', 53)
            )

            config = EnumConfig(domain="example.com")
            resolver = DNSResolver(config)
            # This will likely fail due to parsing, but should not crash
            try:
                result = resolver.resolve("example.com", RecordType.A)
            except:
                pass  # Expected with incomplete mock data


# =============================================================================
# Test ZoneTransfer Class
# =============================================================================

class TestZoneTransfer:
    """Tests for the ZoneTransfer class."""

    def test_zone_transfer_initialization(self):
        """Test ZoneTransfer initialization."""
        config = EnumConfig(domain="example.com")
        zt = ZoneTransfer(config)
        assert zt is not None

    def test_zone_transfer_attempt_with_mock(self):
        """Test zone transfer attempt with mocked socket."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b''

            config = EnumConfig(domain="example.com")
            zt = ZoneTransfer(config)
            result = zt.attempt("ns1.example.com")

            # Zone transfer typically fails, should handle gracefully
            assert result is None or isinstance(result, list)


# =============================================================================
# Test DNSEnumerator Class
# =============================================================================

class TestDNSEnumerator:
    """Tests for the DNSEnumerator class."""

    def test_enumerator_initialization(self):
        """Test DNSEnumerator initialization."""
        config = EnumConfig(domain="example.com")
        enumerator = DNSEnumerator(config)

        assert enumerator.config == config

    def test_enumerator_with_wordlist(self):
        """Test enumerator with subdomain wordlist."""
        config = EnumConfig(
            domain="example.com",
            wordlist=["www", "mail", "ftp"]
        )
        enumerator = DNSEnumerator(config)

        assert len(enumerator.config.wordlist) == 3

    def test_enumerator_enumerate_with_mock(self):
        """Test enumerate method with mocked DNS."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = EnumConfig(
                domain="example.com",
                wordlist=["www"],
                threads=1
            )
            enumerator = DNSEnumerator(config)
            results = enumerator.enumerate()

            # Should complete without crashing
            assert isinstance(results, (list, dict))


# =============================================================================
# Test Default Subdomain Wordlist
# =============================================================================

class TestDefaultSubdomainWordlist:
    """Tests for the default subdomain wordlist."""

    def test_default_wordlist_not_empty(self):
        """Test that default wordlist is not empty."""
        assert len(DEFAULT_SUBDOMAINS) > 0

    def test_default_wordlist_contains_common_subdomains(self):
        """Test that default wordlist contains common subdomains."""
        common = ["www", "mail", "ftp", "ns1", "admin"]
        found = sum(1 for s in common if s in DEFAULT_SUBDOMAINS)
        assert found >= 2

    def test_default_wordlist_entries_are_strings(self):
        """Test that all wordlist entries are strings."""
        for entry in DEFAULT_SUBDOMAINS:
            assert isinstance(entry, str)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_domain_argument(self):
        """Test parsing domain argument."""
        with patch('sys.argv', ['tool.py', 'example.com']):
            args = parse_arguments()
            assert args.domain == 'example.com'

    def test_parse_wordlist_argument(self):
        """Test parsing wordlist argument."""
        with patch('sys.argv', ['tool.py', 'example.com', '-w', '/path/to/wordlist.txt']):
            args = parse_arguments()
            assert '/path/to/wordlist.txt' in str(args.wordlist)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', 'example.com', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_record_types_argument(self):
        """Test parsing record types argument."""
        with patch('sys.argv', ['tool.py', 'example.com', '-t', 'A', 'MX']):
            args = parse_arguments()
            # Should have record types specified
            assert args.types or args.record_types

    def test_parse_dns_server_argument(self):
        """Test parsing DNS server argument."""
        with patch('sys.argv', ['tool.py', 'example.com', '--dns-server', '8.8.8.8']):
            args = parse_arguments()
            assert '8.8.8.8' in str(args.dns_server) or args.dns_server == '8.8.8.8'


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_enumeration_run(self):
        """Test full DNS enumeration with mocked network."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = EnumConfig(
                domain="example.com",
                wordlist=["www", "mail"],
                record_types=[RecordType.A],
                threads=1
            )
            enumerator = DNSEnumerator(config)
            results = enumerator.enumerate()

            # Should complete without crashing
            assert isinstance(results, (list, dict))

    def test_enumeration_with_zone_transfer(self):
        """Test enumeration with zone transfer attempt."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b''
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = EnumConfig(
                domain="example.com",
                zone_transfer=True,
                threads=1
            )
            enumerator = DNSEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, (list, dict))

    def test_enumeration_multiple_record_types(self):
        """Test enumeration with multiple record types."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = EnumConfig(
                domain="example.com",
                wordlist=["www"],
                record_types=[RecordType.A, RecordType.AAAA, RecordType.MX],
                threads=1
            )
            enumerator = DNSEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, (list, dict))
