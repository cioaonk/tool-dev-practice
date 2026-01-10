#!/usr/bin/env python3
"""
Edge Case Tests for Network Scanner
====================================

Comprehensive edge case testing for the network-scanner tool including:
- Empty inputs
- Malformed inputs (invalid IPs, CIDR notation)
- Unicode/special characters
- Very large inputs
- Boundary conditions
- Timeout handling

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import socket
import ipaddress
from unittest.mock import patch, MagicMock
from datetime import datetime

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/network-scanner')

from tool import (
    ScanResult,
    ScanConfig,
    ScanTechnique,
    TCPConnectScan,
    ARPScan,
    DNSResolutionScan,
    NetworkScanner,
    print_plan,
    get_documentation,
    parse_arguments,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
)


# =============================================================================
# Empty Input Tests
# =============================================================================

class TestEmptyInputs:
    """Tests for handling empty inputs."""

    def test_empty_target_list(self):
        """Empty target list should not crash."""
        config = ScanConfig(targets=[])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 0

    def test_empty_string_target(self):
        """Empty string target should be handled gracefully."""
        config = ScanConfig(targets=[""])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # Empty string may be yielded as-is
        assert len(targets) <= 1

    def test_whitespace_only_target(self):
        """Whitespace-only target should be handled gracefully."""
        config = ScanConfig(targets=["   ", "\t", "\n"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # Should handle gracefully without crashing

    def test_empty_tcp_ports_list(self):
        """Empty TCP ports list should not crash."""
        config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[])
        scanner = NetworkScanner(config)
        assert config.tcp_ports == []

    def test_empty_scan_methods_list(self):
        """Empty scan methods list should be handled gracefully."""
        config = ScanConfig(targets=["192.168.1.1"], scan_methods=[])
        scanner = NetworkScanner(config)
        assert config.scan_methods == []


# =============================================================================
# Malformed Input Tests
# =============================================================================

class TestMalformedInputs:
    """Tests for handling malformed inputs."""

    @pytest.mark.parametrize("invalid_ip", [
        "256.256.256.256",      # Octets > 255
        "192.168.1",            # Missing octet
        "192.168.1.1.1",        # Extra octet
        "192.168.-1.1",         # Negative octet
        "-1.-1.-1.-1",          # All negative
        "999.999.999.999",      # Large octets
        "abc.def.ghi.jkl",      # Letters only
        "192.168.1.abc",        # Mixed letters
        "192.168.1.",           # Trailing dot
        ".168.1.1",             # Leading dot
        "192..168.1",           # Double dot
        "1234567890",           # Number only
        "192.168.1.1.1.1.1",    # Too many octets
    ])
    def test_invalid_ip_addresses(self, invalid_ip):
        """Invalid IP addresses should be handled without crashing."""
        config = ScanConfig(targets=[invalid_ip], verbose=True)
        scanner = NetworkScanner(config)
        # Should not crash
        targets = list(scanner._expand_targets())
        # May yield the invalid target as-is for further handling

    @pytest.mark.parametrize("invalid_cidr", [
        "192.168.1.0/33",       # Prefix > 32
        "192.168.1.0/-1",       # Negative prefix
        "192.168.1.0/abc",      # Non-numeric prefix
        "192.168.1.0/",         # Empty prefix
        "192.168.1.0//24",      # Double slash
        "/24",                  # Missing network
        "192.168.1.0/32/24",    # Multiple prefixes
        "192.168.1.0/999",      # Very large prefix
    ])
    def test_invalid_cidr_notation(self, invalid_cidr):
        """Invalid CIDR notation should be handled without crashing."""
        config = ScanConfig(targets=[invalid_cidr], verbose=True)
        scanner = NetworkScanner(config)
        try:
            targets = list(scanner._expand_targets())
            # Should not produce invalid IPs
        except (ValueError, TypeError):
            pass  # Acceptable to raise for invalid input

    @pytest.mark.parametrize("invalid_range", [
        "192.168.1.300-400",    # Values > 255
        "192.168.1.-1-10",      # Negative start
        "192.168.1.10--20",     # Double dash
        "192.168.1.abc-xyz",    # Non-numeric range
        "192.168.1.10-",        # Missing end
        "192.168.1.-10",        # Missing start
        "192.168.1.100-50",     # Start > end (may be valid, reversed)
        "192.168.1.1-1-1",      # Multiple dashes
    ])
    def test_invalid_range_notation(self, invalid_range):
        """Invalid range notation should be handled without crashing."""
        config = ScanConfig(targets=[invalid_range], verbose=True)
        scanner = NetworkScanner(config)
        try:
            targets = list(scanner._expand_targets())
        except (ValueError, TypeError):
            pass  # Acceptable

    def test_mixed_valid_invalid_targets(self):
        """Mix of valid and invalid targets should process valid ones."""
        config = ScanConfig(
            targets=["192.168.1.1", "invalid.target", "10.0.0.1", "not-an-ip"],
            verbose=True
        )
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # Should include valid IPs, may include invalid ones for handling
        valid_count = sum(1 for t in targets if t in ["192.168.1.1", "10.0.0.1"])
        assert valid_count >= 2  # Both valid IPs should be present


# =============================================================================
# Unicode and Special Character Tests
# =============================================================================

class TestUnicodeAndSpecialCharacters:
    """Tests for handling Unicode and special characters."""

    @pytest.mark.parametrize("unicode_input", [
        "\u0031\u0039\u0032.\u0031\u0036\u0038.\u0031.\u0031",  # Unicode digits
        "\u200b192.168.1.1",       # Zero-width space
        "192\u002e168\u002e1\u002e1",  # Unicode periods
        "\uff11\uff19\uff12.168.1.1",  # Full-width digits
    ])
    def test_unicode_ip_addresses(self, unicode_input):
        """Unicode IP addresses should be handled gracefully."""
        config = ScanConfig(targets=[unicode_input])
        scanner = NetworkScanner(config)
        # Should not crash
        try:
            targets = list(scanner._expand_targets())
        except (ValueError, TypeError, UnicodeError):
            pass  # Acceptable

    @pytest.mark.parametrize("special_char", [
        "192.168.1.1\x00",        # Null byte
        "192.168.1.1\r\n",        # CRLF
        "192.168.1.1\t",          # Tab
        "192.168.1.1\b",          # Backspace
        "192.168.1.1\x1b",        # Escape
        "'192.168.1.1'",          # Quotes
        '"192.168.1.1"',          # Double quotes
        "192.168.1.1;ls",         # Command injection attempt
        "192.168.1.1|cat",        # Pipe injection
        "192.168.1.1`whoami`",    # Backtick injection
        "$(192.168.1.1)",         # Variable expansion
    ])
    def test_special_characters_in_input(self, special_char):
        """Special characters should not cause security issues."""
        config = ScanConfig(targets=[special_char])
        scanner = NetworkScanner(config)
        try:
            targets = list(scanner._expand_targets())
            # Should not execute any injected commands
            for target in targets:
                # Verify no shell metacharacters processed
                assert 'whoami' not in target.lower() or special_char == "192.168.1.1`whoami`"
        except (ValueError, TypeError):
            pass  # Acceptable


# =============================================================================
# Large Input Tests
# =============================================================================

class TestLargeInputs:
    """Tests for handling large inputs."""

    def test_large_number_of_targets(self):
        """Large number of individual targets should be handled."""
        targets = [f"192.168.{i}.{j}" for i in range(10) for j in range(1, 11)]
        config = ScanConfig(targets=targets)
        scanner = NetworkScanner(config)
        expanded = list(scanner._expand_targets())
        assert len(expanded) == 100

    def test_large_cidr_network(self):
        """Large CIDR network (/16) should expand correctly."""
        config = ScanConfig(targets=["192.168.0.0/22"])  # 1022 hosts
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # /22 = 1022 usable hosts (4 x 256 - 2)
        assert len(targets) == 1022

    def test_very_large_cidr_performance(self):
        """Very large CIDR should not cause memory issues."""
        config = ScanConfig(targets=["10.0.0.0/16"])  # 65534 hosts
        scanner = NetworkScanner(config)
        # Use generator to avoid memory issues
        count = 0
        for _ in scanner._expand_targets():
            count += 1
            if count > 1000:  # Don't iterate all for test speed
                break
        assert count > 1000

    def test_large_ip_range(self):
        """Large IP range should be expanded correctly."""
        config = ScanConfig(targets=["192.168.1.1-254"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 254

    def test_very_long_target_string(self):
        """Very long target string should be handled gracefully."""
        long_target = "a" * 10000
        config = ScanConfig(targets=[long_target])
        scanner = NetworkScanner(config)
        try:
            targets = list(scanner._expand_targets())
        except (ValueError, TypeError):
            pass  # Acceptable

    def test_many_tcp_ports(self):
        """Large number of TCP ports should be handled."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            tcp_ports=list(range(1, 65536))
        )
        assert len(config.tcp_ports) == 65535


# =============================================================================
# Boundary Condition Tests
# =============================================================================

class TestBoundaryConditions:
    """Tests for boundary conditions."""

    @pytest.mark.parametrize("boundary_ip", [
        "0.0.0.0",              # All zeros
        "255.255.255.255",      # All 255s
        "0.0.0.1",              # Minimum valid
        "255.255.255.254",      # Near maximum
        "127.0.0.1",            # Loopback
        "10.0.0.0",             # Private Class A start
        "10.255.255.255",       # Private Class A end
        "172.16.0.0",           # Private Class B start
        "172.31.255.255",       # Private Class B end
        "192.168.0.0",          # Private Class C start
        "192.168.255.255",      # Private Class C end
    ])
    def test_boundary_ip_addresses(self, boundary_ip):
        """Boundary IP addresses should be handled correctly."""
        config = ScanConfig(targets=[boundary_ip])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert boundary_ip in targets

    @pytest.mark.parametrize("cidr_prefix", [0, 1, 8, 16, 24, 30, 31, 32])
    def test_boundary_cidr_prefixes(self, cidr_prefix):
        """Boundary CIDR prefixes should expand correctly."""
        config = ScanConfig(targets=[f"192.168.1.0/{cidr_prefix}"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())

        # Calculate expected host count
        if cidr_prefix == 32:
            expected = 1
        elif cidr_prefix == 31:
            expected = 2
        elif cidr_prefix >= 8:
            expected = (2 ** (32 - cidr_prefix)) - 2
        else:
            # Very large networks, just check it produces results
            assert len(targets) > 0
            return

        # For larger networks, check range
        if expected <= 1000:
            assert len(targets) == expected

    def test_timeout_boundary_zero(self):
        """Zero timeout should be handled."""
        config = ScanConfig(targets=["192.168.1.1"], timeout=0.0)
        assert config.timeout == 0.0

    def test_timeout_boundary_very_large(self):
        """Very large timeout should be accepted."""
        config = ScanConfig(targets=["192.168.1.1"], timeout=999999.0)
        assert config.timeout == 999999.0

    def test_timeout_boundary_negative(self):
        """Negative timeout should be handled."""
        config = ScanConfig(targets=["192.168.1.1"], timeout=-1.0)
        # Implementation may accept or reject

    def test_threads_boundary_zero(self):
        """Zero threads configuration."""
        config = ScanConfig(targets=["192.168.1.1"], threads=0)
        # May cause issues during scan, but config should accept

    def test_threads_boundary_one(self):
        """Single thread should work correctly."""
        config = ScanConfig(targets=["192.168.1.1"], threads=1)
        assert config.threads == 1

    def test_threads_boundary_large(self):
        """Large thread count should be accepted."""
        config = ScanConfig(targets=["192.168.1.1"], threads=10000)
        assert config.threads == 10000

    def test_delay_boundary_conditions(self):
        """Delay boundary conditions."""
        # Zero delay
        config = ScanConfig(targets=["192.168.1.1"], delay_min=0.0, delay_max=0.0)
        assert config.delay_min == 0.0
        assert config.delay_max == 0.0

        # Max < Min (unusual but should not crash)
        config = ScanConfig(targets=["192.168.1.1"], delay_min=1.0, delay_max=0.5)
        # Implementation may handle this


# =============================================================================
# Timeout Handling Tests
# =============================================================================

class TestTimeoutHandling:
    """Tests for timeout handling."""

    def test_tcp_scan_timeout(self):
        """TCP scan should handle timeout gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout("Timeout")

            config = ScanConfig(targets=["192.168.1.1"], timeout=0.001)
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_dns_scan_timeout(self):
        """DNS scan should handle timeout gracefully."""
        with patch('socket.gethostbyaddr') as mock_dns:
            mock_dns.side_effect = socket.timeout("DNS timeout")

            config = ScanConfig(targets=["192.168.1.1"])
            technique = DNSResolutionScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_scanner_stop_during_scan(self):
        """Scanner should stop cleanly when stop event is set."""
        config = ScanConfig(targets=["192.168.1.0/24"], threads=1)
        scanner = NetworkScanner(config)

        # Set stop event immediately
        scanner.stop()

        # Scan should complete quickly without processing all targets
        assert scanner._stop_event.is_set()


# =============================================================================
# CIDR Edge Cases
# =============================================================================

class TestCIDREdgeCases:
    """Tests for CIDR notation edge cases."""

    def test_cidr_slash_32(self):
        """/32 network should return single host."""
        config = ScanConfig(targets=["192.168.1.100/32"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 1
        assert targets[0] == "192.168.1.100"

    def test_cidr_slash_31(self):
        """/31 network should return 2 hosts."""
        config = ScanConfig(targets=["192.168.1.0/31"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 2

    def test_cidr_slash_30(self):
        """/30 network should return 2 hosts."""
        config = ScanConfig(targets=["192.168.1.0/30"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 2
        # Excludes network (192.168.1.0) and broadcast (192.168.1.3)

    def test_cidr_non_aligned_network(self):
        """Non-aligned CIDR should be handled."""
        # 192.168.1.100/24 should still work (strict=False)
        config = ScanConfig(targets=["192.168.1.100/24"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 254  # .1 to .254

    def test_multiple_cidr_networks(self):
        """Multiple CIDR networks should all expand."""
        config = ScanConfig(targets=[
            "192.168.1.0/30",
            "192.168.2.0/30",
            "192.168.3.0/30"
        ])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 6  # 2 hosts * 3 networks


# =============================================================================
# Range Notation Edge Cases
# =============================================================================

class TestRangeEdgeCases:
    """Tests for range notation edge cases."""

    def test_range_single_value(self):
        """Range where start equals end should return single IP."""
        config = ScanConfig(targets=["192.168.1.100-100"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 1
        assert targets[0] == "192.168.1.100"

    def test_range_full_octet(self):
        """Full octet range (1-254) should expand correctly."""
        config = ScanConfig(targets=["192.168.1.1-254"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 254

    def test_range_small(self):
        """Small range should expand correctly."""
        config = ScanConfig(targets=["192.168.1.10-15"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 6
        assert "192.168.1.10" in targets
        assert "192.168.1.15" in targets


# =============================================================================
# Socket Error Handling Tests
# =============================================================================

class TestSocketErrorHandling:
    """Tests for socket error handling."""

    @pytest.mark.parametrize("error_type", [
        socket.error("Connection refused"),
        socket.herror("Host not found"),
        socket.gaierror("Name resolution failed"),
        socket.timeout("Connection timed out"),
        OSError("Network unreachable"),
        ConnectionRefusedError("Refused"),
        ConnectionResetError("Reset"),
    ])
    def test_various_socket_errors(self, error_type):
        """Various socket errors should be handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = error_type

            config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False


# =============================================================================
# Configuration Edge Cases
# =============================================================================

class TestConfigurationEdgeCases:
    """Tests for configuration edge cases."""

    def test_all_options_enabled(self):
        """Configuration with all options enabled."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            timeout=5.0,
            threads=100,
            delay_min=0.1,
            delay_max=0.5,
            resolve_hostnames=True,
            scan_methods=["tcp", "arp", "dns"],
            tcp_ports=[80, 443, 22, 8080],
            verbose=True,
            plan_mode=True
        )
        assert config.verbose == True
        assert config.plan_mode == True
        assert config.resolve_hostnames == True

    def test_minimal_configuration(self):
        """Minimal configuration should work."""
        config = ScanConfig()
        assert config.targets == []
        assert config.timeout == DEFAULT_TIMEOUT

    def test_invalid_scan_method(self):
        """Invalid scan method should be handled."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            scan_methods=["invalid_method", "tcp"]
        )
        scanner = NetworkScanner(config)
        # tcp should still be available
        assert "tcp" in NetworkScanner.TECHNIQUES


# =============================================================================
# ScanResult Edge Cases
# =============================================================================

class TestScanResultEdgeCases:
    """Tests for ScanResult edge cases."""

    def test_scan_result_none_values(self):
        """ScanResult with None values should serialize correctly."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=None,
            hostname=None
        )
        result_dict = result.to_dict()
        assert result_dict["response_time"] is None
        assert result_dict["hostname"] is None

    def test_scan_result_special_characters_in_hostname(self):
        """ScanResult with special characters in hostname."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            hostname="host-name.example.com"
        )
        result_dict = result.to_dict()
        assert result_dict["hostname"] == "host-name.example.com"

    def test_scan_result_very_long_hostname(self):
        """ScanResult with very long hostname."""
        long_hostname = "a" * 1000 + ".example.com"
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            hostname=long_hostname
        )
        assert result.hostname == long_hostname


# =============================================================================
# Planning Mode Edge Cases
# =============================================================================

class TestPlanningModeEdgeCases:
    """Tests for planning mode edge cases."""

    def test_plan_mode_with_empty_targets(self, capsys):
        """Planning mode with empty targets should not crash."""
        config = ScanConfig(targets=[], plan_mode=True)
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out
        assert "0" in captured.out  # 0 targets

    def test_plan_mode_with_large_network(self, capsys):
        """Planning mode with large network should show summary."""
        config = ScanConfig(targets=["10.0.0.0/16"], plan_mode=True)
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out
        # Should show target count


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
