"""
Tests for the Network Scanner tool.

This module contains unit tests and integration tests for the network-scanner tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO
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
        required_keys = ["name", "version", "category", "description", "author"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "network-scanner"

    def test_get_documentation_has_arguments(self):
        """Test that documentation includes argument definitions."""
        docs = get_documentation()
        assert "arguments" in docs
        assert isinstance(docs["arguments"], dict)
        assert "targets" in docs["arguments"]
        assert "--plan" in docs["arguments"]

    def test_get_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        docs = get_documentation()
        assert "examples" in docs
        assert isinstance(docs["examples"], list)
        assert len(docs["examples"]) > 0

    def test_get_documentation_has_features(self):
        """Test that documentation includes feature list."""
        docs = get_documentation()
        assert "features" in docs
        assert isinstance(docs["features"], list)
        assert len(docs["features"]) > 0


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = ScanConfig(
            targets=["192.168.1.0/24"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.0/24" in captured.out
        assert "Target Specification" in captured.out

    def test_plan_mode_shows_scan_methods(self, capsys):
        """Test that planning mode shows scan methods."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            scan_methods=["tcp", "dns"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "tcp" in captured.out
        assert "dns" in captured.out

    def test_plan_mode_shows_risk_assessment(self, capsys):
        """Test that planning mode includes risk assessment."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "RISK ASSESSMENT" in captured.out
        assert "Risk Level" in captured.out

    def test_plan_mode_does_not_perform_scan(self):
        """Test that planning mode does not actually perform network scans."""
        with patch('socket.socket') as mock_socket:
            config = ScanConfig(
                targets=["192.168.1.1"],
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be called in plan mode
            mock_socket.return_value.connect_ex.assert_not_called()

    def test_plan_mode_shows_opsec_considerations(self, capsys):
        """Test that planning mode shows operational security notes."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "OPSEC CONSIDERATIONS" in captured.out

    def test_plan_mode_expands_cidr(self, capsys):
        """Test that planning mode correctly expands CIDR notation."""
        config = ScanConfig(
            targets=["192.168.1.0/30"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # /30 network has 2 usable hosts
        assert "Total IPs to scan" in captured.out


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_single_ip(self):
        """Test that single IP addresses are accepted."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert "192.168.1.1" in targets

    def test_valid_cidr_notation(self):
        """Test that CIDR notation is correctly expanded."""
        config = ScanConfig(targets=["192.168.1.0/30"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 2  # /30 has 2 usable hosts
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_valid_ip_range(self):
        """Test that IP ranges are correctly expanded."""
        config = ScanConfig(targets=["192.168.1.1-3"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets
        assert "192.168.1.3" in targets

    def test_multiple_targets(self):
        """Test that multiple targets are all expanded."""
        config = ScanConfig(targets=["192.168.1.1", "192.168.1.2"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 2

    def test_invalid_target_handled_gracefully(self):
        """Test that invalid targets are handled without crashing."""
        config = ScanConfig(targets=["invalid.target.spec"], verbose=True)
        scanner = NetworkScanner(config)
        # Should not raise an exception
        targets = list(scanner._expand_targets())
        # Invalid target should be yielded as-is
        assert "invalid.target.spec" in targets

    def test_timeout_validation(self):
        """Test that timeout parameter is properly set."""
        config = ScanConfig(targets=["192.168.1.1"], timeout=5.0)
        assert config.timeout == 5.0

    def test_threads_validation(self):
        """Test that threads parameter is properly set."""
        config = ScanConfig(targets=["192.168.1.1"], threads=50)
        assert config.threads == 50

    def test_default_values(self):
        """Test that default configuration values are correct."""
        config = ScanConfig(targets=["192.168.1.1"])
        assert config.timeout == DEFAULT_TIMEOUT
        assert config.threads == DEFAULT_THREADS
        assert config.plan_mode == False
        assert config.verbose == False


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_socket_error_handled(self):
        """Test that socket errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")

            config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            # Should return a result indicating host is not alive
            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_dns_resolution_error_handled(self):
        """Test that DNS resolution errors are handled gracefully."""
        with patch('socket.gethostbyaddr') as mock_dns:
            mock_dns.side_effect = socket.herror("DNS lookup failed")

            config = ScanConfig(targets=["192.168.1.1"])
            technique = DNSResolutionScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_timeout_handling(self):
        """Test that connection timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout("Timeout")

            config = ScanConfig(targets=["192.168.1.1"], timeout=0.1)
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_scanner_stop_event(self):
        """Test that the scanner can be stopped."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        scanner.stop()
        assert scanner._stop_event.is_set()

    def test_empty_targets_list(self):
        """Test handling of empty targets list."""
        config = ScanConfig(targets=[])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert len(targets) == 0


# =============================================================================
# Test ScanResult Data Class
# =============================================================================

class TestScanResult:
    """Tests for the ScanResult data class."""

    def test_scan_result_creation(self):
        """Test that ScanResult can be created with required fields."""
        result = ScanResult(ip="192.168.1.1", is_alive=True)
        assert result.ip == "192.168.1.1"
        assert result.is_alive == True

    def test_scan_result_to_dict(self):
        """Test that ScanResult can be converted to dictionary."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=0.1,
            method="tcp_connect",
            hostname="host.example.com"
        )
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["ip"] == "192.168.1.1"
        assert result_dict["is_alive"] == True
        assert result_dict["response_time"] == 0.1
        assert result_dict["method"] == "tcp_connect"
        assert result_dict["hostname"] == "host.example.com"

    def test_scan_result_default_values(self):
        """Test ScanResult default values."""
        result = ScanResult(ip="192.168.1.1", is_alive=False)
        assert result.response_time is None
        assert result.method == "unknown"
        assert result.hostname is None
        assert isinstance(result.timestamp, datetime)


# =============================================================================
# Test Scanning Techniques
# =============================================================================

class TestScanningTechniques:
    """Tests for individual scanning techniques."""

    def test_tcp_connect_scan_technique_name(self):
        """Test TCPConnectScan technique name property."""
        technique = TCPConnectScan()
        assert technique.name == "tcp_connect"

    def test_tcp_connect_scan_description(self):
        """Test TCPConnectScan technique description."""
        technique = TCPConnectScan()
        assert isinstance(technique.description, str)
        assert len(technique.description) > 0

    def test_arp_scan_technique_name(self):
        """Test ARPScan technique name property."""
        technique = ARPScan()
        assert technique.name == "arp"

    def test_dns_scan_technique_name(self):
        """Test DNSResolutionScan technique name property."""
        technique = DNSResolutionScan()
        assert technique.name == "dns"

    def test_tcp_connect_scan_success(self):
        """Test TCPConnectScan with successful connection."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0

            config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert result.is_alive == True
            assert "tcp_connect" in result.method

    def test_tcp_connect_scan_failure(self):
        """Test TCPConnectScan with connection refused."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 111  # Connection refused

            config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert result.is_alive == False


# =============================================================================
# Test NetworkScanner Class
# =============================================================================

class TestNetworkScanner:
    """Tests for the NetworkScanner class."""

    def test_scanner_initialization(self):
        """Test NetworkScanner initialization."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)

        assert scanner.config == config
        assert isinstance(scanner.results, list)
        assert len(scanner.results) == 0

    def test_scanner_techniques_registered(self):
        """Test that scanning techniques are properly registered."""
        assert "tcp" in NetworkScanner.TECHNIQUES
        assert "arp" in NetworkScanner.TECHNIQUES
        assert "dns" in NetworkScanner.TECHNIQUES

    def test_get_live_hosts(self):
        """Test get_live_hosts method."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)

        # Add some test results
        scanner.results = [
            ScanResult(ip="192.168.1.1", is_alive=True),
            ScanResult(ip="192.168.1.2", is_alive=False),
            ScanResult(ip="192.168.1.3", is_alive=True),
        ]

        live_hosts = scanner.get_live_hosts()
        assert len(live_hosts) == 2
        assert all(h.is_alive for h in live_hosts)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_single_target(self):
        """Test parsing a single target argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1']):
            args = parse_arguments()
            assert args.targets == ['192.168.1.1']

    def test_parse_multiple_targets(self):
        """Test parsing multiple target arguments."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '192.168.1.2']):
            args = parse_arguments()
            assert len(args.targets) == 2

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_verbose_flag(self):
        """Test parsing --verbose flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--verbose']):
            args = parse_arguments()
            assert args.verbose == True

    def test_parse_timeout_argument(self):
        """Test parsing --timeout argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--timeout', '5.0']):
            args = parse_arguments()
            assert args.timeout == 5.0

    def test_parse_threads_argument(self):
        """Test parsing --threads argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--threads', '20']):
            args = parse_arguments()
            assert args.threads == 20

    def test_parse_methods_argument(self):
        """Test parsing --methods argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--methods', 'tcp', 'dns']):
            args = parse_arguments()
            assert 'tcp' in args.methods
            assert 'dns' in args.methods

    def test_parse_ports_argument(self):
        """Test parsing --ports argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--ports', '80', '443', '8080']):
            args = parse_arguments()
            assert 80 in args.ports
            assert 443 in args.ports
            assert 8080 in args.ports


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_scan_with_mocked_socket(self):
        """Test a full scan operation with mocked socket."""
        with patch('socket.socket') as mock_socket:
            # First connection succeeds, others fail
            mock_socket.return_value.connect_ex.side_effect = [0, 111, 111]

            config = ScanConfig(
                targets=["192.168.1.1"],
                tcp_ports=[80],
                threads=1,
                delay_max=0
            )
            scanner = NetworkScanner(config)
            results = scanner.scan()

            assert len(results) == 1
            assert results[0].ip == "192.168.1.1"

    def test_scan_with_hostname_resolution(self):
        """Test scan with hostname resolution enabled."""
        with patch('socket.socket') as mock_socket, \
             patch('socket.gethostbyaddr') as mock_dns:
            mock_socket.return_value.connect_ex.return_value = 0
            mock_dns.return_value = ("host.example.com", [], ["192.168.1.1"])

            config = ScanConfig(
                targets=["192.168.1.1"],
                tcp_ports=[80],
                resolve_hostnames=True,
                threads=1,
                delay_max=0
            )
            scanner = NetworkScanner(config)
            results = scanner.scan()

            assert len(results) == 1
            assert results[0].hostname == "host.example.com"
