"""
Tests for the Port Scanner tool.

This module contains unit tests and integration tests for the port-scanner tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO

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
        required_keys = ["name", "version", "category", "description"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "port-scanner"

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
        config = ScanConfig(
            target="192.168.1.1",
            ports=[80, 443],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=[80, 443],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out

    def test_plan_mode_shows_ports_to_scan(self, capsys):
        """Test that planning mode shows ports to scan."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=[80, 443, 22],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "80" in captured.out or "Ports" in captured.out

    def test_plan_mode_does_not_perform_scan(self):
        """Test that planning mode does not actually perform network scans."""
        with patch('socket.socket') as mock_socket:
            config = ScanConfig(
                target="192.168.1.1",
                ports=[80],
                plan_mode=True
            )
            print_plan(config)
            # Socket connect should not be called in plan mode
            mock_socket.return_value.connect_ex.assert_not_called()


# =============================================================================
# Test Port Specification Parsing
# =============================================================================

class TestPortSpecificationParsing:
    """Tests for port specification parsing."""

    def test_parse_single_port(self):
        """Test parsing a single port."""
        ports = parse_port_specification("80")
        assert 80 in ports

    def test_parse_port_range(self):
        """Test parsing a port range."""
        ports = parse_port_specification("80-83")
        assert set(ports) == {80, 81, 82, 83}

    def test_parse_comma_separated_ports(self):
        """Test parsing comma-separated ports."""
        ports = parse_port_specification("80,443,8080")
        assert set(ports) == {80, 443, 8080}

    def test_parse_mixed_specification(self):
        """Test parsing mixed port specifications."""
        ports = parse_port_specification("80,443,8000-8002")
        assert set(ports) == {80, 443, 8000, 8001, 8002}

    def test_parse_top_ports(self):
        """Test parsing top-N ports specification."""
        ports = parse_port_specification("top10")
        assert len(ports) == 10
        # Common top ports should be included
        assert 80 in ports
        assert 443 in ports


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_target_ip(self):
        """Test that valid IP addresses are accepted."""
        config = ScanConfig(target="192.168.1.1", ports=[80])
        assert config.target == "192.168.1.1"

    def test_valid_port_list(self):
        """Test that valid port lists are accepted."""
        config = ScanConfig(target="192.168.1.1", ports=[80, 443, 8080])
        assert 80 in config.ports
        assert 443 in config.ports
        assert 8080 in config.ports

    def test_scan_type_tcp(self):
        """Test TCP scan type configuration."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=[80],
            scan_type=ScanType.TCP_CONNECT
        )
        assert config.scan_type == ScanType.TCP_CONNECT

    def test_scan_type_udp(self):
        """Test UDP scan type configuration."""
        config = ScanConfig(
            target="192.168.1.1",
            ports=[53],
            scan_type=ScanType.UDP
        )
        assert config.scan_type == ScanType.UDP


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_socket_error_handled(self):
        """Test that socket errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", 80, config)

            assert isinstance(result, PortResult)
            # Result should indicate port is closed or filtered
            assert result.state != PortState.OPEN

    def test_timeout_handling(self):
        """Test that connection timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout("Timeout")

            config = ScanConfig(target="192.168.1.1", ports=[80], timeout=0.1)
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", 80, config)

            assert isinstance(result, PortResult)

    def test_empty_ports_list(self):
        """Test handling of empty ports list."""
        config = ScanConfig(target="192.168.1.1", ports=[])
        scanner = PortScanner(config)
        # Should not crash with empty port list
        assert scanner.config.ports == []


# =============================================================================
# Test PortResult Data Class
# =============================================================================

class TestPortResult:
    """Tests for the PortResult data class."""

    def test_port_result_creation(self):
        """Test that PortResult can be created with required fields."""
        result = PortResult(port=80, state=PortState.OPEN)
        assert result.port == 80
        assert result.state == PortState.OPEN

    def test_port_result_with_service(self):
        """Test PortResult with service information."""
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            service="http"
        )
        assert result.service == "http"


# =============================================================================
# Test PortState Enum
# =============================================================================

class TestPortStateEnum:
    """Tests for the PortState enum."""

    def test_port_state_open(self):
        """Test OPEN port state."""
        assert PortState.OPEN.value is not None

    def test_port_state_closed(self):
        """Test CLOSED port state."""
        assert PortState.CLOSED.value is not None

    def test_port_state_filtered(self):
        """Test FILTERED port state."""
        assert PortState.FILTERED.value is not None


# =============================================================================
# Test ScanType Enum
# =============================================================================

class TestScanTypeEnum:
    """Tests for the ScanType enum."""

    def test_scan_type_tcp_connect(self):
        """Test TCP_CONNECT scan type."""
        assert ScanType.TCP_CONNECT is not None

    def test_scan_type_tcp_syn(self):
        """Test TCP_SYN scan type."""
        assert ScanType.TCP_SYN is not None

    def test_scan_type_udp(self):
        """Test UDP scan type."""
        assert ScanType.UDP is not None


# =============================================================================
# Test Scanning Techniques
# =============================================================================

class TestScanningTechniques:
    """Tests for individual scanning techniques."""

    def test_tcp_connect_scan_open_port(self):
        """Test TCPConnectScan with open port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", 80, config)

            assert result.state == PortState.OPEN

    def test_tcp_connect_scan_closed_port(self):
        """Test TCPConnectScan with closed port."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 111  # Connection refused

            config = ScanConfig(target="192.168.1.1", ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", 80, config)

            assert result.state == PortState.CLOSED

    def test_udp_scan_technique(self):
        """Test UDPScan technique."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recvfrom.side_effect = socket.timeout()

            config = ScanConfig(target="192.168.1.1", ports=[53])
            technique = UDPScan()
            result = technique.scan("192.168.1.1", 53, config)

            # UDP scan timeout typically means open|filtered
            assert isinstance(result, PortResult)


# =============================================================================
# Test PortScanner Class
# =============================================================================

class TestPortScanner:
    """Tests for the PortScanner class."""

    def test_scanner_initialization(self):
        """Test PortScanner initialization."""
        config = ScanConfig(target="192.168.1.1", ports=[80, 443])
        scanner = PortScanner(config)

        assert scanner.config == config

    def test_scanner_with_mocked_network(self):
        """Test PortScanner with mocked network."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80],
                threads=1
            )
            scanner = PortScanner(config)
            report = scanner.scan()

            assert isinstance(report, ScanReport)


# =============================================================================
# Test ScanReport Class
# =============================================================================

class TestScanReport:
    """Tests for the ScanReport class."""

    def test_scan_report_creation(self):
        """Test ScanReport creation."""
        report = ScanReport(
            target="192.168.1.1",
            results=[]
        )
        assert report.target == "192.168.1.1"

    def test_scan_report_get_open_ports(self):
        """Test getting open ports from report."""
        results = [
            PortResult(port=80, state=PortState.OPEN),
            PortResult(port=443, state=PortState.CLOSED),
            PortResult(port=8080, state=PortState.OPEN),
        ]
        report = ScanReport(target="192.168.1.1", results=results)

        open_ports = report.get_open_ports()
        assert len(open_ports) == 2
        assert all(p.state == PortState.OPEN for p in open_ports)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_target_argument(self):
        """Test parsing target argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1']):
            args = parse_arguments()
            assert args.target == '192.168.1.1'

    def test_parse_ports_argument(self):
        """Test parsing ports argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '-p', '80,443']):
            args = parse_arguments()
            assert '80,443' in str(args.ports) or args.ports == '80,443'

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_scan_type_flag(self):
        """Test parsing scan type flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--scan-type', 'tcp']):
            args = parse_arguments()
            assert 'tcp' in str(args.scan_type).lower()


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_scan_multiple_ports(self):
        """Test a full scan of multiple ports with mocked socket."""
        with patch('socket.socket') as mock_socket:
            # Alternate between open and closed
            mock_socket.return_value.connect_ex.side_effect = [0, 111, 0]

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80, 443, 8080],
                threads=1
            )
            scanner = PortScanner(config)
            report = scanner.scan()

            assert isinstance(report, ScanReport)
            assert len(report.results) == 3

    def test_scan_with_service_detection(self):
        """Test scan with service detection enabled."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0
            mock_socket.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\n"

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80],
                service_detection=True,
                threads=1
            )
            scanner = PortScanner(config)
            report = scanner.scan()

            assert isinstance(report, ScanReport)
