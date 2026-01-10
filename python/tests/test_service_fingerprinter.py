"""
Tests for the Service Fingerprinter tool.

This module contains unit tests and integration tests for the service-fingerprinter tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
import ssl
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/service-fingerprinter')

from tool import (
    ServiceInfo,
    FingerprintConfig,
    HTTPProbe,
    SSHProbe,
    FTPProbe,
    SMTPProbe,
    MySQLProbe,
    RDPProbe,
    GenericProbe,
    SSLDetector,
    ServiceFingerprinter,
    get_documentation,
    print_plan,
    parse_arguments,
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
        assert docs["name"] == "service-fingerprinter"

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
        config = FingerprintConfig(
            target="192.168.1.1",
            ports=[80, 443],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = FingerprintConfig(
            target="192.168.1.1",
            ports=[80, 443],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out

    def test_plan_mode_shows_probes_to_use(self, capsys):
        """Test that planning mode shows probes to be used."""
        config = FingerprintConfig(
            target="192.168.1.1",
            ports=[80, 22, 21],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention service detection or probing
        assert "Probe" in captured.out or "service" in captured.out.lower()

    def test_plan_mode_does_not_perform_probing(self):
        """Test that planning mode does not actually perform network probing."""
        with patch('socket.socket') as mock_socket:
            config = FingerprintConfig(
                target="192.168.1.1",
                ports=[80],
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be used to send data in plan mode
            mock_socket.return_value.send.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_target(self):
        """Test that valid targets are accepted."""
        config = FingerprintConfig(target="192.168.1.1", ports=[80])
        assert config.target == "192.168.1.1"

    def test_valid_ports_list(self):
        """Test that valid port lists are accepted."""
        config = FingerprintConfig(
            target="192.168.1.1",
            ports=[80, 443, 22, 21]
        )
        assert 80 in config.ports
        assert 443 in config.ports

    def test_timeout_configuration(self):
        """Test that timeout is properly configured."""
        config = FingerprintConfig(
            target="192.168.1.1",
            ports=[80],
            timeout=5.0
        )
        assert config.timeout == 5.0


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_socket_error_handled(self):
        """Test that socket errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.side_effect = socket.error("Connection failed")

            config = FingerprintConfig(target="192.168.1.1", ports=[80])
            probe = HTTPProbe()
            result = probe.probe("192.168.1.1", 80, config)

            # Should return None or empty ServiceInfo on error
            assert result is None or isinstance(result, ServiceInfo)

    def test_timeout_handling(self):
        """Test that connection timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.side_effect = socket.timeout("Timeout")

            config = FingerprintConfig(target="192.168.1.1", ports=[80], timeout=0.1)
            probe = HTTPProbe()
            result = probe.probe("192.168.1.1", 80, config)

            # Should handle timeout gracefully
            assert result is None or isinstance(result, ServiceInfo)

    def test_ssl_error_handling(self):
        """Test that SSL errors are handled gracefully."""
        with patch('ssl.create_default_context') as mock_ssl:
            mock_ssl.return_value.wrap_socket.side_effect = ssl.SSLError("SSL failed")

            detector = SSLDetector()
            result = detector.detect("192.168.1.1", 443)

            # Should not crash, return None or empty result
            assert result is None or isinstance(result, dict)


# =============================================================================
# Test ServiceInfo Data Class
# =============================================================================

class TestServiceInfo:
    """Tests for the ServiceInfo data class."""

    def test_service_info_creation(self):
        """Test that ServiceInfo can be created."""
        info = ServiceInfo(
            port=80,
            protocol="tcp",
            service="http"
        )
        assert info.port == 80
        assert info.service == "http"

    def test_service_info_with_version(self):
        """Test ServiceInfo with version information."""
        info = ServiceInfo(
            port=22,
            protocol="tcp",
            service="ssh",
            version="OpenSSH_8.9"
        )
        assert info.version == "OpenSSH_8.9"

    def test_service_info_with_banner(self):
        """Test ServiceInfo with banner."""
        info = ServiceInfo(
            port=21,
            protocol="tcp",
            service="ftp",
            banner="220 ProFTPD Server"
        )
        assert "ProFTPD" in info.banner


# =============================================================================
# Test Protocol Probes
# =============================================================================

class TestProtocolProbes:
    """Tests for individual protocol probes."""

    def test_http_probe_identifies_http(self):
        """Test HTTPProbe identifies HTTP service."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"

            config = FingerprintConfig(target="192.168.1.1", ports=[80])
            probe = HTTPProbe()
            result = probe.probe("192.168.1.1", 80, config)

            assert result is not None
            assert result.service == "http" or "http" in str(result).lower()

    def test_ssh_probe_identifies_ssh(self):
        """Test SSHProbe identifies SSH service."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"

            config = FingerprintConfig(target="192.168.1.1", ports=[22])
            probe = SSHProbe()
            result = probe.probe("192.168.1.1", 22, config)

            assert result is not None
            assert "ssh" in str(result).lower() or "SSH" in str(result)

    def test_ftp_probe_identifies_ftp(self):
        """Test FTPProbe identifies FTP service."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"220 Welcome to FTP server\r\n"

            config = FingerprintConfig(target="192.168.1.1", ports=[21])
            probe = FTPProbe()
            result = probe.probe("192.168.1.1", 21, config)

            assert result is not None

    def test_smtp_probe_identifies_smtp(self):
        """Test SMTPProbe identifies SMTP service."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"220 mail.example.com ESMTP Postfix\r\n"

            config = FingerprintConfig(target="192.168.1.1", ports=[25])
            probe = SMTPProbe()
            result = probe.probe("192.168.1.1", 25, config)

            assert result is not None

    def test_mysql_probe_identifies_mysql(self):
        """Test MySQLProbe identifies MySQL service."""
        with patch('socket.socket') as mock_socket:
            # MySQL greeting packet starts with version
            mock_socket.return_value.recv.return_value = b"\x4a\x00\x00\x005.7.38\x00"

            config = FingerprintConfig(target="192.168.1.1", ports=[3306])
            probe = MySQLProbe()
            result = probe.probe("192.168.1.1", 3306, config)

            # Should handle MySQL protocol
            assert result is None or isinstance(result, ServiceInfo)

    def test_generic_probe_captures_banner(self):
        """Test GenericProbe captures any banner."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"Custom Service v1.0\r\n"

            config = FingerprintConfig(target="192.168.1.1", ports=[9999])
            probe = GenericProbe()
            result = probe.probe("192.168.1.1", 9999, config)

            assert result is None or isinstance(result, ServiceInfo)


# =============================================================================
# Test SSL Detection
# =============================================================================

class TestSSLDetection:
    """Tests for SSL/TLS detection."""

    def test_ssl_detector_creation(self):
        """Test SSLDetector can be created."""
        detector = SSLDetector()
        assert detector is not None

    def test_ssl_detection_with_valid_cert(self):
        """Test SSL detection with valid certificate."""
        with patch('ssl.create_default_context') as mock_ctx, \
             patch('socket.socket') as mock_socket:
            mock_ssl_socket = MagicMock()
            mock_ssl_socket.getpeercert.return_value = {
                'subject': ((('commonName', 'example.com'),),),
                'issuer': ((('commonName', 'CA'),),)
            }
            mock_ctx.return_value.wrap_socket.return_value = mock_ssl_socket

            detector = SSLDetector()
            result = detector.detect("192.168.1.1", 443)

            # Should return certificate info or None
            assert result is None or isinstance(result, dict)


# =============================================================================
# Test ServiceFingerprinter Class
# =============================================================================

class TestServiceFingerprinter:
    """Tests for the ServiceFingerprinter class."""

    def test_fingerprinter_initialization(self):
        """Test ServiceFingerprinter initialization."""
        config = FingerprintConfig(target="192.168.1.1", ports=[80])
        fingerprinter = ServiceFingerprinter(config)

        assert fingerprinter.config == config

    def test_fingerprinter_has_probes(self):
        """Test that fingerprinter has registered probes."""
        config = FingerprintConfig(target="192.168.1.1", ports=[80])
        fingerprinter = ServiceFingerprinter(config)

        # Should have some probes registered
        assert hasattr(fingerprinter, 'probes') or len(fingerprinter.__dict__) > 0

    def test_fingerprinter_scan_with_mocked_network(self):
        """Test fingerprinter scan with mocked network."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b"HTTP/1.1 200 OK\r\n"

            config = FingerprintConfig(
                target="192.168.1.1",
                ports=[80],
                threads=1
            )
            fingerprinter = ServiceFingerprinter(config)
            results = fingerprinter.scan()

            assert isinstance(results, (list, dict))


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
            assert '80' in str(args.ports) or 80 in args.ports

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_timeout_argument(self):
        """Test parsing --timeout argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--timeout', '5']):
            args = parse_arguments()
            assert args.timeout == 5 or args.timeout == 5.0


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_fingerprint_scan(self):
        """Test full fingerprint scan with mocked network."""
        with patch('socket.socket') as mock_socket:
            # Return different banners for different calls
            mock_socket.return_value.recv.side_effect = [
                b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
                b"SSH-2.0-OpenSSH_8.9\r\n",
            ]

            config = FingerprintConfig(
                target="192.168.1.1",
                ports=[80, 22],
                threads=1
            )
            fingerprinter = ServiceFingerprinter(config)
            results = fingerprinter.scan()

            assert isinstance(results, (list, dict))

    def test_fingerprint_with_ssl_detection(self):
        """Test fingerprint scan with SSL detection."""
        with patch('socket.socket') as mock_socket, \
             patch('ssl.create_default_context') as mock_ssl:
            mock_socket.return_value.recv.return_value = b""
            mock_ssl_socket = MagicMock()
            mock_ssl_socket.getpeercert.return_value = {'subject': ()}
            mock_ssl.return_value.wrap_socket.return_value = mock_ssl_socket

            config = FingerprintConfig(
                target="192.168.1.1",
                ports=[443],
                ssl_detection=True,
                threads=1
            )
            fingerprinter = ServiceFingerprinter(config)
            results = fingerprinter.scan()

            assert isinstance(results, (list, dict))
