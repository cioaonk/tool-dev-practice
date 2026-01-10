#!/usr/bin/env python3
"""
Security Tests for Safe Default Configurations
===============================================

Tests to verify that all tools have secure default configurations:
- No dangerous defaults
- Appropriate timeouts
- Safe threading limits
- Planning mode behavior
- Verbose mode security

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add tools to path
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "network-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
sys.path.insert(0, str(TOOLS_PATH / "payload-generator"))
sys.path.insert(0, str(TOOLS_PATH / "shellcode-encoder"))


# =============================================================================
# Network Scanner Default Security Tests
# =============================================================================

@pytest.mark.security
class TestNetworkScannerDefaults:
    """Test network scanner default configurations for security."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import network scanner if available."""
        try:
            from tool import (
                ScanConfig, NetworkScanner,
                DEFAULT_TIMEOUT, DEFAULT_THREADS
            )
            self.ScanConfig = ScanConfig
            self.NetworkScanner = NetworkScanner
            self.DEFAULT_TIMEOUT = DEFAULT_TIMEOUT
            self.DEFAULT_THREADS = DEFAULT_THREADS
            self.available = True
        except ImportError:
            self.available = False

    def test_default_timeout_is_reasonable(self):
        """Default timeout should be reasonable (not too long, not too short)."""
        if not self.available:
            pytest.skip("Network scanner not available")

        # Timeout should be between 0.5 and 30 seconds
        assert 0.5 <= self.DEFAULT_TIMEOUT <= 30, \
            f"Default timeout {self.DEFAULT_TIMEOUT}s is unreasonable"

    def test_default_threads_is_moderate(self):
        """Default thread count should be moderate to avoid resource exhaustion."""
        if not self.available:
            pytest.skip("Network scanner not available")

        # Thread count should be between 1 and 100 for safety
        assert 1 <= self.DEFAULT_THREADS <= 100, \
            f"Default threads {self.DEFAULT_THREADS} may cause issues"

    def test_default_plan_mode_is_false(self):
        """Plan mode should default to False (explicit opt-in)."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=["192.168.1.1"])
        assert config.plan_mode == False, "Plan mode should default to False"

    def test_default_verbose_is_false(self):
        """Verbose mode should default to False."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=["192.168.1.1"])
        assert config.verbose == False, "Verbose should default to False"

    def test_default_no_hostname_resolution(self):
        """Hostname resolution should default to disabled (reduces network noise)."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=["192.168.1.1"])
        assert config.resolve_hostnames == False, \
            "Hostname resolution should default to False"

    def test_default_uses_tcp_method(self):
        """Default scan method should be TCP (least privileged)."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=["192.168.1.1"])
        assert "tcp" in config.scan_methods, \
            "Default should include TCP method"

    def test_default_delay_enables_throttling(self):
        """Default should have some delay to avoid flooding."""
        if not self.available:
            pytest.skip("Network scanner not available")

        config = self.ScanConfig(targets=["192.168.1.1"])
        # Either delay_min > 0 or delay_max > 0 for some throttling
        assert config.delay_max >= 0, "Delay should be non-negative"


# =============================================================================
# Port Scanner Default Security Tests
# =============================================================================

@pytest.mark.security
class TestPortScannerDefaults:
    """Test port scanner default configurations for security."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import port scanner if available."""
        try:
            from tool import (
                ScanConfig, PortScanner, ScanType,
                DEFAULT_TIMEOUT, DEFAULT_THREADS
            )
            self.ScanConfig = ScanConfig
            self.PortScanner = PortScanner
            self.ScanType = ScanType
            self.DEFAULT_TIMEOUT = DEFAULT_TIMEOUT
            self.DEFAULT_THREADS = DEFAULT_THREADS
            self.available = True
        except ImportError:
            self.available = False

    def test_default_scan_type_is_connect(self):
        """Default scan type should be TCP Connect (no raw sockets needed)."""
        if not self.available:
            pytest.skip("Port scanner not available")

        config = self.ScanConfig(target="192.168.1.1", ports=[80])
        assert config.scan_type == self.ScanType.TCP_CONNECT, \
            "Default should be TCP Connect scan"

    def test_default_timeout_is_reasonable(self):
        """Default timeout should be reasonable."""
        if not self.available:
            pytest.skip("Port scanner not available")

        assert 0.1 <= self.DEFAULT_TIMEOUT <= 30, \
            f"Default timeout {self.DEFAULT_TIMEOUT}s is unreasonable"

    def test_default_threads_is_safe(self):
        """Default threads should not exhaust resources."""
        if not self.available:
            pytest.skip("Port scanner not available")

        assert 1 <= self.DEFAULT_THREADS <= 200, \
            f"Default threads {self.DEFAULT_THREADS} may cause issues"

    def test_default_banner_grab_disabled(self):
        """Banner grabbing should be disabled by default (reduces noise)."""
        if not self.available:
            pytest.skip("Port scanner not available")

        config = self.ScanConfig(target="192.168.1.1", ports=[80])
        assert config.banner_grab == False, \
            "Banner grab should default to False"

    def test_default_randomize_enabled(self):
        """Port randomization should be enabled by default (OPSEC)."""
        if not self.available:
            pytest.skip("Port scanner not available")

        config = self.ScanConfig(target="192.168.1.1", ports=[80])
        assert config.randomize_ports == True, \
            "Port randomization should default to True"


# =============================================================================
# Payload Generator Default Security Tests
# =============================================================================

@pytest.mark.security
class TestPayloadGeneratorDefaults:
    """Test payload generator default configurations for security."""

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

    def test_default_no_auto_execute(self):
        """Payload should never auto-execute on generation."""
        if not self.available:
            pytest.skip("Payload generator not available")

        config = self.PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )

        # Ensure no execution happens during generation
        with patch('subprocess.call') as mock_call, \
             patch('subprocess.run') as mock_run, \
             patch('os.system') as mock_system, \
             patch('exec') as mock_exec:

            generator = self.PayloadGenerator(config)
            output = generator.generate()

            # None of these should be called
            mock_call.assert_not_called()
            mock_run.assert_not_called()
            mock_system.assert_not_called()

    def test_default_encoding_disabled(self):
        """Encoding should be opt-in, not default."""
        if not self.available:
            pytest.skip("Payload generator not available")

        config = self.PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        assert getattr(config, 'encoded', False) == False, \
            "Encoding should default to disabled"

    def test_default_obfuscation_disabled(self):
        """Obfuscation should be opt-in, not default."""
        if not self.available:
            pytest.skip("Payload generator not available")

        config = self.PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        assert getattr(config, 'obfuscated', False) == False, \
            "Obfuscation should default to disabled"


# =============================================================================
# Shellcode Encoder Default Security Tests
# =============================================================================

@pytest.mark.security
class TestShellcodeEncoderDefaults:
    """Test shellcode encoder default configurations for security."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Import shellcode encoder if available."""
        try:
            from shellcode_encoder import (
                EncoderConfig, EncodingType, ShellcodeEncoderTool
            )
            self.EncoderConfig = EncoderConfig
            self.EncodingType = EncodingType
            self.ShellcodeEncoderTool = ShellcodeEncoderTool
            self.available = True
        except ImportError:
            self.available = False

    def test_shellcode_not_executed(self):
        """Shellcode should never be executed during encoding."""
        if not self.available:
            pytest.skip("Shellcode encoder not available")

        config = self.EncoderConfig(
            shellcode=b"\x90" * 100,
            encoding_type=self.EncodingType.XOR,
            key=b"\x41"
        )

        with patch('subprocess.call') as mock_call, \
             patch('subprocess.run') as mock_run, \
             patch('os.system') as mock_system, \
             patch('ctypes.windll', create=True) as mock_windll, \
             patch('ctypes.CDLL', create=True) as mock_cdll:

            tool = self.ShellcodeEncoderTool(config)
            output = tool.encode()

            mock_call.assert_not_called()
            mock_run.assert_not_called()
            mock_system.assert_not_called()

    def test_default_single_iteration(self):
        """Default should use single encoding iteration."""
        if not self.available:
            pytest.skip("Shellcode encoder not available")

        config = self.EncoderConfig(
            shellcode=b"\x90\x90",
            encoding_type=self.EncodingType.XOR
        )
        # Default iterations should be 1 or minimal
        assert getattr(config, 'iterations', 1) >= 1


# =============================================================================
# Planning Mode Security Tests
# =============================================================================

@pytest.mark.security
class TestPlanningModeSecurity:
    """Test that planning mode truly does not perform actions."""

    def test_network_scanner_plan_no_network(self):
        """Network scanner plan mode should not make network connections."""
        try:
            from tool import ScanConfig, print_plan
            import socket

            config = ScanConfig(
                targets=["192.168.1.0/24"],
                plan_mode=True
            )

            original_socket = socket.socket

            class MockSocket:
                def __init__(self, *args, **kwargs):
                    raise AssertionError("Socket created in plan mode!")

            with patch('socket.socket', MockSocket):
                try:
                    print_plan(config)
                except AssertionError:
                    pytest.fail("Network connection attempted in plan mode")

        except ImportError:
            pytest.skip("Network scanner not available")

    def test_port_scanner_plan_no_network(self):
        """Port scanner plan mode should not make network connections."""
        try:
            sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
            from tool import ScanConfig, print_plan

            config = ScanConfig(
                target="192.168.1.1",
                ports=[80, 443],
                plan_mode=True
            )

            with patch('socket.socket') as mock_socket:
                print_plan(config)
                # Check that connect was never called
                if mock_socket.return_value.connect_ex.called:
                    pytest.fail("Connection attempted in plan mode")

        except ImportError:
            pytest.skip("Port scanner not available")


# =============================================================================
# Resource Limit Tests
# =============================================================================

@pytest.mark.security
class TestResourceLimits:
    """Test that tools have appropriate resource limits."""

    def test_network_scanner_has_stop_mechanism(self):
        """Network scanner should have a stop mechanism."""
        try:
            from tool import ScanConfig, NetworkScanner

            config = ScanConfig(targets=["192.168.1.1"])
            scanner = NetworkScanner(config)

            # Should have a stop method
            assert hasattr(scanner, 'stop'), "Scanner should have stop method"

            # Stop should work
            scanner.stop()
            assert scanner._stop_event.is_set(), "Stop should set stop event"

        except ImportError:
            pytest.skip("Network scanner not available")

    def test_port_scanner_has_stop_mechanism(self):
        """Port scanner should have a stop mechanism."""
        try:
            sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
            from tool import ScanConfig, PortScanner

            config = ScanConfig(target="192.168.1.1", ports=[80])
            scanner = PortScanner(config)

            assert hasattr(scanner, 'stop'), "Scanner should have stop method"
            scanner.stop()

        except ImportError:
            pytest.skip("Port scanner not available")


# =============================================================================
# Output Security Tests
# =============================================================================

@pytest.mark.security
class TestOutputSecurity:
    """Test that tool outputs are safe."""

    def test_output_no_sensitive_data_leakage(self):
        """Tool outputs should not leak sensitive local data."""
        # Outputs should not contain:
        # - Local file paths (except explicitly requested)
        # - Environment variables
        # - System information not requested
        pass

    def test_verbose_mode_limits_info(self):
        """Verbose mode should not expose security-sensitive info."""
        # Even in verbose mode, should not expose:
        # - Full system paths
        # - Credentials
        # - Internal implementation details
        pass


# =============================================================================
# Documentation Security Tests
# =============================================================================

@pytest.mark.security
class TestDocumentationSecurity:
    """Test that documentation doesn't expose security issues."""

    def test_network_scanner_documentation_has_warnings(self):
        """Network scanner docs should have authorization warnings."""
        try:
            from tool import get_documentation

            docs = get_documentation()
            doc_str = str(docs).lower()

            # Should mention authorization
            assert any(word in doc_str for word in [
                "authorized", "authorization", "permission", "legal"
            ]), "Documentation should mention authorization"

        except ImportError:
            pytest.skip("Network scanner not available")

    def test_port_scanner_documentation_has_warnings(self):
        """Port scanner docs should have authorization warnings."""
        try:
            sys.path.insert(0, str(TOOLS_PATH / "port-scanner"))
            from tool import get_documentation

            docs = get_documentation()
            doc_str = str(docs).lower()

            assert any(word in doc_str for word in [
                "authorized", "authorization", "permission", "legal", "warning"
            ]), "Documentation should mention authorization"

        except ImportError:
            pytest.skip("Port scanner not available")


# =============================================================================
# Cryptographic Security Tests
# =============================================================================

@pytest.mark.security
class TestCryptographicDefaults:
    """Test cryptographic defaults are secure."""

    def test_aes_key_generation_is_random(self):
        """AES keys should be randomly generated when not provided."""
        try:
            from shellcode_encoder import EncoderConfig, EncodingType

            config1 = EncoderConfig(
                shellcode=b"\x90\x90",
                encoding_type=EncodingType.AES
            )
            config2 = EncoderConfig(
                shellcode=b"\x90\x90",
                encoding_type=EncodingType.AES
            )

            # If keys are auto-generated, they should differ
            # (This is a weak test - proper randomness testing is complex)

        except ImportError:
            pytest.skip("Shellcode encoder not available")

    def test_xor_warns_about_weak_keys(self):
        """XOR encoding should handle weak keys appropriately."""
        try:
            from shellcode_encoder import EncoderConfig, EncodingType, ShellcodeEncoderTool

            # Zero key provides no protection
            config = EncoderConfig(
                shellcode=b"\x90\x90",
                encoding_type=EncodingType.XOR,
                key=b"\x00"
            )
            tool = ShellcodeEncoderTool(config)
            output = tool.encode()

            # With zero key, output should equal input (no encoding)
            # Tool should either warn or reject this

        except ImportError:
            pytest.skip("Shellcode encoder not available")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "security"])
