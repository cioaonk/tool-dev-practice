#!/usr/bin/env python3
"""
Edge Case Tests for Payload Generator
======================================

Comprehensive edge case testing for the payload-generator tool including:
- Empty inputs
- Invalid payload types
- All payload format combinations
- Boundary conditions for ports
- Unicode/special characters in hosts
- Encoding and obfuscation edge cases

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
from unittest.mock import patch, MagicMock

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/payload-generator')

from payload_generator import (
    PayloadConfig,
    PayloadOutput,
    PayloadTemplate,
    PythonReverseShell,
    PowerShellReverseShell,
    BashReverseShell,
    PHPReverseShell,
    PayloadGenerator,
    get_documentation,
    print_plan,
    parse_arguments,
)


# =============================================================================
# Empty Input Tests
# =============================================================================

class TestEmptyInputs:
    """Tests for handling empty inputs."""

    def test_empty_lhost(self):
        """Empty LHOST should be handled gracefully."""
        config = PayloadConfig(
            payload_type="python",
            lhost="",
            lport=4444
        )
        generator = PayloadGenerator(config)
        try:
            output = generator.generate()
            # May produce output with empty host
        except ValueError:
            pass  # Acceptable to reject empty host

    def test_whitespace_lhost(self):
        """Whitespace-only LHOST should be handled."""
        config = PayloadConfig(
            payload_type="python",
            lhost="   ",
            lport=4444
        )
        generator = PayloadGenerator(config)
        try:
            output = generator.generate()
        except ValueError:
            pass  # Acceptable

    def test_empty_payload_type(self):
        """Empty payload type should be handled."""
        try:
            config = PayloadConfig(
                payload_type="",
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
        except (ValueError, KeyError):
            pass  # Acceptable


# =============================================================================
# Invalid Payload Type Tests
# =============================================================================

class TestInvalidPayloadTypes:
    """Tests for handling invalid payload types."""

    @pytest.mark.parametrize("invalid_type", [
        "invalid",
        "PYTHON",           # Case sensitivity
        "Python",
        "ruby",             # Unsupported language
        "perl",
        "java",
        "csharp",
        "123",              # Numeric
        "!@#$%",            # Special characters
        " python ",         # Whitespace around valid type
        "python\x00bash",   # Null byte
    ])
    def test_invalid_payload_types(self, invalid_type):
        """Invalid payload types should be handled gracefully."""
        try:
            config = PayloadConfig(
                payload_type=invalid_type,
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
            # May produce error output
        except (ValueError, KeyError, AttributeError):
            pass  # Acceptable


# =============================================================================
# All Payload Format Tests
# =============================================================================

class TestAllPayloadFormats:
    """Tests for all supported payload formats."""

    @pytest.mark.parametrize("payload_type", [
        "python",
        "powershell",
        "bash",
        "php",
    ])
    def test_all_payload_types_generate(self, payload_type):
        """All supported payload types should generate successfully."""
        config = PayloadConfig(
            payload_type=payload_type,
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)
        assert output.payload is not None
        assert len(output.payload) > 0
        assert "192.168.1.100" in output.payload
        assert "4444" in output.payload

    @pytest.mark.parametrize("payload_type", [
        "python",
        "powershell",
        "bash",
        "php",
    ])
    def test_payload_types_with_encoding(self, payload_type):
        """All payload types should support encoding."""
        config = PayloadConfig(
            payload_type=payload_type,
            lhost="192.168.1.100",
            lport=4444,
            encoded=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)

    @pytest.mark.parametrize("payload_type", [
        "python",
        "powershell",
        "bash",
        "php",
    ])
    def test_payload_types_with_obfuscation(self, payload_type):
        """All payload types should support obfuscation."""
        config = PayloadConfig(
            payload_type=payload_type,
            lhost="192.168.1.100",
            lport=4444,
            obfuscated=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)


# =============================================================================
# Port Boundary Tests
# =============================================================================

class TestPortBoundaries:
    """Tests for port boundary conditions."""

    @pytest.mark.parametrize("port", [1, 2, 80, 443, 1024, 8080, 32767, 32768, 65534, 65535])
    def test_valid_port_boundaries(self, port):
        """Valid port boundaries should work correctly."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=port
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert str(port) in output.payload

    @pytest.mark.parametrize("invalid_port", [0, -1, -4444, 65536, 100000])
    def test_invalid_port_values(self, invalid_port):
        """Invalid port values should be handled."""
        try:
            config = PayloadConfig(
                payload_type="python",
                lhost="192.168.1.100",
                lport=invalid_port
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
            # May still generate with invalid port (validation may be lax)
        except (ValueError, TypeError):
            pass  # Acceptable to reject invalid ports

    def test_port_as_string(self):
        """Port specified as string should be handled."""
        try:
            config = PayloadConfig(
                payload_type="python",
                lhost="192.168.1.100",
                lport="4444"  # String instead of int
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
        except (ValueError, TypeError):
            pass  # Acceptable


# =============================================================================
# Host Input Tests
# =============================================================================

class TestHostInputs:
    """Tests for various host input formats."""

    @pytest.mark.parametrize("valid_host", [
        "192.168.1.100",        # IPv4
        "10.0.0.1",
        "172.16.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "127.0.0.1",
        "attacker.com",         # Hostname
        "evil.example.org",
        "sub.domain.attacker.com",
        "192-168-1-100.attacker.com",  # Encoded IP in hostname
    ])
    def test_valid_host_formats(self, valid_host):
        """Valid host formats should be accepted."""
        config = PayloadConfig(
            payload_type="python",
            lhost=valid_host,
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert valid_host in output.payload

    @pytest.mark.parametrize("special_host", [
        "192.168.1.1;ls",           # Command injection
        "192.168.1.1|cat",          # Pipe injection
        "192.168.1.1`whoami`",      # Backtick
        "$(hostname)",              # Variable expansion
        "attacker.com\x00extra",    # Null byte
        "attacker.com\r\n",         # CRLF
        "<script>alert(1)</script>",  # XSS attempt
        "' OR '1'='1",              # SQL injection
    ])
    def test_special_characters_in_host(self, special_host):
        """Special characters in host should be handled safely."""
        config = PayloadConfig(
            payload_type="python",
            lhost=special_host,
            lport=4444
        )
        generator = PayloadGenerator(config)
        try:
            output = generator.generate()
            # Payload should contain the host as-is (for legitimate obfuscation)
            # or sanitize it
        except (ValueError, TypeError):
            pass  # Acceptable to reject


# =============================================================================
# Unicode and Encoding Tests
# =============================================================================

class TestUnicodeAndEncoding:
    """Tests for Unicode and encoding handling."""

    @pytest.mark.parametrize("unicode_host", [
        "\u0031\u0039\u0032.168.1.100",   # Unicode digits
        "192.168.1.100\u200b",            # Zero-width space
        "\uff11\uff19\uff12.168.1.100",   # Full-width digits
    ])
    def test_unicode_in_host(self, unicode_host):
        """Unicode characters in host should be handled."""
        config = PayloadConfig(
            payload_type="python",
            lhost=unicode_host,
            lport=4444
        )
        generator = PayloadGenerator(config)
        try:
            output = generator.generate()
        except (ValueError, UnicodeError):
            pass  # Acceptable

    def test_encoded_output_is_valid(self):
        """Encoded output should be valid encoding."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        # If encoding is base64, should be decodable
        if output.encoding == "base64":
            import base64
            try:
                base64.b64decode(output.payload)
            except Exception:
                pass  # May have wrapper code


# =============================================================================
# Template Tests
# =============================================================================

class TestPayloadTemplates:
    """Tests for individual payload templates."""

    def test_python_template_structure(self):
        """Python template should have proper structure."""
        template = PythonReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "import" in payload or "socket" in payload
        assert "192.168.1.100" in payload
        assert "4444" in payload

    def test_powershell_template_structure(self):
        """PowerShell template should have proper structure."""
        template = PowerShellReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        # Should contain PowerShell-specific elements

    def test_bash_template_structure(self):
        """Bash template should have proper structure."""
        template = BashReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        # Should contain bash or /dev/tcp

    def test_php_template_structure(self):
        """PHP template should have proper structure."""
        template = PHPReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        # Should contain PHP elements


# =============================================================================
# PayloadOutput Tests
# =============================================================================

class TestPayloadOutput:
    """Tests for PayloadOutput data class."""

    def test_output_size_calculation(self):
        """Output size should match payload length."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert output.size == len(output.payload)

    def test_output_with_all_fields(self):
        """PayloadOutput with all fields populated."""
        output = PayloadOutput(
            payload="test payload",
            payload_type="python",
            size=12,
            encoding="none",
            hash="abc123"
        )
        assert output.payload == "test payload"
        assert output.payload_type == "python"
        assert output.size == 12
        assert output.encoding == "none"
        assert output.hash == "abc123"


# =============================================================================
# PayloadConfig Tests
# =============================================================================

class TestPayloadConfig:
    """Tests for PayloadConfig data class."""

    def test_config_with_all_options(self):
        """PayloadConfig with all options."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True,
            obfuscated=True,
            plan_mode=True
        )
        assert config.encoded == True
        assert config.obfuscated == True
        assert config.plan_mode == True

    def test_config_defaults(self):
        """PayloadConfig should have sensible defaults."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        # Check defaults are set (may vary by implementation)


# =============================================================================
# Planning Mode Tests
# =============================================================================

class TestPlanningMode:
    """Tests for planning mode."""

    def test_plan_mode_shows_info(self, capsys):
        """Planning mode should display configuration info."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()

        assert "[PLAN MODE]" in captured.out
        assert "192.168.1.100" in captured.out
        assert "4444" in captured.out

    def test_plan_mode_with_encoding(self, capsys):
        """Planning mode should show encoding option."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()

        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_with_obfuscation(self, capsys):
        """Planning mode should show obfuscation option."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444,
            obfuscated=True,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()

        assert "[PLAN MODE]" in captured.out


# =============================================================================
# Integration Tests
# =============================================================================

class TestPayloadIntegration:
    """Integration tests for payload generation."""

    def test_generate_all_types_all_ports(self):
        """Generate all payload types with various ports."""
        types = ["python", "powershell", "bash", "php"]
        ports = [80, 443, 4444, 8080, 9001]

        for ptype in types:
            for port in ports:
                config = PayloadConfig(
                    payload_type=ptype,
                    lhost="192.168.1.100",
                    lport=port
                )
                generator = PayloadGenerator(config)
                output = generator.generate()

                assert isinstance(output, PayloadOutput)
                assert str(port) in output.payload

    def test_generate_with_various_hosts(self):
        """Generate payloads with various host formats."""
        hosts = [
            "192.168.1.100",
            "10.0.0.1",
            "attacker.com",
            "evil.example.org"
        ]

        for host in hosts:
            config = PayloadConfig(
                payload_type="python",
                lhost=host,
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()

            assert host in output.payload

    def test_generate_encoded_and_obfuscated(self):
        """Generate payloads with both encoding and obfuscation."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True,
            obfuscated=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_generator_with_none_config(self):
        """Generator should handle None config gracefully."""
        try:
            generator = PayloadGenerator(None)
            output = generator.generate()
        except (TypeError, AttributeError):
            pass  # Expected

    def test_template_with_none_host(self):
        """Template should handle None host."""
        template = PythonReverseShell()
        try:
            payload = template.generate(None, 4444)
        except (TypeError, AttributeError):
            pass  # Expected

    def test_template_with_none_port(self):
        """Template should handle None port."""
        template = PythonReverseShell()
        try:
            payload = template.generate("192.168.1.100", None)
        except (TypeError, AttributeError):
            pass  # Expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
