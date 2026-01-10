"""
Tests for the Payload Generator tool.

This module contains unit tests and integration tests for the payload-generator tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO

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
        assert docs["name"] == "payload-generator"

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

    def test_get_documentation_has_payload_types(self):
        """Test that documentation lists available payload types."""
        docs = get_documentation()
        # Should list available payload types somewhere
        assert "features" in docs or "payload" in str(docs).lower()


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_payload_type(self, capsys):
        """Test that planning mode shows payload type."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "powershell" in captured.out.lower() or "PowerShell" in captured.out

    def test_plan_mode_shows_connection_info(self, capsys):
        """Test that planning mode shows connection information."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.100" in captured.out
        assert "4444" in captured.out

    def test_plan_mode_does_not_generate_payload(self):
        """Test that planning mode does not generate actual payload."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            plan_mode=True
        )
        # print_plan should not produce executable code
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        print_plan(config)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout

        # Output should be plan description, not actual payload
        assert "[PLAN MODE]" in output


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_payload_type_python(self):
        """Test Python payload type is accepted."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        assert config.payload_type == "python"

    def test_valid_payload_type_powershell(self):
        """Test PowerShell payload type is accepted."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444
        )
        assert config.payload_type == "powershell"

    def test_valid_payload_type_bash(self):
        """Test Bash payload type is accepted."""
        config = PayloadConfig(
            payload_type="bash",
            lhost="192.168.1.100",
            lport=4444
        )
        assert config.payload_type == "bash"

    def test_valid_payload_type_php(self):
        """Test PHP payload type is accepted."""
        config = PayloadConfig(
            payload_type="php",
            lhost="192.168.1.100",
            lport=4444
        )
        assert config.payload_type == "php"

    def test_valid_lhost(self):
        """Test valid LHOST is accepted."""
        config = PayloadConfig(
            payload_type="python",
            lhost="10.0.0.1",
            lport=4444
        )
        assert config.lhost == "10.0.0.1"

    def test_valid_lport(self):
        """Test valid LPORT is accepted."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=8080
        )
        assert config.lport == 8080


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_payload_type_handling(self):
        """Test handling of invalid payload type."""
        try:
            config = PayloadConfig(
                payload_type="invalid_type",
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            result = generator.generate()
            # Should either fail or return error
        except (ValueError, KeyError):
            pass  # Expected behavior

    def test_empty_lhost_handling(self):
        """Test handling of empty LHOST."""
        config = PayloadConfig(
            payload_type="python",
            lhost="",
            lport=4444
        )
        generator = PayloadGenerator(config)
        # Should handle gracefully
        try:
            result = generator.generate()
        except ValueError:
            pass  # Acceptable


# =============================================================================
# Test PayloadConfig Data Class
# =============================================================================

class TestPayloadConfig:
    """Tests for the PayloadConfig data class."""

    def test_payload_config_creation(self):
        """Test that PayloadConfig can be created."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        assert config.payload_type == "python"
        assert config.lhost == "192.168.1.100"
        assert config.lport == 4444

    def test_payload_config_with_options(self):
        """Test PayloadConfig with additional options."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True,
            obfuscated=True
        )
        assert config.encoded == True
        assert config.obfuscated == True


# =============================================================================
# Test PayloadOutput Data Class
# =============================================================================

class TestPayloadOutput:
    """Tests for the PayloadOutput data class."""

    def test_payload_output_creation(self):
        """Test that PayloadOutput can be created."""
        output = PayloadOutput(
            payload="print('test')",
            payload_type="python",
            size=len("print('test')")
        )
        assert output.payload == "print('test')"
        assert output.payload_type == "python"

    def test_payload_output_with_metadata(self):
        """Test PayloadOutput with metadata."""
        output = PayloadOutput(
            payload="echo test",
            payload_type="bash",
            size=9,
            encoding="base64",
            hash="abc123"
        )
        assert output.encoding == "base64"


# =============================================================================
# Test Payload Templates
# =============================================================================

class TestPayloadTemplates:
    """Tests for payload template classes."""

    def test_python_reverse_shell_template(self):
        """Test PythonReverseShell template."""
        template = PythonReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "socket" in payload or "import" in payload

    def test_powershell_reverse_shell_template(self):
        """Test PowerShellReverseShell template."""
        template = PowerShellReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        # PowerShell specific keywords
        assert "TCPClient" in payload or "Net.Sockets" in payload or "powershell" in payload.lower()

    def test_bash_reverse_shell_template(self):
        """Test BashReverseShell template."""
        template = BashReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "bash" in payload.lower() or "/dev/tcp" in payload

    def test_php_reverse_shell_template(self):
        """Test PHPReverseShell template."""
        template = PHPReverseShell()
        payload = template.generate("192.168.1.100", 4444)

        assert "192.168.1.100" in payload
        assert "4444" in payload
        assert "php" in payload.lower() or "fsockopen" in payload


# =============================================================================
# Test PayloadGenerator Class
# =============================================================================

class TestPayloadGenerator:
    """Tests for the PayloadGenerator class."""

    def test_generator_initialization(self):
        """Test PayloadGenerator initialization."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        assert generator is not None

    def test_generator_python_payload(self):
        """Test generating Python payload."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)
        assert "192.168.1.100" in output.payload
        assert "4444" in output.payload

    def test_generator_powershell_payload(self):
        """Test generating PowerShell payload."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)
        assert "192.168.1.100" in output.payload

    def test_generator_bash_payload(self):
        """Test generating Bash payload."""
        config = PayloadConfig(
            payload_type="bash",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)
        assert "192.168.1.100" in output.payload

    def test_generator_php_payload(self):
        """Test generating PHP payload."""
        config = PayloadConfig(
            payload_type="php",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)
        assert "192.168.1.100" in output.payload

    def test_generator_with_encoding(self):
        """Test generating encoded payload."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444,
            encoded=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)

    def test_generator_with_obfuscation(self):
        """Test generating obfuscated payload."""
        config = PayloadConfig(
            payload_type="powershell",
            lhost="192.168.1.100",
            lport=4444,
            obfuscated=True
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        assert isinstance(output, PayloadOutput)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_payload_type_argument(self):
        """Test parsing payload type argument."""
        with patch('sys.argv', ['payload_generator.py', '-t', 'python']):
            args = parse_arguments()
            assert args.type == 'python' or 'python' in str(args.payload_type)

    def test_parse_lhost_argument(self):
        """Test parsing LHOST argument."""
        with patch('sys.argv', ['payload_generator.py', '-l', '192.168.1.100']):
            args = parse_arguments()
            assert args.lhost == '192.168.1.100'

    def test_parse_lport_argument(self):
        """Test parsing LPORT argument."""
        with patch('sys.argv', ['payload_generator.py', '-p', '4444']):
            args = parse_arguments()
            assert args.lport == 4444

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['payload_generator.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_encode_flag(self):
        """Test parsing --encode flag."""
        with patch('sys.argv', ['payload_generator.py', '--encode']):
            args = parse_arguments()
            assert args.encode == True or args.encoded == True

    def test_parse_output_argument(self):
        """Test parsing --output argument."""
        with patch('sys.argv', ['payload_generator.py', '-o', 'payload.txt']):
            args = parse_arguments()
            assert args.output == 'payload.txt' or 'payload.txt' in str(args.output)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for the payload generator."""

    def test_generate_all_payload_types(self):
        """Test generating all supported payload types."""
        payload_types = ["python", "powershell", "bash", "php"]

        for ptype in payload_types:
            config = PayloadConfig(
                payload_type=ptype,
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()

            assert isinstance(output, PayloadOutput)
            assert "192.168.1.100" in output.payload
            assert "4444" in output.payload

    def test_payload_size_calculation(self):
        """Test that payload size is correctly calculated."""
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        output = generator.generate()

        # Size should match actual payload length
        assert output.size == len(output.payload)

    def test_different_port_values(self):
        """Test payloads with different port values."""
        for port in [80, 443, 4444, 8080, 9001]:
            config = PayloadConfig(
                payload_type="python",
                lhost="192.168.1.100",
                lport=port
            )
            generator = PayloadGenerator(config)
            output = generator.generate()

            assert str(port) in output.payload

    def test_different_host_values(self):
        """Test payloads with different host values."""
        hosts = ["192.168.1.100", "10.0.0.1", "attacker.example.com"]

        for host in hosts:
            config = PayloadConfig(
                payload_type="bash",
                lhost=host,
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()

            assert host in output.payload
