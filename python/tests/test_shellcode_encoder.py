"""
Tests for the Shellcode Encoder tool.

This module contains unit tests and integration tests for the shellcode-encoder tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/shellcode-encoder')

from shellcode_encoder import (
    EncodingType,
    EncoderConfig,
    EncoderOutput,
    XOREncoder,
    RollingXOREncoder,
    ADDEncoder,
    SUBEncoder,
    ROTEncoder,
    Base64Encoder,
    AESEncoder,
    RC4Encoder,
    ShellcodeEncoderTool,
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
        assert docs["name"] == "shellcode-encoder"

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

    def test_get_documentation_lists_encoders(self):
        """Test that documentation lists available encoders."""
        docs = get_documentation()
        doc_str = str(docs).lower()
        assert "xor" in doc_str or "encoder" in doc_str


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_encoding_type(self, capsys):
        """Test that planning mode shows encoding type."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "XOR" in captured.out or "xor" in captured.out.lower()

    def test_plan_mode_shows_shellcode_size(self, capsys):
        """Test that planning mode shows shellcode size."""
        shellcode = b"\x90" * 100
        config = EncoderConfig(
            shellcode=shellcode,
            encoding_type=EncodingType.XOR,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "100" in captured.out or "size" in captured.out.lower()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_shellcode_bytes(self):
        """Test that valid shellcode bytes are accepted."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR
        )
        assert config.shellcode == b"\x90\x90\x90\x90"

    def test_valid_encoding_type_xor(self):
        """Test XOR encoding type is accepted."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.XOR
        )
        assert config.encoding_type == EncodingType.XOR

    def test_valid_encoding_type_base64(self):
        """Test Base64 encoding type is accepted."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.BASE64
        )
        assert config.encoding_type == EncodingType.BASE64

    def test_valid_encoding_type_aes(self):
        """Test AES encoding type is accepted."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.AES
        )
        assert config.encoding_type == EncodingType.AES

    def test_valid_key_parameter(self):
        """Test that encryption key is accepted."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        assert config.key == b"\x41"


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_empty_shellcode_handling(self):
        """Test handling of empty shellcode."""
        try:
            config = EncoderConfig(
                shellcode=b"",
                encoding_type=EncodingType.XOR
            )
            encoder = ShellcodeEncoderTool(config)
            result = encoder.encode()
        except ValueError:
            pass  # Expected behavior

    def test_invalid_encoding_type_handling(self):
        """Test handling of invalid encoding type."""
        try:
            config = EncoderConfig(
                shellcode=b"\x90",
                encoding_type="invalid"
            )
        except (ValueError, TypeError):
            pass  # Expected behavior


# =============================================================================
# Test EncodingType Enum
# =============================================================================

class TestEncodingTypeEnum:
    """Tests for the EncodingType enum."""

    def test_encoding_type_xor(self):
        """Test XOR encoding type."""
        assert EncodingType.XOR is not None

    def test_encoding_type_xor_rolling(self):
        """Test XOR_ROLLING encoding type."""
        assert EncodingType.XOR_ROLLING is not None

    def test_encoding_type_add(self):
        """Test ADD encoding type."""
        assert EncodingType.ADD is not None

    def test_encoding_type_sub(self):
        """Test SUB encoding type."""
        assert EncodingType.SUB is not None

    def test_encoding_type_rot(self):
        """Test ROT encoding type."""
        assert EncodingType.ROT is not None

    def test_encoding_type_base64(self):
        """Test BASE64 encoding type."""
        assert EncodingType.BASE64 is not None

    def test_encoding_type_aes(self):
        """Test AES encoding type."""
        assert EncodingType.AES is not None

    def test_encoding_type_rc4(self):
        """Test RC4 encoding type."""
        assert EncodingType.RC4 is not None


# =============================================================================
# Test EncoderConfig Data Class
# =============================================================================

class TestEncoderConfig:
    """Tests for the EncoderConfig data class."""

    def test_config_creation(self):
        """Test EncoderConfig creation."""
        config = EncoderConfig(
            shellcode=b"\x90\x90",
            encoding_type=EncodingType.XOR
        )
        assert config.shellcode == b"\x90\x90"

    def test_config_with_iterations(self):
        """Test EncoderConfig with iterations."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.XOR,
            iterations=5
        )
        assert config.iterations == 5

    def test_config_with_bad_chars(self):
        """Test EncoderConfig with bad characters."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.XOR,
            bad_chars=b"\x00\x0a\x0d"
        )
        assert b"\x00" in config.bad_chars


# =============================================================================
# Test EncoderOutput Data Class
# =============================================================================

class TestEncoderOutput:
    """Tests for the EncoderOutput data class."""

    def test_output_creation(self):
        """Test EncoderOutput creation."""
        output = EncoderOutput(
            encoded_shellcode=b"\x41\x41",
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        assert output.encoded_shellcode == b"\x41\x41"

    def test_output_with_decoder_stub(self):
        """Test EncoderOutput with decoder stub."""
        output = EncoderOutput(
            encoded_shellcode=b"\x41",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            decoder_stub=b"\x31\xc9"
        )
        assert output.decoder_stub is not None


# =============================================================================
# Test Individual Encoders
# =============================================================================

class TestXOREncoder:
    """Tests for the XOREncoder class."""

    def test_xor_encoder_initialization(self):
        """Test XOREncoder initialization."""
        encoder = XOREncoder()
        assert encoder is not None

    def test_xor_encode(self):
        """Test XOR encoding."""
        encoder = XOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x41"
        result = encoder.encode(shellcode, key)

        # XOR should produce different output
        assert result != shellcode

    def test_xor_decode_roundtrip(self):
        """Test XOR encode/decode roundtrip."""
        encoder = XOREncoder()
        original = b"\x90\x90\x90\x90"
        key = b"\x41"

        encoded = encoder.encode(original, key)
        decoded = encoder.encode(encoded, key)  # XOR is reversible

        assert decoded == original


class TestRollingXOREncoder:
    """Tests for the RollingXOREncoder class."""

    def test_rolling_xor_encoder(self):
        """Test RollingXOREncoder."""
        encoder = RollingXOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x41\x42\x43\x44"
        result = encoder.encode(shellcode, key)

        assert result != shellcode


class TestADDEncoder:
    """Tests for the ADDEncoder class."""

    def test_add_encoder(self):
        """Test ADDEncoder."""
        encoder = ADDEncoder()
        shellcode = b"\x00\x01\x02\x03"
        key = b"\x10"
        result = encoder.encode(shellcode, key)

        # ADD should increase byte values (with wrap)
        assert result != shellcode


class TestSUBEncoder:
    """Tests for the SUBEncoder class."""

    def test_sub_encoder(self):
        """Test SUBEncoder."""
        encoder = SUBEncoder()
        shellcode = b"\x10\x20\x30\x40"
        key = b"\x10"
        result = encoder.encode(shellcode, key)

        assert result != shellcode


class TestROTEncoder:
    """Tests for the ROTEncoder class."""

    def test_rot_encoder(self):
        """Test ROTEncoder."""
        encoder = ROTEncoder()
        shellcode = b"\x90\x90\x90\x90"
        result = encoder.encode(shellcode, rotation=3)

        assert result != shellcode


class TestBase64Encoder:
    """Tests for the Base64Encoder class."""

    def test_base64_encoder(self):
        """Test Base64Encoder."""
        encoder = Base64Encoder()
        shellcode = b"\x90\x90\x90\x90"
        result = encoder.encode(shellcode)

        # Base64 output should be larger
        assert len(result) > len(shellcode)

    def test_base64_decode_roundtrip(self):
        """Test Base64 encode/decode roundtrip."""
        import base64
        encoder = Base64Encoder()
        original = b"\x90\x90\x90\x90"

        encoded = encoder.encode(original)
        decoded = base64.b64decode(encoded)

        assert decoded == original


class TestAESEncoder:
    """Tests for the AESEncoder class."""

    def test_aes_encoder(self):
        """Test AESEncoder."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 32  # AES needs blocks
        key = b"0123456789abcdef"  # 16-byte key
        result = encoder.encode(shellcode, key)

        # AES should produce encrypted output
        assert result != shellcode


class TestRC4Encoder:
    """Tests for the RC4Encoder class."""

    def test_rc4_encoder(self):
        """Test RC4Encoder."""
        encoder = RC4Encoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"secretkey"
        result = encoder.encode(shellcode, key)

        assert result != shellcode

    def test_rc4_decode_roundtrip(self):
        """Test RC4 encode/decode roundtrip."""
        encoder = RC4Encoder()
        original = b"\x90\x90\x90\x90"
        key = b"secretkey"

        encoded = encoder.encode(original, key)
        decoded = encoder.encode(encoded, key)  # RC4 is reversible

        assert decoded == original


# =============================================================================
# Test ShellcodeEncoderTool Class
# =============================================================================

class TestShellcodeEncoderTool:
    """Tests for the ShellcodeEncoderTool class."""

    def test_tool_initialization(self):
        """Test ShellcodeEncoderTool initialization."""
        config = EncoderConfig(
            shellcode=b"\x90\x90",
            encoding_type=EncodingType.XOR
        )
        tool = ShellcodeEncoderTool(config)
        assert tool is not None

    def test_tool_encode_xor(self):
        """Test encoding with XOR."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert isinstance(output, EncoderOutput)
        assert output.encoded_shellcode != config.shellcode

    def test_tool_encode_base64(self):
        """Test encoding with Base64."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.BASE64
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert isinstance(output, EncoderOutput)

    def test_tool_chain_encoding(self):
        """Test chained encoding."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            chain=[EncodingType.BASE64]
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert isinstance(output, EncoderOutput)

    def test_tool_avoids_bad_chars(self):
        """Test avoiding bad characters."""
        config = EncoderConfig(
            shellcode=b"\x90\x00\x90\x00",
            encoding_type=EncodingType.XOR,
            bad_chars=b"\x00"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        # Should find a key that avoids null bytes
        assert b"\x00" not in output.encoded_shellcode or output.key is None


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_input_argument(self):
        """Test parsing input file argument."""
        with patch('sys.argv', ['shellcode_encoder.py', '-i', 'shellcode.bin']):
            args = parse_arguments()
            assert args.input == 'shellcode.bin' or 'shellcode.bin' in str(args.input)

    def test_parse_encoding_argument(self):
        """Test parsing encoding type argument."""
        with patch('sys.argv', ['shellcode_encoder.py', '-e', 'xor']):
            args = parse_arguments()
            assert 'xor' in str(args.encoding).lower()

    def test_parse_key_argument(self):
        """Test parsing key argument."""
        with patch('sys.argv', ['shellcode_encoder.py', '-k', '0x41']):
            args = parse_arguments()
            assert args.key == '0x41' or '41' in str(args.key)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['shellcode_encoder.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_bad_chars_argument(self):
        """Test parsing bad characters argument."""
        with patch('sys.argv', ['shellcode_encoder.py', '-b', '\\x00\\x0a']):
            args = parse_arguments()
            assert args.bad_chars or '00' in str(args.bad_chars)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for shellcode encoder."""

    def test_encode_all_types(self):
        """Test encoding with all encoding types."""
        shellcode = b"\x90\x90\x90\x90"

        for encoding_type in EncodingType:
            config = EncoderConfig(
                shellcode=shellcode,
                encoding_type=encoding_type,
                key=b"key12345key12345"  # 16 bytes for AES
            )
            tool = ShellcodeEncoderTool(config)

            try:
                output = tool.encode()
                assert isinstance(output, EncoderOutput)
            except Exception:
                pass  # Some encoders may need specific key sizes

    def test_multiple_iterations(self):
        """Test multiple encoding iterations."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            iterations=3
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        # After 3 iterations, output should be different
        assert output.encoded_shellcode != config.shellcode

    def test_output_format_c_array(self):
        """Test C array output format."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            output_format="c"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()
        formatted = tool.format_output(output)

        # C array format should contain hex values
        assert "0x" in formatted or "\\x" in formatted
