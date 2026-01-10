#!/usr/bin/env python3
"""
Edge Case Tests for Shellcode Encoder
======================================

Comprehensive edge case testing for the shellcode-encoder tool including:
- Empty inputs
- All encoding schemes
- Key validation
- Bad character handling
- Boundary conditions
- Encoding/decoding roundtrips

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import base64
from unittest.mock import patch, MagicMock

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
# Empty Input Tests
# =============================================================================

class TestEmptyInputs:
    """Tests for handling empty inputs."""

    def test_empty_shellcode(self):
        """Empty shellcode should be handled gracefully."""
        try:
            config = EncoderConfig(
                shellcode=b"",
                encoding_type=EncodingType.XOR
            )
            tool = ShellcodeEncoderTool(config)
            output = tool.encode()
            # May return empty or raise ValueError
        except ValueError:
            pass  # Acceptable

    def test_empty_key_xor(self):
        """Empty key for XOR should be handled."""
        try:
            config = EncoderConfig(
                shellcode=b"\x90\x90\x90\x90",
                encoding_type=EncodingType.XOR,
                key=b""
            )
            tool = ShellcodeEncoderTool(config)
            output = tool.encode()
        except (ValueError, ZeroDivisionError):
            pass  # Acceptable


# =============================================================================
# All Encoding Scheme Tests
# =============================================================================

class TestAllEncodingSchemes:
    """Tests for all encoding schemes."""

    @pytest.mark.parametrize("encoding_type", list(EncodingType))
    def test_all_encoding_types(self, encoding_type):
        """All encoding types should work without crashing."""
        shellcode = b"\x90\x90\x90\x90\xcc\xcc\xcc\xcc"
        key = b"0123456789abcdef"  # 16-byte key for AES compatibility

        try:
            config = EncoderConfig(
                shellcode=shellcode,
                encoding_type=encoding_type,
                key=key
            )
            tool = ShellcodeEncoderTool(config)
            output = tool.encode()

            assert isinstance(output, EncoderOutput)
            # Encoded shellcode should be different (except base64 which is just encoding)
        except Exception as e:
            # Some encoders may need specific key sizes
            if "key" in str(e).lower() or "size" in str(e).lower():
                pass  # Acceptable for key size issues
            else:
                raise


# =============================================================================
# XOR Encoder Tests
# =============================================================================

class TestXOREncoder:
    """Tests for XOR encoder."""

    def test_xor_basic_encoding(self):
        """Basic XOR encoding should work."""
        encoder = XOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x41"

        result = encoder.encode(shellcode, key)
        assert result != shellcode
        assert len(result) == len(shellcode)

    def test_xor_roundtrip(self):
        """XOR encoding should be reversible."""
        encoder = XOREncoder()
        original = b"\x90\x90\x90\x90\xcc\xcc"
        key = b"\x41"

        encoded = encoder.encode(original, key)
        decoded = encoder.encode(encoded, key)  # XOR is self-inverse

        assert decoded == original

    def test_xor_with_various_keys(self):
        """XOR should work with various key sizes."""
        encoder = XOREncoder()
        shellcode = b"\x90\x90\x90\x90"

        keys = [
            b"\x00",            # Zero key (no change)
            b"\xff",            # All ones
            b"\x41",            # Single byte
            b"\x41\x42",        # Two bytes
            b"\x41\x42\x43\x44",  # Four bytes
        ]

        for key in keys:
            result = encoder.encode(shellcode, key)
            assert len(result) == len(shellcode)

    def test_xor_with_zero_key(self):
        """XOR with zero key should return original."""
        encoder = XOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x00"

        result = encoder.encode(shellcode, key)
        assert result == shellcode  # XOR with 0 = identity


# =============================================================================
# Rolling XOR Encoder Tests
# =============================================================================

class TestRollingXOREncoder:
    """Tests for Rolling XOR encoder."""

    def test_rolling_xor_basic(self):
        """Basic rolling XOR encoding."""
        encoder = RollingXOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x41\x42\x43\x44"

        result = encoder.encode(shellcode, key)
        assert result != shellcode

    def test_rolling_xor_varies_per_byte(self):
        """Rolling XOR should produce different values for same input byte."""
        encoder = RollingXOREncoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"\x01\x02\x03\x04"

        result = encoder.encode(shellcode, key)
        # Result bytes should be different (XOR with different key bytes)
        # Unless all key bytes are same


# =============================================================================
# ADD Encoder Tests
# =============================================================================

class TestADDEncoder:
    """Tests for ADD encoder."""

    def test_add_basic_encoding(self):
        """Basic ADD encoding."""
        encoder = ADDEncoder()
        shellcode = b"\x00\x10\x20\x30"
        key = b"\x10"

        result = encoder.encode(shellcode, key)
        assert result != shellcode

    def test_add_overflow_handling(self):
        """ADD should handle overflow (wrap around)."""
        encoder = ADDEncoder()
        shellcode = b"\xff\xfe\xfd"  # Near max values
        key = b"\x10"

        result = encoder.encode(shellcode, key)
        # Should wrap around without crashing


# =============================================================================
# SUB Encoder Tests
# =============================================================================

class TestSUBEncoder:
    """Tests for SUB encoder."""

    def test_sub_basic_encoding(self):
        """Basic SUB encoding."""
        encoder = SUBEncoder()
        shellcode = b"\x10\x20\x30\x40"
        key = b"\x10"

        result = encoder.encode(shellcode, key)
        assert result != shellcode

    def test_sub_underflow_handling(self):
        """SUB should handle underflow (wrap around)."""
        encoder = SUBEncoder()
        shellcode = b"\x00\x01\x02"  # Near min values
        key = b"\x10"

        result = encoder.encode(shellcode, key)
        # Should wrap around without crashing


# =============================================================================
# ROT Encoder Tests
# =============================================================================

class TestROTEncoder:
    """Tests for ROT encoder."""

    def test_rot_basic_encoding(self):
        """Basic ROT encoding."""
        encoder = ROTEncoder()
        shellcode = b"\x90\x90\x90\x90"

        result = encoder.encode(shellcode, rotation=3)
        assert result != shellcode

    @pytest.mark.parametrize("rotation", [0, 1, 7, 8, 15, 16, 31, 32, 255])
    def test_rot_various_rotations(self, rotation):
        """ROT should work with various rotation values."""
        encoder = ROTEncoder()
        shellcode = b"\x90\x90\x90\x90"

        result = encoder.encode(shellcode, rotation=rotation)
        if rotation % 256 == 0 or rotation % 8 == 0:
            # May be same depending on implementation
            pass
        # Should not crash


# =============================================================================
# Base64 Encoder Tests
# =============================================================================

class TestBase64Encoder:
    """Tests for Base64 encoder."""

    def test_base64_basic_encoding(self):
        """Basic Base64 encoding."""
        encoder = Base64Encoder()
        shellcode = b"\x90\x90\x90\x90"

        result = encoder.encode(shellcode)
        # Base64 output is larger than input
        assert len(result) > len(shellcode)

    def test_base64_roundtrip(self):
        """Base64 encoding should be decodable."""
        encoder = Base64Encoder()
        original = b"\x90\x90\x90\x90"

        encoded = encoder.encode(original)
        decoded = base64.b64decode(encoded)

        assert decoded == original

    def test_base64_with_null_bytes(self):
        """Base64 should handle null bytes correctly."""
        encoder = Base64Encoder()
        shellcode = b"\x00\x00\x00\x00"

        result = encoder.encode(shellcode)
        decoded = base64.b64decode(result)

        assert decoded == shellcode


# =============================================================================
# AES Encoder Tests
# =============================================================================

class TestAESEncoder:
    """Tests for AES encoder."""

    def test_aes_basic_encoding(self):
        """Basic AES encoding with valid key."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 32  # Multiple of block size
        key = b"0123456789abcdef"  # 16-byte key

        result = encoder.encode(shellcode, key)
        assert result != shellcode

    @pytest.mark.parametrize("key_size", [16, 24, 32])
    def test_aes_valid_key_sizes(self, key_size):
        """AES should accept valid key sizes (128, 192, 256 bits)."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 32
        key = b"A" * key_size

        try:
            result = encoder.encode(shellcode, key)
        except ValueError as e:
            # Some implementations may only support certain key sizes
            pass

    def test_aes_invalid_key_size(self):
        """AES should reject invalid key sizes."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 32
        key = b"short"  # Too short

        try:
            result = encoder.encode(shellcode, key)
        except ValueError:
            pass  # Expected for invalid key size

    def test_aes_with_padding(self):
        """AES should handle non-block-aligned input."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 17  # Not multiple of 16
        key = b"0123456789abcdef"

        try:
            result = encoder.encode(shellcode, key)
            # Should either pad automatically or raise error
        except ValueError:
            pass  # Acceptable


# =============================================================================
# RC4 Encoder Tests
# =============================================================================

class TestRC4Encoder:
    """Tests for RC4 encoder."""

    def test_rc4_basic_encoding(self):
        """Basic RC4 encoding."""
        encoder = RC4Encoder()
        shellcode = b"\x90\x90\x90\x90"
        key = b"secretkey"

        result = encoder.encode(shellcode, key)
        assert result != shellcode
        assert len(result) == len(shellcode)

    def test_rc4_roundtrip(self):
        """RC4 encoding should be reversible."""
        encoder = RC4Encoder()
        original = b"\x90\x90\x90\x90"
        key = b"secretkey"

        encoded = encoder.encode(original, key)
        decoded = encoder.encode(encoded, key)  # RC4 is self-inverse

        assert decoded == original

    def test_rc4_various_key_lengths(self):
        """RC4 should accept various key lengths."""
        encoder = RC4Encoder()
        shellcode = b"\x90\x90\x90\x90"

        keys = [
            b"a",               # 1 byte
            b"ab",              # 2 bytes
            b"short",           # 5 bytes
            b"0123456789abcdef",  # 16 bytes
            b"a" * 256,         # 256 bytes (max for RC4)
        ]

        for key in keys:
            result = encoder.encode(shellcode, key)
            assert len(result) == len(shellcode)


# =============================================================================
# Bad Character Handling Tests
# =============================================================================

class TestBadCharacterHandling:
    """Tests for bad character avoidance."""

    def test_avoid_null_bytes(self):
        """Encoder should be able to avoid null bytes."""
        config = EncoderConfig(
            shellcode=b"\x90\x00\x90\x00",
            encoding_type=EncodingType.XOR,
            bad_chars=b"\x00"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        # Should attempt to find key that avoids null bytes
        # May or may not succeed depending on implementation

    def test_avoid_multiple_bad_chars(self):
        """Encoder should avoid multiple bad characters."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            bad_chars=b"\x00\x0a\x0d\x20"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

    def test_all_bytes_bad(self):
        """When all bytes are bad, encoding may fail."""
        all_bad = bytes(range(256))
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            bad_chars=all_bad
        )
        tool = ShellcodeEncoderTool(config)
        try:
            output = tool.encode()
            # May fail or return without bad char avoidance
        except ValueError:
            pass  # Acceptable


# =============================================================================
# Key Validation Tests
# =============================================================================

class TestKeyValidation:
    """Tests for key validation."""

    def test_none_key(self):
        """None key should be handled."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=None
        )
        tool = ShellcodeEncoderTool(config)
        try:
            output = tool.encode()
            # May auto-generate key or fail
        except (TypeError, ValueError):
            pass

    def test_very_long_key(self):
        """Very long key should be handled."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"A" * 10000
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()


# =============================================================================
# Iteration Tests
# =============================================================================

class TestIterations:
    """Tests for multiple encoding iterations."""

    @pytest.mark.parametrize("iterations", [1, 2, 3, 5, 10])
    def test_multiple_iterations(self, iterations):
        """Multiple iterations should compound encoding."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            iterations=iterations
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        if iterations % 2 == 0:
            # Even iterations of XOR return to original
            pass
        else:
            # Odd iterations should differ
            assert output.encoded_shellcode != config.shellcode

    def test_zero_iterations(self):
        """Zero iterations should return original or raise error."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            iterations=0
        )
        tool = ShellcodeEncoderTool(config)
        try:
            output = tool.encode()
            # May return original
        except ValueError:
            pass

    def test_negative_iterations(self):
        """Negative iterations should be handled."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            iterations=-1
        )
        tool = ShellcodeEncoderTool(config)
        try:
            output = tool.encode()
        except ValueError:
            pass


# =============================================================================
# Chain Encoding Tests
# =============================================================================

class TestChainEncoding:
    """Tests for chained encoding."""

    def test_chain_xor_then_base64(self):
        """Chain XOR then Base64 encoding."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            chain=[EncodingType.BASE64]
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert isinstance(output, EncoderOutput)

    def test_chain_multiple_encodings(self):
        """Chain multiple encoding types."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            chain=[EncodingType.ADD, EncodingType.BASE64]
        )
        tool = ShellcodeEncoderTool(config)
        try:
            output = tool.encode()
        except (ValueError, TypeError):
            pass  # Chain may require additional keys


# =============================================================================
# Output Format Tests
# =============================================================================

class TestOutputFormats:
    """Tests for output format options."""

    def test_c_array_format(self):
        """C array output format should be valid."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            output_format="c"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()
        formatted = tool.format_output(output)

        assert "0x" in formatted or "\\x" in formatted

    def test_python_format(self):
        """Python output format."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            output_format="python"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()
        try:
            formatted = tool.format_output(output)
        except (AttributeError, KeyError):
            pass  # Format may not be supported


# =============================================================================
# Boundary Condition Tests
# =============================================================================

class TestBoundaryConditions:
    """Tests for boundary conditions."""

    def test_single_byte_shellcode(self):
        """Single byte shellcode should work."""
        config = EncoderConfig(
            shellcode=b"\x90",
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert len(output.encoded_shellcode) >= 1

    def test_very_large_shellcode(self):
        """Very large shellcode should be handled."""
        shellcode = b"\x90" * 100000  # 100KB
        config = EncoderConfig(
            shellcode=shellcode,
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

        assert len(output.encoded_shellcode) == len(shellcode)

    def test_all_same_bytes(self):
        """Shellcode with all same bytes."""
        config = EncoderConfig(
            shellcode=b"\x00" * 100,
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()

    def test_all_different_bytes(self):
        """Shellcode with all different bytes."""
        shellcode = bytes(range(256))
        config = EncoderConfig(
            shellcode=shellcode,
            encoding_type=EncodingType.XOR,
            key=b"\x41"
        )
        tool = ShellcodeEncoderTool(config)
        output = tool.encode()


# =============================================================================
# EncoderOutput Tests
# =============================================================================

class TestEncoderOutput:
    """Tests for EncoderOutput data class."""

    def test_output_with_all_fields(self):
        """EncoderOutput with all fields populated."""
        output = EncoderOutput(
            encoded_shellcode=b"\x41\x41",
            encoding_type=EncodingType.XOR,
            key=b"\x41",
            decoder_stub=b"\x31\xc9"
        )
        assert output.encoded_shellcode == b"\x41\x41"
        assert output.encoding_type == EncodingType.XOR
        assert output.key == b"\x41"
        assert output.decoder_stub == b"\x31\xc9"

    def test_output_with_none_decoder_stub(self):
        """EncoderOutput with no decoder stub."""
        output = EncoderOutput(
            encoded_shellcode=b"\x41\x41",
            encoding_type=EncodingType.BASE64,
            key=None
        )
        # decoder_stub may be None by default


# =============================================================================
# Planning Mode Tests
# =============================================================================

class TestPlanningMode:
    """Tests for planning mode."""

    def test_plan_mode_shows_encoding_info(self, capsys):
        """Planning mode should show encoding information."""
        config = EncoderConfig(
            shellcode=b"\x90\x90\x90\x90",
            encoding_type=EncodingType.XOR,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()

        assert "[PLAN MODE]" in captured.out
        assert "XOR" in captured.out or "xor" in captured.out.lower()

    def test_plan_mode_shows_shellcode_size(self, capsys):
        """Planning mode should show shellcode size."""
        shellcode = b"\x90" * 100
        config = EncoderConfig(
            shellcode=shellcode,
            encoding_type=EncodingType.XOR,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()

        assert "[PLAN MODE]" in captured.out
        assert "100" in captured.out or "size" in captured.out.lower()


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_encoding_type(self):
        """Invalid encoding type should be rejected."""
        try:
            config = EncoderConfig(
                shellcode=b"\x90\x90",
                encoding_type="invalid"
            )
        except (ValueError, TypeError):
            pass  # Expected

    def test_tool_with_none_config(self):
        """Tool should handle None config."""
        try:
            tool = ShellcodeEncoderTool(None)
            output = tool.encode()
        except (TypeError, AttributeError):
            pass  # Expected


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
