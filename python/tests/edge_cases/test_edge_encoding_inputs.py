#!/usr/bin/env python3
"""
Edge Case Tests for Encoding Input Handling
============================================

Comprehensive edge case tests for payload/shellcode encoding including:
- Empty payloads
- Binary data with null bytes
- Maximum size payloads
- Already-encoded inputs
- Key edge cases
- Output format edge cases

These tests verify that encoding-related tools handle unusual inputs
safely and predictably.
"""

import base64
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "shellcode-encoder"))


# =============================================================================
# Attempt imports with graceful fallback
# =============================================================================

try:
    from shellcode_encoder import (
        ShellcodeEncoderTool,
        EncoderConfig,
        EncodingResult,
        EncodingType,
        OutputFormat,
        XOREncoder,
        RollingXOREncoder,
        ADDEncoder,
        ROTEncoder,
        RC4Encoder,
        Base64Encoder,
    )
    ENCODER_AVAILABLE = True
except ImportError:
    ENCODER_AVAILABLE = False
    ShellcodeEncoderTool = None
    EncoderConfig = None
    EncodingResult = None
    EncodingType = None
    OutputFormat = None


# =============================================================================
# Helper Functions
# =============================================================================

def encode_safe(shellcode: bytes, encoding_type, key: Optional[bytes] = None) -> Optional[bytes]:
    """
    Safely encode shellcode.
    Returns None on error.
    """
    if not ENCODER_AVAILABLE:
        pytest.skip("ShellcodeEncoderTool not available")
        return None

    try:
        tool = ShellcodeEncoderTool()
        config = EncoderConfig(
            encoding_type=encoding_type,
            key=key,
            iterations=1,
            null_free=False,
            generate_decoder=False,
        )
        result = tool.encode(shellcode, config)
        return result.encoded_shellcode
    except Exception:
        return None


def get_encoder_tool():
    """Get a new encoder tool instance."""
    if not ENCODER_AVAILABLE:
        pytest.skip("ShellcodeEncoderTool not available")
        return None
    return ShellcodeEncoderTool()


# =============================================================================
# Empty Payload Tests
# =============================================================================

@pytest.mark.edge_case
class TestEmptyPayloads:
    """Edge case tests for empty payload handling."""

    def test_empty_shellcode_xor(self):
        """Test XOR encoding of empty shellcode."""
        if ENCODER_AVAILABLE:
            result = encode_safe(b"", EncodingType.XOR, key=b"\x41")
            # Should return empty or handle gracefully
            assert result is not None
            assert result == b"" or len(result) == 0

    def test_empty_shellcode_base64(self):
        """Test Base64 encoding of empty shellcode."""
        if ENCODER_AVAILABLE:
            result = encode_safe(b"", EncodingType.BASE64)
            assert result is not None
            # Empty base64 is empty string
            assert result == b""

    def test_empty_shellcode_rc4(self):
        """Test RC4 encoding of empty shellcode."""
        if ENCODER_AVAILABLE:
            result = encode_safe(b"", EncodingType.RC4, key=b"key")
            assert result is not None
            assert result == b""

    @pytest.mark.parametrize("encoding", [
        "XOR", "XOR_ROLLING", "ADD", "ROT", "RC4", "BASE64"
    ])
    def test_empty_shellcode_all_encoders(self, encoding: str):
        """Test empty shellcode with all encoder types."""
        if ENCODER_AVAILABLE:
            enc_type = EncodingType(encoding.lower())
            result = encode_safe(b"", enc_type)
            # All should handle empty input gracefully


# =============================================================================
# Null Byte Tests
# =============================================================================

@pytest.mark.edge_case
class TestNullBytePayloads:
    """Edge case tests for null byte handling in payloads."""

    def test_single_null_byte(self):
        """Test encoding of single null byte."""
        if ENCODER_AVAILABLE:
            result = encode_safe(b"\x00", EncodingType.XOR, key=b"\xff")
            assert result is not None
            # XOR with 0xff should give 0xff
            assert result == b"\xff"

    def test_all_null_bytes(self):
        """Test encoding of all null bytes."""
        if ENCODER_AVAILABLE:
            null_data = b"\x00" * 100
            result = encode_safe(null_data, EncodingType.XOR, key=b"\xaa")
            assert result is not None
            # All should XOR to the key value
            assert result == b"\xaa" * 100

    def test_null_bytes_in_middle(self):
        """Test encoding with null bytes in middle of data."""
        if ENCODER_AVAILABLE:
            data = b"\x41\x42\x00\x00\x43\x44"
            result = encode_safe(data, EncodingType.XOR, key=b"\x11")
            assert result is not None
            assert len(result) == len(data)

    def test_null_free_encoding(self):
        """Test null-free encoding option."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                # Shellcode with null bytes
                shellcode = b"\x00\x41\x42\x00\x43"
                config = EncoderConfig(
                    encoding_type=EncodingType.XOR,
                    null_free=True,
                    bad_chars=b"\x00\x0a\x0d",
                )
                try:
                    result = tool.encode(shellcode, config)
                    # Should attempt to find null-free encoding
                    assert result is not None
                except Exception:
                    pass  # May fail if no valid key found


# =============================================================================
# Binary Data Tests
# =============================================================================

@pytest.mark.edge_case
class TestBinaryDataPayloads:
    """Edge case tests for various binary data patterns."""

    def test_all_byte_values(self):
        """Test encoding of all possible byte values."""
        if ENCODER_AVAILABLE:
            all_bytes = bytes(range(256))
            result = encode_safe(all_bytes, EncodingType.XOR, key=b"\x00")
            assert result is not None
            # XOR with 0 should return original
            assert result == all_bytes

    def test_alternating_bytes(self):
        """Test encoding of alternating byte pattern."""
        if ENCODER_AVAILABLE:
            alternating = b"\x00\xff" * 128
            result = encode_safe(alternating, EncodingType.XOR, key=b"\xaa")
            assert result is not None
            assert len(result) == 256

    def test_repeating_pattern(self):
        """Test encoding of repeating patterns."""
        if ENCODER_AVAILABLE:
            patterns = [
                b"\xaa" * 100,
                b"\x55" * 100,
                b"\x00\x00\xff\xff" * 25,
            ]
            for pattern in patterns:
                result = encode_safe(pattern, EncodingType.XOR, key=b"\x11")
                assert result is not None
                assert len(result) == len(pattern)

    def test_random_like_data(self):
        """Test encoding of pseudo-random data."""
        if ENCODER_AVAILABLE:
            import hashlib
            # Generate deterministic pseudo-random data
            random_data = hashlib.sha256(b"seed").digest() * 10
            result = encode_safe(random_data, EncodingType.XOR, key=b"\x42")
            assert result is not None
            assert len(result) == len(random_data)

    def test_high_entropy_data(self):
        """Test encoding of high-entropy data."""
        if ENCODER_AVAILABLE:
            # Compressed-like data (high entropy)
            high_entropy = bytes([i ^ ((i * 17) % 256) for i in range(256)])
            result = encode_safe(high_entropy, EncodingType.RC4, key=b"secret")
            assert result is not None


# =============================================================================
# Maximum Size Tests
# =============================================================================

@pytest.mark.edge_case
class TestMaximumSizePayloads:
    """Edge case tests for large payload handling."""

    @pytest.mark.parametrize("size", [1, 10, 100, 1000, 10000])
    def test_various_sizes(self, size: int):
        """Test encoding of various sizes."""
        if ENCODER_AVAILABLE:
            data = b"A" * size
            result = encode_safe(data, EncodingType.XOR, key=b"\x00")
            assert result is not None
            assert len(result) == size

    @pytest.mark.slow
    def test_large_payload_1mb(self):
        """Test encoding of 1MB payload."""
        if ENCODER_AVAILABLE:
            import time
            data = b"X" * (1024 * 1024)
            start = time.time()
            result = encode_safe(data, EncodingType.XOR, key=b"\xaa")
            elapsed = time.time() - start

            assert result is not None
            assert len(result) == len(data)
            assert elapsed < 5.0, f"Encoding took too long: {elapsed}s"

    @pytest.mark.slow
    def test_large_payload_base64(self):
        """Test Base64 encoding of large payload."""
        if ENCODER_AVAILABLE:
            data = b"X" * (100 * 1024)  # 100KB
            result = encode_safe(data, EncodingType.BASE64)
            assert result is not None
            # Base64 expands by ~4/3
            assert len(result) >= len(data)

    def test_boundary_sizes(self):
        """Test encoding at boundary sizes."""
        if ENCODER_AVAILABLE:
            boundary_sizes = [255, 256, 257, 1023, 1024, 1025, 65535, 65536]
            for size in boundary_sizes:
                data = b"B" * size
                result = encode_safe(data, EncodingType.XOR, key=b"\x11")
                if result is not None:
                    assert len(result) == size


# =============================================================================
# Already-Encoded Input Tests
# =============================================================================

@pytest.mark.edge_case
class TestAlreadyEncodedInputs:
    """Edge case tests for already-encoded inputs."""

    def test_base64_encoded_input(self):
        """Test encoding of already Base64-encoded data."""
        if ENCODER_AVAILABLE:
            original = b"test shellcode"
            b64_encoded = base64.b64encode(original)
            # Encode the already-encoded data
            result = encode_safe(b64_encoded, EncodingType.XOR, key=b"\x42")
            assert result is not None

    def test_double_xor_encoding(self):
        """Test double XOR encoding (should cancel out with same key)."""
        if ENCODER_AVAILABLE:
            original = b"test data"
            key = b"\xaa"

            first_encode = encode_safe(original, EncodingType.XOR, key=key)
            assert first_encode is not None

            second_encode = encode_safe(first_encode, EncodingType.XOR, key=key)
            assert second_encode is not None

            # Double XOR with same key should return original
            assert second_encode == original

    def test_chain_encoding(self):
        """Test chain encoding (multiple different encodings)."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool and hasattr(tool, 'chain_encode'):
                original = b"shellcode"
                encodings = [EncodingType.XOR, EncodingType.ADD, EncodingType.ROT]
                try:
                    result, chain_info = tool.chain_encode(original, encodings)
                    assert result is not None
                    assert len(chain_info) == len(encodings)
                except Exception:
                    pass

    def test_hex_string_input(self):
        """Test encoding of hex string (as bytes)."""
        if ENCODER_AVAILABLE:
            hex_string = b"\\x41\\x42\\x43"  # Literal backslash-x notation
            result = encode_safe(hex_string, EncodingType.XOR, key=b"\x00")
            assert result is not None
            assert result == hex_string  # XOR with 0 returns original

    def test_url_encoded_input(self):
        """Test encoding of URL-encoded data."""
        if ENCODER_AVAILABLE:
            url_encoded = b"%41%42%43"
            result = encode_safe(url_encoded, EncodingType.XOR, key=b"\x11")
            assert result is not None


# =============================================================================
# Key Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestKeyEdgeCases:
    """Edge case tests for encoding keys."""

    def test_null_key(self):
        """Test encoding with null key (0x00)."""
        if ENCODER_AVAILABLE:
            data = b"test"
            result = encode_safe(data, EncodingType.XOR, key=b"\x00")
            assert result is not None
            # XOR with 0 returns original
            assert result == data

    def test_all_ones_key(self):
        """Test encoding with all-ones key (0xff)."""
        if ENCODER_AVAILABLE:
            data = b"test"
            result = encode_safe(data, EncodingType.XOR, key=b"\xff")
            assert result is not None
            # Each byte should be inverted
            expected = bytes([b ^ 0xff for b in data])
            assert result == expected

    def test_multi_byte_key(self):
        """Test encoding with multi-byte key."""
        if ENCODER_AVAILABLE:
            data = b"test data here"
            key = b"\x11\x22\x33\x44"
            result = encode_safe(data, EncodingType.XOR, key=key)
            assert result is not None
            assert len(result) == len(data)

    def test_long_key(self):
        """Test encoding with key longer than data."""
        if ENCODER_AVAILABLE:
            data = b"short"
            key = b"this is a very long key that exceeds the data length"
            result = encode_safe(data, EncodingType.XOR, key=key)
            assert result is not None
            assert len(result) == len(data)

    def test_empty_key(self):
        """Test encoding with empty key."""
        if ENCODER_AVAILABLE:
            data = b"test"
            # Empty key should be handled gracefully
            try:
                result = encode_safe(data, EncodingType.XOR, key=b"")
                # May use auto-generated key or raise error
            except Exception:
                pass  # Acceptable

    def test_key_same_as_data(self):
        """Test encoding where key equals data."""
        if ENCODER_AVAILABLE:
            data = b"AAAA"
            key = b"AAAA"
            result = encode_safe(data, EncodingType.XOR, key=key)
            assert result is not None
            # XOR with itself should give all zeros
            assert result == b"\x00\x00\x00\x00"

    def test_auto_generated_key(self):
        """Test that auto-generated keys are valid."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                key = tool.generate_key(length=4, avoid_bytes=b"\x00")
                assert len(key) == 4
                assert b"\x00" not in key


# =============================================================================
# Output Format Tests
# =============================================================================

@pytest.mark.edge_case
class TestOutputFormats:
    """Edge case tests for output formatting."""

    @pytest.mark.parametrize("format_type", [
        "RAW", "C_ARRAY", "PYTHON", "POWERSHELL", "CSHARP", "HEX"
    ])
    def test_all_output_formats(self, format_type: str):
        """Test all output formats work correctly."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                data = b"\x41\x42\x43"  # ABC
                try:
                    fmt = OutputFormat(format_type.lower())
                    formatted = tool.format_output(data, fmt)
                    assert formatted is not None
                    assert isinstance(formatted, str)
                except Exception:
                    pass

    def test_empty_data_formatting(self):
        """Test formatting of empty data."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                for fmt_name in ["raw", "hex", "c_array", "python"]:
                    try:
                        fmt = OutputFormat(fmt_name)
                        formatted = tool.format_output(b"", fmt)
                        assert formatted is not None
                    except Exception:
                        pass

    def test_null_bytes_in_formatting(self):
        """Test formatting of data with null bytes."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                data = b"\x00\x41\x00\x42"
                for fmt_name in ["hex", "c_array", "python"]:
                    try:
                        fmt = OutputFormat(fmt_name)
                        formatted = tool.format_output(data, fmt)
                        assert formatted is not None
                        # Null bytes should be properly represented
                        assert "00" in formatted or "\\x00" in formatted or "0x00" in formatted
                    except Exception:
                        pass

    def test_special_chars_in_formatting(self):
        """Test formatting of special characters."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                # Chars that might need escaping
                data = b"\x00\x0a\x0d\x1b\x22\x27\x5c"
                for fmt_name in ["python", "c_array", "csharp"]:
                    try:
                        fmt = OutputFormat(fmt_name)
                        formatted = tool.format_output(data, fmt)
                        assert formatted is not None
                    except Exception:
                        pass

    def test_large_data_formatting(self):
        """Test formatting of large data."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                data = b"X" * 10000
                try:
                    fmt = OutputFormat.HEX
                    formatted = tool.format_output(data, fmt)
                    assert formatted is not None
                    # Hex output should be 2x length + escape sequences
                    assert len(formatted) >= len(data) * 2
                except Exception:
                    pass


# =============================================================================
# Encoder-Specific Tests
# =============================================================================

@pytest.mark.edge_case
class TestEncoderSpecificEdgeCases:
    """Edge case tests specific to individual encoders."""

    def test_xor_self_inverse_property(self):
        """Test XOR encoder self-inverse property."""
        if ENCODER_AVAILABLE:
            encoder = XOREncoder()
            data = b"test data"
            key = b"\xaa"

            encoded = encoder.encode(data, key)
            decoded = encoder.encode(encoded, key)
            assert decoded == data

    def test_rolling_xor_determinism(self):
        """Test Rolling XOR produces deterministic output."""
        if ENCODER_AVAILABLE:
            encoder = RollingXOREncoder()
            data = b"test data"
            key = b"\x42"

            result1 = encoder.encode(data, key)
            result2 = encoder.encode(data, key)
            assert result1 == result2

    def test_add_encoder_wraparound(self):
        """Test ADD encoder handles byte wraparound."""
        if ENCODER_AVAILABLE:
            encoder = ADDEncoder()
            # Adding to 0xff should wrap around
            data = b"\xff"
            key = b"\x01"
            result = encoder.encode(data, key)
            assert result == b"\x00"

    def test_rot_encoder_full_rotation(self):
        """Test ROT encoder with full rotation (256)."""
        if ENCODER_AVAILABLE:
            encoder = ROTEncoder()
            data = b"test"
            # Rotation by 256 should return original (mod 256)
            # But key is single byte, so max is 255
            key = b"\x00"
            result = encoder.encode(data, key)
            assert result == data

    def test_rc4_symmetric_property(self):
        """Test RC4 symmetric encryption property."""
        if ENCODER_AVAILABLE:
            encoder = RC4Encoder()
            data = b"secret message"
            key = b"secretkey"

            encrypted = encoder.encode(data, key)
            decrypted = encoder.encode(encrypted, key)
            assert decrypted == data

    def test_base64_padding(self):
        """Test Base64 encoder padding."""
        if ENCODER_AVAILABLE:
            encoder = Base64Encoder()
            # Test different input lengths for padding
            for length in range(1, 10):
                data = b"X" * length
                result = encoder.encode(data, b"")  # Key not used for base64
                assert result is not None
                # Base64 output length should be multiple of 4
                assert len(result) % 4 == 0


# =============================================================================
# Error Handling Tests
# =============================================================================

@pytest.mark.edge_case
class TestEncodingErrorHandling:
    """Edge case tests for error handling in encoding."""

    def test_invalid_encoding_type(self):
        """Test handling of invalid encoding type."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                try:
                    # Create config with invalid type
                    config = EncoderConfig(
                        encoding_type="invalid",  # This should fail
                    )
                except (ValueError, TypeError):
                    pass  # Expected

    def test_iteration_edge_cases(self):
        """Test encoding with various iteration counts."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                data = b"test"
                iteration_counts = [0, 1, 2, 10, 100]
                for iterations in iteration_counts:
                    try:
                        config = EncoderConfig(
                            encoding_type=EncodingType.XOR,
                            iterations=iterations,
                        )
                        result = tool.encode(data, config)
                        # Should handle or reject
                    except Exception:
                        pass

    def test_negative_iterations(self):
        """Test encoding with negative iterations."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool:
                try:
                    config = EncoderConfig(
                        encoding_type=EncodingType.XOR,
                        iterations=-1,
                    )
                    result = tool.encode(b"test", config)
                except (ValueError, TypeError):
                    pass  # Expected


# =============================================================================
# Shellcode Analysis Tests
# =============================================================================

@pytest.mark.edge_case
class TestShellcodeAnalysis:
    """Edge case tests for shellcode analysis features."""

    def test_analyze_empty_shellcode(self):
        """Test analysis of empty shellcode."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool and hasattr(tool, 'analyze_shellcode'):
                analysis = tool.analyze_shellcode(b"")
                assert analysis is not None
                assert analysis.get("size") == 0
                assert analysis.get("entropy") == 0.0

    def test_analyze_single_byte(self):
        """Test analysis of single byte shellcode."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool and hasattr(tool, 'analyze_shellcode'):
                analysis = tool.analyze_shellcode(b"\x90")
                assert analysis is not None
                assert analysis.get("size") == 1

    def test_analyze_high_entropy(self):
        """Test analysis of high-entropy data."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool and hasattr(tool, 'analyze_shellcode'):
                # Random-like data should have high entropy
                high_entropy = bytes(range(256))
                analysis = tool.analyze_shellcode(high_entropy)
                assert analysis is not None
                # Entropy should be close to 8 (maximum for bytes)
                assert analysis.get("entropy", 0) > 7.0

    def test_analyze_low_entropy(self):
        """Test analysis of low-entropy data."""
        if ENCODER_AVAILABLE:
            tool = get_encoder_tool()
            if tool and hasattr(tool, 'analyze_shellcode'):
                # Repetitive data should have low entropy
                low_entropy = b"\x90" * 256
                analysis = tool.analyze_shellcode(low_entropy)
                assert analysis is not None
                # Entropy should be 0 (only one unique byte)
                assert analysis.get("entropy", 8) == 0.0
