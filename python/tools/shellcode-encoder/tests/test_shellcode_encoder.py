#!/usr/bin/env python3
"""
Unit tests for Shellcode Encoder
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shellcode_encoder import (
    ShellcodeEncoderTool,
    EncoderConfig,
    EncodingType,
    OutputFormat,
    XOREncoder,
    RollingXOREncoder,
    ADDEncoder,
    RC4Encoder,
    get_documentation
)


class TestShellcodeEncoderTool(unittest.TestCase):
    """Test cases for ShellcodeEncoderTool"""

    def setUp(self):
        """Set up test fixtures"""
        self.tool = ShellcodeEncoderTool()
        self.test_shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"

    def test_available_encoders(self):
        """Test listing available encoders"""
        encoders = self.tool.get_available_encoders()
        self.assertIn("xor", encoders)
        self.assertIn("rc4", encoders)
        self.assertIn("base64", encoders)

    def test_xor_encoding(self):
        """Test XOR encoding"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            key=b"\xaa"
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertEqual(len(result.encoded_shellcode), len(self.test_shellcode))
        self.assertNotEqual(result.encoded_shellcode, self.test_shellcode)

    def test_xor_decoding(self):
        """Test XOR encoding is reversible"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            key=b"\xaa"
        )
        result = self.tool.encode(self.test_shellcode, config)
        # XOR again with same key should give original
        decoded_result = self.tool.encode(result.encoded_shellcode, config)
        self.assertEqual(decoded_result.encoded_shellcode, self.test_shellcode)

    def test_rolling_xor(self):
        """Test rolling XOR encoding"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR_ROLLING,
            key=b"\x41"
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertNotEqual(result.encoded_shellcode, self.test_shellcode)

    def test_add_encoding(self):
        """Test ADD encoding"""
        config = EncoderConfig(
            encoding_type=EncodingType.ADD,
            key=b"\x10"
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertNotEqual(result.encoded_shellcode, self.test_shellcode)
        # Each byte should be increased by 0x10
        for i in range(len(self.test_shellcode)):
            expected = (self.test_shellcode[i] + 0x10) & 0xFF
            self.assertEqual(result.encoded_shellcode[i], expected)

    def test_rc4_encoding(self):
        """Test RC4 encoding"""
        config = EncoderConfig(
            encoding_type=EncodingType.RC4,
            key=b"secretkey"
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertEqual(len(result.encoded_shellcode), len(self.test_shellcode))

    def test_rc4_roundtrip(self):
        """Test RC4 encoding is reversible"""
        config = EncoderConfig(
            encoding_type=EncodingType.RC4,
            key=b"secretkey"
        )
        result = self.tool.encode(self.test_shellcode, config)
        decoded = self.tool.encode(result.encoded_shellcode, config)
        self.assertEqual(decoded.encoded_shellcode, self.test_shellcode)

    def test_base64_encoding(self):
        """Test Base64 encoding"""
        config = EncoderConfig(
            encoding_type=EncodingType.BASE64
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertTrue(len(result.encoded_shellcode) > len(self.test_shellcode))

    def test_multiple_iterations(self):
        """Test multiple encoding iterations"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            key=b"\xaa",
            iterations=3
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertEqual(result.iterations, 3)

    def test_null_free_generation(self):
        """Test null-free key generation"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            null_free=True,
            bad_chars=b'\x00'
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertNotIn(0, result.key_used)

    def test_chain_encoding(self):
        """Test chain encoding"""
        encodings = [EncodingType.XOR, EncodingType.ADD]
        encoded, chain_info = self.tool.chain_encode(self.test_shellcode, encodings)
        self.assertEqual(len(chain_info), 2)
        self.assertNotEqual(encoded, self.test_shellcode)

    def test_decoder_stub_generation(self):
        """Test decoder stub is generated"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            generate_decoder=True
        )
        result = self.tool.encode(self.test_shellcode, config)
        self.assertTrue(len(result.decoder_stub) > 0)
        self.assertIn("Decoder", result.decoder_stub)


class TestOutputFormats(unittest.TestCase):
    """Test output format generation"""

    def setUp(self):
        """Set up test fixtures"""
        self.tool = ShellcodeEncoderTool()
        self.test_bytes = b"\x31\xc0\x50"

    def test_hex_format(self):
        """Test hex format output"""
        output = self.tool.format_output(self.test_bytes, OutputFormat.HEX)
        self.assertIn("\\x31", output)
        self.assertIn("\\xc0", output)

    def test_c_array_format(self):
        """Test C array format"""
        output = self.tool.format_output(self.test_bytes, OutputFormat.C_ARRAY)
        self.assertIn("unsigned char", output)
        self.assertIn("0x31", output)

    def test_python_format(self):
        """Test Python format"""
        output = self.tool.format_output(self.test_bytes, OutputFormat.PYTHON)
        self.assertIn('b"', output)
        self.assertIn("\\x31", output)

    def test_powershell_format(self):
        """Test PowerShell format"""
        output = self.tool.format_output(self.test_bytes, OutputFormat.POWERSHELL)
        self.assertIn("[Byte[]]", output)
        self.assertIn("0x31", output)

    def test_csharp_format(self):
        """Test C# format"""
        output = self.tool.format_output(self.test_bytes, OutputFormat.CSHARP)
        self.assertIn("byte[]", output)
        self.assertIn("new byte[]", output)


class TestShellcodeAnalysis(unittest.TestCase):
    """Test shellcode analysis"""

    def setUp(self):
        """Set up test fixtures"""
        self.tool = ShellcodeEncoderTool()

    def test_basic_analysis(self):
        """Test basic analysis"""
        shellcode = b"\x31\xc0\x50\x68\x00\x0a"
        analysis = self.tool.analyze_shellcode(shellcode)
        self.assertEqual(analysis['size'], 6)
        self.assertEqual(analysis['null_bytes'], 1)
        self.assertEqual(analysis['newline_bytes'], 1)

    def test_entropy_calculation(self):
        """Test entropy is calculated"""
        shellcode = b"\x00" * 100  # Low entropy
        analysis = self.tool.analyze_shellcode(shellcode)
        self.assertEqual(analysis['entropy'], 0.0)

        shellcode = bytes(range(256))  # Max entropy
        analysis = self.tool.analyze_shellcode(shellcode)
        self.assertGreater(analysis['entropy'], 7.0)


class TestIndividualEncoders(unittest.TestCase):
    """Test individual encoder classes"""

    def test_xor_encoder(self):
        """Test XOR encoder directly"""
        encoder = XOREncoder()
        shellcode = b"\x41\x42\x43"
        key = b"\xff"
        encoded = encoder.encode(shellcode, key)
        self.assertEqual(encoded, b"\xbe\xbd\xbc")

    def test_add_encoder(self):
        """Test ADD encoder directly"""
        encoder = ADDEncoder()
        shellcode = b"\x10\x20\x30"
        key = b"\x05"
        encoded = encoder.encode(shellcode, key)
        self.assertEqual(encoded, b"\x15\x25\x35")


class TestPlanMode(unittest.TestCase):
    """Test planning mode"""

    def setUp(self):
        """Set up test fixtures"""
        self.tool = ShellcodeEncoderTool()

    def test_plan_output(self):
        """Test plan mode generates correct output"""
        config = EncoderConfig(
            encoding_type=EncodingType.XOR,
            iterations=2,
            null_free=True
        )
        plan = self.tool.plan("test.bin", config)
        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("xor", plan.lower())
        self.assertIn("DISCLAIMER", plan)


class TestDocumentation(unittest.TestCase):
    """Test documentation hooks"""

    def test_documentation_structure(self):
        """Test documentation has required fields"""
        docs = get_documentation()
        required_fields = ['name', 'version', 'category', 'description',
                          'usage', 'encoders', 'arguments']
        for field in required_fields:
            self.assertIn(field, docs)

    def test_encoders_documented(self):
        """Test all encoders are documented"""
        docs = get_documentation()
        encoder_names = [e['name'] for e in docs['encoders']]
        self.assertIn('xor', encoder_names)
        self.assertIn('rc4', encoder_names)


if __name__ == '__main__':
    unittest.main()
