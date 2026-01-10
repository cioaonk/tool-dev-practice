#!/usr/bin/env python3
"""
Unit tests for Payload Generator
"""

import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payload_generator import PayloadGenerator, PayloadConfig, get_documentation


class TestPayloadGenerator(unittest.TestCase):
    """Test cases for PayloadGenerator class"""

    def setUp(self):
        """Set up test fixtures"""
        self.generator = PayloadGenerator()

    def test_available_payloads(self):
        """Test that available payloads are returned correctly"""
        available = self.generator.get_available_payloads()
        self.assertIn("reverse_shell", available)
        self.assertIn("python", available["reverse_shell"])
        self.assertIn("powershell", available["reverse_shell"])

    def test_python_reverse_shell(self):
        """Test Python reverse shell generation"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444
        )
        result = self.generator.generate(config)
        self.assertIn("socket", result.payload)
        self.assertIn("10.0.0.1", result.payload)
        self.assertIn("4444", result.payload)

    def test_powershell_reverse_shell(self):
        """Test PowerShell reverse shell generation"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="powershell",
            lhost="192.168.1.100",
            lport=8080
        )
        result = self.generator.generate(config)
        self.assertIn("TCPClient", result.payload)
        self.assertIn("192.168.1.100", result.payload)
        self.assertIn("8080", result.payload)

    def test_bash_reverse_shell(self):
        """Test Bash reverse shell generation"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="bash",
            lhost="10.10.10.10",
            lport=9001
        )
        result = self.generator.generate(config)
        self.assertIn("/dev/tcp", result.payload)
        self.assertIn("10.10.10.10", result.payload)

    def test_php_webshell(self):
        """Test PHP web shell generation"""
        config = PayloadConfig(
            payload_type="web_shell",
            language="php",
            lport=4444
        )
        result = self.generator.generate(config)
        self.assertIn("<?php", result.payload)
        self.assertIn("system", result.payload.lower())

    def test_base64_encoding(self):
        """Test base64 encoding of payload"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444,
            encoding="base64"
        )
        result = self.generator.generate(config)
        self.assertEqual(result.encoding, "base64")
        # Should not contain plain text socket
        self.assertNotIn("socket.socket", result.payload)

    def test_hex_encoding(self):
        """Test hex encoding of payload"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444,
            encoding="hex"
        )
        result = self.generator.generate(config)
        self.assertEqual(result.encoding, "hex")
        # Should be hex string
        self.assertTrue(all(c in '0123456789abcdef' for c in result.payload))

    def test_obfuscation_level(self):
        """Test that obfuscation modifies payload"""
        config_plain = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444,
            obfuscation_level=0
        )
        config_obfuscated = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444,
            obfuscation_level=1
        )
        result_plain = self.generator.generate(config_plain)
        result_obfuscated = self.generator.generate(config_obfuscated)
        self.assertNotEqual(result_plain.payload, result_obfuscated.payload)

    def test_invalid_payload_type(self):
        """Test error handling for invalid payload type"""
        config = PayloadConfig(
            payload_type="invalid_type",
            language="python",
            lhost="10.0.0.1",
            lport=4444
        )
        with self.assertRaises(ValueError):
            self.generator.generate(config)

    def test_invalid_language(self):
        """Test error handling for invalid language"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="cobol",
            lhost="10.0.0.1",
            lport=4444
        )
        with self.assertRaises(ValueError):
            self.generator.generate(config)

    def test_plan_mode(self):
        """Test planning mode output"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444
        )
        plan_output = self.generator.plan(config)
        self.assertIn("[PLAN MODE]", plan_output)
        self.assertIn("reverse_shell", plan_output)
        self.assertIn("python", plan_output)
        self.assertIn("Detection Considerations", plan_output)

    def test_payload_notes(self):
        """Test that payload includes notes"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444
        )
        result = self.generator.generate(config)
        self.assertTrue(len(result.notes) > 0)

    def test_detection_vectors(self):
        """Test that payload includes detection vectors"""
        config = PayloadConfig(
            payload_type="reverse_shell",
            language="python",
            lhost="10.0.0.1",
            lport=4444
        )
        result = self.generator.generate(config)
        self.assertTrue(len(result.detection_considerations) > 0)


class TestDocumentation(unittest.TestCase):
    """Test cases for documentation hooks"""

    def test_documentation_structure(self):
        """Test that documentation has required fields"""
        docs = get_documentation()
        required_fields = ['name', 'version', 'category', 'description',
                          'usage', 'supported_payloads', 'arguments']
        for field in required_fields:
            self.assertIn(field, docs)

    def test_documentation_payloads(self):
        """Test that documentation lists supported payloads"""
        docs = get_documentation()
        self.assertIn('reverse_shell', docs['supported_payloads'])
        self.assertIn('web_shell', docs['supported_payloads'])


if __name__ == '__main__':
    unittest.main()
