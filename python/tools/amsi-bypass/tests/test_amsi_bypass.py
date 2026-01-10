#!/usr/bin/env python3
"""
Unit tests for AMSI Bypass Generator
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from amsi_bypass import (
    AMSIBypassGenerator,
    BypassCategory,
    RiskLevel,
    StringObfuscator,
    get_documentation
)


class TestAMSIBypassGenerator(unittest.TestCase):
    """Test cases for AMSIBypassGenerator"""

    def setUp(self):
        """Set up test fixtures"""
        self.generator = AMSIBypassGenerator()

    def test_available_techniques(self):
        """Test that techniques are available"""
        techniques = self.generator.get_available_techniques()
        self.assertTrue(len(techniques) > 0)
        self.assertIn("force_amsi_error", techniques)
        self.assertIn("amsi_scan_buffer_patch", techniques)

    def test_technique_structure(self):
        """Test that techniques have required fields"""
        for name, tech in self.generator.techniques.items():
            self.assertTrue(hasattr(tech, 'name'))
            self.assertTrue(hasattr(tech, 'category'))
            self.assertTrue(hasattr(tech, 'code'))
            self.assertTrue(hasattr(tech, 'risk_level'))
            self.assertTrue(hasattr(tech, 'detection_methods'))

    def test_generate_bypass(self):
        """Test bypass generation"""
        result = self.generator.generate_bypass("force_amsi_error")
        self.assertIn("code", result)
        self.assertIn("name", result)
        self.assertIn("risk_level", result)
        self.assertTrue(len(result['code']) > 0)

    def test_generate_with_obfuscation(self):
        """Test obfuscation changes output"""
        plain = self.generator.generate_bypass("force_amsi_error", obfuscation=0)
        obfuscated = self.generator.generate_bypass("force_amsi_error", obfuscation=2)
        self.assertNotEqual(plain['code'], obfuscated['code'])

    def test_generate_with_base64(self):
        """Test base64 encoding"""
        result = self.generator.generate_bypass("force_amsi_error", encode_base64=True)
        self.assertTrue(result['base64_encoded'])
        self.assertIn("-enc", result['code'])

    def test_invalid_technique(self):
        """Test error on invalid technique"""
        with self.assertRaises(ValueError):
            self.generator.generate_bypass("nonexistent_technique")

    def test_get_by_category(self):
        """Test filtering by category"""
        memory_techniques = self.generator.get_techniques_by_category(
            BypassCategory.MEMORY_PATCHING
        )
        self.assertTrue(len(memory_techniques) > 0)
        for tech in memory_techniques:
            self.assertEqual(tech.category, BypassCategory.MEMORY_PATCHING)

    def test_plan_mode(self):
        """Test plan mode output"""
        plan = self.generator.plan("force_amsi_error")
        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("DISCLAIMER", plan)
        self.assertIn("Detection Methods", plan)

    def test_plan_all(self):
        """Test plan mode for all techniques"""
        plan = self.generator.plan("all")
        self.assertIn("Available AMSI Bypass Techniques", plan)

    def test_chain_generation(self):
        """Test multi-technique chain"""
        chain = self.generator.get_chained_bypass()
        self.assertIn("Technique 1", chain)
        self.assertIn("Technique 2", chain)


class TestStringObfuscator(unittest.TestCase):
    """Test cases for StringObfuscator"""

    def test_split_string(self):
        """Test string splitting"""
        result = StringObfuscator.split_string("AmsiUtils")
        self.assertIn("'+'", result)
        self.assertNotIn("AmsiUtils", result)

    def test_char_array(self):
        """Test char array conversion"""
        result = StringObfuscator.char_array("test")
        self.assertIn("char[]", result)

    def test_base64_decode(self):
        """Test base64 decode wrapper"""
        result = StringObfuscator.base64_decode("test")
        self.assertIn("FromBase64String", result)
        self.assertIn("Unicode", result)

    def test_reverse_string(self):
        """Test string reversal"""
        result = StringObfuscator.reverse_string("test")
        self.assertIn("tset", result)  # reversed
        self.assertIn("-join", result)

    def test_format_string(self):
        """Test format string"""
        result = StringObfuscator.format_string("testvalue")
        self.assertIn("-f", result)


class TestBypassCategories(unittest.TestCase):
    """Test bypass categories"""

    def test_all_categories_exist(self):
        """Test all categories are defined"""
        categories = [
            BypassCategory.MEMORY_PATCHING,
            BypassCategory.REFLECTION,
            BypassCategory.COM_HIJACKING,
            BypassCategory.POWERSHELL_DOWNGRADE,
            BypassCategory.CONTEXT_MANIPULATION
        ]
        for cat in categories:
            self.assertIsNotNone(cat.value)


class TestDocumentation(unittest.TestCase):
    """Test documentation hooks"""

    def test_documentation_structure(self):
        """Test documentation has required fields"""
        docs = get_documentation()
        required_fields = ['name', 'version', 'category', 'description',
                          'usage', 'techniques', 'arguments']
        for field in required_fields:
            self.assertIn(field, docs)

    def test_amsi_overview(self):
        """Test AMSI overview in documentation"""
        docs = get_documentation()
        self.assertIn('amsi_overview', docs)
        self.assertIn('full_name', docs['amsi_overview'])

    def test_disclaimer(self):
        """Test disclaimer is present"""
        docs = get_documentation()
        self.assertIn('disclaimer', docs)


if __name__ == '__main__':
    unittest.main()
