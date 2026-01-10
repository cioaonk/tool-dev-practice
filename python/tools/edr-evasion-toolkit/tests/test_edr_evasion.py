#!/usr/bin/env python3
"""
Unit tests for EDR Evasion Toolkit
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from edr_evasion import (
    EDREvasionToolkit,
    DirectSyscallGenerator,
    APIHashingTechniques,
    TechniqueCategory,
    Platform,
    RiskLevel,
    get_documentation
)


class TestEDREvasionToolkit(unittest.TestCase):
    """Test cases for EDREvasionToolkit"""

    def setUp(self):
        """Set up test fixtures"""
        self.toolkit = EDREvasionToolkit()

    def test_list_techniques(self):
        """Test listing techniques"""
        techniques = self.toolkit.list_techniques()
        self.assertTrue(len(techniques) > 0)
        self.assertIn("direct_syscalls", techniques)
        self.assertIn("full_unhooking", techniques)

    def test_get_technique(self):
        """Test getting specific technique"""
        tech = self.toolkit.get_technique("direct_syscalls")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.name, "Direct Syscalls")
        self.assertEqual(tech.category, TechniqueCategory.DIRECT_SYSCALLS)

    def test_get_invalid_technique(self):
        """Test getting invalid technique returns None"""
        tech = self.toolkit.get_technique("nonexistent")
        self.assertIsNone(tech)

    def test_techniques_have_required_fields(self):
        """Test that all techniques have required fields"""
        for name in self.toolkit.list_techniques():
            tech = self.toolkit.get_technique(name)
            self.assertTrue(hasattr(tech, 'name'))
            self.assertTrue(hasattr(tech, 'category'))
            self.assertTrue(hasattr(tech, 'description'))
            self.assertTrue(hasattr(tech, 'detection_methods'))
            self.assertTrue(hasattr(tech, 'mitigations'))
            self.assertTrue(len(tech.detection_methods) > 0)

    def test_get_by_category(self):
        """Test filtering by category"""
        syscall_techs = self.toolkit.get_techniques_by_category(
            TechniqueCategory.DIRECT_SYSCALLS
        )
        self.assertTrue(len(syscall_techs) > 0)
        for tech in syscall_techs:
            self.assertEqual(tech.category, TechniqueCategory.DIRECT_SYSCALLS)

    def test_plan_mode(self):
        """Test plan mode output"""
        plan = self.toolkit.plan("direct_syscalls")
        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("DISCLAIMER", plan)
        self.assertIn("Detection Methods", plan)

    def test_plan_all(self):
        """Test plan all techniques"""
        plan = self.toolkit.plan("all")
        self.assertIn("Available EDR Evasion Techniques", plan)


class TestDirectSyscallGenerator(unittest.TestCase):
    """Test cases for DirectSyscallGenerator"""

    def setUp(self):
        """Set up test fixtures"""
        self.generator = DirectSyscallGenerator()

    def test_list_syscalls(self):
        """Test listing syscalls"""
        syscalls = self.generator.list_syscalls()
        self.assertTrue(len(syscalls) > 0)
        self.assertIn("NtAllocateVirtualMemory", syscalls)
        self.assertIn("NtWriteVirtualMemory", syscalls)

    def test_get_syscall_info(self):
        """Test getting syscall info"""
        info = self.generator.get_syscall_info("NtAllocateVirtualMemory")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "NtAllocateVirtualMemory")
        self.assertTrue(info.syscall_number_win10 > 0)
        self.assertTrue(len(info.parameters) > 0)

    def test_get_invalid_syscall(self):
        """Test getting invalid syscall returns None"""
        info = self.generator.get_syscall_info("FakeSyscall")
        self.assertIsNone(info)

    def test_generate_x64_stub(self):
        """Test generating x64 syscall stub"""
        stub = self.generator.get_syscall_stub_x64("NtTest", 0x18)
        self.assertIn("NtTest", stub)
        self.assertIn("syscall", stub)
        self.assertIn("mov r10, rcx", stub)

    def test_generate_x86_stub(self):
        """Test generating x86 syscall stub"""
        stub = self.generator.get_syscall_stub_x86("NtTest", 0x18)
        self.assertIn("NtTest", stub)
        self.assertIn("sysenter", stub)


class TestAPIHashingTechniques(unittest.TestCase):
    """Test cases for API hashing"""

    def setUp(self):
        """Set up test fixtures"""
        self.hasher = APIHashingTechniques()

    def test_djb2_hash(self):
        """Test DJB2 hash generation"""
        h = self.hasher.djb2_hash("VirtualAlloc")
        self.assertIsInstance(h, int)
        self.assertTrue(h > 0)

        # Same input should produce same hash
        h2 = self.hasher.djb2_hash("VirtualAlloc")
        self.assertEqual(h, h2)

    def test_ror13_hash(self):
        """Test ROR13 hash generation"""
        h = self.hasher.ror13_hash("CreateThread")
        self.assertIsInstance(h, int)
        self.assertTrue(h > 0)

    def test_different_inputs_different_hashes(self):
        """Test different inputs produce different hashes"""
        h1 = self.hasher.djb2_hash("VirtualAlloc")
        h2 = self.hasher.djb2_hash("CreateThread")
        self.assertNotEqual(h1, h2)

    def test_generate_hash_table(self):
        """Test generating hash table"""
        apis = ["VirtualAlloc", "CreateThread", "WriteProcessMemory"]
        table = self.hasher.generate_hash_table(apis)

        self.assertEqual(len(table), 3)
        for api in apis:
            self.assertIn(api, table)
            self.assertIn("djb2", table[api])
            self.assertIn("ror13", table[api])


class TestToolkitIntegration(unittest.TestCase):
    """Integration tests for toolkit"""

    def setUp(self):
        """Set up test fixtures"""
        self.toolkit = EDREvasionToolkit()

    def test_generate_syscall_stub(self):
        """Test generating syscall stub via toolkit"""
        stub = self.toolkit.generate_syscall_stub(
            "NtAllocateVirtualMemory",
            Platform.WINDOWS_X64
        )
        self.assertIn("NtAllocateVirtualMemory", stub)
        self.assertIn("syscall", stub)

    def test_generate_syscall_stub_invalid(self):
        """Test error on invalid syscall"""
        with self.assertRaises(ValueError):
            self.toolkit.generate_syscall_stub("FakeSyscall")

    def test_generate_api_hashes(self):
        """Test generating API hashes via toolkit"""
        apis = ["VirtualAlloc", "CreateThread"]
        hashes = self.toolkit.generate_api_hashes(apis)
        self.assertEqual(len(hashes), 2)


class TestDocumentation(unittest.TestCase):
    """Test documentation hooks"""

    def test_documentation_structure(self):
        """Test documentation has required fields"""
        docs = get_documentation()
        required_fields = ['name', 'version', 'category', 'description',
                          'usage', 'techniques', 'arguments']
        for field in required_fields:
            self.assertIn(field, docs)

    def test_mitre_techniques(self):
        """Test MITRE techniques are documented"""
        docs = get_documentation()
        self.assertIn('mitre_techniques', docs)
        self.assertTrue(len(docs['mitre_techniques']) > 0)

    def test_disclaimer(self):
        """Test disclaimer is present"""
        docs = get_documentation()
        self.assertIn('disclaimer', docs)


class TestTechniqueCategories(unittest.TestCase):
    """Test technique category coverage"""

    def test_all_categories_have_techniques(self):
        """Test that major categories have techniques"""
        toolkit = EDREvasionToolkit()

        # Check key categories have at least one technique
        categories_to_check = [
            TechniqueCategory.DIRECT_SYSCALLS,
            TechniqueCategory.UNHOOKING,
            TechniqueCategory.MEMORY_EVASION,
            TechniqueCategory.ETW_BYPASS,
        ]

        for category in categories_to_check:
            techs = toolkit.get_techniques_by_category(category)
            self.assertTrue(
                len(techs) > 0,
                f"Category {category.value} has no techniques"
            )


if __name__ == '__main__':
    unittest.main()
