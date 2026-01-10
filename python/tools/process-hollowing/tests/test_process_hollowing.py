#!/usr/bin/env python3
"""
Unit tests for Process Hollowing Demonstrator
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from process_hollowing import (
    ProcessHollowingDemonstrator,
    HollowingConfig,
    Platform,
    WindowsAPISimulator,
    get_documentation
)


class TestProcessHollowingDemonstrator(unittest.TestCase):
    """Test cases for ProcessHollowingDemonstrator"""

    def setUp(self):
        """Set up test fixtures"""
        self.demonstrator = ProcessHollowingDemonstrator()

    def test_steps_defined(self):
        """Test that all hollowing steps are defined"""
        self.assertEqual(len(self.demonstrator.steps), 8)

    def test_step_structure(self):
        """Test that steps have required attributes"""
        for step in self.demonstrator.steps:
            self.assertTrue(hasattr(step, 'name'))
            self.assertTrue(hasattr(step, 'description'))
            self.assertTrue(hasattr(step, 'api_calls'))
            self.assertTrue(hasattr(step, 'detection_vectors'))
            self.assertTrue(len(step.api_calls) > 0)

    def test_common_targets(self):
        """Test that common targets are defined"""
        targets = self.demonstrator.get_common_targets()
        self.assertTrue(len(targets) > 0)

        # Check svchost.exe is included
        target_names = [t.name for t in targets]
        self.assertIn("svchost.exe", target_names)

    def test_target_structure(self):
        """Test target process structure"""
        targets = self.demonstrator.get_common_targets()
        for target in targets:
            self.assertTrue(hasattr(target, 'name'))
            self.assertTrue(hasattr(target, 'path'))
            self.assertTrue(hasattr(target, 'architecture'))
            self.assertTrue(hasattr(target, 'suspicion_level'))

    def test_explain_step_valid(self):
        """Test step explanation with valid index"""
        explanation = self.demonstrator.explain_step(0)
        self.assertIn("Create Suspended Process", explanation)
        self.assertIn("API Calls", explanation)

    def test_explain_step_invalid(self):
        """Test step explanation with invalid index"""
        explanation = self.demonstrator.explain_step(99)
        self.assertEqual(explanation, "Invalid step index")

    def test_plan_mode(self):
        """Test planning mode output"""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_source="test.exe",
            platform=Platform.WINDOWS_X64
        )
        plan = self.demonstrator.plan(config)
        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("svchost.exe", plan)
        self.assertIn("DISCLAIMER", plan)
        self.assertIn("no actions were performed", plan)

    def test_plan_with_ppid_spoof(self):
        """Test plan mode with PPID spoofing"""
        config = HollowingConfig(
            target_process="notepad.exe",
            payload_source="test.exe",
            platform=Platform.WINDOWS_X64,
            ppid_spoof=True
        )
        plan = self.demonstrator.plan(config)
        self.assertIn("PPID Spoofing: Enabled", plan)

    def test_demonstration_mode(self):
        """Test demonstration mode output"""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_source="test.exe",
            platform=Platform.WINDOWS_X64
        )
        demo = self.demonstrator.demonstrate(config)
        self.assertIn("[DEMONSTRATION MODE]", demo)
        self.assertIn("educational demonstration", demo.lower())
        self.assertIn("Key Takeaways", demo)

    def test_detection_guidance(self):
        """Test detection guidance output"""
        guidance = self.demonstrator.get_detection_guidance()
        self.assertIn("API Monitoring", guidance)
        self.assertIn("Memory Analysis", guidance)
        self.assertIn("Behavioral Indicators", guidance)


class TestWindowsAPISimulator(unittest.TestCase):
    """Test cases for WindowsAPISimulator"""

    def test_get_known_api(self):
        """Test getting known API prototype"""
        info = WindowsAPISimulator.get_api_prototype("CreateProcessA")
        self.assertEqual(info['dll'], "kernel32.dll")
        self.assertIn("BOOL", info['prototype'])

    def test_get_ntdll_api(self):
        """Test getting ntdll API"""
        info = WindowsAPISimulator.get_api_prototype("NtUnmapViewOfSection")
        self.assertEqual(info['dll'], "ntdll.dll")

    def test_get_unknown_api(self):
        """Test getting unknown API"""
        info = WindowsAPISimulator.get_api_prototype("FakeAPICall")
        self.assertEqual(info['dll'], "unknown")


class TestHollowingConfig(unittest.TestCase):
    """Test cases for HollowingConfig"""

    def test_default_values(self):
        """Test default configuration values"""
        config = HollowingConfig(
            target_process="test.exe",
            payload_source="payload.exe",
            platform=Platform.WINDOWS_X64
        )
        self.assertFalse(config.ppid_spoof)
        self.assertFalse(config.block_dlls)
        self.assertTrue(config.create_no_window)
        self.assertIsNone(config.parent_pid)

    def test_custom_values(self):
        """Test custom configuration values"""
        config = HollowingConfig(
            target_process="test.exe",
            payload_source="payload.exe",
            platform=Platform.WINDOWS_X86,
            ppid_spoof=True,
            block_dlls=True,
            parent_pid=1234
        )
        self.assertTrue(config.ppid_spoof)
        self.assertTrue(config.block_dlls)
        self.assertEqual(config.parent_pid, 1234)


class TestDocumentation(unittest.TestCase):
    """Test cases for documentation hooks"""

    def test_documentation_structure(self):
        """Test documentation has required fields"""
        docs = get_documentation()
        required_fields = ['name', 'version', 'category', 'description',
                          'usage', 'technique_reference', 'arguments']
        for field in required_fields:
            self.assertIn(field, docs)

    def test_mitre_reference(self):
        """Test MITRE ATT&CK reference"""
        docs = get_documentation()
        self.assertIn('mitre_attack', docs['technique_reference'])
        self.assertEqual(docs['technique_reference']['mitre_attack'], 'T1055.012')

    def test_disclaimer_present(self):
        """Test disclaimer is present"""
        docs = get_documentation()
        self.assertIn('disclaimer', docs)


if __name__ == '__main__':
    unittest.main()
