#!/usr/bin/env python3
"""
Unit tests for Baseline Auditor tool.
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    FileEntry,
    ProcessEntry,
    NetworkEntry,
    Baseline,
    Violation,
    AuditResult,
    FileCollector,
    BaselineAuditor,
    BaselineManager,
    get_documentation,
)


class TestFileEntry(unittest.TestCase):
    """Tests for FileEntry data class."""

    def test_to_dict(self):
        """Test serialization."""
        entry = FileEntry(
            path="/etc/passwd",
            hash_sha256="abc123",
            size=1024,
            mode=33188,
            mtime=1705312200.0,
            owner="root"
        )
        data = entry.to_dict()
        self.assertEqual(data["path"], "/etc/passwd")
        self.assertEqual(data["hash_sha256"], "abc123")

    def test_from_dict(self):
        """Test deserialization."""
        data = {
            "path": "/etc/passwd",
            "hash_sha256": "abc123",
            "size": 1024,
            "mode": 33188,
            "mtime": 1705312200.0,
            "owner": "root"
        }
        entry = FileEntry.from_dict(data)
        self.assertEqual(entry.path, "/etc/passwd")
        self.assertEqual(entry.owner, "root")


class TestBaseline(unittest.TestCase):
    """Tests for Baseline data class."""

    def test_to_dict(self):
        """Test baseline serialization."""
        baseline = Baseline(
            created=datetime.now(),
            hostname="test-host",
            files={},
            processes={},
            listening_ports={},
            metadata={}
        )
        data = baseline.to_dict()
        self.assertEqual(data["hostname"], "test-host")
        self.assertIn("created", data)

    def test_from_dict(self):
        """Test baseline deserialization."""
        data = {
            "created": "2024-01-15T10:30:00",
            "hostname": "test-host",
            "files": {},
            "processes": {},
            "listening_ports": {},
            "metadata": {}
        }
        baseline = Baseline.from_dict(data)
        self.assertEqual(baseline.hostname, "test-host")


class TestFileCollector(unittest.TestCase):
    """Tests for FileCollector."""

    def test_collect_single_file(self):
        """Test collecting a single file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_path = f.name

        try:
            collector = FileCollector([temp_path])
            entries = collector.collect()

            self.assertEqual(len(entries), 1)
            self.assertIn(temp_path, entries)
            self.assertNotEqual(entries[temp_path].hash_sha256, "ERROR")
        finally:
            os.unlink(temp_path)

    def test_collect_directory(self):
        """Test collecting files from directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            for i in range(3):
                path = os.path.join(tmpdir, f"file{i}.txt")
                with open(path, 'w') as f:
                    f.write(f"content {i}")

            collector = FileCollector([tmpdir])
            entries = collector.collect()

            self.assertEqual(len(entries), 3)

    def test_exclude_patterns(self):
        """Test exclusion patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            with open(os.path.join(tmpdir, "include.txt"), 'w') as f:
                f.write("include")
            with open(os.path.join(tmpdir, "exclude.log"), 'w') as f:
                f.write("exclude")

            collector = FileCollector([tmpdir], exclude_patterns=["*.log"])
            entries = collector.collect()

            self.assertEqual(len(entries), 1)


class TestBaselineAuditor(unittest.TestCase):
    """Tests for BaselineAuditor."""

    def setUp(self):
        """Set up test baseline."""
        self.baseline = Baseline(
            created=datetime.now(),
            hostname="test",
            files={
                "/test/file1": FileEntry("/test/file1", "hash1", 100, 33188, 1000.0, "root"),
                "/test/file2": FileEntry("/test/file2", "hash2", 200, 33188, 1000.0, "root"),
            },
            processes={},
            listening_ports={},
            metadata={}
        )
        self.auditor = BaselineAuditor(self.baseline)

    def test_detect_new_file(self):
        """Test detection of new files."""
        current = {
            "/test/file1": FileEntry("/test/file1", "hash1", 100, 33188, 1000.0, "root"),
            "/test/file2": FileEntry("/test/file2", "hash2", 200, 33188, 1000.0, "root"),
            "/test/file3": FileEntry("/test/file3", "hash3", 300, 33188, 1000.0, "root"),
        }
        violations = self.auditor.audit_files(current)

        added = [v for v in violations if v.violation_type == "added"]
        self.assertEqual(len(added), 1)
        self.assertIn("/test/file3", added[0].description)

    def test_detect_removed_file(self):
        """Test detection of removed files."""
        current = {
            "/test/file1": FileEntry("/test/file1", "hash1", 100, 33188, 1000.0, "root"),
        }
        violations = self.auditor.audit_files(current)

        removed = [v for v in violations if v.violation_type == "removed"]
        self.assertEqual(len(removed), 1)
        self.assertIn("/test/file2", removed[0].description)

    def test_detect_modified_file(self):
        """Test detection of modified files."""
        current = {
            "/test/file1": FileEntry("/test/file1", "hash1", 100, 33188, 1000.0, "root"),
            "/test/file2": FileEntry("/test/file2", "modified_hash", 200, 33188, 1000.0, "root"),
        }
        violations = self.auditor.audit_files(current)

        modified = [v for v in violations if v.violation_type == "modified"]
        self.assertEqual(len(modified), 1)

    def test_severity_critical_path(self):
        """Test critical path severity."""
        severity = self.auditor._get_file_severity("/etc/passwd")
        self.assertEqual(severity, "CRITICAL")

    def test_severity_high_path(self):
        """Test high severity path."""
        severity = self.auditor._get_file_severity("/etc/hosts")
        self.assertEqual(severity, "HIGH")

    def test_severity_medium_path(self):
        """Test medium severity path."""
        severity = self.auditor._get_file_severity("/var/log/test.log")
        self.assertEqual(severity, "MEDIUM")


class TestBaselineManager(unittest.TestCase):
    """Tests for BaselineManager."""

    def test_save_and_load(self):
        """Test saving and loading baseline."""
        manager = BaselineManager()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test")

            # Create and save baseline
            baseline = manager.create_baseline([test_file])
            baseline_path = os.path.join(tmpdir, "baseline.json")
            manager.save_baseline(baseline, baseline_path)

            # Load and verify
            loaded = manager.load_baseline(baseline_path)
            self.assertEqual(loaded.hostname, baseline.hostname)
            self.assertEqual(len(loaded.files), len(baseline.files))

    def test_plan_mode(self):
        """Test planning mode output."""
        manager = BaselineManager()
        plan = manager.get_plan("create", ["/etc"], "baseline.json")

        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("baseline-auditor", plan)
        self.assertIn("create", plan)


class TestAuditResult(unittest.TestCase):
    """Tests for AuditResult."""

    def test_has_violations(self):
        """Test has_violations property."""
        result = AuditResult(
            timestamp=datetime.now(),
            baseline_date=datetime.now(),
            hostname="test",
            files_checked=10,
            processes_checked=5,
            ports_checked=3,
            violations=[Violation("file", "added", "HIGH", "Test")],
            summary="Test"
        )
        self.assertTrue(result.has_violations)

    def test_critical_count(self):
        """Test critical count."""
        result = AuditResult(
            timestamp=datetime.now(),
            baseline_date=datetime.now(),
            hostname="test",
            files_checked=10,
            processes_checked=5,
            ports_checked=3,
            violations=[
                Violation("file", "added", "CRITICAL", "Test1"),
                Violation("file", "added", "CRITICAL", "Test2"),
                Violation("file", "added", "HIGH", "Test3"),
            ],
            summary="Test"
        )
        self.assertEqual(result.critical_count, 2)
        self.assertEqual(result.high_count, 1)


class TestDocumentation(unittest.TestCase):
    """Tests for documentation."""

    def test_documentation_structure(self):
        """Test documentation returns required fields."""
        docs = get_documentation()

        self.assertIn("name", docs)
        self.assertIn("description", docs)
        self.assertIn("features", docs)
        self.assertIn("usage_examples", docs)
        self.assertEqual(docs["name"], "baseline-auditor")


if __name__ == '__main__':
    unittest.main(verbosity=2)
