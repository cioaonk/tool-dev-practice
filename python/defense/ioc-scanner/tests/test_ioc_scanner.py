#!/usr/bin/env python3
"""
Unit tests for IOC Scanner tool.

Tests cover:
- IOC database operations
- File scanning
- Network scanning
- Process scanning
- Planning mode
- Output formatting
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    IOC,
    IOCDatabase,
    IOCScanner,
    FileScanner,
    NetworkScanner,
    ProcessScanner,
    Match,
    ScanResult,
    get_documentation,
    format_output_text,
    format_output_json,
)


class TestIOC(unittest.TestCase):
    """Tests for IOC data class."""

    def test_create_ioc(self):
        """Test IOC creation."""
        ioc = IOC(
            ioc_type="ip",
            value="192.168.1.100",
            description="Test malicious IP",
            severity="HIGH",
            source="test",
            tags=["apt", "c2"],
        )

        self.assertEqual(ioc.ioc_type, "ip")
        self.assertEqual(ioc.value, "192.168.1.100")
        self.assertEqual(ioc.severity, "HIGH")
        self.assertEqual(len(ioc.tags), 2)

    def test_ioc_to_dict(self):
        """Test IOC serialization."""
        ioc = IOC(
            ioc_type="domain",
            value="malware.example.com",
            description="Test domain",
            severity="MEDIUM",
        )

        data = ioc.to_dict()

        self.assertEqual(data["type"], "domain")
        self.assertEqual(data["value"], "malware.example.com")
        self.assertEqual(data["severity"], "MEDIUM")


class TestIOCDatabase(unittest.TestCase):
    """Tests for IOC database."""

    def setUp(self):
        self.db = IOCDatabase()

    def test_add_ioc(self):
        """Test adding IOCs to database."""
        ioc = IOC("ip", "10.0.0.1", severity="HIGH")
        self.db.add_ioc(ioc)

        self.assertEqual(len(self.db.iocs["ip"]), 1)
        self.assertEqual(self.db.total_iocs(), 1)

    def test_add_multiple_iocs(self):
        """Test adding multiple IOCs."""
        self.db.add_ioc(IOC("ip", "10.0.0.1"))
        self.db.add_ioc(IOC("ip", "10.0.0.2"))
        self.db.add_ioc(IOC("domain", "evil.com"))

        self.assertEqual(len(self.db.iocs["ip"]), 2)
        self.assertEqual(len(self.db.iocs["domain"]), 1)
        self.assertEqual(self.db.total_iocs(), 3)

    def test_get_hash_set(self):
        """Test hash set retrieval."""
        self.db.add_ioc(IOC("hash_sha256", "ABC123"))
        self.db.add_ioc(IOC("hash_sha256", "DEF456"))

        hash_set = self.db.get_hash_set("hash_sha256")

        self.assertIn("abc123", hash_set)  # Should be lowercase
        self.assertIn("def456", hash_set)

    def test_get_compiled_patterns(self):
        """Test regex pattern compilation."""
        self.db.add_ioc(IOC("domain", "test.example.com"))

        patterns = self.db.get_compiled_patterns("domain")

        self.assertEqual(len(patterns), 1)
        pattern, ioc = patterns[0]
        self.assertTrue(pattern.search("connected to test.example.com"))

    def test_load_from_json(self):
        """Test loading IOCs from JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {"type": "ip", "value": "1.2.3.4", "severity": "HIGH"},
                {"type": "domain", "value": "malware.com", "severity": "MEDIUM"},
            ], f)
            temp_path = f.name

        try:
            count = self.db.load_from_json(temp_path)
            self.assertEqual(count, 2)
            self.assertEqual(len(self.db.iocs["ip"]), 1)
            self.assertEqual(len(self.db.iocs["domain"]), 1)
        finally:
            os.unlink(temp_path)

    def test_load_from_csv(self):
        """Test loading IOCs from CSV file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("abc123\n")
            f.write("def456\n")
            f.write("# comment\n")
            f.write("ghi789\n")
            temp_path = f.name

        try:
            count = self.db.load_from_csv(temp_path, "hash_sha256")
            self.assertEqual(count, 3)  # Comments are skipped
        finally:
            os.unlink(temp_path)

    def test_get_statistics(self):
        """Test statistics generation."""
        self.db.add_ioc(IOC("ip", "10.0.0.1"))
        self.db.add_ioc(IOC("ip", "10.0.0.2"))
        self.db.add_ioc(IOC("domain", "evil.com"))

        stats = self.db.get_statistics()

        self.assertEqual(stats["ip"], 2)
        self.assertEqual(stats["domain"], 1)


class TestMatch(unittest.TestCase):
    """Tests for Match data class."""

    def test_create_match(self):
        """Test Match creation."""
        ioc = IOC("ip", "192.168.1.100", severity="HIGH")
        match = Match(
            ioc=ioc,
            location="/var/log/test.log",
            context="Connection from 192.168.1.100",
            timestamp=datetime.now(),
            match_type="file_content",
        )

        self.assertEqual(match.ioc.value, "192.168.1.100")
        self.assertEqual(match.match_type, "file_content")

    def test_match_to_dict(self):
        """Test Match serialization."""
        ioc = IOC("domain", "malware.com")
        match = Match(
            ioc=ioc,
            location="test.txt",
            context="context",
            timestamp=datetime.now(),
            match_type="file_content",
        )

        data = match.to_dict()

        self.assertEqual(data["ioc"]["value"], "malware.com")
        self.assertEqual(data["location"], "test.txt")


class TestFileScanner(unittest.TestCase):
    """Tests for file scanning."""

    def setUp(self):
        self.db = IOCDatabase()
        self.scanner = FileScanner(self.db)

    def test_scan_file_with_matching_hash(self):
        """Test scanning file with matching hash."""
        # Create a test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test content")
            temp_path = f.name

        try:
            # Calculate the hash and add to database
            import hashlib
            with open(temp_path, 'rb') as f:
                content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()

            self.db.add_ioc(IOC("hash_sha256", sha256, "Test hash", "HIGH"))

            # Scan
            matches = self.scanner.scan(temp_path)

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].match_type, "hash")
        finally:
            os.unlink(temp_path)

    def test_scan_file_with_matching_content(self):
        """Test scanning file with matching content."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("Connection to 10.0.0.1 established")
            temp_path = f.name

        try:
            self.db.add_ioc(IOC("ip", "10.0.0.1", "Test IP", "MEDIUM"))

            matches = self.scanner.scan(temp_path)

            # Should find the IP in content
            ip_matches = [m for m in matches if m.match_type == "file_content"]
            self.assertGreater(len(ip_matches), 0)
        finally:
            os.unlink(temp_path)

    def test_scan_file_with_matching_filename(self):
        """Test scanning file with matching filename."""
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='mimikatz', suffix='.exe', delete=False
        ) as f:
            f.write("dummy")
            temp_path = f.name

        try:
            self.db.add_ioc(IOC("filename", "mimikatz", "Credential tool", "CRITICAL"))

            matches = self.scanner.scan(temp_path)

            filename_matches = [m for m in matches if m.match_type == "filename"]
            self.assertGreater(len(filename_matches), 0)
        finally:
            os.unlink(temp_path)

    def test_scan_directory(self):
        """Test scanning directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some test files
            for i in range(3):
                path = os.path.join(tmpdir, f"file{i}.txt")
                with open(path, 'w') as f:
                    f.write(f"content {i}")

            matches = self.scanner.scan(tmpdir)

            self.assertEqual(self.scanner.files_scanned, 3)

    def test_skip_large_files(self):
        """Test that large files are skipped."""
        scanner = FileScanner(self.db, max_file_size=10)  # 10 bytes max

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("x" * 100)  # Larger than max
            temp_path = f.name

        try:
            matches = scanner.scan(temp_path)
            self.assertIn("Skipped large file", scanner.errors[0])
        finally:
            os.unlink(temp_path)

    def test_get_statistics(self):
        """Test scanner statistics."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            temp_path = f.name

        try:
            self.scanner.scan(temp_path)
            stats = self.scanner.get_statistics()

            self.assertEqual(stats["files_scanned"], 1)
            self.assertGreater(stats["bytes_scanned"], 0)
        finally:
            os.unlink(temp_path)


class TestIOCScanner(unittest.TestCase):
    """Tests for main IOC Scanner class."""

    def setUp(self):
        self.scanner = IOCScanner()

    def test_add_builtin_iocs(self):
        """Test adding built-in IOCs."""
        count = self.scanner.add_builtin_iocs()

        self.assertGreater(count, 0)
        self.assertGreater(self.scanner.db.total_iocs(), 0)

    def test_load_iocs_from_json(self):
        """Test loading IOCs from JSON file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {"type": "ip", "value": "1.2.3.4"},
            ], f)
            temp_path = f.name

        try:
            count = self.scanner.load_iocs(temp_path)
            self.assertEqual(count, 1)
        finally:
            os.unlink(temp_path)

    def test_scan_files(self):
        """Test file scanning through main scanner."""
        self.scanner.add_builtin_iocs()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("test content")

            result = self.scanner.scan_files(tmpdir)

            self.assertEqual(result.scan_type, "file")
            self.assertIsInstance(result.matches, list)
            self.assertGreater(result.duration, 0)

    def test_plan_mode(self):
        """Test planning mode output."""
        self.scanner.add_builtin_iocs()

        plan = self.scanner.get_plan(
            scan_types=["file"],
            target="/test/path",
            ioc_files=[]
        )

        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("ioc-scanner", plan)
        self.assertIn("File scan target", plan)
        self.assertIn("No actions will be taken", plan)

    def test_plan_mode_all_scans(self):
        """Test planning mode with all scan types."""
        plan = self.scanner.get_plan(
            scan_types=["all"],
            target="/test",
            ioc_files=["threats.json"]
        )

        self.assertIn("File scan", plan)
        self.assertIn("Network scan", plan)
        self.assertIn("Process scan", plan)


class TestScanResult(unittest.TestCase):
    """Tests for ScanResult data class."""

    def test_duration_calculation(self):
        """Test duration calculation."""
        start = datetime.now()
        end = datetime.now()

        result = ScanResult(
            scan_type="file",
            target="/test",
            start_time=start,
            end_time=end,
            matches=[],
            statistics={},
            errors=[],
        )

        self.assertGreaterEqual(result.duration, 0)

    def test_to_dict(self):
        """Test serialization."""
        result = ScanResult(
            scan_type="file",
            target="/test",
            start_time=datetime.now(),
            end_time=datetime.now(),
            matches=[],
            statistics={"files_scanned": 10},
            errors=["test error"],
        )

        data = result.to_dict()

        self.assertEqual(data["scan_type"], "file")
        self.assertEqual(data["total_matches"], 0)
        self.assertEqual(data["statistics"]["files_scanned"], 10)


class TestOutputFormatters(unittest.TestCase):
    """Tests for output formatters."""

    def setUp(self):
        self.result = ScanResult(
            scan_type="file",
            target="/test/path",
            start_time=datetime.now(),
            end_time=datetime.now(),
            matches=[
                Match(
                    ioc=IOC("ip", "192.168.1.100", "Test", "HIGH"),
                    location="/test/file.txt",
                    context="connection to 192.168.1.100",
                    timestamp=datetime.now(),
                    match_type="file_content",
                )
            ],
            statistics={"files_scanned": 10},
            errors=[],
        )

    def test_text_output(self):
        """Test text format output."""
        output = format_output_text(self.result)

        self.assertIn("IOC SCAN REPORT", output)
        self.assertIn("file", output)
        self.assertIn("192.168.1.100", output)
        self.assertIn("HIGH", output)

    def test_json_output(self):
        """Test JSON format output."""
        output = format_output_json(self.result)
        data = json.loads(output)

        self.assertEqual(data["scan_type"], "file")
        self.assertEqual(data["total_matches"], 1)
        self.assertEqual(data["matches"][0]["ioc"]["value"], "192.168.1.100")


class TestDocumentation(unittest.TestCase):
    """Tests for documentation function."""

    def test_documentation_structure(self):
        """Test documentation returns required fields."""
        docs = get_documentation()

        self.assertIn("name", docs)
        self.assertIn("category", docs)
        self.assertIn("version", docs)
        self.assertIn("description", docs)
        self.assertIn("features", docs)
        self.assertIn("usage_examples", docs)
        self.assertIn("arguments", docs)
        self.assertEqual(docs["name"], "ioc-scanner")

    def test_documentation_ioc_types(self):
        """Test documentation includes IOC types."""
        docs = get_documentation()

        self.assertIn("supported_ioc_types", docs)
        self.assertIn("ip", docs["supported_ioc_types"])
        self.assertIn("domain", docs["supported_ioc_types"])
        self.assertIn("hash_sha256", docs["supported_ioc_types"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
