#!/usr/bin/env python3
"""
Test Suite for Hash Cracker
============================

Comprehensive tests for the hash cracking tool including
plan mode, documentation, and hash operations.
"""

import sys
import unittest
from unittest.mock import Mock, MagicMock, patch
from io import StringIO
from pathlib import Path
import hashlib

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tool import (
    HashTarget,
    CrackConfig,
    CrackResult,
    HashType,
    HashEngine,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_THREADS
)


class TestHashTarget(unittest.TestCase):
    """Tests for HashTarget dataclass."""

    def test_target_creation(self):
        """Test creating a HashTarget instance."""
        target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_type=HashType.MD5
        )

        self.assertEqual(target.hash_value, "5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(target.hash_type, HashType.MD5)
        self.assertFalse(target.cracked)

    def test_target_with_username(self):
        """Test target with associated username."""
        target = HashTarget(
            hash_value="abc123",
            username="admin"
        )

        self.assertEqual(target.username, "admin")

    def test_target_cracked(self):
        """Test cracked hash target."""
        target = HashTarget(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            hash_type=HashType.MD5,
            cracked=True,
            plaintext="hello"
        )

        self.assertTrue(target.cracked)
        self.assertEqual(target.plaintext, "hello")

    def test_target_to_dict(self):
        """Test serialization to dictionary."""
        target = HashTarget(
            hash_value="abc123",
            hash_type=HashType.SHA256,
            cracked=True,
            plaintext="test"
        )

        data = target.to_dict()

        self.assertIn("hash", data)
        self.assertIn("cracked", data)
        self.assertEqual(data["plaintext"], "test")


class TestCrackConfig(unittest.TestCase):
    """Tests for CrackConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = CrackConfig()

        self.assertEqual(config.threads, DEFAULT_THREADS)
        self.assertEqual(config.plan_mode, False)
        self.assertEqual(config.min_length, 1)
        self.assertEqual(config.max_length, 8)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        targets = [HashTarget("abc123")]

        config = CrackConfig(
            hashes=targets,
            wordlist="/path/to/wordlist.txt",
            hash_type=HashType.MD5,
            threads=8,
            plan_mode=True
        )

        self.assertEqual(len(config.hashes), 1)
        self.assertEqual(config.threads, 8)
        self.assertTrue(config.plan_mode)


class TestCrackResult(unittest.TestCase):
    """Tests for CrackResult dataclass."""

    def test_result_creation(self):
        """Test creating a CrackResult instance."""
        result = CrackResult(
            total_hashes=10,
            cracked_count=3,
            attempts=1000000,
            duration=120.5,
            rate=8298.76
        )

        self.assertEqual(result.total_hashes, 10)
        self.assertEqual(result.cracked_count, 3)

    def test_result_to_dict(self):
        """Test serialization to dictionary."""
        cracked_target = HashTarget(
            hash_value="abc",
            cracked=True,
            plaintext="test"
        )

        result = CrackResult(
            total_hashes=5,
            cracked_count=1,
            attempts=100,
            duration=1.0,
            rate=100.0,
            results=[cracked_target]
        )

        data = result.to_dict()

        self.assertIn("total_hashes", data)
        self.assertIn("results", data)


class TestHashType(unittest.TestCase):
    """Tests for HashType enum."""

    def test_hash_type_values(self):
        """Test hash type values."""
        self.assertEqual(HashType.MD5.value, "md5")
        self.assertEqual(HashType.SHA1.value, "sha1")
        self.assertEqual(HashType.SHA256.value, "sha256")
        self.assertEqual(HashType.NTLM.value, "ntlm")

    def test_all_hash_types(self):
        """Test all hash types are defined."""
        expected = ["md5", "sha1", "sha256", "sha512", "ntlm"]

        defined = [t.value for t in HashType]

        for exp in expected:
            self.assertIn(exp, defined)


class TestHashEngine(unittest.TestCase):
    """Tests for HashEngine class."""

    def test_md5_hash(self):
        """Test MD5 hash computation."""
        result = HashEngine.md5("hello")
        expected = hashlib.md5(b"hello").hexdigest()

        self.assertEqual(result, expected)
        self.assertEqual(result, "5d41402abc4b2a76b9719d911017c592")

    def test_sha1_hash(self):
        """Test SHA1 hash computation."""
        result = HashEngine.sha1("hello")
        expected = hashlib.sha1(b"hello").hexdigest()

        self.assertEqual(result, expected)

    def test_sha256_hash(self):
        """Test SHA256 hash computation."""
        result = HashEngine.sha256("hello")
        expected = hashlib.sha256(b"hello").hexdigest()

        self.assertEqual(result, expected)

    def test_sha512_hash(self):
        """Test SHA512 hash computation."""
        result = HashEngine.sha512("hello")
        expected = hashlib.sha512(b"hello").hexdigest()

        self.assertEqual(result, expected)

    def test_ntlm_hash(self):
        """Test NTLM hash computation."""
        result = HashEngine.ntlm("hello")
        expected = hashlib.new('md4', "hello".encode('utf-16-le')).hexdigest()

        self.assertEqual(result, expected)

    def test_get_hasher(self):
        """Test getting hasher function by type."""
        md5_hasher = HashEngine.get_hasher(HashType.MD5)
        sha256_hasher = HashEngine.get_hasher(HashType.SHA256)

        self.assertEqual(md5_hasher("test"), HashEngine.md5("test"))
        self.assertEqual(sha256_hasher("test"), HashEngine.sha256("test"))


class TestDocumentation(unittest.TestCase):
    """Tests for tool documentation."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        doc = get_documentation()
        self.assertIsInstance(doc, dict)

    def test_documentation_has_required_fields(self):
        """Test that documentation has all required fields."""
        doc = get_documentation()

        required_fields = ["name", "description", "usage"]
        for field in required_fields:
            self.assertIn(field, doc, f"Missing required field: {field}")

    def test_documentation_lists_algorithms(self):
        """Test documentation lists supported algorithms."""
        doc = get_documentation()

        doc_str = str(doc).lower()
        self.assertTrue("md5" in doc_str or "algorithm" in doc_str)


class TestArgumentParser(unittest.TestCase):
    """Tests for argument parser."""

    def test_parser_creation(self):
        """Test parser can be created."""
        parser = create_argument_parser()
        self.assertIsNotNone(parser)

    def test_parser_has_plan_flag(self):
        """Test parser has --plan flag."""
        parser = create_argument_parser()

        plan_found = False
        for action in parser._actions:
            if '--plan' in action.option_strings or '-p' in action.option_strings:
                plan_found = True
                break

        self.assertTrue(plan_found, "Parser should have --plan flag")

    def test_parser_hash_argument(self):
        """Test parser accepts hash argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--hash', '5d41402abc4b2a76b9719d911017c592'])

        self.assertEqual(args.hash, '5d41402abc4b2a76b9719d911017c592')

    def test_parser_type_argument(self):
        """Test parser accepts hash type argument."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--hash', 'abc123',
            '--type', 'md5'
        ])

        self.assertEqual(args.type, 'md5')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = CrackConfig(
            hashes=[HashTarget("5d41402abc4b2a76b9719d911017c592")],
            hash_type=HashType.MD5,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertTrue(len(output) > 0)

    def test_plan_mode_shows_hash_count(self):
        """Test that plan shows number of hashes."""
        config = CrackConfig(
            hashes=[
                HashTarget("hash1"),
                HashTarget("hash2"),
                HashTarget("hash3")
            ],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertTrue("3" in output or "hash" in output.lower())

    def test_plan_mode_shows_algorithm(self):
        """Test that plan shows algorithm."""
        config = CrackConfig(
            hashes=[HashTarget("abc123")],
            hash_type=HashType.SHA256,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue().lower()
        self.assertTrue("sha256" in output or "algorithm" in output)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_hash_error(self):
        """Test error handling for missing hash."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])


# =============================================================================
# Test Fixtures
# =============================================================================

class HashCrackerFixtures:
    """Test fixtures for hash cracker."""

    # Known hash/plaintext pairs
    KNOWN_HASHES = {
        "md5": {
            "5d41402abc4b2a76b9719d911017c592": "hello",
            "098f6bcd4621d373cade4e832627b4f6": "test",
            "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty"
        },
        "sha1": {
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": "hello",
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": "test"
        },
        "sha256": {
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": "hello",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": "test"
        }
    }

    # Common wordlist
    WORDLIST = [
        "password", "123456", "qwerty", "admin", "letmein",
        "welcome", "monkey", "dragon", "master", "hello",
        "test", "abc123", "password1", "root", "toor"
    ]

    @classmethod
    def get_known_hash(cls, algorithm: str, plaintext: str) -> str:
        """Get known hash for a plaintext."""
        return cls.KNOWN_HASHES.get(algorithm, {}).get(plaintext)

    @classmethod
    def create_test_targets(cls, algorithm: str, count: int = 3) -> list:
        """Create test hash targets."""
        targets = []
        hashes = cls.KNOWN_HASHES.get(algorithm, {})

        for hash_val, plaintext in list(hashes.items())[:count]:
            targets.append(HashTarget(
                hash_value=hash_val,
                hash_type=HashType(algorithm)
            ))

        return targets


if __name__ == '__main__':
    unittest.main(verbosity=2)
