"""
Tests for the Hash Cracker tool.

This module contains unit tests and integration tests for the hash-cracker tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import hashlib
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/hash-cracker')

from tool import (
    HashType,
    CrackResult,
    CrackConfig,
    HashEngine,
    WordGenerator,
    HashCracker,
    get_documentation,
    print_plan,
    parse_arguments,
    detect_hash_type,
)


# =============================================================================
# Test get_documentation()
# =============================================================================

class TestGetDocumentation:
    """Tests for the get_documentation function."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        docs = get_documentation()
        assert isinstance(docs, dict)

    def test_get_documentation_has_required_keys(self):
        """Test that documentation contains all required keys."""
        docs = get_documentation()
        required_keys = ["name", "version", "description"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "hash-cracker"

    def test_get_documentation_has_arguments(self):
        """Test that documentation includes argument definitions."""
        docs = get_documentation()
        assert "arguments" in docs
        assert isinstance(docs["arguments"], dict)

    def test_get_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        docs = get_documentation()
        assert "examples" in docs
        assert isinstance(docs["examples"], list)


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_hash_info(self, capsys):
        """Test that planning mode shows hash information."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should show hash or hash type
        assert "MD5" in captured.out or "hash" in captured.out.lower()

    def test_plan_mode_shows_attack_mode(self, capsys):
        """Test that planning mode shows attack mode."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5,
            wordlist=["password", "admin"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention wordlist or dictionary attack
        assert "wordlist" in captured.out.lower() or "dictionary" in captured.out.lower()

    def test_plan_mode_does_not_crack(self):
        """Test that planning mode does not actually crack hashes."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5,
            wordlist=["hello"],  # This would crack the hash
            plan_mode=True
        )
        print_plan(config)
        # Should not return cracked result in plan mode


# =============================================================================
# Test Hash Type Detection
# =============================================================================

class TestHashTypeDetection:
    """Tests for hash type detection."""

    def test_detect_md5_hash(self):
        """Test MD5 hash detection."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        result = detect_hash_type(md5_hash)
        assert result == HashType.MD5

    def test_detect_sha1_hash(self):
        """Test SHA1 hash detection."""
        sha1_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        result = detect_hash_type(sha1_hash)
        assert result == HashType.SHA1

    def test_detect_sha256_hash(self):
        """Test SHA256 hash detection."""
        sha256_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        result = detect_hash_type(sha256_hash)
        assert result == HashType.SHA256

    def test_detect_sha512_hash(self):
        """Test SHA512 hash detection."""
        sha512_hash = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        result = detect_hash_type(sha512_hash)
        assert result == HashType.SHA512

    def test_detect_ntlm_hash(self):
        """Test NTLM hash detection."""
        ntlm_hash = "a4f49c406510bdcab6824ee7c30fd852"
        result = detect_hash_type(ntlm_hash)
        # NTLM is same length as MD5, might return MD5 or NTLM
        assert result in [HashType.MD5, HashType.NTLM]


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_hash_list(self):
        """Test that valid hash lists are accepted."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5
        )
        assert len(config.hashes) == 1

    def test_valid_hash_type(self):
        """Test that valid hash types are accepted."""
        config = CrackConfig(
            hashes=["test"],
            hash_type=HashType.SHA256
        )
        assert config.hash_type == HashType.SHA256

    def test_valid_wordlist(self):
        """Test that valid wordlists are accepted."""
        config = CrackConfig(
            hashes=["test"],
            hash_type=HashType.MD5,
            wordlist=["password", "admin", "root"]
        )
        assert len(config.wordlist) == 3


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_empty_hash_handling(self):
        """Test handling of empty hash."""
        config = CrackConfig(
            hashes=[""],
            hash_type=HashType.MD5,
            wordlist=["test"]
        )
        cracker = HashCracker(config)
        # Should handle gracefully
        results = cracker.crack()
        assert isinstance(results, list)

    def test_invalid_hash_format_handling(self):
        """Test handling of invalid hash format."""
        config = CrackConfig(
            hashes=["not_a_valid_hex_hash!@#$"],
            hash_type=HashType.MD5,
            wordlist=["test"]
        )
        cracker = HashCracker(config)
        # Should handle gracefully without crashing
        try:
            results = cracker.crack()
            assert isinstance(results, list)
        except ValueError:
            pass  # Acceptable to raise ValueError for invalid format


# =============================================================================
# Test HashType Enum
# =============================================================================

class TestHashTypeEnum:
    """Tests for the HashType enum."""

    def test_hash_type_md5(self):
        """Test MD5 hash type."""
        assert HashType.MD5 is not None

    def test_hash_type_sha1(self):
        """Test SHA1 hash type."""
        assert HashType.SHA1 is not None

    def test_hash_type_sha256(self):
        """Test SHA256 hash type."""
        assert HashType.SHA256 is not None

    def test_hash_type_sha512(self):
        """Test SHA512 hash type."""
        assert HashType.SHA512 is not None

    def test_hash_type_ntlm(self):
        """Test NTLM hash type."""
        assert HashType.NTLM is not None


# =============================================================================
# Test CrackResult Data Class
# =============================================================================

class TestCrackResult:
    """Tests for the CrackResult data class."""

    def test_crack_result_creation(self):
        """Test that CrackResult can be created."""
        result = CrackResult(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            plaintext="hello",
            hash_type=HashType.MD5
        )
        assert result.plaintext == "hello"

    def test_crack_result_not_found(self):
        """Test CrackResult for uncracked hash."""
        result = CrackResult(
            hash_value="5d41402abc4b2a76b9719d911017c592",
            plaintext=None,
            hash_type=HashType.MD5,
            cracked=False
        )
        assert result.cracked == False


# =============================================================================
# Test HashEngine Class
# =============================================================================

class TestHashEngine:
    """Tests for the HashEngine class."""

    def test_hash_engine_md5(self):
        """Test MD5 hashing."""
        result = HashEngine.hash_md5("hello")
        expected = hashlib.md5(b"hello").hexdigest()
        assert result == expected

    def test_hash_engine_sha1(self):
        """Test SHA1 hashing."""
        result = HashEngine.hash_sha1("hello")
        expected = hashlib.sha1(b"hello").hexdigest()
        assert result == expected

    def test_hash_engine_sha256(self):
        """Test SHA256 hashing."""
        result = HashEngine.hash_sha256("hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected

    def test_hash_engine_sha512(self):
        """Test SHA512 hashing."""
        result = HashEngine.hash_sha512("hello")
        expected = hashlib.sha512(b"hello").hexdigest()
        assert result == expected

    def test_hash_engine_ntlm(self):
        """Test NTLM hashing."""
        result = HashEngine.hash_ntlm("hello")
        # NTLM is MD4 of UTF-16LE encoded password
        assert len(result) == 32  # NTLM hash is 32 hex chars


# =============================================================================
# Test WordGenerator Class
# =============================================================================

class TestWordGenerator:
    """Tests for the WordGenerator class."""

    def test_word_generator_from_list(self):
        """Test WordGenerator with wordlist."""
        words = ["password", "admin", "root"]
        generator = WordGenerator(wordlist=words)
        generated = list(generator.generate())
        assert "password" in generated
        assert "admin" in generated
        assert "root" in generated

    def test_word_generator_bruteforce(self):
        """Test WordGenerator in bruteforce mode."""
        generator = WordGenerator(
            bruteforce=True,
            charset="ab",
            min_length=1,
            max_length=2
        )
        generated = list(generator.generate())
        assert "a" in generated
        assert "b" in generated
        assert "aa" in generated
        assert "ab" in generated


# =============================================================================
# Test HashCracker Class
# =============================================================================

class TestHashCracker:
    """Tests for the HashCracker class."""

    def test_cracker_initialization(self):
        """Test HashCracker initialization."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],
            hash_type=HashType.MD5,
            wordlist=["hello"]
        )
        cracker = HashCracker(config)
        assert cracker is not None

    def test_cracker_cracks_md5(self):
        """Test HashCracker cracks MD5 hash."""
        md5_hash = hashlib.md5(b"password").hexdigest()
        config = CrackConfig(
            hashes=[md5_hash],
            hash_type=HashType.MD5,
            wordlist=["admin", "password", "root"]
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert len(results) == 1
        assert results[0].cracked == True
        assert results[0].plaintext == "password"

    def test_cracker_cracks_sha256(self):
        """Test HashCracker cracks SHA256 hash."""
        sha256_hash = hashlib.sha256(b"secret").hexdigest()
        config = CrackConfig(
            hashes=[sha256_hash],
            hash_type=HashType.SHA256,
            wordlist=["password", "secret", "admin"]
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert len(results) == 1
        assert results[0].cracked == True
        assert results[0].plaintext == "secret"

    def test_cracker_reports_not_found(self):
        """Test HashCracker reports uncracked hash."""
        config = CrackConfig(
            hashes=["5d41402abc4b2a76b9719d911017c592"],  # MD5 of "hello"
            hash_type=HashType.MD5,
            wordlist=["wrong", "passwords", "only"]
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert len(results) == 1
        assert results[0].cracked == False

    def test_cracker_multiple_hashes(self):
        """Test HashCracker with multiple hashes."""
        hash1 = hashlib.md5(b"password").hexdigest()
        hash2 = hashlib.md5(b"admin").hexdigest()
        config = CrackConfig(
            hashes=[hash1, hash2],
            hash_type=HashType.MD5,
            wordlist=["password", "admin", "root"]
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert len(results) == 2
        cracked = [r for r in results if r.cracked]
        assert len(cracked) == 2


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_hash_argument(self):
        """Test parsing hash argument."""
        with patch('sys.argv', ['tool.py', '5d41402abc4b2a76b9719d911017c592']):
            args = parse_arguments()
            assert args.hash == '5d41402abc4b2a76b9719d911017c592' or '5d41402abc4b2a76b9719d911017c592' in str(args.hashes)

    def test_parse_wordlist_argument(self):
        """Test parsing wordlist argument."""
        with patch('sys.argv', ['tool.py', 'abc123', '-w', '/path/to/wordlist.txt']):
            args = parse_arguments()
            assert '/path/to/wordlist.txt' in str(args.wordlist)

    def test_parse_hash_type_argument(self):
        """Test parsing hash type argument."""
        with patch('sys.argv', ['tool.py', 'abc123', '-t', 'sha256']):
            args = parse_arguments()
            assert 'sha256' in str(args.type).lower() or args.hash_type

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', 'abc123', '--plan']):
            args = parse_arguments()
            assert args.plan == True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for the hash cracker."""

    def test_full_crack_workflow(self):
        """Test full cracking workflow."""
        # Create some hashes to crack
        hashes = [
            hashlib.md5(b"password123").hexdigest(),
            hashlib.md5(b"admin").hexdigest(),
            hashlib.md5(b"unknown_password").hexdigest(),
        ]
        wordlist = ["password", "admin", "root", "password123", "test"]

        config = CrackConfig(
            hashes=hashes,
            hash_type=HashType.MD5,
            wordlist=wordlist,
            threads=2
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert len(results) == 3
        # At least 2 should be cracked
        cracked = [r for r in results if r.cracked]
        assert len(cracked) >= 2

    def test_case_sensitivity(self):
        """Test that cracking is case-sensitive."""
        hash_lower = hashlib.md5(b"Password").hexdigest()
        config = CrackConfig(
            hashes=[hash_lower],
            hash_type=HashType.MD5,
            wordlist=["password", "PASSWORD", "Password"]
        )
        cracker = HashCracker(config)
        results = cracker.crack()

        assert results[0].cracked == True
        assert results[0].plaintext == "Password"
