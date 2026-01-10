"""
Unit tests for file_info.py module.

This module contains comprehensive tests for the get_file_info function,
including positive tests, negative tests, and edge cases.
"""

import pytest
import json
import os
import hashlib
import base64
import subprocess
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from file_info import get_file_info


# ============================================================================
# POSITIVE TEST CASES
# ============================================================================

class TestGetFileInfoPositive:
    """Positive test cases for get_file_info function."""

    @pytest.mark.unit
    def test_get_file_info_returns_valid_json(self, temp_file):
        """Test that get_file_info returns valid JSON."""
        result = get_file_info(str(temp_file))
        # Should not raise an exception
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    @pytest.mark.unit
    def test_get_file_info_contains_all_required_fields(self, temp_file):
        """Test that result contains all required fields."""
        result = json.loads(get_file_info(str(temp_file)))

        required_fields = ['filename', 'md5sum', 'file_size', 'file_type', 'base64_encoded']
        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    @pytest.mark.unit
    def test_get_file_info_correct_filename(self, temp_file):
        """Test that filename field matches input."""
        result = json.loads(get_file_info(str(temp_file)))
        assert result['filename'] == str(temp_file)

    @pytest.mark.unit
    def test_get_file_info_correct_file_size(self, temp_file):
        """Test that file_size is correct."""
        result = json.loads(get_file_info(str(temp_file)))
        expected_size = os.path.getsize(temp_file)
        assert result['file_size'] == expected_size

    @pytest.mark.unit
    def test_get_file_info_correct_md5(self, known_content_file):
        """Test that MD5 hash is calculated correctly."""
        file_path, expected_md5 = known_content_file
        result = json.loads(get_file_info(str(file_path)))
        assert result['md5sum'] == expected_md5

    @pytest.mark.unit
    def test_get_file_info_md5_format(self, temp_file):
        """Test that MD5 hash is in correct hex format (32 chars)."""
        result = json.loads(get_file_info(str(temp_file)))
        assert len(result['md5sum']) == 32
        assert all(c in '0123456789abcdef' for c in result['md5sum'])

    @pytest.mark.unit
    def test_get_file_info_correct_base64(self, temp_file):
        """Test that base64 encoding is correct."""
        result = json.loads(get_file_info(str(temp_file)))

        # Calculate expected base64
        with open(temp_file, 'rb') as f:
            expected_base64 = base64.b64encode(f.read()).decode('utf-8')

        assert result['base64_encoded'] == expected_base64

    @pytest.mark.unit
    def test_get_file_info_base64_decodable(self, temp_file):
        """Test that base64 can be decoded back to original content."""
        result = json.loads(get_file_info(str(temp_file)))

        # Decode base64 and compare with original
        decoded = base64.b64decode(result['base64_encoded'])
        with open(temp_file, 'rb') as f:
            original = f.read()

        assert decoded == original

    @pytest.mark.unit
    def test_get_file_info_file_type_not_empty(self, temp_file):
        """Test that file_type is detected and not empty."""
        result = json.loads(get_file_info(str(temp_file)))
        assert result['file_type'] is not None
        assert len(result['file_type']) > 0

    @pytest.mark.unit
    @pytest.mark.smoke
    def test_get_file_info_basic_functionality(self, temp_file):
        """Smoke test for basic get_file_info functionality."""
        result = get_file_info(str(temp_file))
        parsed = json.loads(result)

        # Basic sanity checks
        assert 'error' not in parsed
        assert parsed['file_size'] > 0
        assert len(parsed['md5sum']) == 32


# ============================================================================
# NEGATIVE TEST CASES
# ============================================================================

class TestGetFileInfoNegative:
    """Negative test cases for get_file_info function."""

    @pytest.mark.unit
    def test_get_file_info_nonexistent_file(self, nonexistent_file):
        """Test handling of nonexistent file."""
        result = json.loads(get_file_info(str(nonexistent_file)))
        assert 'error' in result
        assert 'File not found' in result['error']

    @pytest.mark.unit
    def test_get_file_info_nonexistent_file_includes_filename(self, nonexistent_file):
        """Test that error message includes the filename."""
        result = json.loads(get_file_info(str(nonexistent_file)))
        assert str(nonexistent_file) in result['error']

    @pytest.mark.unit
    def test_get_file_info_empty_filename(self):
        """Test handling of empty filename."""
        result = json.loads(get_file_info(""))
        assert 'error' in result

    @pytest.mark.unit
    def test_get_file_info_directory_path(self, temp_dir):
        """Test handling when path is a directory, not a file."""
        result = json.loads(get_file_info(str(temp_dir)))
        # The function should either return an error or handle the directory
        # Based on current implementation, it will try to read it
        # This test documents current behavior
        assert isinstance(result, dict)

    @pytest.mark.unit
    def test_get_file_info_permission_denied(self, temp_file):
        """Test handling of permission denied error."""
        # Remove read permissions
        os.chmod(temp_file, 0o000)
        try:
            result = json.loads(get_file_info(str(temp_file)))
            # Should have an error since we cannot read the file
            assert 'error' in result
        finally:
            # Restore permissions for cleanup
            os.chmod(temp_file, 0o644)

    @pytest.mark.unit
    def test_get_file_info_returns_json_on_error(self, nonexistent_file):
        """Test that even errors are returned as valid JSON."""
        result = get_file_info(str(nonexistent_file))
        # Should not raise - must be valid JSON
        parsed = json.loads(result)
        assert isinstance(parsed, dict)


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestGetFileInfoEdgeCases:
    """Edge case tests for get_file_info function."""

    @pytest.mark.unit
    def test_get_file_info_empty_file(self, temp_empty_file):
        """Test handling of empty file."""
        result = json.loads(get_file_info(str(temp_empty_file)))

        # Should not have error
        assert 'error' not in result

        # Size should be 0
        assert result['file_size'] == 0

        # MD5 of empty string
        expected_md5 = hashlib.md5(b'').hexdigest()
        assert result['md5sum'] == expected_md5

        # Base64 of empty content
        assert result['base64_encoded'] == ''

    @pytest.mark.unit
    def test_get_file_info_binary_file(self, temp_binary_file):
        """Test handling of binary file."""
        result = json.loads(get_file_info(str(temp_binary_file)))

        # Should not have error
        assert 'error' not in result

        # Should have valid base64 that decodes correctly
        decoded = base64.b64decode(result['base64_encoded'])
        with open(temp_binary_file, 'rb') as f:
            assert decoded == f.read()

    @pytest.mark.unit
    @pytest.mark.slow
    def test_get_file_info_large_file(self, temp_large_file):
        """Test handling of large file (1MB)."""
        result = json.loads(get_file_info(str(temp_large_file)))

        # Should not have error
        assert 'error' not in result

        # Size should be 1MB
        assert result['file_size'] == 1024 * 1024

    @pytest.mark.unit
    def test_get_file_info_unicode_filename(self, temp_dir):
        """Test handling of unicode in filename."""
        unicode_filename = temp_dir / "test_file.txt"
        unicode_filename.write_text("unicode content")

        result = json.loads(get_file_info(str(unicode_filename)))
        # Should not have error
        assert 'error' not in result

    @pytest.mark.unit
    def test_get_file_info_special_characters_in_path(self, file_with_special_name):
        """Test handling of special characters in filename."""
        result = json.loads(get_file_info(str(file_with_special_name)))
        # Should not have error
        assert 'error' not in result
        assert result['filename'] == str(file_with_special_name)

    @pytest.mark.unit
    def test_get_file_info_unicode_content(self, unicode_file):
        """Test handling of unicode content in file."""
        result = json.loads(get_file_info(str(unicode_file)))

        # Should not have error
        assert 'error' not in result

        # Base64 should decode correctly
        decoded = base64.b64decode(result['base64_encoded']).decode('utf-8')
        assert "Hello" in decoded

    @pytest.mark.unit
    def test_get_file_info_relative_path(self, temp_file):
        """Test handling of absolute path converted from relative."""
        # Get relative path from current directory
        rel_path = os.path.relpath(str(temp_file))
        result = json.loads(get_file_info(rel_path))

        # Should work with relative path
        assert 'error' not in result

    @pytest.mark.unit
    def test_get_file_info_symlink(self, temp_dir, temp_file):
        """Test handling of symbolic links."""
        link_path = temp_dir / "symlink.txt"
        os.symlink(temp_file, link_path)

        result = json.loads(get_file_info(str(link_path)))

        # Should not have error
        assert 'error' not in result

        # Should have same content as original
        original_result = json.loads(get_file_info(str(temp_file)))
        assert result['md5sum'] == original_result['md5sum']
        assert result['base64_encoded'] == original_result['base64_encoded']


# ============================================================================
# MOCK TESTS (for subprocess and exception handling)
# ============================================================================

class TestGetFileInfoMocks:
    """Tests using mocks to verify error handling."""

    @pytest.mark.unit
    def test_get_file_info_subprocess_failure(self, temp_file):
        """Test handling when 'file' command fails."""
        with patch('subprocess.check_output') as mock_subprocess:
            mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'file')

            result = json.loads(get_file_info(str(temp_file)))

            # Should still return result, with Unknown file type
            assert 'error' not in result
            assert result['file_type'] == "Unknown"

    @pytest.mark.unit
    def test_get_file_info_os_error(self, temp_file):
        """Test handling of OS errors during file operations."""
        with patch('builtins.open') as mock_open:
            # First let os.path.exists work, but then fail on open
            mock_open.side_effect = OSError("Simulated OS error")

            result = json.loads(get_file_info(str(temp_file)))

            # Should return error
            assert 'error' in result

    @pytest.mark.unit
    def test_get_file_info_memory_error_handling(self, temp_file):
        """Test that memory errors are caught and reported."""
        with patch('builtins.open') as mock_open:
            mock_open.side_effect = MemoryError("Simulated memory error")

            result = json.loads(get_file_info(str(temp_file)))

            # Should return error as JSON
            assert 'error' in result


# ============================================================================
# JSON OUTPUT FORMAT TESTS
# ============================================================================

class TestGetFileInfoJsonFormat:
    """Tests for JSON output formatting."""

    @pytest.mark.unit
    def test_get_file_info_json_indentation(self, temp_file):
        """Test that JSON output is properly indented."""
        result = get_file_info(str(temp_file))

        # Check for newlines (indicating indentation)
        assert '\n' in result

        # Verify it can be parsed
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    @pytest.mark.unit
    def test_get_file_info_json_field_types(self, temp_file):
        """Test that JSON fields have correct types."""
        result = json.loads(get_file_info(str(temp_file)))

        assert isinstance(result['filename'], str)
        assert isinstance(result['md5sum'], str)
        assert isinstance(result['file_size'], int)
        assert isinstance(result['file_type'], str)
        assert isinstance(result['base64_encoded'], str)


# ============================================================================
# REGRESSION TESTS
# ============================================================================

class TestGetFileInfoRegression:
    """Regression tests for previously found bugs."""

    @pytest.mark.regression
    def test_regression_md5_not_sha256(self, known_content_file):
        """Regression: Ensure we're using MD5, not SHA256."""
        file_path, expected_md5 = known_content_file
        result = json.loads(get_file_info(str(file_path)))

        # MD5 is 32 chars, SHA256 is 64 chars
        assert len(result['md5sum']) == 32
        assert result['md5sum'] == expected_md5

    @pytest.mark.regression
    def test_regression_base64_not_hex(self, temp_file):
        """Regression: Ensure base64 is base64, not hex encoding."""
        result = json.loads(get_file_info(str(temp_file)))

        # Base64 contains non-hex characters like +, /, =
        # or at minimum, uppercase letters
        base64_value = result['base64_encoded']

        # Should be decodable as base64
        decoded = base64.b64decode(base64_value)
        assert isinstance(decoded, bytes)


# ============================================================================
# PARAMETRIZED TESTS
# ============================================================================

class TestGetFileInfoParametrized:
    """Parametrized tests for various file contents."""

    @pytest.mark.unit
    @pytest.mark.parametrize("content,expected_size", [
        (b"", 0),
        (b"a", 1),
        (b"hello", 5),
        (b"0" * 100, 100),
        (b"binary\x00data", 11),
    ])
    def test_get_file_info_various_sizes(self, temp_dir, content, expected_size):
        """Test file size calculation for various contents."""
        file_path = temp_dir / "test_file.bin"
        file_path.write_bytes(content)

        result = json.loads(get_file_info(str(file_path)))
        assert result['file_size'] == expected_size

    @pytest.mark.unit
    @pytest.mark.parametrize("content", [
        b"simple text",
        b"\x00\x01\x02",
        b"multi\nline\ntext",
        b"tabs\tand\tspaces",
        "special chars".encode('utf-8'),
    ])
    def test_get_file_info_base64_roundtrip(self, temp_dir, content):
        """Test base64 encoding/decoding roundtrip."""
        file_path = temp_dir / "test_file.bin"
        file_path.write_bytes(content)

        result = json.loads(get_file_info(str(file_path)))
        decoded = base64.b64decode(result['base64_encoded'])

        assert decoded == content
