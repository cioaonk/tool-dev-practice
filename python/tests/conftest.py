"""
Pytest configuration and shared fixtures for CPTC11 test suite.

This module contains fixtures that can be used across all test modules.
"""

import pytest
import tempfile
import os
import shutil
from pathlib import Path


# ============================================================================
# TEMPORARY FILE FIXTURES
# ============================================================================

@pytest.fixture
def temp_dir():
    """
    Create a temporary directory for test files.

    Yields:
        Path: Path to the temporary directory.

    The directory is automatically cleaned up after the test.
    """
    temp_path = tempfile.mkdtemp(prefix="cptc11_test_")
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir):
    """
    Create a temporary file with sample content.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the temporary file containing "Hello, World!".
    """
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("Hello, World!")
    yield file_path


@pytest.fixture
def temp_binary_file(temp_dir):
    """
    Create a temporary binary file.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the temporary binary file.
    """
    file_path = temp_dir / "test_binary.bin"
    file_path.write_bytes(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09')
    yield file_path


@pytest.fixture
def temp_empty_file(temp_dir):
    """
    Create an empty temporary file.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the empty temporary file.
    """
    file_path = temp_dir / "empty_file.txt"
    file_path.touch()
    yield file_path


@pytest.fixture
def temp_large_file(temp_dir):
    """
    Create a larger temporary file (1MB).

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the 1MB temporary file.
    """
    file_path = temp_dir / "large_file.bin"
    # Create a 1MB file with repeating pattern
    content = b'A' * (1024 * 1024)
    file_path.write_bytes(content)
    yield file_path


@pytest.fixture
def nonexistent_file(temp_dir):
    """
    Return path to a file that does not exist.

    Args:
        temp_dir: The temporary directory fixture.

    Returns:
        Path: Path to a nonexistent file.
    """
    return temp_dir / "nonexistent_file.txt"


# ============================================================================
# KNOWN CONTENT FIXTURES (for hash verification)
# ============================================================================

@pytest.fixture
def known_content_file(temp_dir):
    """
    Create a file with known content for hash verification.

    The content "test" has known hash values:
    - MD5: 098f6bcd4621d373cade4e832627b4f6

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        tuple: (Path to file, expected_md5)
    """
    file_path = temp_dir / "known_content.txt"
    content = "test"
    file_path.write_text(content)
    expected_md5 = "098f6bcd4621d373cade4e832627b4f6"
    yield (file_path, expected_md5)


# ============================================================================
# SPECIAL FILE FIXTURES
# ============================================================================

@pytest.fixture
def unicode_file(temp_dir):
    """
    Create a file with unicode content.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the unicode content file.
    """
    file_path = temp_dir / "unicode_file.txt"
    file_path.write_text("Hello, World!")
    yield file_path


@pytest.fixture
def file_with_special_name(temp_dir):
    """
    Create a file with special characters in filename.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to file with special name.
    """
    file_path = temp_dir / "test file (1).txt"
    file_path.write_text("content with special filename")
    yield file_path


# ============================================================================
# MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_subprocess_error(mocker):
    """
    Mock subprocess.check_output to raise CalledProcessError.

    This is useful for testing error handling in file type detection.

    Args:
        mocker: pytest-mock fixture.

    Returns:
        Mock object.
    """
    import subprocess
    mock = mocker.patch('subprocess.check_output')
    mock.side_effect = subprocess.CalledProcessError(1, 'file')
    return mock


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_test_file(directory, filename, content=b'test content'):
    """
    Helper function to create a test file with specified content.

    Args:
        directory: Directory to create file in.
        filename: Name of the file to create.
        content: Content to write (bytes or str).

    Returns:
        Path: Path to the created file.
    """
    file_path = Path(directory) / filename
    if isinstance(content, str):
        file_path.write_text(content)
    else:
        file_path.write_bytes(content)
    return file_path
