"""
Pytest configuration and shared fixtures for CPTC11 test suite.

This module contains fixtures that can be used across all test modules,
including edge case tests, fuzz tests, and integration tests.
"""

import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path
from typing import Optional

import pytest


# ============================================================================
# CUSTOM PYTEST MARKERS
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers and Hypothesis profiles."""

    # Register custom markers
    config.addinivalue_line(
        "markers", "edge_case: mark test as an edge case test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "security: mark test as security-focused"
    )
    config.addinivalue_line(
        "markers", "fuzz: mark test as a fuzz/property-based test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "requires_root: mark test as requiring root/admin privileges"
    )

    # Configure Hypothesis profiles
    try:
        from hypothesis import settings, Verbosity, Phase

        # CI Profile: Reduced examples, longer deadlines for slower CI runners
        settings.register_profile(
            "ci",
            max_examples=50,
            deadline=5000,  # 5 second deadline (CI can be slow)
            suppress_health_check=[],
            verbosity=Verbosity.normal,
            phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.shrink],
        )

        # Fast Profile: Minimal examples for quick local testing
        settings.register_profile(
            "fast",
            max_examples=10,
            deadline=1000,
        )

        # Dev Profile: Default for local development
        settings.register_profile(
            "dev",
            max_examples=100,
            deadline=2000,
        )

        # Thorough Profile: Extensive testing for release validation
        settings.register_profile(
            "thorough",
            max_examples=500,
            deadline=10000,
        )

        # Load profile from environment variable, default to "dev"
        profile_name = os.environ.get("HYPOTHESIS_PROFILE", "dev")
        settings.load_profile(profile_name)
        print(f"Hypothesis profile: {profile_name}")

    except ImportError:
        # Hypothesis not installed, skip configuration
        pass


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Auto-add edge_case marker for tests in edge_cases directory
        if "edge_cases" in str(item.fspath):
            item.add_marker(pytest.mark.edge_case)

        # Auto-add fuzz marker for tests in fuzz directory
        if "fuzz" in str(item.fspath):
            item.add_marker(pytest.mark.fuzz)

        # Auto-add integration marker for tests in integration directory
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)


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
