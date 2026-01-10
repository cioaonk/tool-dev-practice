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


# ============================================================================
# EDGE CASE TEST FIXTURES
# ============================================================================

@pytest.fixture
def null_bytes_file(temp_dir):
    """
    Create a file containing only null bytes.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the null bytes file.
    """
    file_path = temp_dir / "null_bytes.bin"
    file_path.write_bytes(b"\x00" * 100)
    yield file_path


@pytest.fixture
def all_byte_values_file(temp_dir):
    """
    Create a file containing all possible byte values (0-255).

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the file with all byte values.
    """
    file_path = temp_dir / "all_bytes.bin"
    file_path.write_bytes(bytes(range(256)))
    yield file_path


@pytest.fixture
def symlink_file(temp_dir, temp_file):
    """
    Create a symbolic link to a file.

    Args:
        temp_dir: The temporary directory fixture.
        temp_file: The target file fixture.

    Yields:
        Path: Path to the symbolic link, or None if symlinks not supported.
    """
    link_path = temp_dir / "symlink.txt"
    try:
        link_path.symlink_to(temp_file)
        yield link_path
    except (OSError, NotImplementedError):
        yield None


@pytest.fixture
def broken_symlink(temp_dir):
    """
    Create a broken symbolic link (pointing to nonexistent target).

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the broken symbolic link, or None if symlinks not supported.
    """
    link_path = temp_dir / "broken_link.txt"
    target_path = temp_dir / "nonexistent_target.txt"
    try:
        link_path.symlink_to(target_path)
        yield link_path
    except (OSError, NotImplementedError):
        yield None


@pytest.fixture
def readonly_file(temp_dir):
    """
    Create a read-only file.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the read-only file.
    """
    file_path = temp_dir / "readonly.txt"
    file_path.write_text("read only content")
    file_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    yield file_path
    # Restore permissions for cleanup
    file_path.chmod(stat.S_IRWXU)


@pytest.fixture
def no_permission_file(temp_dir):
    """
    Create a file with no permissions.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the no-permission file.
    """
    if os.name == 'nt':
        pytest.skip("Windows handles permissions differently")

    file_path = temp_dir / "no_permission.txt"
    file_path.write_text("no permissions")
    file_path.chmod(0o000)
    yield file_path
    # Restore permissions for cleanup
    file_path.chmod(stat.S_IRWXU)


@pytest.fixture
def file_with_null_in_content(temp_dir):
    """
    Create a file with null bytes embedded in text content.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the file with embedded nulls.
    """
    file_path = temp_dir / "embedded_nulls.bin"
    file_path.write_bytes(b"Hello\x00World\x00Test")
    yield file_path


@pytest.fixture
def high_entropy_file(temp_dir):
    """
    Create a file with high-entropy (pseudo-random) content.

    Args:
        temp_dir: The temporary directory fixture.

    Yields:
        Path: Path to the high-entropy file.
    """
    import hashlib
    file_path = temp_dir / "high_entropy.bin"
    # Generate pseudo-random content deterministically
    content = hashlib.sha256(b"seed").digest() * 100
    file_path.write_bytes(content)
    yield file_path


# ============================================================================
# NETWORK EDGE CASE FIXTURES
# ============================================================================

@pytest.fixture
def localhost_ipv4():
    """Return localhost IPv4 address."""
    return "127.0.0.1"


@pytest.fixture
def localhost_ipv6():
    """Return localhost IPv6 address."""
    return "::1"


@pytest.fixture
def broadcast_ipv4():
    """Return broadcast IPv4 address."""
    return "255.255.255.255"


@pytest.fixture
def unspecified_ipv4():
    """Return unspecified IPv4 address."""
    return "0.0.0.0"


@pytest.fixture
def sample_cidr_ranges():
    """Return sample CIDR ranges for testing."""
    return [
        "10.0.0.0/8",       # Class A private
        "172.16.0.0/12",    # Class B private
        "192.168.0.0/16",   # Class C private
        "192.168.1.0/24",   # Common LAN
        "192.168.1.0/30",   # Point-to-point
        "192.168.1.0/32",   # Single host
    ]


@pytest.fixture
def invalid_ip_addresses():
    """Return sample invalid IP addresses for testing."""
    return [
        "256.0.0.0",
        "-1.0.0.0",
        "192.168.1",
        "192.168.1.1.1",
        "abc.def.ghi.jkl",
        "",
        " ",
        "192.168.1.1/33",
    ]


# ============================================================================
# PORT EDGE CASE FIXTURES
# ============================================================================

@pytest.fixture
def boundary_ports():
    """Return boundary port values for testing."""
    return {
        "min_valid": 1,
        "max_valid": 65535,
        "below_min": 0,
        "above_max": 65536,
        "well_known_max": 1023,
        "registered_min": 1024,
        "registered_max": 49151,
        "ephemeral_min": 49152,
    }


@pytest.fixture
def common_service_ports():
    """Return common service ports for testing."""
    return {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "smtp": 25,
        "dns": 53,
        "http": 80,
        "pop3": 110,
        "imap": 143,
        "https": 443,
        "smb": 445,
        "mysql": 3306,
        "rdp": 3389,
        "postgresql": 5432,
    }


# ============================================================================
# CREDENTIAL EDGE CASE FIXTURES
# ============================================================================

@pytest.fixture
def special_character_credentials():
    """Return credentials with special characters for testing."""
    return [
        ("admin", "P@$$w0rd!"),
        ("user'name", "pass\"word"),
        ("user;drop", "pass|pipe"),
        ("admin\x00user", "pass\x00word"),
        ("user\nname", "pass\nword"),
    ]


@pytest.fixture
def unicode_credentials():
    """Return credentials with unicode characters for testing."""
    return [
        ("admin", "password"),      # ASCII
        ("usuario", "contrasena"),  # Spanish ASCII
        ("user", "\u5bc6\u7801"),   # Chinese for "password"
        ("\u7528\u6237", "pass"),   # Chinese for "user"
    ]


@pytest.fixture
def empty_credentials():
    """Return empty credential variations for testing."""
    return [
        ("", "password"),
        ("admin", ""),
        ("", ""),
        (" ", " "),
    ]


@pytest.fixture
def long_credentials():
    """Return long credential values for testing."""
    return [
        ("a" * 100, "password"),
        ("admin", "p" * 100),
        ("a" * 256, "p" * 256),
        ("a" * 1000, "p" * 1000),
    ]


# ============================================================================
# ENCODING EDGE CASE FIXTURES
# ============================================================================

@pytest.fixture
def sample_shellcode():
    """Return sample shellcode bytes for testing."""
    # NOP sled pattern (safe for testing)
    return b"\x90" * 10 + b"\xcc"  # NOPs + INT3


@pytest.fixture
def empty_payload():
    """Return empty payload for testing."""
    return b""


@pytest.fixture
def null_heavy_payload():
    """Return payload with many null bytes."""
    return b"\x00" * 50 + b"\x41" * 10 + b"\x00" * 50


@pytest.fixture
def all_bytes_payload():
    """Return payload containing all byte values."""
    return bytes(range(256))


@pytest.fixture
def encoding_keys():
    """Return various encoding keys for testing."""
    return {
        "null": b"\x00",
        "ones": b"\xff",
        "single": b"\xaa",
        "multi": b"\x11\x22\x33\x44",
        "long": b"thisisaverylongkey" * 10,
    }
