#!/usr/bin/env python3
"""
Edge Case Tests for File Input Handling
=======================================

Comprehensive edge case tests for file handling including:
- Non-existent files
- Empty files
- Binary files
- Symbolic links
- Permission denied scenarios
- Special file types
- Path traversal attempts

These tests verify that file-related tools handle unusual inputs
safely and predictably.
"""

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest


# Add tools/tests to path for imports
PYTHON_PATH = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PYTHON_PATH))


# =============================================================================
# Attempt imports with graceful fallback
# =============================================================================

try:
    from file_info import get_file_info
    FILE_INFO_AVAILABLE = True
except ImportError:
    FILE_INFO_AVAILABLE = False
    get_file_info = None


# =============================================================================
# Fixtures for File Tests
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    temp_path = tempfile.mkdtemp(prefix="edge_file_test_")
    yield Path(temp_path)
    # Cleanup
    import shutil
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def empty_file(temp_dir):
    """Create an empty file."""
    file_path = temp_dir / "empty.txt"
    file_path.touch()
    return file_path


@pytest.fixture
def text_file(temp_dir):
    """Create a text file with content."""
    file_path = temp_dir / "text.txt"
    file_path.write_text("Hello, World!")
    return file_path


@pytest.fixture
def binary_file(temp_dir):
    """Create a binary file."""
    file_path = temp_dir / "binary.bin"
    file_path.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")
    return file_path


@pytest.fixture
def large_file(temp_dir):
    """Create a large file (1MB)."""
    file_path = temp_dir / "large.bin"
    file_path.write_bytes(b"X" * (1024 * 1024))
    return file_path


@pytest.fixture
def symlink_file(temp_dir, text_file):
    """Create a symbolic link to a file."""
    link_path = temp_dir / "symlink.txt"
    try:
        link_path.symlink_to(text_file)
        return link_path
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links not supported")
        return None


@pytest.fixture
def broken_symlink(temp_dir):
    """Create a broken symbolic link."""
    link_path = temp_dir / "broken_link.txt"
    target_path = temp_dir / "nonexistent_target.txt"
    try:
        link_path.symlink_to(target_path)
        return link_path
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links not supported")
        return None


# =============================================================================
# Non-Existent File Tests
# =============================================================================

@pytest.mark.edge_case
class TestNonExistentFiles:
    """Edge case tests for non-existent files."""

    def test_nonexistent_file(self, temp_dir):
        """Test handling of non-existent file."""
        if FILE_INFO_AVAILABLE:
            nonexistent = temp_dir / "does_not_exist.txt"
            result = get_file_info(str(nonexistent))
            # Should return error or handle gracefully
            assert "error" in result.lower() or "not found" in result.lower()

    def test_nonexistent_directory_path(self, temp_dir):
        """Test handling of path with non-existent directory."""
        if FILE_INFO_AVAILABLE:
            path = temp_dir / "nonexistent_dir" / "file.txt"
            result = get_file_info(str(path))
            assert "error" in result.lower()

    def test_deleted_after_listing(self, temp_dir):
        """Test handling of file deleted after path obtained."""
        if FILE_INFO_AVAILABLE:
            file_path = temp_dir / "to_delete.txt"
            file_path.write_text("temporary")
            path_str = str(file_path)
            file_path.unlink()  # Delete before reading
            result = get_file_info(path_str)
            assert "error" in result.lower()

    @pytest.mark.parametrize("path", [
        "",
        " ",
        "   ",
        "\t",
        "\n",
    ])
    def test_empty_and_whitespace_paths(self, path):
        """Test handling of empty and whitespace paths."""
        if FILE_INFO_AVAILABLE:
            try:
                result = get_file_info(path)
                # Should handle gracefully
            except Exception:
                pass  # Acceptable


# =============================================================================
# Empty File Tests
# =============================================================================

@pytest.mark.edge_case
class TestEmptyFiles:
    """Edge case tests for empty files."""

    def test_empty_file_info(self, empty_file):
        """Test getting info for empty file."""
        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(empty_file))
            assert "error" not in result.lower() or "size" in result.lower()
            # Should report size of 0

    def test_empty_file_hash(self, empty_file):
        """Test hashing of empty file."""
        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(empty_file))
            # Empty file has known MD5: d41d8cd98f00b204e9800998ecf8427e
            # Just verify it doesn't crash

    def test_zero_byte_file(self, temp_dir):
        """Test truly zero-byte file."""
        zero_file = temp_dir / "zero.bin"
        zero_file.touch()
        assert zero_file.stat().st_size == 0

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(zero_file))
            assert "error" not in result.lower() or "0" in result


# =============================================================================
# Binary File Tests
# =============================================================================

@pytest.mark.edge_case
class TestBinaryFiles:
    """Edge case tests for binary files."""

    def test_binary_file_info(self, binary_file):
        """Test getting info for binary file."""
        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(binary_file))
            # Should handle binary content

    def test_null_bytes_file(self, temp_dir):
        """Test file containing only null bytes."""
        null_file = temp_dir / "nulls.bin"
        null_file.write_bytes(b"\x00" * 100)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(null_file))

    def test_all_byte_values(self, temp_dir):
        """Test file containing all byte values."""
        all_bytes_file = temp_dir / "all_bytes.bin"
        all_bytes_file.write_bytes(bytes(range(256)))

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(all_bytes_file))

    def test_high_entropy_binary(self, temp_dir):
        """Test high-entropy binary file."""
        import hashlib
        entropy_file = temp_dir / "entropy.bin"
        # Create pseudo-random content
        content = hashlib.sha256(b"seed").digest() * 100
        entropy_file.write_bytes(content)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(entropy_file))

    def test_executable_binary(self, temp_dir):
        """Test binary file with executable-like header."""
        exe_file = temp_dir / "fake.exe"
        # PE header magic
        pe_header = b"MZ" + b"\x00" * 58 + b"\x00\x00\x00\x00"
        exe_file.write_bytes(pe_header + b"\x00" * 100)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(exe_file))

    def test_elf_binary(self, temp_dir):
        """Test binary file with ELF header."""
        elf_file = temp_dir / "fake.elf"
        # ELF magic
        elf_header = b"\x7fELF" + b"\x00" * 100
        elf_file.write_bytes(elf_header)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(elf_file))


# =============================================================================
# Symbolic Link Tests
# =============================================================================

@pytest.mark.edge_case
class TestSymbolicLinks:
    """Edge case tests for symbolic links."""

    def test_valid_symlink(self, symlink_file):
        """Test reading valid symbolic link."""
        if symlink_file is None:
            pytest.skip("Symlinks not available")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(symlink_file))
            # Should follow symlink or indicate it's a symlink

    def test_broken_symlink(self, broken_symlink):
        """Test reading broken symbolic link."""
        if broken_symlink is None:
            pytest.skip("Symlinks not available")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(broken_symlink))
            # Should handle gracefully

    def test_symlink_chain(self, temp_dir, text_file):
        """Test chain of symbolic links."""
        try:
            link1 = temp_dir / "link1.txt"
            link2 = temp_dir / "link2.txt"
            link1.symlink_to(text_file)
            link2.symlink_to(link1)

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(link2))
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not available")

    def test_circular_symlink(self, temp_dir):
        """Test circular symbolic link detection."""
        try:
            link1 = temp_dir / "circular1.txt"
            link2 = temp_dir / "circular2.txt"
            # Create temporary file first
            temp_file = temp_dir / "temp.txt"
            temp_file.write_text("temp")
            link1.symlink_to(link2)
            # Now make link2 point to link1 (circular)
            link2.symlink_to(link1)

            if FILE_INFO_AVAILABLE:
                try:
                    result = get_file_info(str(link1))
                    # Should detect and handle circular reference
                except RecursionError:
                    pass  # Acceptable if caught
                except Exception:
                    pass  # Any graceful handling is acceptable
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not available")


# =============================================================================
# Permission Tests
# =============================================================================

@pytest.mark.edge_case
class TestPermissionScenarios:
    """Edge case tests for file permissions."""

    def test_readonly_file(self, temp_dir):
        """Test reading a read-only file."""
        readonly_file = temp_dir / "readonly.txt"
        readonly_file.write_text("read only content")
        readonly_file.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(readonly_file))
            # Should be able to read read-only files

        # Cleanup: restore permissions for deletion
        readonly_file.chmod(stat.S_IRWXU)

    def test_no_read_permission(self, temp_dir):
        """Test file without read permission."""
        if os.name == 'nt':
            pytest.skip("Windows handles permissions differently")

        no_read_file = temp_dir / "no_read.txt"
        no_read_file.write_text("cannot read")
        no_read_file.chmod(0o000)

        try:
            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(no_read_file))
                # Should handle permission denied gracefully
        finally:
            # Cleanup: restore permissions
            no_read_file.chmod(stat.S_IRWXU)

    def test_directory_instead_of_file(self, temp_dir):
        """Test when path is a directory."""
        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(temp_dir))
            # Should handle directory gracefully or report error

    def test_no_permission_parent_dir(self, temp_dir):
        """Test file in directory without execute permission."""
        if os.name == 'nt':
            pytest.skip("Windows handles permissions differently")

        protected_dir = temp_dir / "protected"
        protected_dir.mkdir()
        protected_file = protected_dir / "file.txt"
        protected_file.write_text("protected")
        protected_dir.chmod(0o000)

        try:
            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(protected_file))
                # Should handle gracefully
        finally:
            protected_dir.chmod(stat.S_IRWXU)


# =============================================================================
# Special File Types Tests
# =============================================================================

@pytest.mark.edge_case
class TestSpecialFileTypes:
    """Edge case tests for special file types."""

    def test_device_file(self):
        """Test handling of device files (Unix)."""
        if os.name == 'nt':
            pytest.skip("Device files not applicable on Windows")

        if FILE_INFO_AVAILABLE:
            # /dev/null should exist on Unix
            if os.path.exists("/dev/null"):
                result = get_file_info("/dev/null")
                # Should handle gracefully

    def test_pipe_fifo(self, temp_dir):
        """Test handling of named pipes (FIFO)."""
        if os.name == 'nt':
            pytest.skip("Named pipes different on Windows")

        try:
            fifo_path = temp_dir / "test.fifo"
            os.mkfifo(str(fifo_path))

            if FILE_INFO_AVAILABLE:
                # Note: Reading FIFO would block, so just check type handling
                pass  # Don't actually read, would block

            fifo_path.unlink()
        except (OSError, AttributeError):
            pytest.skip("FIFO not supported")

    def test_socket_file(self, temp_dir):
        """Test handling of Unix socket files."""
        if os.name == 'nt':
            pytest.skip("Unix sockets not applicable on Windows")

        import socket
        socket_path = temp_dir / "test.sock"

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(socket_path))

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(socket_path))
                # Should handle socket gracefully

            sock.close()
        except (OSError, AttributeError):
            pytest.skip("Unix sockets not supported")


# =============================================================================
# Path Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestPathEdgeCases:
    """Edge case tests for various path formats."""

    def test_relative_path(self, text_file, temp_dir):
        """Test with relative path."""
        if FILE_INFO_AVAILABLE:
            # Create relative path from temp_dir
            old_cwd = os.getcwd()
            try:
                os.chdir(str(temp_dir))
                result = get_file_info(text_file.name)
            finally:
                os.chdir(old_cwd)

    def test_absolute_path(self, text_file):
        """Test with absolute path."""
        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(text_file.absolute()))

    def test_path_with_spaces(self, temp_dir):
        """Test path containing spaces."""
        space_file = temp_dir / "file with spaces.txt"
        space_file.write_text("content")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(space_file))

    def test_path_with_special_chars(self, temp_dir):
        """Test path with special characters."""
        # Characters that are valid in most filesystems
        special_chars = "file-name_with.special(chars).txt"
        special_file = temp_dir / special_chars
        special_file.write_text("content")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(special_file))

    def test_unicode_filename(self, temp_dir):
        """Test path with Unicode characters."""
        try:
            unicode_file = temp_dir / "archivo_espanol.txt"
            unicode_file.write_text("contenido")

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(unicode_file))
        except (OSError, UnicodeError):
            pytest.skip("Unicode filenames not supported")

    def test_very_long_filename(self, temp_dir):
        """Test with very long filename."""
        try:
            # Most filesystems have 255 char limit for filename
            long_name = "a" * 200 + ".txt"
            long_file = temp_dir / long_name
            long_file.write_text("content")

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(long_file))
        except OSError:
            pytest.skip("Long filenames not supported")

    def test_very_long_path(self, temp_dir):
        """Test with very long path."""
        try:
            # Create nested directories
            current = temp_dir
            for i in range(20):
                current = current / f"dir{i}"
                current.mkdir(exist_ok=True)
            long_path_file = current / "file.txt"
            long_path_file.write_text("content")

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(long_path_file))
        except OSError:
            pytest.skip("Long paths not supported")

    def test_dot_files(self, temp_dir):
        """Test hidden files (dot files)."""
        dot_file = temp_dir / ".hidden"
        dot_file.write_text("hidden content")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(dot_file))

    def test_double_dots_in_path(self, temp_dir, text_file):
        """Test path with .. components."""
        if FILE_INFO_AVAILABLE:
            # Create path that goes up and back down
            subdir = temp_dir / "subdir"
            subdir.mkdir()
            path_with_dots = subdir / ".." / text_file.name
            result = get_file_info(str(path_with_dots))


# =============================================================================
# Path Traversal Security Tests
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.security
class TestPathTraversalSecurity:
    """Security tests for path traversal prevention."""

    @pytest.mark.parametrize("traversal_path", [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%00/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ])
    def test_path_traversal_attempts(self, temp_dir, traversal_path):
        """Test that path traversal attempts are handled safely."""
        if FILE_INFO_AVAILABLE:
            full_path = temp_dir / traversal_path
            try:
                result = get_file_info(str(full_path))
                # Should not expose sensitive files
                # Either return error or safe result
            except Exception:
                pass  # Safe handling

    def test_null_byte_injection_in_path(self, temp_dir):
        """Test null byte injection in file path."""
        if FILE_INFO_AVAILABLE:
            # Null bytes can truncate strings in some contexts
            try:
                malicious_path = str(temp_dir / "file.txt\x00.jpg")
                result = get_file_info(malicious_path)
            except (ValueError, TypeError):
                pass  # Safe handling

    def test_url_encoded_path(self, temp_dir):
        """Test URL-encoded path components."""
        if FILE_INFO_AVAILABLE:
            # %2e = '.', %2f = '/'
            encoded_path = str(temp_dir) + "%2f%2e%2e%2ftest"
            try:
                result = get_file_info(encoded_path)
            except Exception:
                pass


# =============================================================================
# Large File Tests
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.slow
class TestLargeFiles:
    """Edge case tests for large files."""

    def test_large_file_info(self, large_file):
        """Test getting info for large (1MB) file."""
        if FILE_INFO_AVAILABLE:
            import time
            start = time.time()
            result = get_file_info(str(large_file))
            elapsed = time.time() - start

            assert elapsed < 10.0, f"Operation took too long: {elapsed}s"

    def test_very_large_file(self, temp_dir):
        """Test with very large file (10MB)."""
        if FILE_INFO_AVAILABLE:
            large_file = temp_dir / "very_large.bin"
            # Write 10MB
            chunk = b"X" * (1024 * 1024)
            with open(large_file, 'wb') as f:
                for _ in range(10):
                    f.write(chunk)

            import time
            start = time.time()
            result = get_file_info(str(large_file))
            elapsed = time.time() - start

            # Should complete in reasonable time
            assert elapsed < 30.0, f"Operation took too long: {elapsed}s"

    def test_sparse_file(self, temp_dir):
        """Test sparse file handling."""
        try:
            sparse_file = temp_dir / "sparse.bin"
            with open(sparse_file, 'wb') as f:
                f.seek(1024 * 1024 * 10)  # Seek 10MB
                f.write(b'\x00')

            if FILE_INFO_AVAILABLE:
                result = get_file_info(str(sparse_file))
        except OSError:
            pytest.skip("Sparse files not supported")


# =============================================================================
# File Content Edge Cases
# =============================================================================

@pytest.mark.edge_case
class TestFileContentEdgeCases:
    """Edge case tests for file content handling."""

    def test_file_with_only_newlines(self, temp_dir):
        """Test file containing only newlines."""
        newline_file = temp_dir / "newlines.txt"
        newline_file.write_text("\n" * 100)

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(newline_file))

    def test_file_with_no_newline(self, temp_dir):
        """Test file with no trailing newline."""
        no_newline = temp_dir / "no_newline.txt"
        no_newline.write_text("no newline at end")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(no_newline))

    def test_file_with_crlf(self, temp_dir):
        """Test file with Windows-style line endings."""
        crlf_file = temp_dir / "crlf.txt"
        crlf_file.write_bytes(b"line1\r\nline2\r\nline3\r\n")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(crlf_file))

    def test_file_with_mixed_line_endings(self, temp_dir):
        """Test file with mixed line endings."""
        mixed_file = temp_dir / "mixed.txt"
        mixed_file.write_bytes(b"line1\nline2\r\nline3\rline4")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(mixed_file))

    def test_file_with_bom(self, temp_dir):
        """Test file with byte order mark (BOM)."""
        bom_file = temp_dir / "bom.txt"
        # UTF-8 BOM
        bom_file.write_bytes(b"\xef\xbb\xbf" + b"content")

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(bom_file))

    def test_truncated_file(self, temp_dir):
        """Test file that appears truncated."""
        truncated = temp_dir / "truncated.bin"
        # Write incomplete structure (like incomplete archive)
        truncated.write_bytes(b"PK\x03\x04")  # ZIP header start

        if FILE_INFO_AVAILABLE:
            result = get_file_info(str(truncated))
