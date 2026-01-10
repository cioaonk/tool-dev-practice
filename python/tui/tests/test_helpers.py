"""
Tests for TUI utility helpers.

This module tests:
- Terminal size detection
- Timestamp formatting
- String manipulation utilities
- Port range parsing
- IP/CIDR validation
- Command execution
- Formatting utilities
- ASCII box generation
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tui.utils.helpers import (
    get_terminal_size,
    format_timestamp,
    truncate_string,
    parse_port_range,
    validate_ip_address,
    validate_cidr,
    run_command,
    format_bytes,
    format_duration,
    sanitize_filename,
    create_ascii_box,
)


class TestGetTerminalSize:
    """Test suite for get_terminal_size function."""

    def test_get_terminal_size_returns_tuple(self):
        """Test that get_terminal_size returns a tuple."""
        result = get_terminal_size()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_get_terminal_size_returns_integers(self):
        """Test that get_terminal_size returns integers."""
        columns, rows = get_terminal_size()
        assert isinstance(columns, int)
        assert isinstance(rows, int)

    def test_get_terminal_size_positive_values(self):
        """Test that get_terminal_size returns positive values."""
        columns, rows = get_terminal_size()
        assert columns > 0
        assert rows > 0

    def test_get_terminal_size_fallback_on_error(self):
        """Test that get_terminal_size returns default on OSError."""
        with patch("os.get_terminal_size", side_effect=OSError()):
            columns, rows = get_terminal_size()
            assert columns == 80
            assert rows == 24


class TestFormatTimestamp:
    """Test suite for format_timestamp function."""

    def test_format_timestamp_default_format(self):
        """Test format_timestamp with default format."""
        dt = datetime(2024, 1, 15, 10, 30, 45)
        result = format_timestamp(dt)
        assert result == "2024-01-15 10:30:45"

    def test_format_timestamp_custom_format(self):
        """Test format_timestamp with custom format."""
        dt = datetime(2024, 1, 15, 10, 30, 45)
        result = format_timestamp(dt, "%Y/%m/%d")
        assert result == "2024/01/15"

    def test_format_timestamp_none_uses_now(self):
        """Test format_timestamp with None uses current time."""
        result = format_timestamp(None)
        # Should be a valid timestamp string
        assert len(result) == 19  # YYYY-MM-DD HH:MM:SS

    def test_format_timestamp_time_only(self):
        """Test format_timestamp with time only format."""
        dt = datetime(2024, 1, 15, 10, 30, 45)
        result = format_timestamp(dt, "%H:%M:%S")
        assert result == "10:30:45"


class TestTruncateString:
    """Test suite for truncate_string function."""

    def test_truncate_string_no_truncation_needed(self):
        """Test truncate_string when string is short enough."""
        result = truncate_string("hello", 10)
        assert result == "hello"

    def test_truncate_string_exact_length(self):
        """Test truncate_string when string is exactly max length."""
        result = truncate_string("hello", 5)
        assert result == "hello"

    def test_truncate_string_truncates_long_string(self):
        """Test truncate_string truncates long strings."""
        result = truncate_string("hello world", 8)
        assert result == "hello..."
        assert len(result) == 8

    def test_truncate_string_custom_suffix(self):
        """Test truncate_string with custom suffix."""
        result = truncate_string("hello world", 9, suffix=">>")
        assert result == "hello w>>"
        assert len(result) == 9

    def test_truncate_string_empty_string(self):
        """Test truncate_string with empty string."""
        result = truncate_string("", 10)
        assert result == ""


class TestParsePortRange:
    """Test suite for parse_port_range function."""

    def test_parse_port_range_single_port(self):
        """Test parse_port_range with single port."""
        result = parse_port_range("80")
        assert result == [80]

    def test_parse_port_range_comma_separated(self):
        """Test parse_port_range with comma-separated ports."""
        result = parse_port_range("22,80,443")
        assert result == [22, 80, 443]

    def test_parse_port_range_range(self):
        """Test parse_port_range with port range."""
        result = parse_port_range("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_parse_port_range_mixed(self):
        """Test parse_port_range with mixed format."""
        result = parse_port_range("22, 80-82, 443")
        assert result == [22, 80, 81, 82, 443]

    def test_parse_port_range_with_spaces(self):
        """Test parse_port_range handles spaces."""
        result = parse_port_range("22 , 80 , 443")
        assert result == [22, 80, 443]


class TestValidateIpAddress:
    """Test suite for validate_ip_address function."""

    def test_validate_ip_address_valid(self):
        """Test validate_ip_address with valid IP."""
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("0.0.0.0") is True
        assert validate_ip_address("255.255.255.255") is True
        assert validate_ip_address("10.0.0.1") is True

    def test_validate_ip_address_invalid_format(self):
        """Test validate_ip_address with invalid format."""
        assert validate_ip_address("192.168.1") is False
        assert validate_ip_address("192.168.1.1.1") is False
        assert validate_ip_address("192.168.1.") is False

    def test_validate_ip_address_out_of_range(self):
        """Test validate_ip_address with out of range values."""
        assert validate_ip_address("256.0.0.1") is False
        assert validate_ip_address("192.168.1.256") is False
        assert validate_ip_address("-1.0.0.1") is False

    def test_validate_ip_address_non_numeric(self):
        """Test validate_ip_address with non-numeric values."""
        assert validate_ip_address("abc.def.ghi.jkl") is False
        assert validate_ip_address("192.168.1.a") is False


class TestValidateCidr:
    """Test suite for validate_cidr function."""

    def test_validate_cidr_valid(self):
        """Test validate_cidr with valid CIDR."""
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True
        assert validate_cidr("0.0.0.0/0") is True
        assert validate_cidr("255.255.255.255/32") is True

    def test_validate_cidr_invalid_ip(self):
        """Test validate_cidr with invalid IP."""
        assert validate_cidr("256.0.0.0/24") is False
        assert validate_cidr("192.168.1/24") is False

    def test_validate_cidr_invalid_prefix(self):
        """Test validate_cidr with invalid prefix."""
        assert validate_cidr("192.168.1.0/33") is False
        assert validate_cidr("192.168.1.0/-1") is False
        assert validate_cidr("192.168.1.0/abc") is False

    def test_validate_cidr_no_prefix(self):
        """Test validate_cidr without prefix."""
        assert validate_cidr("192.168.1.0") is False


class TestRunCommand:
    """Test suite for run_command function."""

    @pytest.mark.asyncio
    async def test_run_command_success(self):
        """Test run_command with successful command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b'output', b''))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["echo", "hello"])

            assert returncode == 0
            assert stdout == "output"
            assert stderr == ""

    @pytest.mark.asyncio
    async def test_run_command_failure(self):
        """Test run_command with failed command."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate = AsyncMock(return_value=(b'', b'error'))
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["false"])

            assert returncode == 1
            assert stderr == "error"

    @pytest.mark.asyncio
    async def test_run_command_timeout(self):
        """Test run_command with timeout."""
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_process.kill = MagicMock()
            mock_exec.return_value = mock_process

            returncode, stdout, stderr = await run_command(["sleep", "10"], timeout=0.1)

            assert returncode == -1
            assert stderr == "Command timed out"

    @pytest.mark.asyncio
    async def test_run_command_exception(self):
        """Test run_command handles exceptions."""
        with patch("asyncio.create_subprocess_exec", side_effect=Exception("Test error")):
            returncode, stdout, stderr = await run_command(["invalid"])

            assert returncode == -1
            assert "Test error" in stderr


class TestFormatBytes:
    """Test suite for format_bytes function."""

    def test_format_bytes_bytes(self):
        """Test format_bytes with bytes."""
        assert format_bytes(100) == "100.0 B"
        assert format_bytes(0) == "0.0 B"

    def test_format_bytes_kilobytes(self):
        """Test format_bytes with kilobytes."""
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(2048) == "2.0 KB"

    def test_format_bytes_megabytes(self):
        """Test format_bytes with megabytes."""
        assert format_bytes(1024 * 1024) == "1.0 MB"

    def test_format_bytes_gigabytes(self):
        """Test format_bytes with gigabytes."""
        assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"

    def test_format_bytes_terabytes(self):
        """Test format_bytes with terabytes."""
        assert format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"


class TestFormatDuration:
    """Test suite for format_duration function."""

    def test_format_duration_seconds(self):
        """Test format_duration with seconds."""
        assert format_duration(30) == "30.0s"
        assert format_duration(45.5) == "45.5s"

    def test_format_duration_minutes(self):
        """Test format_duration with minutes."""
        assert format_duration(90) == "1m 30s"
        assert format_duration(150) == "2m 30s"

    def test_format_duration_hours(self):
        """Test format_duration with hours."""
        assert format_duration(3600) == "1h 0m"
        assert format_duration(5400) == "1h 30m"


class TestSanitizeFilename:
    """Test suite for sanitize_filename function."""

    def test_sanitize_filename_clean(self):
        """Test sanitize_filename with clean filename."""
        assert sanitize_filename("document.txt") == "document.txt"

    def test_sanitize_filename_dangerous_chars(self):
        """Test sanitize_filename removes dangerous characters."""
        assert sanitize_filename("file<name>.txt") == "file_name_.txt"
        assert sanitize_filename("file:name.txt") == "file_name.txt"
        assert sanitize_filename("file/name.txt") == "file_name.txt"
        assert sanitize_filename("file\\name.txt") == "file_name.txt"

    def test_sanitize_filename_strips_dots_spaces(self):
        """Test sanitize_filename strips leading/trailing dots and spaces."""
        assert sanitize_filename("  file.txt  ") == "file.txt"
        assert sanitize_filename("..file.txt..") == "file.txt"


class TestCreateAsciiBox:
    """Test suite for create_ascii_box function."""

    def test_create_ascii_box_simple(self):
        """Test create_ascii_box with simple content."""
        result = create_ascii_box("Hello")
        assert "Hello" in result
        assert result.startswith("+")

    def test_create_ascii_box_with_title(self):
        """Test create_ascii_box with title."""
        result = create_ascii_box("Content", title="Title")
        assert "Title" in result
        assert "Content" in result

    def test_create_ascii_box_multiline(self):
        """Test create_ascii_box with multiline content."""
        result = create_ascii_box("Line 1\nLine 2\nLine 3")
        assert "Line 1" in result
        assert "Line 2" in result
        assert "Line 3" in result

    def test_create_ascii_box_double_style(self):
        """Test create_ascii_box with double style."""
        result = create_ascii_box("Hello", style="double")
        assert "=" in result

    def test_create_ascii_box_rounded_style(self):
        """Test create_ascii_box with rounded style."""
        result = create_ascii_box("Hello", style="rounded")
        assert "/" in result

    def test_create_ascii_box_custom_width(self):
        """Test create_ascii_box with custom width."""
        result = create_ascii_box("Hi", width=20)
        lines = result.split("\n")
        # First line should be 20 characters
        assert len(lines[0]) == 20
