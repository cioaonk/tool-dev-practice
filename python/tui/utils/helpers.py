"""
TUI Utility Helpers

Common utility functions for the TUI application.
"""

from __future__ import annotations

import os
import sys
import subprocess
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime


def get_terminal_size() -> Tuple[int, int]:
    """
    Get the current terminal size.

    Returns:
        Tuple of (columns, rows)
    """
    try:
        size = os.get_terminal_size()
        return (size.columns, size.lines)
    except OSError:
        return (80, 24)  # Default fallback


def format_timestamp(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format a datetime object.

    Args:
        dt: Datetime to format (defaults to now)
        fmt: Format string

    Returns:
        Formatted timestamp string
    """
    if dt is None:
        dt = datetime.now()
    return dt.strftime(fmt)


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse a port range string.

    Args:
        port_str: Port range string (e.g., "1-100", "22,80,443")

    Returns:
        List of port numbers
    """
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def validate_ip_address(ip: str) -> bool:
    """
    Validate an IP address.

    Args:
        ip: IP address string

    Returns:
        True if valid
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate a CIDR notation string.

    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")

    Returns:
        True if valid
    """
    if "/" not in cidr:
        return False
    ip, prefix = cidr.rsplit("/", 1)
    if not validate_ip_address(ip):
        return False
    try:
        prefix_int = int(prefix)
        return 0 <= prefix_int <= 32
    except ValueError:
        return False


async def run_command(
    command: List[str],
    timeout: Optional[float] = None,
    cwd: Optional[Path] = None
) -> Tuple[int, str, str]:
    """
    Run an external command asynchronously.

    Args:
        command: Command and arguments
        timeout: Optional timeout in seconds
        cwd: Working directory

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return (
                process.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace")
            )
        except asyncio.TimeoutError:
            process.kill()
            return (-1, "", "Command timed out")

    except Exception as e:
        return (-1, "", str(e))


def format_bytes(num_bytes: int) -> str:
    """
    Format bytes as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 KB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration as human-readable string.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe filesystem usage.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove or replace dangerous characters
    dangerous_chars = '<>:"/\\|?*'
    for char in dangerous_chars:
        filename = filename.replace(char, "_")
    return filename.strip(". ")


def create_ascii_box(
    content: str,
    title: Optional[str] = None,
    width: Optional[int] = None,
    style: str = "single"
) -> str:
    """
    Create an ASCII box around content.

    Args:
        content: Content to box
        title: Optional title
        width: Box width (auto if None)
        style: Box style ("single", "double", "rounded")

    Returns:
        Boxed content string
    """
    # Box characters
    styles = {
        "single": {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|"},
        "double": {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "=", "v": "|"},
        "rounded": {"tl": "/", "tr": "\\", "bl": "\\", "br": "/", "h": "-", "v": "|"},
    }
    chars = styles.get(style, styles["single"])

    lines = content.split("\n")
    if width is None:
        width = max(len(line) for line in lines) + 4

    result = []

    # Top border
    if title:
        title_part = f" {title} "
        remaining = width - 2 - len(title_part)
        left_border = remaining // 2
        right_border = remaining - left_border
        result.append(
            chars["tl"] + chars["h"] * left_border + title_part +
            chars["h"] * right_border + chars["tr"]
        )
    else:
        result.append(chars["tl"] + chars["h"] * (width - 2) + chars["tr"])

    # Content
    for line in lines:
        padding = width - 4 - len(line)
        result.append(f"{chars['v']} {line}{' ' * padding} {chars['v']}")

    # Bottom border
    result.append(chars["bl"] + chars["h"] * (width - 2) + chars["br"])

    return "\n".join(result)
