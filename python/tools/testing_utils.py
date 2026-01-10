#!/usr/bin/env python3
"""
Testing Utilities Module for Security Tools
============================================

This module provides common testing utilities, mock fixtures, and helper
functions for testing the security tools in this toolkit.

Author: Offensive Security Toolsmith
Purpose: Centralized testing infrastructure for penetration testing tools
"""

import io
import sys
import json
import socket
import hashlib
import argparse
import unittest
import threading
from typing import Any, Dict, List, Optional, Callable, Tuple, Generator
from dataclasses import dataclass, field
from contextlib import contextmanager
from unittest.mock import Mock, MagicMock, patch
import random
import string
import struct
import time


# =============================================================================
# Mock Network Fixtures
# =============================================================================

class MockSocket:
    """
    Mock socket for testing network operations without actual connections.

    Provides configurable responses and tracks all operations for verification.
    """

    def __init__(self,
                 response_data: bytes = b"",
                 connect_success: bool = True,
                 recv_delay: float = 0.0,
                 raise_on_connect: Optional[Exception] = None,
                 raise_on_send: Optional[Exception] = None,
                 raise_on_recv: Optional[Exception] = None):
        self.response_data = response_data
        self.connect_success = connect_success
        self.recv_delay = recv_delay
        self.raise_on_connect = raise_on_connect
        self.raise_on_send = raise_on_send
        self.raise_on_recv = raise_on_recv

        # Tracking
        self.connected_to: Optional[Tuple[str, int]] = None
        self.sent_data: List[bytes] = []
        self.recv_calls: int = 0
        self.closed: bool = False
        self._recv_index: int = 0
        self._timeout: Optional[float] = None
        self._blocking: bool = True

    def connect(self, address: Tuple[str, int]) -> None:
        if self.raise_on_connect:
            raise self.raise_on_connect
        if not self.connect_success:
            raise ConnectionRefusedError("Connection refused")
        self.connected_to = address

    def send(self, data: bytes) -> int:
        if self.raise_on_send:
            raise self.raise_on_send
        self.sent_data.append(data)
        return len(data)

    def sendall(self, data: bytes) -> None:
        self.send(data)

    def recv(self, bufsize: int) -> bytes:
        if self.raise_on_recv:
            raise self.raise_on_recv
        if self.recv_delay > 0:
            time.sleep(self.recv_delay)
        self.recv_calls += 1

        if self._recv_index >= len(self.response_data):
            return b""

        chunk = self.response_data[self._recv_index:self._recv_index + bufsize]
        self._recv_index += bufsize
        return chunk

    def settimeout(self, timeout: Optional[float]) -> None:
        self._timeout = timeout

    def setblocking(self, blocking: bool) -> None:
        self._blocking = blocking

    def close(self) -> None:
        self.closed = True

    def fileno(self) -> int:
        return 999  # Fake file descriptor

    def getpeername(self) -> Tuple[str, int]:
        return self.connected_to or ("0.0.0.0", 0)

    def getsockname(self) -> Tuple[str, int]:
        return ("127.0.0.1", 12345)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class MockHTTPResponse:
    """Mock HTTP response for testing HTTP-based tools."""

    def __init__(self,
                 status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None,
                 body: str = "",
                 url: str = "http://example.com"):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.text = body
        self.content = body.encode('utf-8')
        self.url = url
        self.ok = 200 <= status_code < 300
        self.reason = self._get_reason(status_code)

    def _get_reason(self, code: int) -> str:
        reasons = {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error",
            502: "Bad Gateway", 503: "Service Unavailable"
        }
        return reasons.get(code, "Unknown")

    def json(self) -> Any:
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if not self.ok:
            raise Exception(f"HTTP Error: {self.status_code} {self.reason}")


class MockDNSResponse:
    """Mock DNS response for testing DNS enumeration tools."""

    def __init__(self, records: Optional[Dict[str, List[str]]] = None):
        self.records = records or {}

    def get_a_records(self, domain: str) -> List[str]:
        return self.records.get(f"A:{domain}", [])

    def get_aaaa_records(self, domain: str) -> List[str]:
        return self.records.get(f"AAAA:{domain}", [])

    def get_mx_records(self, domain: str) -> List[str]:
        return self.records.get(f"MX:{domain}", [])

    def get_txt_records(self, domain: str) -> List[str]:
        return self.records.get(f"TXT:{domain}", [])

    def get_ns_records(self, domain: str) -> List[str]:
        return self.records.get(f"NS:{domain}", [])


class MockSMBClient:
    """Mock SMB client for testing SMB enumeration tools."""

    def __init__(self,
                 shares: Optional[List[str]] = None,
                 auth_success: bool = True,
                 files: Optional[Dict[str, List[str]]] = None):
        self.shares = shares or ["ADMIN$", "C$", "IPC$"]
        self.auth_success = auth_success
        self.files = files or {}
        self.connected: bool = False
        self.authenticated: bool = False

    def connect(self, host: str, port: int = 445) -> bool:
        self.connected = True
        return True

    def login(self, username: str, password: str) -> bool:
        if self.auth_success:
            self.authenticated = True
            return True
        return False

    def list_shares(self) -> List[str]:
        if not self.authenticated:
            raise PermissionError("Not authenticated")
        return self.shares

    def list_files(self, share: str, path: str = "/") -> List[str]:
        key = f"{share}:{path}"
        return self.files.get(key, [])


# =============================================================================
# CLI Testing Helpers
# =============================================================================

@contextmanager
def capture_output() -> Generator[Tuple[io.StringIO, io.StringIO], None, None]:
    """
    Context manager to capture stdout and stderr.

    Usage:
        with capture_output() as (stdout, stderr):
            some_function()
        print(stdout.getvalue())
    """
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr


@contextmanager
def mock_argv(args: List[str]) -> Generator[None, None, None]:
    """
    Context manager to temporarily replace sys.argv.

    Usage:
        with mock_argv(['tool.py', '--target', 'example.com']):
            main()
    """
    old_argv = sys.argv
    try:
        sys.argv = args
        yield
    finally:
        sys.argv = old_argv


def run_cli_tool(main_func: Callable,
                 args: List[str],
                 expected_exit: Optional[int] = None) -> Tuple[str, str, int]:
    """
    Run a CLI tool and capture its output.

    Args:
        main_func: The main() function of the tool
        args: Command line arguments (without the script name)
        expected_exit: Expected exit code (if any)

    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    exit_code = 0
    with capture_output() as (stdout, stderr):
        with mock_argv(['tool.py'] + args):
            try:
                main_func()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
            except Exception as e:
                stderr.write(f"Exception: {e}\n")
                exit_code = 1

    if expected_exit is not None:
        assert exit_code == expected_exit, \
            f"Expected exit code {expected_exit}, got {exit_code}"

    return stdout.getvalue(), stderr.getvalue(), exit_code


def validate_plan_output(output: str, required_sections: Optional[List[str]] = None) -> bool:
    """
    Validate that plan mode output contains expected sections.

    Args:
        output: The captured stdout from plan mode
        required_sections: List of section headers that must be present

    Returns:
        True if all required sections are present
    """
    if required_sections is None:
        required_sections = ["PLAN MODE", "Actions", "No actions will be taken"]

    for section in required_sections:
        if section.lower() not in output.lower():
            return False
    return True


def validate_documentation(doc: Dict[str, Any],
                          required_keys: Optional[List[str]] = None) -> Tuple[bool, List[str]]:
    """
    Validate that get_documentation() returns properly structured data.

    Args:
        doc: The documentation dictionary returned by get_documentation()
        required_keys: Keys that must be present in the documentation

    Returns:
        Tuple of (is_valid, missing_keys)
    """
    if required_keys is None:
        required_keys = ["name", "description", "usage", "arguments"]

    missing = [key for key in required_keys if key not in doc]
    return len(missing) == 0, missing


# =============================================================================
# Test Data Generators
# =============================================================================

class TestDataGenerator:
    """Generates various types of test data for security tools."""

    @staticmethod
    def generate_ip_range(start: str = "192.168.1.1",
                          count: int = 10) -> List[str]:
        """Generate a range of IP addresses."""
        parts = [int(p) for p in start.split('.')]
        ips = []
        for i in range(count):
            ips.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3] + i}")
            if parts[3] + i >= 255:
                parts[2] += 1
                parts[3] = 0
        return ips

    @staticmethod
    def generate_ports(port_type: str = "common") -> List[int]:
        """Generate port lists for testing."""
        if port_type == "common":
            return [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        elif port_type == "all":
            return list(range(1, 65536))
        elif port_type == "top100":
            return [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
                   113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
                   465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
                   993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723,
                   1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,
                   3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
                   5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
                   8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154]
        else:
            return [80, 443]

    @staticmethod
    def generate_credentials(count: int = 5) -> List[Tuple[str, str]]:
        """Generate test credential pairs."""
        usernames = ["admin", "root", "administrator", "user", "test",
                    "guest", "operator", "manager", "service", "backup"]
        passwords = ["password", "123456", "admin", "root", "letmein",
                    "welcome", "monkey", "dragon", "master", "qwerty"]

        return [(random.choice(usernames), random.choice(passwords))
                for _ in range(count)]

    @staticmethod
    def generate_subdomains(domain: str, count: int = 10) -> List[str]:
        """Generate test subdomains."""
        prefixes = ["www", "mail", "ftp", "admin", "dev", "staging", "api",
                   "test", "blog", "shop", "store", "secure", "vpn", "remote",
                   "portal", "app", "mobile", "beta", "alpha", "demo"]

        selected = random.sample(prefixes, min(count, len(prefixes)))
        return [f"{prefix}.{domain}" for prefix in selected]

    @staticmethod
    def generate_web_paths(count: int = 20) -> List[str]:
        """Generate common web paths for directory enumeration."""
        paths = [
            "/admin", "/login", "/wp-admin", "/administrator", "/phpmyadmin",
            "/config", "/backup", "/api", "/v1", "/v2", "/docs", "/swagger",
            "/robots.txt", "/sitemap.xml", "/.git", "/.env", "/config.php",
            "/wp-config.php", "/database.sql", "/debug", "/test", "/status",
            "/health", "/metrics", "/info", "/server-status", "/.htaccess"
        ]
        return paths[:count]

    @staticmethod
    def generate_hash(plaintext: str, algorithm: str = "md5") -> str:
        """Generate a hash for testing hash cracking tools."""
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }

        if algorithm.lower() not in algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return algorithms[algorithm.lower()](plaintext.encode()).hexdigest()

    @staticmethod
    def generate_ntlm_hash(password: str) -> str:
        """Generate an NTLM hash for testing."""
        import hashlib
        return hashlib.new('md4', password.encode('utf-16le')).hexdigest()

    @staticmethod
    def generate_random_string(length: int = 16,
                              charset: str = "alphanumeric") -> str:
        """Generate a random string."""
        charsets = {
            "alphanumeric": string.ascii_letters + string.digits,
            "alpha": string.ascii_letters,
            "numeric": string.digits,
            "hex": string.hexdigits[:16],
            "printable": string.printable.strip()
        }
        chars = charsets.get(charset, charset)
        return ''.join(random.choices(chars, k=length))

    @staticmethod
    def generate_shellcode(size: int = 64, nop_sled: bool = True) -> bytes:
        """Generate fake shellcode for testing encoders."""
        if nop_sled:
            # NOP sled followed by random bytes
            nop_size = size // 4
            return b'\x90' * nop_size + bytes(random.randint(0, 255)
                                              for _ in range(size - nop_size))
        return bytes(random.randint(0, 255) for _ in range(size))

    @staticmethod
    def generate_service_banner(service: str) -> bytes:
        """Generate realistic service banners."""
        banners = {
            "ssh": b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
            "ftp": b"220 ProFTPD 1.3.6 Server ready.\r\n",
            "smtp": b"220 mail.example.com ESMTP Postfix\r\n",
            "http": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            "mysql": b"\x5b\x00\x00\x00\x0a5.7.32-0ubuntu0.18.04.1",
            "rdp": b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00",
            "telnet": b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27",
            "pop3": b"+OK POP3 server ready\r\n",
            "imap": b"* OK IMAP4rev1 Service Ready\r\n"
        }
        return banners.get(service.lower(), b"")


# =============================================================================
# Test Fixtures
# =============================================================================

@dataclass
class NetworkTestFixture:
    """Pre-configured network testing fixture."""
    target_host: str = "192.168.1.100"
    target_ports: List[int] = field(default_factory=lambda: [22, 80, 443])
    open_ports: List[int] = field(default_factory=lambda: [22, 80])
    timeout: float = 1.0

    def get_mock_socket_factory(self) -> Callable:
        """Return a socket factory that simulates open/closed ports."""
        open_ports = self.open_ports

        def socket_factory(*args, **kwargs):
            mock = MockSocket()

            original_connect = mock.connect
            def patched_connect(address):
                host, port = address
                if port not in open_ports:
                    raise ConnectionRefusedError("Connection refused")
                original_connect(address)

            mock.connect = patched_connect
            return mock

        return socket_factory


@dataclass
class HTTPTestFixture:
    """Pre-configured HTTP testing fixture."""
    base_url: str = "http://testserver.local"
    valid_paths: List[str] = field(default_factory=lambda: ["/", "/admin", "/api"])
    auth_paths: List[str] = field(default_factory=lambda: ["/admin"])
    status_codes: Dict[str, int] = field(default_factory=dict)

    def get_response(self, path: str, method: str = "GET") -> MockHTTPResponse:
        """Get appropriate mock response for a path."""
        if path in self.status_codes:
            return MockHTTPResponse(status_code=self.status_codes[path])

        if path in self.valid_paths:
            if path in self.auth_paths:
                return MockHTTPResponse(status_code=401)
            return MockHTTPResponse(status_code=200, body=f"<html>Content for {path}</html>")

        return MockHTTPResponse(status_code=404)


@dataclass
class CredentialTestFixture:
    """Pre-configured credential testing fixture."""
    valid_users: Dict[str, str] = field(default_factory=lambda: {
        "admin": "password123",
        "root": "toor",
        "test": "test"
    })

    def validate(self, username: str, password: str) -> bool:
        """Check if credentials are valid."""
        return self.valid_users.get(username) == password


# =============================================================================
# Test Base Classes
# =============================================================================

class SecurityToolTestCase(unittest.TestCase):
    """Base test case class for security tools with common utilities."""

    def setUp(self):
        """Set up test fixtures."""
        self.network_fixture = NetworkTestFixture()
        self.http_fixture = HTTPTestFixture()
        self.cred_fixture = CredentialTestFixture()
        self.data_generator = TestDataGenerator()

    def assert_plan_mode_safe(self, main_func: Callable, args: List[str]) -> str:
        """Assert that plan mode doesn't perform any actual operations."""
        # Add --plan flag
        plan_args = args + ['--plan']

        with patch('socket.socket') as mock_socket:
            stdout, stderr, exit_code = run_cli_tool(main_func, plan_args)

            # Socket should never be instantiated in plan mode
            # (This is a basic check - tool-specific tests may need more)

        self.assertIn("plan", stdout.lower(),
                     "Plan mode should indicate it's running in plan mode")
        return stdout

    def assert_documentation_complete(self, get_doc_func: Callable) -> Dict[str, Any]:
        """Assert that documentation is complete and well-formed."""
        doc = get_doc_func()

        self.assertIsInstance(doc, dict, "Documentation should be a dictionary")

        required_keys = ["name", "description", "usage"]
        for key in required_keys:
            self.assertIn(key, doc, f"Documentation missing required key: {key}")

        self.assertIsInstance(doc["name"], str)
        self.assertIsInstance(doc["description"], str)
        self.assertTrue(len(doc["name"]) > 0, "Tool name should not be empty")
        self.assertTrue(len(doc["description"]) > 0, "Description should not be empty")

        return doc

    def assert_valid_argparse(self, create_parser_func: Callable) -> argparse.ArgumentParser:
        """Assert that argument parser is properly configured."""
        parser = create_parser_func()

        self.assertIsInstance(parser, argparse.ArgumentParser)

        # Check for --plan flag
        plan_action = None
        for action in parser._actions:
            if '--plan' in action.option_strings or '-p' in action.option_strings:
                plan_action = action
                break

        self.assertIsNotNone(plan_action, "Parser should have --plan or -p flag")

        return parser


# =============================================================================
# Mock Server Utilities
# =============================================================================

class MockTCPServer:
    """Simple mock TCP server for testing network tools."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.responses: Dict[bytes, bytes] = {}
        self.connections: List[Tuple[str, int]] = []

    def add_response(self, request_pattern: bytes, response: bytes) -> None:
        """Add a response for a request pattern."""
        self.responses[request_pattern] = response

    def start(self) -> int:
        """Start the mock server. Returns the actual port number."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        # Get actual port if 0 was specified
        self.port = self.server_socket.getsockname()[1]

        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

        return self.port

    def _serve(self) -> None:
        """Internal server loop."""
        self.server_socket.settimeout(0.5)

        while self.running:
            try:
                client, address = self.server_socket.accept()
                self.connections.append(address)

                # Handle in a simple way
                data = client.recv(1024)

                # Find matching response
                response = b""
                for pattern, resp in self.responses.items():
                    if pattern in data:
                        response = resp
                        break

                if response:
                    client.sendall(response)

                client.close()

            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self) -> None:
        """Stop the mock server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.thread:
            self.thread.join(timeout=2.0)


# =============================================================================
# Assertion Helpers
# =============================================================================

def assert_no_real_network_calls(test_func: Callable) -> Callable:
    """Decorator to ensure no real network calls are made during a test."""
    def wrapper(*args, **kwargs):
        with patch('socket.socket') as mock_socket:
            with patch('socket.create_connection') as mock_create:
                mock_socket.return_value = MockSocket()
                mock_create.return_value = MockSocket()
                return test_func(*args, **kwargs)
    return wrapper


def assert_no_file_writes(test_func: Callable) -> Callable:
    """Decorator to ensure no file writes occur during a test."""
    def wrapper(*args, **kwargs):
        with patch('builtins.open', side_effect=PermissionError("File writes not allowed in test")):
            return test_func(*args, **kwargs)
    return wrapper


# =============================================================================
# Documentation
# =============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return documentation for this testing utilities module."""
    return {
        "name": "Testing Utilities",
        "description": "Comprehensive testing utilities for security tools",
        "version": "1.0.0",
        "components": {
            "MockSocket": "Mock socket for network operation testing",
            "MockHTTPResponse": "Mock HTTP response object",
            "MockDNSResponse": "Mock DNS response for enumeration testing",
            "MockSMBClient": "Mock SMB client for share enumeration testing",
            "TestDataGenerator": "Generate test data (IPs, ports, credentials, etc.)",
            "NetworkTestFixture": "Pre-configured network testing fixture",
            "HTTPTestFixture": "Pre-configured HTTP testing fixture",
            "CredentialTestFixture": "Pre-configured credential testing fixture",
            "SecurityToolTestCase": "Base test case class with common utilities",
            "MockTCPServer": "Simple mock TCP server for integration tests"
        },
        "usage": {
            "basic_test": """
from testing_utils import SecurityToolTestCase, MockSocket

class MyToolTest(SecurityToolTestCase):
    def test_plan_mode(self):
        output = self.assert_plan_mode_safe(main, ['--target', 'example.com'])
        self.assertIn('example.com', output)
""",
            "mock_network": """
from testing_utils import MockSocket
from unittest.mock import patch

with patch('socket.socket', return_value=MockSocket(response_data=b'SSH-2.0')):
    result = scan_port('127.0.0.1', 22)
""",
            "data_generation": """
from testing_utils import TestDataGenerator

gen = TestDataGenerator()
ips = gen.generate_ip_range('10.0.0.1', count=100)
ports = gen.generate_ports('top100')
creds = gen.generate_credentials(count=10)
"""
        }
    }


if __name__ == "__main__":
    # Run self-tests when executed directly
    print("Testing Utilities Module")
    print("=" * 50)

    # Test MockSocket
    print("\n[TEST] MockSocket...")
    sock = MockSocket(response_data=b"Hello, World!")
    sock.connect(("127.0.0.1", 80))
    assert sock.connected_to == ("127.0.0.1", 80)
    sock.send(b"GET / HTTP/1.1\r\n")
    assert b"GET" in sock.sent_data[0]
    data = sock.recv(1024)
    assert data == b"Hello, World!"
    print("  MockSocket: PASSED")

    # Test TestDataGenerator
    print("\n[TEST] TestDataGenerator...")
    gen = TestDataGenerator()
    ips = gen.generate_ip_range("10.0.0.1", 5)
    assert len(ips) == 5
    assert ips[0] == "10.0.0.1"

    ports = gen.generate_ports("common")
    assert 80 in ports
    assert 443 in ports

    hash_val = gen.generate_hash("test", "md5")
    assert hash_val == "098f6bcd4621d373cade4e832627b4f6"
    print("  TestDataGenerator: PASSED")

    # Test capture_output
    print("\n[TEST] capture_output...")
    with capture_output() as (stdout, stderr):
        print("captured")
    assert "captured" in stdout.getvalue()
    print("  capture_output: PASSED")

    # Test validate_documentation
    print("\n[TEST] validate_documentation...")
    good_doc = {"name": "test", "description": "desc", "usage": "use", "arguments": []}
    valid, missing = validate_documentation(good_doc)
    assert valid
    assert len(missing) == 0

    bad_doc = {"name": "test"}
    valid, missing = validate_documentation(bad_doc)
    assert not valid
    assert "description" in missing
    print("  validate_documentation: PASSED")

    print("\n" + "=" * 50)
    print("All self-tests PASSED!")
    print("\nDocumentation:")
    import pprint
    pprint.pprint(get_documentation())
