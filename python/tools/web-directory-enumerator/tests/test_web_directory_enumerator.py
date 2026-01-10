#!/usr/bin/env python3
"""
Test Suite for Web Directory Enumerator
========================================

Comprehensive tests for the web directory enumeration tool including
plan mode, documentation, and mock HTTP operations.
"""

import sys
import unittest
from unittest.mock import Mock, MagicMock, patch
from io import StringIO
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tool import (
    DirectoryResult,
    EnumConfig,
    StatusCategory,
    HTTPClient,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS,
    DEFAULT_WORDLIST,
    COMMON_EXTENSIONS
)


class TestDirectoryResult(unittest.TestCase):
    """Tests for DirectoryResult dataclass."""

    def test_result_creation(self):
        """Test creating a DirectoryResult instance."""
        result = DirectoryResult(
            url="http://example.com/admin",
            path="/admin",
            status_code=200,
            content_length=1234
        )

        self.assertEqual(result.url, "http://example.com/admin")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content_length, 1234)

    def test_status_category_success(self):
        """Test success status category."""
        result = DirectoryResult(
            url="http://test.com/",
            path="/",
            status_code=200,
            content_length=100
        )

        self.assertEqual(result.status_category, StatusCategory.SUCCESS)

    def test_status_category_redirect(self):
        """Test redirect status category."""
        result = DirectoryResult(
            url="http://test.com/old",
            path="/old",
            status_code=301,
            content_length=0
        )

        self.assertEqual(result.status_category, StatusCategory.REDIRECT)

    def test_status_category_client_error(self):
        """Test client error status category."""
        result = DirectoryResult(
            url="http://test.com/notfound",
            path="/notfound",
            status_code=404,
            content_length=0
        )

        self.assertEqual(result.status_category, StatusCategory.CLIENT_ERROR)

    def test_status_category_server_error(self):
        """Test server error status category."""
        result = DirectoryResult(
            url="http://test.com/error",
            path="/error",
            status_code=500,
            content_length=0
        )

        self.assertEqual(result.status_category, StatusCategory.SERVER_ERROR)

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = DirectoryResult(
            url="http://test.com/api",
            path="/api",
            status_code=200,
            content_length=500,
            interesting=True
        )

        data = result.to_dict()
        self.assertIn("url", data)
        self.assertIn("status_code", data)
        self.assertTrue(data["interesting"])


class TestEnumConfig(unittest.TestCase):
    """Tests for EnumConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = EnumConfig()

        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.threads, DEFAULT_THREADS)
        self.assertEqual(config.plan_mode, False)
        self.assertEqual(config.follow_redirects, False)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = EnumConfig(
            target_url="http://example.com",
            wordlist=["admin", "login", "api"],
            timeout=15.0,
            threads=20,
            plan_mode=True
        )

        self.assertEqual(config.target_url, "http://example.com")
        self.assertEqual(len(config.wordlist), 3)
        self.assertTrue(config.plan_mode)

    def test_config_status_codes(self):
        """Test default status codes."""
        config = EnumConfig()

        self.assertIn(200, config.status_codes)
        self.assertIn(403, config.status_codes)


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

    def test_documentation_name_matches_tool(self):
        """Test that documentation name matches tool."""
        doc = get_documentation()
        self.assertIn("directory", doc["name"].lower())


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

    def test_parser_url_argument(self):
        """Test parser has URL argument."""
        parser = create_argument_parser()
        args = parser.parse_args(['--url', 'http://example.com'])

        self.assertEqual(args.url, 'http://example.com')

    def test_parser_wordlist_argument(self):
        """Test parser accepts wordlist."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--url', 'http://example.com',
            '--wordlist', '/path/to/wordlist.txt'
        ])

        self.assertEqual(args.wordlist, '/path/to/wordlist.txt')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = EnumConfig(
            target_url="http://example.com",
            wordlist=["admin", "login", "api"],
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

    def test_plan_mode_shows_url(self):
        """Test that plan output shows target URL."""
        config = EnumConfig(
            target_url="http://example.com",
            wordlist=["admin"],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("example.com", output)

    def test_plan_mode_shows_path_count(self):
        """Test that plan output shows number of paths."""
        config = EnumConfig(
            target_url="http://example.com",
            wordlist=["admin", "login", "api", "config", "backup"],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        # Should mention paths or wordlist entries
        self.assertTrue("path" in output.lower() or "5" in output)


class TestHTTPClient(unittest.TestCase):
    """Tests for HTTP client."""

    def test_client_creation(self):
        """Test HTTP client can be created."""
        config = EnumConfig(target_url="http://example.com")
        client = HTTPClient(config)

        self.assertIsNotNone(client)

    def test_client_url_parsing(self):
        """Test HTTP client URL parsing."""
        config = EnumConfig(target_url="https://example.com:8443/app")
        client = HTTPClient(config)

        self.assertEqual(client.host, "example.com")
        self.assertEqual(client.port, 8443)
        self.assertTrue(client.use_ssl)


class TestDefaultWordlist(unittest.TestCase):
    """Tests for default wordlist."""

    def test_default_wordlist_not_empty(self):
        """Test default wordlist has entries."""
        self.assertTrue(len(DEFAULT_WORDLIST) > 0)

    def test_default_wordlist_has_common_paths(self):
        """Test default wordlist has common paths."""
        self.assertIn("admin", DEFAULT_WORDLIST)
        self.assertIn("login", DEFAULT_WORDLIST)
        self.assertIn("api", DEFAULT_WORDLIST)

    def test_common_extensions(self):
        """Test common extensions list."""
        self.assertIn(".php", COMMON_EXTENSIONS)
        self.assertIn(".html", COMMON_EXTENSIONS)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_url_error(self):
        """Test error handling for missing URL."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])

    def test_invalid_url_format(self):
        """Test handling of invalid URL formats."""
        parser = create_argument_parser()

        # Parser should accept any string, validation happens later
        args = parser.parse_args(['--url', 'not-a-valid-url'])
        self.assertEqual(args.url, 'not-a-valid-url')


# =============================================================================
# Test Fixtures
# =============================================================================

class WebDirectoryEnumeratorFixtures:
    """Test fixtures for web directory enumerator."""

    # Sample HTTP responses
    RESPONSES = {
        200: {"status": "OK", "body": "<html><body>Content</body></html>"},
        301: {"status": "Moved Permanently", "body": ""},
        403: {"status": "Forbidden", "body": "Access Denied"},
        404: {"status": "Not Found", "body": "Page not found"},
        500: {"status": "Internal Server Error", "body": "Error"}
    }

    # Interesting paths
    INTERESTING_PATHS = [
        "/admin", "/wp-admin", "/.git", "/.env",
        "/backup", "/config.php", "/database.sql"
    ]

    # Common wordlist
    WORDLIST = [
        "admin", "login", "dashboard", "config", "backup",
        "api", "v1", "v2", "test", "dev", "staging"
    ]

    @classmethod
    def get_mock_response(cls, status_code: int):
        """Get a mock HTTP response."""
        mock = MagicMock()
        resp = cls.RESPONSES.get(status_code, cls.RESPONSES[404])
        mock.status = status_code
        mock.reason = resp["status"]
        mock.read.return_value = resp["body"].encode()
        mock.getheaders.return_value = [("Content-Type", "text/html")]
        return mock


if __name__ == '__main__':
    unittest.main(verbosity=2)
