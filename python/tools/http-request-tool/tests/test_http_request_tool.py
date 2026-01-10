#!/usr/bin/env python3
"""
Test Suite for HTTP Request Tool
=================================

Comprehensive tests for the HTTP request tool including
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
    HTTPRequest,
    HTTPResponse,
    RequestConfig,
    HTTPClient,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    DEFAULT_USER_AGENT
)


class TestHTTPRequest(unittest.TestCase):
    """Tests for HTTPRequest dataclass."""

    def test_request_creation(self):
        """Test creating an HTTPRequest instance."""
        request = HTTPRequest(
            method="POST",
            url="http://example.com/api",
            body='{"key": "value"}'
        )

        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, "http://example.com/api")
        self.assertIsNotNone(request.body)

    def test_request_defaults(self):
        """Test request default values."""
        request = HTTPRequest()

        self.assertEqual(request.method, "GET")
        self.assertEqual(request.timeout, DEFAULT_TIMEOUT)
        self.assertFalse(request.follow_redirects)
        self.assertFalse(request.verify_ssl)

    def test_request_headers(self):
        """Test request with custom headers."""
        request = HTTPRequest(
            url="http://test.com",
            headers={
                "Authorization": "Bearer token123",
                "Content-Type": "application/json"
            }
        )

        self.assertIn("Authorization", request.headers)
        self.assertEqual(len(request.headers), 2)


class TestHTTPResponse(unittest.TestCase):
    """Tests for HTTPResponse dataclass."""

    def test_response_creation(self):
        """Test creating an HTTPResponse instance."""
        response = HTTPResponse(
            status_code=200,
            status_reason="OK",
            headers={"Content-Type": "text/html"},
            body=b"<html>Test</html>",
            response_time=0.5
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.status_reason, "OK")
        self.assertEqual(response.response_time, 0.5)

    def test_response_to_dict(self):
        """Test serialization to dictionary."""
        response = HTTPResponse(
            status_code=404,
            status_reason="Not Found",
            headers={},
            body=b"Not found",
            response_time=0.2
        )

        data = response.to_dict()

        self.assertIn("status_code", data)
        self.assertIn("body_length", data)
        self.assertEqual(data["body_length"], 9)

    def test_response_with_redirects(self):
        """Test response with redirect chain."""
        response = HTTPResponse(
            status_code=200,
            status_reason="OK",
            headers={},
            body=b"Final",
            response_time=1.0,
            redirects=["http://a.com", "http://b.com", "http://c.com"]
        )

        self.assertEqual(len(response.redirects), 3)


class TestRequestConfig(unittest.TestCase):
    """Tests for RequestConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = RequestConfig()

        self.assertEqual(config.method, "GET")
        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertFalse(config.plan_mode)
        self.assertTrue(config.show_headers)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = RequestConfig(
            url="https://api.example.com/endpoint",
            method="POST",
            headers={"X-Custom": "value"},
            data='{"test": true}',
            timeout=60.0,
            plan_mode=True
        )

        self.assertEqual(config.url, "https://api.example.com/endpoint")
        self.assertEqual(config.method, "POST")
        self.assertTrue(config.plan_mode)


class TestHTTPClient(unittest.TestCase):
    """Tests for HTTPClient class."""

    def test_client_creation(self):
        """Test HTTP client can be created."""
        config = RequestConfig(url="http://example.com")
        client = HTTPClient(config)

        self.assertIsNotNone(client)
        self.assertEqual(client.host, "example.com")

    def test_client_url_parsing_http(self):
        """Test HTTP URL parsing."""
        config = RequestConfig(url="http://example.com/path")
        client = HTTPClient(config)

        self.assertEqual(client.host, "example.com")
        self.assertEqual(client.port, 80)
        self.assertFalse(client.use_ssl)

    def test_client_url_parsing_https(self):
        """Test HTTPS URL parsing."""
        config = RequestConfig(url="https://secure.example.com/api")
        client = HTTPClient(config)

        self.assertEqual(client.host, "secure.example.com")
        self.assertEqual(client.port, 443)
        self.assertTrue(client.use_ssl)

    def test_client_url_parsing_custom_port(self):
        """Test URL parsing with custom port."""
        config = RequestConfig(url="http://example.com:8080/app")
        client = HTTPClient(config)

        self.assertEqual(client.host, "example.com")
        self.assertEqual(client.port, 8080)

    def test_client_url_parsing_query_string(self):
        """Test URL parsing with query string."""
        config = RequestConfig(url="http://example.com/search?q=test&page=1")
        client = HTTPClient(config)

        self.assertIn("q=test", client.path)


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

    def test_documentation_name(self):
        """Test documentation name."""
        doc = get_documentation()
        self.assertIn("http", doc["name"].lower())


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

    def test_parser_method_argument(self):
        """Test parser accepts method argument."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--url', 'http://example.com',
            '--method', 'POST'
        ])

        self.assertEqual(args.method, 'POST')

    def test_parser_header_argument(self):
        """Test parser accepts header argument."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--url', 'http://example.com',
            '--header', 'X-Custom: value'
        ])

        self.assertIsNotNone(args.header)


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = RequestConfig(
            url="http://example.com/api",
            method="POST",
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
        """Test that plan output shows URL."""
        config = RequestConfig(
            url="http://example.com/test",
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

    def test_plan_mode_shows_method(self):
        """Test that plan shows HTTP method."""
        config = RequestConfig(
            url="http://example.com",
            method="DELETE",
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("DELETE", output)


class TestConstants(unittest.TestCase):
    """Tests for module constants."""

    def test_default_timeout(self):
        """Test default timeout constant."""
        self.assertEqual(DEFAULT_TIMEOUT, 30.0)

    def test_default_user_agent(self):
        """Test default user agent constant."""
        self.assertIn("Mozilla", DEFAULT_USER_AGENT)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_url_error(self):
        """Test error handling for missing URL."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])


# =============================================================================
# Test Fixtures
# =============================================================================

class HTTPRequestToolFixtures:
    """Test fixtures for HTTP request tool."""

    # Sample responses
    RESPONSES = {
        "success": HTTPResponse(
            status_code=200,
            status_reason="OK",
            headers={"Content-Type": "application/json"},
            body=b'{"status": "success"}',
            response_time=0.5
        ),
        "not_found": HTTPResponse(
            status_code=404,
            status_reason="Not Found",
            headers={"Content-Type": "text/html"},
            body=b"Not Found",
            response_time=0.2
        ),
        "server_error": HTTPResponse(
            status_code=500,
            status_reason="Internal Server Error",
            headers={},
            body=b"Error",
            response_time=0.1
        )
    }

    # Common HTTP methods
    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    @classmethod
    def get_response(cls, response_type: str) -> HTTPResponse:
        """Get a predefined response."""
        return cls.RESPONSES.get(response_type, cls.RESPONSES["not_found"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
