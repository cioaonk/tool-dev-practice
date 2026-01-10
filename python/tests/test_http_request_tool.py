"""
Tests for the HTTP Request Tool.

This module contains unit tests and integration tests for the http-request-tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
import ssl
import http.client
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/http-request-tool')

from tool import (
    HTTPRequest,
    HTTPResponse,
    RequestConfig,
    HTTPClient,
    get_documentation,
    print_plan,
    parse_arguments,
)


# =============================================================================
# Test get_documentation()
# =============================================================================

class TestGetDocumentation:
    """Tests for the get_documentation function."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        docs = get_documentation()
        assert isinstance(docs, dict)

    def test_get_documentation_has_required_keys(self):
        """Test that documentation contains all required keys."""
        docs = get_documentation()
        required_keys = ["name", "version", "description"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "http-request-tool"

    def test_get_documentation_has_arguments(self):
        """Test that documentation includes argument definitions."""
        docs = get_documentation()
        assert "arguments" in docs
        assert isinstance(docs["arguments"], dict)

    def test_get_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        docs = get_documentation()
        assert "examples" in docs
        assert isinstance(docs["examples"], list)


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = RequestConfig(
            url="http://example.com",
            method="GET",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_url_info(self, capsys):
        """Test that planning mode shows URL information."""
        config = RequestConfig(
            url="http://example.com/api/test",
            method="GET",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_plan_mode_shows_method(self, capsys):
        """Test that planning mode shows HTTP method."""
        config = RequestConfig(
            url="http://example.com",
            method="POST",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "POST" in captured.out

    def test_plan_mode_does_not_make_request(self):
        """Test that planning mode does not make HTTP requests."""
        with patch('http.client.HTTPConnection') as mock_http:
            config = RequestConfig(
                url="http://example.com",
                method="GET",
                plan_mode=True
            )
            print_plan(config)
            # HTTP request should not be made in plan mode
            mock_http.return_value.request.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_http_url(self):
        """Test that valid HTTP URLs are accepted."""
        config = RequestConfig(url="http://example.com", method="GET")
        assert config.url == "http://example.com"

    def test_valid_https_url(self):
        """Test that valid HTTPS URLs are accepted."""
        config = RequestConfig(url="https://example.com", method="GET")
        assert config.url == "https://example.com"

    def test_valid_get_method(self):
        """Test GET method is accepted."""
        config = RequestConfig(url="http://example.com", method="GET")
        assert config.method == "GET"

    def test_valid_post_method(self):
        """Test POST method is accepted."""
        config = RequestConfig(url="http://example.com", method="POST")
        assert config.method == "POST"

    def test_valid_put_method(self):
        """Test PUT method is accepted."""
        config = RequestConfig(url="http://example.com", method="PUT")
        assert config.method == "PUT"

    def test_valid_delete_method(self):
        """Test DELETE method is accepted."""
        config = RequestConfig(url="http://example.com", method="DELETE")
        assert config.method == "DELETE"

    def test_valid_headers(self):
        """Test that headers are properly configured."""
        config = RequestConfig(
            url="http://example.com",
            method="GET",
            headers={"Authorization": "Bearer token123"}
        )
        assert "Authorization" in config.headers

    def test_valid_body(self):
        """Test that request body is properly configured."""
        config = RequestConfig(
            url="http://example.com",
            method="POST",
            body='{"key": "value"}'
        )
        assert config.body == '{"key": "value"}'


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_connection_error_handled(self):
        """Test that connection errors are handled gracefully."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_http.return_value.request.side_effect = socket.error("Connection failed")

            config = RequestConfig(url="http://example.com", method="GET")
            client = HTTPClient(config)
            response = client.send_request()

            # Should handle error gracefully
            assert response is None or isinstance(response, HTTPResponse)

    def test_timeout_handling(self):
        """Test that timeouts are handled properly."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_http.return_value.request.side_effect = socket.timeout("Timeout")

            config = RequestConfig(
                url="http://example.com",
                method="GET",
                timeout=0.1
            )
            client = HTTPClient(config)
            response = client.send_request()

            # Should handle timeout gracefully
            assert response is None or isinstance(response, HTTPResponse)

    def test_ssl_error_handling(self):
        """Test that SSL errors are handled gracefully."""
        with patch('http.client.HTTPSConnection') as mock_https:
            mock_https.return_value.request.side_effect = ssl.SSLError("SSL Error")

            config = RequestConfig(url="https://example.com", method="GET")
            client = HTTPClient(config)
            response = client.send_request()

            # Should handle SSL error gracefully
            assert response is None or isinstance(response, HTTPResponse)


# =============================================================================
# Test HTTPRequest Data Class
# =============================================================================

class TestHTTPRequest:
    """Tests for the HTTPRequest data class."""

    def test_http_request_creation(self):
        """Test that HTTPRequest can be created."""
        request = HTTPRequest(
            method="GET",
            url="http://example.com",
            headers={}
        )
        assert request.method == "GET"
        assert request.url == "http://example.com"

    def test_http_request_with_body(self):
        """Test HTTPRequest with body."""
        request = HTTPRequest(
            method="POST",
            url="http://example.com",
            headers={"Content-Type": "application/json"},
            body='{"data": "test"}'
        )
        assert request.body == '{"data": "test"}'


# =============================================================================
# Test HTTPResponse Data Class
# =============================================================================

class TestHTTPResponse:
    """Tests for the HTTPResponse data class."""

    def test_http_response_creation(self):
        """Test that HTTPResponse can be created."""
        response = HTTPResponse(
            status_code=200,
            headers={},
            body=""
        )
        assert response.status_code == 200

    def test_http_response_with_headers(self):
        """Test HTTPResponse with headers."""
        response = HTTPResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html></html>"
        )
        assert "Content-Type" in response.headers

    def test_http_response_with_body(self):
        """Test HTTPResponse with body."""
        response = HTTPResponse(
            status_code=200,
            headers={},
            body="Response body content"
        )
        assert response.body == "Response body content"


# =============================================================================
# Test HTTPClient Class
# =============================================================================

class TestHTTPClient:
    """Tests for the HTTPClient class."""

    def test_client_initialization(self):
        """Test HTTPClient initialization."""
        config = RequestConfig(url="http://example.com", method="GET")
        client = HTTPClient(config)
        assert client is not None

    def test_client_get_request(self):
        """Test HTTPClient GET request."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheaders.return_value = [("Content-Type", "text/html")]
            mock_response.read.return_value = b"<html></html>"
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(url="http://example.com", method="GET")
            client = HTTPClient(config)
            response = client.send_request()

            assert response is not None
            assert response.status_code == 200

    def test_client_post_request(self):
        """Test HTTPClient POST request."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 201
            mock_response.getheaders.return_value = []
            mock_response.read.return_value = b'{"created": true}'
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(
                url="http://example.com/api",
                method="POST",
                body='{"data": "test"}',
                headers={"Content-Type": "application/json"}
            )
            client = HTTPClient(config)
            response = client.send_request()

            assert response is not None
            assert response.status_code == 201

    def test_client_https_request(self):
        """Test HTTPClient HTTPS request."""
        with patch('http.client.HTTPSConnection') as mock_https:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheaders.return_value = []
            mock_response.read.return_value = b"Secure content"
            mock_https.return_value.getresponse.return_value = mock_response

            config = RequestConfig(url="https://example.com", method="GET")
            client = HTTPClient(config)
            response = client.send_request()

            assert response is not None


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_url_argument(self):
        """Test parsing URL argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com']):
            args = parse_arguments()
            assert args.url == 'http://example.com'

    def test_parse_method_argument(self):
        """Test parsing method argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '-X', 'POST']):
            args = parse_arguments()
            assert args.method == 'POST'

    def test_parse_header_argument(self):
        """Test parsing header argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '-H', 'Authorization: Bearer token']):
            args = parse_arguments()
            # Headers should be captured
            assert 'Authorization' in str(args.headers) or args.header

    def test_parse_data_argument(self):
        """Test parsing data argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '-d', '{"key":"value"}']):
            args = parse_arguments()
            assert args.data == '{"key":"value"}' or '{"key":"value"}' in str(args.data)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_timeout_argument(self):
        """Test parsing --timeout argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '--timeout', '30']):
            args = parse_arguments()
            assert args.timeout == 30


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_get_request(self):
        """Test full GET request with mocked network."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheaders.return_value = [
                ("Content-Type", "text/html"),
                ("Content-Length", "100")
            ]
            mock_response.read.return_value = b"<html><body>Test</body></html>"
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(
                url="http://example.com/page",
                method="GET",
                headers={"User-Agent": "TestClient/1.0"}
            )
            client = HTTPClient(config)
            response = client.send_request()

            assert response.status_code == 200
            assert "<html>" in response.body

    def test_full_post_request_with_json(self):
        """Test full POST request with JSON body."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 201
            mock_response.getheaders.return_value = [
                ("Content-Type", "application/json")
            ]
            mock_response.read.return_value = b'{"id": 123, "status": "created"}'
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(
                url="http://example.com/api/items",
                method="POST",
                headers={"Content-Type": "application/json"},
                body='{"name": "test item"}'
            )
            client = HTTPClient(config)
            response = client.send_request()

            assert response.status_code == 201

    def test_request_with_custom_headers(self):
        """Test request with custom headers."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheaders.return_value = []
            mock_response.read.return_value = b"OK"
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(
                url="http://example.com/api",
                method="GET",
                headers={
                    "Authorization": "Bearer token123",
                    "X-Custom-Header": "custom-value"
                }
            )
            client = HTTPClient(config)
            response = client.send_request()

            assert response is not None

    def test_redirect_handling(self):
        """Test handling of redirects."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 301
            mock_response.getheaders.return_value = [
                ("Location", "http://example.com/new-location")
            ]
            mock_response.read.return_value = b""
            mock_http.return_value.getresponse.return_value = mock_response

            config = RequestConfig(
                url="http://example.com/old-page",
                method="GET",
                follow_redirects=False
            )
            client = HTTPClient(config)
            response = client.send_request()

            assert response.status_code == 301
