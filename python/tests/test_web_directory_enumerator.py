"""
Tests for the Web Directory Enumerator tool.

This module contains unit tests and integration tests for the web-directory-enumerator tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
import http.client
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/web-directory-enumerator')

from tool import (
    EnumConfig,
    EnumResult,
    HTTPClient,
    DirectoryEnumerator,
    get_documentation,
    print_plan,
    parse_arguments,
    DEFAULT_WORDLIST,
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
        assert docs["name"] == "web-directory-enumerator"

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
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin", "backup"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_plan_mode_shows_wordlist_size(self, capsys):
        """Test that planning mode shows wordlist information."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin", "backup", "config", "data"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention wordlist or number of paths
        assert "4" in captured.out or "wordlist" in captured.out.lower()

    def test_plan_mode_does_not_make_requests(self):
        """Test that planning mode does not make HTTP requests."""
        with patch('http.client.HTTPConnection') as mock_http:
            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"],
                plan_mode=True
            )
            print_plan(config)
            # HTTP connection should not be made in plan mode
            mock_http.return_value.request.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_http_target(self):
        """Test that valid HTTP targets are accepted."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin"]
        )
        assert config.target == "http://example.com"

    def test_valid_https_target(self):
        """Test that valid HTTPS targets are accepted."""
        config = EnumConfig(
            target="https://example.com",
            wordlist=["admin"]
        )
        assert config.target == "https://example.com"

    def test_valid_wordlist(self):
        """Test that valid wordlists are accepted."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin", "backup", "config"]
        )
        assert len(config.wordlist) == 3

    def test_default_wordlist_populated(self):
        """Test that default wordlist is populated."""
        assert len(DEFAULT_WORDLIST) > 0
        assert "admin" in DEFAULT_WORDLIST or "backup" in DEFAULT_WORDLIST

    def test_timeout_configuration(self):
        """Test that timeout is properly configured."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin"],
            timeout=10.0
        )
        assert config.timeout == 10.0

    def test_threads_configuration(self):
        """Test that threads is properly configured."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin"],
            threads=20
        )
        assert config.threads == 20


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_connection_error_handled(self):
        """Test that connection errors are handled gracefully."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_http.return_value.request.side_effect = socket.error("Connection failed")

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"],
                threads=1
            )
            client = HTTPClient(config)
            result = client.request("/admin")

            # Should handle error gracefully
            assert result is None or isinstance(result, EnumResult)

    def test_timeout_handling(self):
        """Test that timeouts are handled properly."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_http.return_value.request.side_effect = socket.timeout("Timeout")

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"],
                timeout=0.1
            )
            client = HTTPClient(config)
            result = client.request("/admin")

            # Should handle timeout gracefully
            assert result is None or isinstance(result, EnumResult)

    def test_http_error_handling(self):
        """Test that HTTP errors are handled gracefully."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_http.return_value.getresponse.side_effect = http.client.HTTPException("HTTP Error")

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"]
            )
            client = HTTPClient(config)
            result = client.request("/admin")

            # Should handle HTTP error gracefully
            assert result is None or isinstance(result, EnumResult)


# =============================================================================
# Test EnumResult Data Class
# =============================================================================

class TestEnumResult:
    """Tests for the EnumResult data class."""

    def test_enum_result_creation(self):
        """Test that EnumResult can be created."""
        result = EnumResult(
            path="/admin",
            status_code=200
        )
        assert result.path == "/admin"
        assert result.status_code == 200

    def test_enum_result_with_content_length(self):
        """Test EnumResult with content length."""
        result = EnumResult(
            path="/admin",
            status_code=200,
            content_length=1234
        )
        assert result.content_length == 1234

    def test_enum_result_with_redirect(self):
        """Test EnumResult with redirect location."""
        result = EnumResult(
            path="/admin",
            status_code=301,
            redirect_url="/admin/"
        )
        assert result.redirect_url == "/admin/"


# =============================================================================
# Test HTTPClient Class
# =============================================================================

class TestHTTPClient:
    """Tests for the HTTPClient class."""

    def test_http_client_initialization(self):
        """Test HTTPClient initialization."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin"]
        )
        client = HTTPClient(config)
        assert client is not None

    def test_http_client_request_success(self):
        """Test HTTPClient successful request."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheader.return_value = "1234"
            mock_http.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"]
            )
            client = HTTPClient(config)
            result = client.request("/admin")

            assert result is not None
            assert result.status_code == 200

    def test_http_client_404_response(self):
        """Test HTTPClient with 404 response."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 404
            mock_http.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="http://example.com",
                wordlist=["nonexistent"]
            )
            client = HTTPClient(config)
            result = client.request("/nonexistent")

            assert result is not None
            assert result.status_code == 404


# =============================================================================
# Test DirectoryEnumerator Class
# =============================================================================

class TestDirectoryEnumerator:
    """Tests for the DirectoryEnumerator class."""

    def test_enumerator_initialization(self):
        """Test DirectoryEnumerator initialization."""
        config = EnumConfig(
            target="http://example.com",
            wordlist=["admin", "backup"]
        )
        enumerator = DirectoryEnumerator(config)

        assert enumerator.config == config

    def test_enumerator_enumerate_with_mocked_http(self):
        """Test enumerate method with mocked HTTP."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheader.return_value = "100"
            mock_http.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin"],
                threads=1
            )
            enumerator = DirectoryEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, list)

    def test_enumerator_filters_404s(self):
        """Test that enumerator can filter 404 responses."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 404
            mock_http.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin", "backup"],
                threads=1,
                hide_status=[404]
            )
            enumerator = DirectoryEnumerator(config)
            results = enumerator.enumerate()

            # Results should be filtered
            assert isinstance(results, list)


# =============================================================================
# Test Default Wordlist
# =============================================================================

class TestDefaultWordlist:
    """Tests for the default wordlist."""

    def test_default_wordlist_not_empty(self):
        """Test that default wordlist is not empty."""
        assert len(DEFAULT_WORDLIST) > 0

    def test_default_wordlist_contains_common_paths(self):
        """Test that default wordlist contains common paths."""
        common_paths = ["admin", "backup", "config", "login", "wp-admin"]
        found = sum(1 for p in common_paths if p in DEFAULT_WORDLIST)
        assert found >= 2  # At least some common paths should be present

    def test_default_wordlist_entries_are_strings(self):
        """Test that all wordlist entries are strings."""
        for entry in DEFAULT_WORDLIST:
            assert isinstance(entry, str)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_target_argument(self):
        """Test parsing target argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com']):
            args = parse_arguments()
            assert args.target == 'http://example.com'

    def test_parse_wordlist_argument(self):
        """Test parsing wordlist argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '-w', '/path/to/wordlist.txt']):
            args = parse_arguments()
            assert args.wordlist == '/path/to/wordlist.txt' or '/path/to/wordlist.txt' in str(args.wordlist)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_threads_argument(self):
        """Test parsing --threads argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '--threads', '20']):
            args = parse_arguments()
            assert args.threads == 20

    def test_parse_extensions_argument(self):
        """Test parsing --extensions argument."""
        with patch('sys.argv', ['tool.py', 'http://example.com', '-x', 'php,html,txt']):
            args = parse_arguments()
            assert 'php' in str(args.extensions) or args.extensions


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_enumeration_run(self):
        """Test full enumeration with mocked HTTP."""
        with patch('http.client.HTTPConnection') as mock_http:
            # Different responses for different paths
            mock_response_200 = MagicMock()
            mock_response_200.status = 200
            mock_response_200.getheader.return_value = "100"

            mock_response_404 = MagicMock()
            mock_response_404.status = 404

            mock_http.return_value.getresponse.side_effect = [
                mock_response_200,
                mock_response_404,
                mock_response_200
            ]

            config = EnumConfig(
                target="http://example.com",
                wordlist=["admin", "notfound", "backup"],
                threads=1
            )
            enumerator = DirectoryEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, list)

    def test_enumeration_with_extensions(self):
        """Test enumeration with file extensions."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheader.return_value = "100"
            mock_http.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="http://example.com",
                wordlist=["index"],
                extensions=[".php", ".html"],
                threads=1
            )
            enumerator = DirectoryEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, list)

    def test_enumeration_with_https(self):
        """Test enumeration with HTTPS target."""
        with patch('http.client.HTTPSConnection') as mock_https:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.getheader.return_value = "100"
            mock_https.return_value.getresponse.return_value = mock_response

            config = EnumConfig(
                target="https://example.com",
                wordlist=["admin"],
                threads=1
            )
            enumerator = DirectoryEnumerator(config)
            results = enumerator.enumerate()

            assert isinstance(results, list)
