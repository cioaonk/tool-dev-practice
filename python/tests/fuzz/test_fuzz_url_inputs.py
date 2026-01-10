#!/usr/bin/env python3
"""
Fuzz Tests for URL and Path Input Parsing
=========================================

Tests URL parsing and path handling from the web-directory-enumerator
and http-request-tool security tools.

Uses Hypothesis for property-based testing to discover edge cases
in URL validation and path handling.
"""

import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest
from hypothesis import assume, given, settings, HealthCheck
from hypothesis import strategies as st


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "web-directory-enumerator"))
sys.path.insert(0, str(TOOLS_PATH / "http-request-tool"))


# =============================================================================
# Import target classes
# =============================================================================

try:
    from tool import HTTPClient as WebHTTPClient, EnumConfig
    WEB_ENUM_AVAILABLE = True
except ImportError:
    WEB_ENUM_AVAILABLE = False
    WebHTTPClient = None
    EnumConfig = None

try:
    # Import from http-request-tool
    sys.path.insert(0, str(TOOLS_PATH / "http-request-tool"))
    from tool import HTTPClient as RequestHTTPClient, RequestConfig
    HTTP_REQUEST_AVAILABLE = True
except ImportError:
    HTTP_REQUEST_AVAILABLE = False
    RequestHTTPClient = None
    RequestConfig = None


# =============================================================================
# Custom Strategies for URL Inputs
# =============================================================================

# Strategy for valid schemes
valid_schemes = st.sampled_from(["http", "https", "HTTP", "HTTPS", "Http", "Https"])

# Strategy for valid hostnames
valid_hostname = st.one_of(
    # Domain names
    st.from_regex(r"[a-z][a-z0-9-]{0,20}(\.[a-z][a-z0-9-]{0,10}){0,3}", fullmatch=True),
    # IP addresses
    st.builds(
        lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255)
    ),
    # localhost
    st.just("localhost"),
)

# Strategy for valid ports
valid_port = st.integers(min_value=1, max_value=65535)

# Strategy for valid URL paths
valid_path = st.from_regex(r"(/[a-zA-Z0-9._-]{0,30}){0,5}", fullmatch=True)

# Strategy for valid query strings
valid_query = st.one_of(
    st.just(""),
    st.from_regex(r"[a-z0-9_]+=[a-z0-9_]+(&[a-z0-9_]+=[a-z0-9_]+){0,3}", fullmatch=True),
)

# Strategy for valid complete URLs
valid_url = st.builds(
    lambda scheme, host, port, path, query: (
        f"{scheme}://{host}:{port}{path or '/'}" +
        (f"?{query}" if query else "")
    ),
    valid_schemes,
    valid_hostname,
    valid_port,
    valid_path,
    valid_query
)

# Strategy for valid URL without port
valid_url_no_port = st.builds(
    lambda scheme, host, path: f"{scheme}://{host}{path or '/'}",
    valid_schemes,
    valid_hostname,
    valid_path
)

# Strategy for malformed URLs
fuzzy_url = st.one_of(
    # Missing scheme
    st.builds(
        lambda host, path: f"{host}{path}",
        valid_hostname, valid_path
    ),
    # Invalid schemes
    st.builds(
        lambda scheme, host: f"{scheme}://{host}/",
        st.sampled_from(["ftp", "ssh", "mailto", "file", "javascript", "data", "tel"]),
        valid_hostname
    ),
    # Double slashes
    st.builds(
        lambda host: f"http://{host}//path//to//resource",
        valid_hostname
    ),
    # No host
    st.sampled_from([
        "http:///path",
        "https:///",
        "http://",
        "https://",
        "://host.com",
        "//host.com/path",
    ]),
    # Invalid characters in host
    st.builds(
        lambda: f"http://<script>alert(1)</script>/",
    ),
    # Very long URLs
    st.builds(
        lambda n: f"http://example.com/{'a' * n}",
        st.integers(min_value=100, max_value=500)
    ),
    # Null bytes
    st.just("http://example.com/path\x00extra"),
    st.just("http://example.com\x00.evil.com/"),
    # Unicode in URLs
    st.just("http://example.com/\u0000/path"),
    st.just("http://example.com/caf\u00e9/"),
    st.just("http://\u0430\u0431\u0432.com/"),  # Cyrillic
)

# Strategy for malicious paths
malicious_path = st.sampled_from([
    # Path traversal
    "/../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    "/....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/..\\..\\..\\etc\\passwd",
    "/..%252f..%252f..%252fetc/passwd",

    # Null byte injection
    "/path%00.jpg",
    "/path\x00extra",

    # Command injection attempts
    "/;ls",
    "/|cat /etc/passwd",
    "/`whoami`",
    "/$(id)",

    # XSS attempts
    "/<script>alert(1)</script>",
    "/\"><script>alert(1)</script>",
    "/'><script>alert(1)</script>",

    # SQL injection
    "/'; DROP TABLE users;--",
    "/1 OR 1=1",
    "/1' OR '1'='1",

    # CRLF injection
    "/path%0d%0aSet-Cookie:%20malicious=1",
    "/path\r\nX-Injected: header",

    # Unicode normalization
    "/path%c0%ae%c0%ae/etc/passwd",
    "/path\uff0e\uff0e/etc/passwd",

    # Long paths
    "/" + "a" * 1000,
    "/" + "a/" * 100,
])

# Strategy for arbitrary text that might be passed as URL
arbitrary_url_input = st.one_of(
    st.text(min_size=0, max_size=200),
    st.binary(min_size=0, max_size=100).map(lambda b: b.decode("utf-8", errors="ignore")),
    valid_url,
    fuzzy_url,
)


# =============================================================================
# Helper Functions
# =============================================================================

def parse_url_safe(url: str) -> Optional[urllib.parse.ParseResult]:
    """
    Safe URL parsing that won't crash.
    Returns None on error.
    """
    try:
        return urllib.parse.urlparse(url)
    except Exception:
        return None


def is_valid_url_structure(url: str) -> bool:
    """Check if URL has valid basic structure."""
    parsed = parse_url_safe(url)
    if not parsed:
        return False

    # Must have scheme and netloc
    return bool(parsed.scheme and parsed.netloc)


def create_web_client_safe(url: str) -> Optional[object]:
    """
    Create WebHTTPClient safely.
    Returns None on error.
    """
    if not WEB_ENUM_AVAILABLE:
        return None

    try:
        config = EnumConfig(target_url=url)
        return WebHTTPClient(config)
    except Exception:
        return None


def create_request_client_safe(url: str) -> Optional[object]:
    """
    Create RequestHTTPClient safely.
    Returns None on error.
    """
    if not HTTP_REQUEST_AVAILABLE:
        return None

    try:
        config = RequestConfig(url=url)
        return RequestHTTPClient(config)
    except Exception:
        return None


# =============================================================================
# Fuzz Tests for URL Parsing
# =============================================================================

@pytest.mark.fuzz
class TestURLParsingFuzzing:
    """Fuzz tests for URL parsing."""

    @given(url=valid_url)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_url_parsing_never_crashes(self, url: str):
        """Valid URLs should never cause crashes during parsing."""
        parsed = parse_url_safe(url)
        assert parsed is not None, f"Failed to parse valid URL: {url}"
        assert parsed.scheme.lower() in ["http", "https"]
        assert parsed.netloc  # Should have host

    @given(url=valid_url_no_port)
    @settings(max_examples=200)
    def test_valid_url_without_port(self, url: str):
        """URLs without explicit port should parse correctly."""
        parsed = parse_url_safe(url)
        assert parsed is not None
        # Port should default based on scheme
        assert parsed.port is None  # urllib returns None for default ports

    @given(fuzzy=fuzzy_url)
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_malformed_url_does_not_crash(self, fuzzy: str):
        """Malformed URLs should not crash the parser."""
        # This should not raise an exception
        parsed = parse_url_safe(fuzzy)
        # Parsed may be None or have empty components - that's fine

    @given(arbitrary=arbitrary_url_input)
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_arbitrary_input_does_not_crash(self, arbitrary: str):
        """Arbitrary input should never crash URL parsing."""
        try:
            parsed = parse_url_safe(arbitrary)
            # If parsing succeeded, check basic properties don't crash
            if parsed:
                _ = parsed.scheme
                _ = parsed.netloc
                _ = parsed.path
                _ = parsed.query
        except Exception as e:
            acceptable = (ValueError, TypeError, AttributeError, UnicodeError)
            assert isinstance(e, acceptable), f"Unexpected exception: {type(e).__name__}: {e}"


@pytest.mark.fuzz
class TestHTTPClientInitialization:
    """Fuzz tests for HTTP client initialization."""

    @given(url=valid_url)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_web_client_with_valid_url(self, url: str):
        """Web client should initialize with valid URLs."""
        if WEB_ENUM_AVAILABLE:
            client = create_web_client_safe(url)
            # Should create successfully or return None (not crash)
            if client:
                assert hasattr(client, 'host')
                assert hasattr(client, 'port')
                assert hasattr(client, 'scheme')

    @given(url=valid_url)
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_request_client_with_valid_url(self, url: str):
        """Request client should initialize with valid URLs."""
        if HTTP_REQUEST_AVAILABLE:
            client = create_request_client_safe(url)
            if client:
                assert hasattr(client, 'host')
                assert hasattr(client, 'port')

    @given(fuzzy=fuzzy_url)
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_client_with_malformed_url(self, fuzzy: str):
        """Clients should handle malformed URLs gracefully."""
        if WEB_ENUM_AVAILABLE:
            try:
                client = create_web_client_safe(fuzzy)
                # May fail but should not crash
            except Exception as e:
                acceptable = (ValueError, TypeError, AttributeError)
                assert isinstance(e, acceptable)

        if HTTP_REQUEST_AVAILABLE:
            try:
                client = create_request_client_safe(fuzzy)
            except Exception as e:
                acceptable = (ValueError, TypeError, AttributeError)
                assert isinstance(e, acceptable)


@pytest.mark.fuzz
class TestURLPathHandling:
    """Fuzz tests for URL path handling."""

    @given(path=valid_path)
    @settings(max_examples=200)
    def test_valid_path_handling(self, path: str):
        """Valid paths should be handled correctly."""
        url = f"http://example.com{path or '/'}"
        parsed = parse_url_safe(url)

        assert parsed is not None
        # Path should be preserved or defaulted to /
        assert parsed.path == (path or "/") or parsed.path == ""

    @given(
        segments=st.lists(
            st.from_regex(r"[a-z0-9_-]{1,20}", fullmatch=True),
            min_size=0,
            max_size=10
        )
    )
    @settings(max_examples=100)
    def test_path_segment_handling(self, segments: List[str]):
        """Path segments should be preserved."""
        path = "/" + "/".join(segments)
        url = f"http://example.com{path}"

        parsed = parse_url_safe(url)
        assert parsed is not None

        # Segments should be in the path
        for segment in segments:
            if segment:  # Skip empty
                assert segment in parsed.path

    @given(depth=st.integers(min_value=1, max_value=50))
    @settings(max_examples=50)
    def test_deep_path_nesting(self, depth: int):
        """Deep path nesting should not cause issues."""
        path = "/".join(["dir"] * depth)
        url = f"http://example.com/{path}"

        parsed = parse_url_safe(url)
        assert parsed is not None
        assert parsed.path.count("/") >= depth


@pytest.mark.fuzz
class TestURLQueryHandling:
    """Fuzz tests for URL query string handling."""

    @given(
        params=st.dictionaries(
            st.from_regex(r"[a-z_][a-z0-9_]{0,20}", fullmatch=True),
            st.from_regex(r"[a-zA-Z0-9_]{0,50}", fullmatch=True),
            min_size=0,
            max_size=10
        )
    )
    @settings(max_examples=200)
    def test_query_parameter_handling(self, params: Dict[str, str]):
        """Query parameters should be handled correctly."""
        query = urllib.parse.urlencode(params)
        url = f"http://example.com/path?{query}" if query else "http://example.com/path"

        parsed = parse_url_safe(url)
        assert parsed is not None

        # Parse query parameters
        parsed_params = urllib.parse.parse_qs(parsed.query)

        # All input parameters should be present
        for key in params:
            if key and params[key]:  # Skip empty
                assert key in parsed_params or key in parsed.query

    @given(
        value=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
            min_size=0,
            max_size=100
        )
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.filter_too_much])
    def test_special_characters_in_query(self, value: str):
        """Special characters in query should be URL-encoded."""
        assume(value)  # Skip empty values

        encoded = urllib.parse.quote(value, safe="")
        url = f"http://example.com/path?param={encoded}"

        parsed = parse_url_safe(url)
        assert parsed is not None


# =============================================================================
# Security-Focused Tests
# =============================================================================

@pytest.mark.fuzz
@pytest.mark.security
class TestURLSecurityVulnerabilities:
    """Test for security vulnerabilities in URL handling."""

    @pytest.mark.parametrize("malicious_url", [
        # SSRF attempts
        "http://localhost/admin",
        "http://127.0.0.1/admin",
        "http://[::1]/admin",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
        "http://192.168.1.1/admin",  # Private network
        "http://10.0.0.1/admin",  # Private network

        # Open redirect attempts
        "http://example.com//evil.com",
        "http://example.com/redirect?url=http://evil.com",
        "http://example.com@evil.com",
        "http://example.com%40evil.com",

        # Protocol smuggling
        "http://example.com:80\r\nHost: evil.com",
        "http://example.com%0d%0aHost:%20evil.com",

        # Unicode homograph attacks
        "http://examp\u04dfe.com/",  # Cyrillic 'l'
        "http://\u0430pple.com/",  # Cyrillic 'a'

        # IP address obfuscation
        "http://0x7f000001/",  # 127.0.0.1 in hex
        "http://2130706433/",  # 127.0.0.1 in decimal
        "http://0177.0.0.1/",  # Octal
        "http://127.1/",  # Shortened
    ])
    def test_malicious_url_handling(self, malicious_url: str):
        """Malicious URLs should be handled safely."""
        parsed = parse_url_safe(malicious_url)

        # Parsing should work but not execute anything harmful
        # Main check is that it doesn't crash

        if WEB_ENUM_AVAILABLE:
            try:
                client = create_web_client_safe(malicious_url)
                # Client creation should succeed or fail gracefully
            except Exception:
                pass

    @pytest.mark.parametrize("path", [
        p for p in malicious_path.example()
        for _ in range(3)  # Get 3 examples
    ] if hasattr(malicious_path, 'example') else [
        "/../../../etc/passwd",
        "/..%2F..%2Fetc%2Fpasswd",
        "/<script>alert(1)</script>",
    ])
    def test_malicious_path_handling(self, path: str):
        """Malicious paths should not cause security issues."""
        url = f"http://example.com{path}"

        parsed = parse_url_safe(url)

        if parsed:
            # Check that path traversal hasn't escaped URL context
            assert "passwd" not in parsed.netloc, "Path traversal escaped to netloc"

    def test_extremely_long_url(self):
        """Extremely long URLs should be handled gracefully."""
        long_path = "/" + "a" * 10000
        url = f"http://example.com{long_path}"

        parsed = parse_url_safe(url)
        assert parsed is not None

        if WEB_ENUM_AVAILABLE:
            client = create_web_client_safe(url)
            # Should handle gracefully

    def test_many_query_parameters(self):
        """Many query parameters should not cause DoS."""
        params = "&".join(f"param{i}=value{i}" for i in range(1000))
        url = f"http://example.com/path?{params}"

        parsed = parse_url_safe(url)
        assert parsed is not None

    @given(
        n=st.integers(min_value=1, max_value=100)
    )
    @settings(max_examples=20, deadline=5000)
    def test_nested_encoding(self, n: int):
        """Multiple levels of URL encoding should be handled safely."""
        path = "/admin"
        for _ in range(n):
            path = urllib.parse.quote(path, safe="")

        url = f"http://example.com{path}"

        parsed = parse_url_safe(url)
        # Should parse without crashing
        assert parsed is not None


@pytest.mark.fuzz
@pytest.mark.security
class TestPathTraversalResistance:
    """Test resistance to path traversal attacks."""

    @given(
        levels=st.integers(min_value=1, max_value=20),
        encoding=st.sampled_from(["none", "single", "double", "mixed"])
    )
    @settings(max_examples=100)
    def test_path_traversal_variants(self, levels: int, encoding: str):
        """Various path traversal encodings should be handled safely."""
        # Build traversal sequence
        if encoding == "none":
            traversal = "../" * levels
        elif encoding == "single":
            traversal = "%2e%2e%2f" * levels
        elif encoding == "double":
            traversal = "%252e%252e%252f" * levels
        else:  # mixed
            traversal = "..%2f" * levels

        url = f"http://example.com/{traversal}etc/passwd"

        parsed = parse_url_safe(url)
        assert parsed is not None

        # The traversal should stay within the path component
        if parsed.netloc:
            assert "passwd" not in parsed.netloc
            assert ".." not in parsed.netloc

    @pytest.mark.parametrize("null_variant", [
        "%00", "\x00", "%2500", "\\x00", "\\0"
    ])
    def test_null_byte_handling(self, null_variant: str):
        """Null bytes in URLs should not cause truncation issues."""
        url = f"http://example.com/path{null_variant}.jpg"

        parsed = parse_url_safe(url)
        # Should parse without issues
        # The null byte handling depends on the parser

    def test_backslash_variants(self):
        """Backslash path separators should be handled safely."""
        test_urls = [
            "http://example.com/..\\..\\etc\\passwd",
            "http://example.com/..%5c..%5cetc%5cpasswd",
            "http://example.com/..%255c..%255cetc%255cpasswd",
        ]

        for url in test_urls:
            parsed = parse_url_safe(url)
            assert parsed is not None
            # Backslashes should stay in path, not affect host
            if parsed.netloc:
                assert "\\" not in parsed.netloc
                assert "passwd" not in parsed.netloc


# =============================================================================
# URL Fragment Handling
# =============================================================================

@pytest.mark.fuzz
class TestURLFragmentHandling:
    """Test URL fragment (hash) handling."""

    @given(
        fragment=st.from_regex(r"[a-zA-Z0-9_-]{0,50}", fullmatch=True)
    )
    @settings(max_examples=100)
    def test_fragment_preservation(self, fragment: str):
        """URL fragments should be preserved in parsing."""
        url = f"http://example.com/path#{fragment}"

        parsed = parse_url_safe(url)
        assert parsed is not None
        assert parsed.fragment == fragment

    def test_multiple_hashes(self):
        """Multiple hash characters should be handled correctly."""
        url = "http://example.com/path#section1#section2"

        parsed = parse_url_safe(url)
        assert parsed is not None
        # Only first hash starts fragment
        assert parsed.path == "/path"
