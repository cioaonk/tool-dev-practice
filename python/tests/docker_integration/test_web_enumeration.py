"""
Integration tests for web directory enumeration against Docker environment.
"""

import pytest
import sys
import os

# Add tools path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'web-directory-enumerator'))

try:
    from tool import DirectoryEnumerator, EnumConfig, HTTPClient
except ImportError:
    DirectoryEnumerator = None
    EnumConfig = None
    HTTPClient = None


@pytest.mark.skipif(DirectoryEnumerator is None, reason="Web enumerator tool not available")
class TestWebDirectoryEnumeration:
    """Test web directory enumeration against vulnerable-web container."""

    def test_http_client_connection(self, web_service):
        """Test that HTTP client can connect to web service."""
        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=["index.php"],
            timeout=10.0
        )

        client = HTTPClient(config)
        result = client.request("/")

        assert result is not None
        assert result.status_code == 200

    def test_enumerate_known_paths(self, web_service):
        """Test enumeration of known vulnerable paths."""
        known_paths = [
            "admin",
            "login.php",
            "robots.txt",
            "api",
            "config"
        ]

        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=known_paths,
            extensions=[],
            timeout=10.0,
            threads=5,
            status_codes=[200, 301, 302, 401, 403]
        )

        enumerator = DirectoryEnumerator(config)
        results = enumerator.enumerate()

        # Should find at least some of the known paths
        found_paths = [r.path for r in results]
        assert len(found_paths) > 0, "Should find at least one known path"

        # robots.txt should definitely be found
        assert any("robots" in p for p in found_paths), "Should find robots.txt"

    def test_admin_requires_auth(self, web_service):
        """Test that admin directory returns 401."""
        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=["admin/"],
            timeout=10.0
        )

        client = HTTPClient(config)
        result = client.request("/admin/")

        assert result is not None
        assert result.status_code == 401, "Admin should require authentication"

    def test_robots_txt_content(self, web_service):
        """Test that robots.txt contains expected disallow entries."""
        import http.client

        conn = http.client.HTTPConnection(web_service["host"], web_service["port"], timeout=10)
        conn.request("GET", "/robots.txt")
        response = conn.getresponse()
        body = response.read().decode('utf-8')
        conn.close()

        assert response.status == 200
        assert "Disallow" in body
        assert "/admin/" in body
        assert "/config/" in body

    def test_extension_enumeration(self, web_service):
        """Test enumeration with extensions."""
        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=["index", "login", "config"],
            extensions=[".php", ".html", ".bak"],
            timeout=10.0,
            threads=5,
            status_codes=[200, 301, 302, 401, 403]
        )

        enumerator = DirectoryEnumerator(config)
        results = enumerator.enumerate()

        # Should find PHP files
        found_paths = [r.path for r in results]
        assert any(".php" in p for p in found_paths), "Should find PHP files"

    def test_baseline_calibration(self, web_service):
        """Test that baseline calibration works for soft 404 detection."""
        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=["nonexistent_path_12345"],
            timeout=10.0,
            verbose=False
        )

        enumerator = DirectoryEnumerator(config)
        enumerator._calibrate_baseline()

        # Should have established a baseline
        assert enumerator._baseline_length is not None or enumerator._baseline_length == 0


@pytest.mark.skipif(DirectoryEnumerator is None, reason="Web enumerator tool not available")
class TestHTTPBasicAuth:
    """Test HTTP Basic Authentication against vulnerable-web."""

    def test_unauthenticated_access_denied(self, web_service):
        """Test that unauthenticated access to admin is denied."""
        import http.client

        conn = http.client.HTTPConnection(web_service["host"], web_service["port"], timeout=10)
        conn.request("GET", "/admin/")
        response = conn.getresponse()
        conn.close()

        assert response.status == 401

    def test_valid_credentials_accepted(self, web_service):
        """Test that valid credentials are accepted."""
        import http.client
        import base64

        auth_string = base64.b64encode(b"admin:admin123").decode()
        headers = {"Authorization": f"Basic {auth_string}"}

        conn = http.client.HTTPConnection(web_service["host"], web_service["port"], timeout=10)
        conn.request("GET", "/admin/", headers=headers)
        response = conn.getresponse()
        conn.close()

        assert response.status == 200

    def test_invalid_credentials_rejected(self, web_service):
        """Test that invalid credentials are rejected."""
        import http.client
        import base64

        auth_string = base64.b64encode(b"admin:wrongpassword").decode()
        headers = {"Authorization": f"Basic {auth_string}"}

        conn = http.client.HTTPConnection(web_service["host"], web_service["port"], timeout=10)
        conn.request("GET", "/admin/", headers=headers)
        response = conn.getresponse()
        conn.close()

        assert response.status == 401
