#!/usr/bin/env python3
"""
HTTP Request Tool - Flexible HTTP Client for Security Testing
==============================================================

A comprehensive HTTP request utility for crafting custom requests,
testing endpoints, and analyzing responses during penetration testing.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
"""

import argparse
import http.client
import json
import socket
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 30.0
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class HTTPRequest:
    """Represents an HTTP request."""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT
    follow_redirects: bool = False
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: Optional[str] = None


@dataclass
class HTTPResponse:
    """Represents an HTTP response."""
    status_code: int
    status_reason: str
    headers: Dict[str, str]
    body: bytes
    response_time: float
    redirects: List[str] = field(default_factory=list)
    ssl_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "status_reason": self.status_reason,
            "headers": self.headers,
            "body_length": len(self.body),
            "response_time": self.response_time,
            "redirects": self.redirects,
            "ssl_info": self.ssl_info
        }


@dataclass
class RequestConfig:
    """Configuration for HTTP request tool."""
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Optional[str] = None
    data_file: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT
    follow_redirects: bool = False
    max_redirects: int = 5
    verify_ssl: bool = False
    proxy: Optional[str] = None
    output_file: Optional[str] = None
    show_headers: bool = True
    show_body: bool = True
    raw_output: bool = False
    verbose: bool = False
    plan_mode: bool = False


# =============================================================================
# HTTP Client
# =============================================================================

class HTTPClient:
    """
    Flexible HTTP client for security testing.

    Supports custom methods, headers, body data, and SSL options.
    """

    def __init__(self, config: RequestConfig):
        self.config = config
        self._parse_url()

    def _parse_url(self) -> None:
        """Parse URL into components."""
        parsed = urllib.parse.urlparse(self.config.url)

        self.scheme = parsed.scheme or "http"
        self.host = parsed.netloc
        self.path = parsed.path or "/"
        self.query = parsed.query
        self.use_ssl = self.scheme == "https"

        if self.query:
            self.path = f"{self.path}?{self.query}"

        # Handle port
        if ':' in self.host:
            self.host, port_str = self.host.rsplit(':', 1)
            self.port = int(port_str)
        else:
            self.port = 443 if self.use_ssl else 80

    def _create_connection(self) -> http.client.HTTPConnection:
        """Create HTTP(S) connection."""
        if self.use_ssl:
            context = ssl.create_default_context()
            if not self.config.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.config.timeout,
                context=context
            )
        else:
            return http.client.HTTPConnection(
                self.host,
                self.port,
                timeout=self.config.timeout
            )

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "Host": self.host,
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
            "Connection": "close",
        }

        # Add/override with custom headers
        headers.update(self.config.headers)

        # Add content-type for POST/PUT with data
        if self.config.data and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        return headers

    def _get_ssl_info(self, conn: http.client.HTTPSConnection) -> Optional[Dict[str, Any]]:
        """Extract SSL certificate information."""
        try:
            cert = conn.sock.getpeercert()
            if cert:
                return {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "version": cert.get('version'),
                    "not_before": cert.get('notBefore'),
                    "not_after": cert.get('notAfter'),
                    "serial_number": cert.get('serialNumber'),
                }
        except Exception:
            pass
        return None

    def request(self) -> HTTPResponse:
        """
        Execute HTTP request.

        Returns:
            HTTPResponse object
        """
        start_time = time.time()
        redirects = []

        # Load body data
        body = self.config.data
        if self.config.data_file:
            try:
                with open(self.config.data_file, 'r') as f:
                    body = f.read()
            except Exception as e:
                raise ValueError(f"Failed to load data file: {e}")

        current_url = self.config.url
        redirect_count = 0

        while True:
            # Parse current URL
            parsed = urllib.parse.urlparse(current_url)
            host = parsed.netloc
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            use_ssl = parsed.scheme == "https"

            if ':' in host:
                host, port_str = host.rsplit(':', 1)
                port = int(port_str)
            else:
                port = 443 if use_ssl else 80

            # Create connection
            if use_ssl:
                context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=self.config.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.config.timeout)

            headers = self._build_headers()
            headers["Host"] = host

            # Send request
            conn.request(self.config.method, path, body, headers)
            response = conn.getresponse()

            # Get SSL info
            ssl_info = None
            if use_ssl and hasattr(conn, 'sock'):
                ssl_info = self._get_ssl_info(conn)

            # Read response
            response_body = response.read()
            response_headers = dict(response.getheaders())

            conn.close()

            # Handle redirects
            if self.config.follow_redirects and response.status in [301, 302, 303, 307, 308]:
                if redirect_count >= self.config.max_redirects:
                    break

                location = response_headers.get('Location') or response_headers.get('location')
                if location:
                    # Handle relative URLs
                    if location.startswith('/'):
                        location = f"{parsed.scheme}://{host}{location}"
                    elif not location.startswith('http'):
                        location = f"{parsed.scheme}://{host}/{location}"

                    redirects.append(current_url)
                    current_url = location
                    redirect_count += 1
                    continue

            break

        response_time = time.time() - start_time

        return HTTPResponse(
            status_code=response.status,
            status_reason=response.reason,
            headers=response_headers,
            body=response_body,
            response_time=response_time,
            redirects=redirects,
            ssl_info=ssl_info
        )


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: RequestConfig) -> None:
    """Display execution plan without performing any actions."""
    # Parse URL
    parsed = urllib.parse.urlparse(config.url)

    print("""
[PLAN MODE] Tool: http-request-tool
================================================================================
""")

    print("REQUEST DETAILS")
    print("-" * 40)
    print(f"  Method:          {config.method}")
    print(f"  URL:             {config.url}")
    print(f"  Host:            {parsed.netloc}")
    print(f"  Path:            {parsed.path or '/'}")
    print(f"  Scheme:          {parsed.scheme}")
    print()

    print("REQUEST OPTIONS")
    print("-" * 40)
    print(f"  Timeout:           {config.timeout}s")
    print(f"  Follow Redirects:  {config.follow_redirects}")
    print(f"  Max Redirects:     {config.max_redirects}")
    print(f"  Verify SSL:        {config.verify_ssl}")
    if config.proxy:
        print(f"  Proxy:             {config.proxy}")
    print()

    if config.headers:
        print("CUSTOM HEADERS")
        print("-" * 40)
        for name, value in config.headers.items():
            print(f"  {name}: {value[:50]}{'...' if len(value) > 50 else ''}")
        print()

    if config.data:
        print("REQUEST BODY")
        print("-" * 40)
        preview = config.data[:100]
        print(f"  {preview}{'...' if len(config.data) > 100 else ''}")
        print(f"  Length: {len(config.data)} bytes")
        print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print(f"  1. Establish {'HTTPS' if parsed.scheme == 'https' else 'HTTP'} connection to {parsed.netloc}")
    print(f"  2. Send {config.method} request to {parsed.path or '/'}")
    if config.data:
        print(f"  3. Include request body ({len(config.data)} bytes)")
    print(f"  4. Receive and parse response")
    if config.follow_redirects:
        print(f"  5. Follow up to {config.max_redirects} redirects if returned")
    print()

    print("=" * 80)
    print("No actions will be taken. Remove --plan flag to execute.")
    print("=" * 80)


# =============================================================================
# Documentation Hooks
# =============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return structured documentation for integration."""
    return {
        "name": "http-request-tool",
        "version": "1.0.0",
        "category": "utility",
        "description": "Flexible HTTP client for security testing",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Custom HTTP methods",
            "Custom headers support",
            "Request body from file or argument",
            "SSL certificate inspection",
            "Redirect following",
            "Response timing",
            "Planning mode"
        ],
        "arguments": {
            "url": {
                "type": "string",
                "required": True,
                "description": "Target URL"
            },
            "--method": {
                "type": "string",
                "default": "GET",
                "description": "HTTP method"
            },
            "--header": {
                "type": "list",
                "description": "Custom header (repeatable)"
            },
            "--data": {
                "type": "string",
                "description": "Request body"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan"
            }
        }
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="HTTP Request Tool - Flexible HTTP Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://target.com --plan
  %(prog)s http://target.com/api -X POST -d '{"key":"value"}'
  %(prog)s https://target.com -H "Authorization: Bearer token"

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "url",
        help="Target URL"
    )

    parser.add_argument(
        "-X", "--method",
        default="GET",
        help="HTTP method (default: GET)"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        help="Custom header (format: 'Name: Value')"
    )

    parser.add_argument(
        "-d", "--data",
        help="Request body data"
    )

    parser.add_argument(
        "-f", "--data-file",
        help="File containing request body"
    )

    parser.add_argument(
        "-L", "--follow-redirects",
        action="store_true",
        help="Follow redirects"
    )

    parser.add_argument(
        "--max-redirects",
        type=int,
        default=5,
        help="Maximum redirects to follow (default: 5)"
    )

    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        help="Skip SSL verification"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--no-headers",
        action="store_true",
        help="Don't show response headers"
    )

    parser.add_argument(
        "--no-body",
        action="store_true",
        help="Don't show response body"
    )

    parser.add_argument(
        "-r", "--raw",
        action="store_true",
        help="Raw output (body only, no formatting)"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without sending request"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-o", "--output",
        help="Save response body to file"
    )

    return parser.parse_args()


def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """Parse header list into dictionary."""
    headers = {}
    if header_list:
        for h in header_list:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()
    return headers


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Build configuration
    config = RequestConfig(
        url=args.url,
        method=args.method.upper(),
        headers=parse_headers(args.header),
        data=args.data,
        data_file=args.data_file,
        timeout=args.timeout,
        follow_redirects=args.follow_redirects,
        max_redirects=args.max_redirects,
        verify_ssl=not args.insecure,
        show_headers=not args.no_headers,
        show_body=not args.no_body,
        raw_output=args.raw,
        verbose=args.verbose,
        plan_mode=args.plan,
        output_file=args.output
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute request
    if not config.raw_output:
        print(f"[*] {config.method} {config.url}")

    client = HTTPClient(config)

    try:
        response = client.request()

        if config.raw_output:
            # Raw body output
            sys.stdout.buffer.write(response.body)
            return 0

        # Formatted output
        print()
        print("=" * 60)
        print(f"HTTP/{response.status_code} {response.status_reason}")
        print(f"Response Time: {response.response_time:.3f}s")
        print("=" * 60)

        if response.redirects:
            print(f"\nRedirects: {' -> '.join(response.redirects)}")

        if config.show_headers:
            print("\nRESPONSE HEADERS:")
            print("-" * 40)
            for name, value in response.headers.items():
                print(f"  {name}: {value}")

        if response.ssl_info:
            print("\nSSL CERTIFICATE:")
            print("-" * 40)
            if response.ssl_info.get('subject'):
                print(f"  Subject: {response.ssl_info['subject']}")
            if response.ssl_info.get('issuer'):
                print(f"  Issuer: {response.ssl_info['issuer']}")
            if response.ssl_info.get('not_after'):
                print(f"  Expires: {response.ssl_info['not_after']}")

        if config.show_body and response.body:
            print(f"\nRESPONSE BODY ({len(response.body)} bytes):")
            print("-" * 40)
            try:
                body_str = response.body.decode('utf-8')
                # Truncate long bodies
                if len(body_str) > 5000:
                    print(body_str[:5000])
                    print(f"\n... truncated ({len(body_str)} total bytes)")
                else:
                    print(body_str)
            except UnicodeDecodeError:
                print(f"[Binary data - {len(response.body)} bytes]")

        # Save to file if requested
        if config.output_file:
            with open(config.output_file, 'wb') as f:
                f.write(response.body)
            print(f"\n[*] Response saved to {config.output_file}")

        return 0

    except Exception as e:
        print(f"[!] Request failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
