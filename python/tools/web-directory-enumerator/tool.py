#!/usr/bin/env python3
"""
Web Directory Enumerator - Stealthy Web Content Discovery Tool
==============================================================

A comprehensive web directory and file enumeration utility designed for
authorized penetration testing. Features configurable wordlists, stealth
options, and intelligent response analysis.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized web scanning may violate laws and regulations.
"""

import argparse
import http.client
import queue
import re
import socket
import ssl
import sys
import time
import random
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 10.0
DEFAULT_THREADS = 10
DEFAULT_DELAY_MIN = 0.0
DEFAULT_DELAY_MAX = 0.1

# Default wordlist entries (minimal built-in list)
DEFAULT_WORDLIST = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "config", "backup", "test", "dev", "api", "v1", "v2",
    "robots.txt", "sitemap.xml", ".git", ".svn", ".htaccess", ".env",
    "phpinfo.php", "info.php", "server-status", "wp-config.php",
    "web.config", "config.php", "database", "db", "sql", "mysql",
    "phpmyadmin", "pma", "adminer", "console", "shell", "cmd",
    "uploads", "upload", "files", "images", "img", "assets", "static",
    "css", "js", "javascript", "include", "includes", "lib", "libs",
    "vendor", "node_modules", "packages", "temp", "tmp", "cache",
    "log", "logs", "debug", "error", "errors", "private", "secret",
    "hidden", "internal", "manage", "management", "portal", "user",
    "users", "member", "members", "account", "accounts", "profile",
    "register", "signup", "signin", "auth", "authentication", "oauth",
    "token", "session", "api-docs", "swagger", "graphql", "rest",
]

# Common extensions
COMMON_EXTENSIONS = [
    "", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".txt",
    ".xml", ".json", ".bak", ".old", ".orig", ".backup"
]

# Status code categories
class StatusCategory(Enum):
    SUCCESS = "success"
    REDIRECT = "redirect"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DirectoryResult:
    """Result of a directory/file check."""
    url: str
    path: str
    status_code: int
    content_length: int
    redirect_url: Optional[str] = None
    response_time: Optional[float] = None
    title: Optional[str] = None
    interesting: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def status_category(self) -> StatusCategory:
        if 200 <= self.status_code < 300:
            return StatusCategory.SUCCESS
        elif 300 <= self.status_code < 400:
            return StatusCategory.REDIRECT
        elif 400 <= self.status_code < 500:
            return StatusCategory.CLIENT_ERROR
        else:
            return StatusCategory.SERVER_ERROR

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "redirect_url": self.redirect_url,
            "response_time": self.response_time,
            "title": self.title,
            "interesting": self.interesting,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class EnumConfig:
    """Configuration for directory enumeration."""
    target_url: str = ""
    wordlist: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    follow_redirects: bool = False
    status_codes: List[int] = field(default_factory=lambda: [200, 201, 204, 301, 302, 307, 401, 403])
    exclude_codes: List[int] = field(default_factory=list)
    exclude_lengths: List[int] = field(default_factory=list)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    recursive: bool = False
    recursive_depth: int = 2
    verbose: bool = False
    plan_mode: bool = False


# =============================================================================
# HTTP Client
# =============================================================================

class HTTPClient:
    """
    Lightweight HTTP client for directory enumeration.

    Uses standard library for minimal dependencies and
    operational security (no external fingerprints).
    """

    def __init__(self, config: EnumConfig):
        self.config = config
        self._parse_target()

    def _parse_target(self) -> None:
        """Parse target URL into components."""
        parsed = urllib.parse.urlparse(self.config.target_url)
        self.scheme = parsed.scheme or "http"
        self.host = parsed.netloc or parsed.path.split('/')[0]
        self.base_path = parsed.path if parsed.path != self.host else ""
        self.use_ssl = self.scheme == "https"

        # Handle port
        if ':' in self.host:
            self.host, port_str = self.host.rsplit(':', 1)
            self.port = int(port_str)
        else:
            self.port = 443 if self.use_ssl else 80

    def _create_connection(self) -> http.client.HTTPConnection:
        """Create appropriate HTTP(S) connection."""
        if self.use_ssl:
            context = ssl.create_default_context()
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
            "User-Agent": self.config.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }

        # Add custom headers
        headers.update(self.config.headers)

        # Add cookies
        if self.config.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.config.cookies.items())
            headers["Cookie"] = cookie_str

        return headers

    def request(self, path: str, method: str = "GET") -> Optional[DirectoryResult]:
        """
        Make HTTP request to a path.

        Args:
            path: Path to request
            method: HTTP method

        Returns:
            DirectoryResult or None on error
        """
        full_path = f"{self.base_path.rstrip('/')}/{path.lstrip('/')}"
        full_url = f"{self.scheme}://{self.host}:{self.port}{full_path}"

        start_time = time.time()

        try:
            conn = self._create_connection()
            headers = self._build_headers()

            conn.request(method, full_path, headers=headers)
            response = conn.getresponse()

            response_time = time.time() - start_time

            # Read response body for length and title extraction
            body = response.read(65536)  # Limit read size
            content_length = len(body)

            # Extract title if HTML
            title = None
            if b'<title>' in body.lower():
                title_match = re.search(b'<title[^>]*>([^<]+)</title>', body, re.I)
                if title_match:
                    title = title_match.group(1).decode('utf-8', errors='ignore').strip()

            # Get redirect URL
            redirect_url = None
            if 300 <= response.status < 400:
                redirect_url = response.getheader('Location')

            conn.close()

            return DirectoryResult(
                url=full_url,
                path=path,
                status_code=response.status,
                content_length=content_length,
                redirect_url=redirect_url,
                response_time=response_time,
                title=title
            )

        except socket.timeout:
            return None
        except Exception as e:
            if self.config.verbose:
                print(f"[!] Request error for {path}: {e}")
            return None


# =============================================================================
# Directory Enumerator Core
# =============================================================================

class DirectoryEnumerator:
    """
    Main directory enumeration engine.

    Coordinates wordlist processing, threading, and result filtering
    with operational security considerations.
    """

    def __init__(self, config: EnumConfig):
        self.config = config
        self.client = HTTPClient(config)
        self.results: List[DirectoryResult] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._found_dirs: Set[str] = set()
        self._baseline_length: Optional[int] = None

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _calibrate_baseline(self) -> None:
        """Determine baseline 404 response characteristics."""
        # Request non-existent paths to establish baseline
        random_paths = [
            f"nonexistent_{random.randint(10000, 99999)}",
            f"definitely_not_here_{random.randint(10000, 99999)}",
        ]

        lengths = []
        for path in random_paths:
            result = self.client.request(path)
            if result:
                lengths.append(result.content_length)

        if lengths:
            # Use average as baseline
            self._baseline_length = sum(lengths) // len(lengths)

    def _is_interesting(self, result: DirectoryResult) -> bool:
        """Determine if result is interesting (not a false positive)."""
        # Check against explicit exclude codes
        if result.status_code in self.config.exclude_codes:
            return False

        # Check against exclude lengths
        if result.content_length in self.config.exclude_lengths:
            return False

        # Check against baseline (soft 404 detection)
        if self._baseline_length:
            # Allow 5% variance for dynamic content
            variance = self._baseline_length * 0.05
            if abs(result.content_length - self._baseline_length) <= variance:
                if result.status_code == 200:
                    return False

        return result.status_code in self.config.status_codes

    def _generate_paths(self) -> List[str]:
        """Generate all paths to test."""
        paths = []

        for word in self.config.wordlist:
            word = word.strip()
            if not word or word.startswith('#'):
                continue

            # Add base word
            paths.append(word)

            # Add with extensions
            for ext in self.config.extensions:
                if ext and not word.endswith(ext):
                    paths.append(f"{word}{ext}")

        return paths

    def _check_path(self, path: str) -> Optional[DirectoryResult]:
        """
        Check a single path.

        Args:
            path: Path to check

        Returns:
            DirectoryResult if interesting, None otherwise
        """
        if self._stop_event.is_set():
            return None

        self._apply_jitter()

        result = self.client.request(path)

        if result and self._is_interesting(result):
            result.interesting = True
            return result

        return None

    def enumerate(self) -> List[DirectoryResult]:
        """
        Execute directory enumeration.

        Returns:
            List of interesting DirectoryResult objects
        """
        # Calibrate baseline
        if self.config.verbose:
            print("[*] Calibrating baseline response...")
        self._calibrate_baseline()

        # Generate paths
        paths = self._generate_paths()

        if self.config.verbose:
            print(f"[*] Testing {len(paths)} paths against {self.config.target_url}")
            if self._baseline_length:
                print(f"[*] Baseline 404 length: {self._baseline_length} bytes")

        # Execute enumeration
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._check_path, path): path for path in paths}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.results.append(result)
                            if self.config.verbose:
                                status_str = f"{result.status_code}"
                                if result.redirect_url:
                                    status_str += f" -> {result.redirect_url}"
                                print(f"[+] {result.path} ({status_str}) [{result.content_length}b]")

                            # Track found directories for recursive scan
                            if result.status_code in [200, 301, 302] and result.path.endswith('/'):
                                self._found_dirs.add(result.path)

                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error checking path: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the enumerator to stop."""
        self._stop_event.set()


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: EnumConfig) -> None:
    """Display execution plan without performing any actions."""
    paths = []
    for word in config.wordlist:
        word = word.strip()
        if not word or word.startswith('#'):
            continue
        paths.append(word)
        for ext in config.extensions:
            if ext:
                paths.append(f"{word}{ext}")

    print("""
[PLAN MODE] Tool: web-directory-enumerator
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Target URL:      {config.target_url}")

    # Parse URL for display
    parsed = urllib.parse.urlparse(config.target_url)
    scheme = parsed.scheme or "http"
    host = parsed.netloc or parsed.path.split('/')[0]
    print(f"  Scheme:          {scheme}")
    print(f"  Host:            {host}")
    print()

    print("ENUMERATION CONFIGURATION")
    print("-" * 40)
    print(f"  Wordlist Size:   {len(config.wordlist)} words")
    print(f"  Extensions:      {config.extensions if config.extensions else 'None'}")
    print(f"  Total Paths:     {len(paths)}")
    print(f"  Threads:         {config.threads}")
    print(f"  Timeout:         {config.timeout}s")
    print(f"  Delay Range:     {config.delay_min}s - {config.delay_max}s")
    print(f"  Follow Redirects:{config.follow_redirects}")
    print(f"  Status Codes:    {config.status_codes}")
    print()

    print("REQUEST CONFIGURATION")
    print("-" * 40)
    print(f"  User-Agent:      {config.user_agent[:50]}...")
    if config.headers:
        print(f"  Custom Headers:  {len(config.headers)}")
    if config.cookies:
        print(f"  Cookies:         {len(config.cookies)}")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Calibrate baseline response (404 detection)")
    print("  2. Generate path list from wordlist + extensions")
    print(f"  3. Initialize {config.threads} worker threads")
    print("  4. For each path:")
    print(f"     - Apply random delay ({config.delay_min}s - {config.delay_max}s)")
    print("     - Send HTTP GET request")
    print("     - Analyze response code and content length")
    print("     - Filter against baseline and exclude rules")
    print("  5. Aggregate interesting results")
    print()

    print("PATH PREVIEW (first 15)")
    print("-" * 40)
    for path in paths[:15]:
        print(f"  - /{path}")
    if len(paths) > 15:
        print(f"  ... and {len(paths) - 15} more")
    print()

    # Time estimate
    avg_delay = (config.delay_min + config.delay_max) / 2
    estimated_time = (len(paths) * (config.timeout + avg_delay)) / config.threads
    print("TIME ESTIMATE")
    print("-" * 40)
    print(f"  Worst case:      {estimated_time:.0f} seconds")
    print(f"  Typical:         {estimated_time * 0.2:.0f} seconds")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if len(paths) > 10000:
        risk_factors.append("Large wordlist generates high traffic")
    if config.delay_max < 0.1:
        risk_factors.append("Low delay may trigger WAF/rate limiting")
    if config.threads > 20:
        risk_factors.append("High thread count increases detection risk")

    risk_level = "LOW"
    if len(risk_factors) >= 2:
        risk_level = "MEDIUM"
    if len(risk_factors) >= 3:
        risk_level = "HIGH"

    print(f"  Risk Level: {risk_level}")
    for factor in risk_factors:
        print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Web server access logs will record all requests")
    print("  - WAF/IDS may detect enumeration patterns")
    print("  - Rate limiting may slow or block requests")
    print("  - 404 response analysis may reveal scanning")
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
        "name": "web-directory-enumerator",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Stealthy web directory and file enumeration tool",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Built-in and custom wordlist support",
            "Extension bruteforcing",
            "Soft 404 detection via baseline calibration",
            "Status code and content length filtering",
            "Custom headers and cookies",
            "Configurable delays for stealth",
            "Planning mode for operation preview"
        ],
        "arguments": {
            "url": {
                "type": "string",
                "required": True,
                "description": "Target URL (e.g., http://target.com)"
            },
            "--wordlist": {
                "type": "file",
                "default": "built-in",
                "description": "Path to wordlist file"
            },
            "--extensions": {
                "type": "list",
                "default": [],
                "description": "Extensions to append (e.g., php,html,txt)"
            },
            "--status-codes": {
                "type": "list",
                "default": [200, 201, 204, 301, 302, 307, 401, 403],
                "description": "Status codes to report"
            },
            "--threads": {
                "type": "int",
                "default": 10,
                "description": "Number of concurrent threads"
            },
            "--timeout": {
                "type": "float",
                "default": 10.0,
                "description": "Request timeout in seconds"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without scanning"
            }
        },
        "examples": [
            {
                "command": "python tool.py http://target.com --plan",
                "description": "Preview enumeration operation"
            },
            {
                "command": "python tool.py http://target.com -w wordlist.txt -x php,html",
                "description": "Enumerate with custom wordlist and extensions"
            }
        ]
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Web Directory Enumerator - Content Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http://target.com --plan
  %(prog)s http://target.com -w wordlist.txt -x php,html
  %(prog)s https://target.com -t 20 --delay-max 1

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "url",
        help="Target URL (e.g., http://target.com)"
    )

    parser.add_argument(
        "-w", "--wordlist",
        help="Path to wordlist file (uses built-in if not specified)"
    )

    parser.add_argument(
        "-x", "--extensions",
        help="Comma-separated extensions to append (e.g., php,html,txt)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--delay-min",
        type=float,
        default=DEFAULT_DELAY_MIN,
        help=f"Minimum delay between requests (default: {DEFAULT_DELAY_MIN})"
    )

    parser.add_argument(
        "--delay-max",
        type=float,
        default=DEFAULT_DELAY_MAX,
        help=f"Maximum delay between requests (default: {DEFAULT_DELAY_MAX})"
    )

    parser.add_argument(
        "-s", "--status-codes",
        help="Comma-separated status codes to report (default: 200,201,204,301,302,307,401,403)"
    )

    parser.add_argument(
        "-e", "--exclude-codes",
        help="Comma-separated status codes to exclude"
    )

    parser.add_argument(
        "--exclude-length",
        help="Comma-separated content lengths to exclude"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        help="Custom header (format: 'Name: Value')"
    )

    parser.add_argument(
        "-c", "--cookie",
        help="Cookies to include (format: 'name=value; name2=value2')"
    )

    parser.add_argument(
        "-a", "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        help="Custom User-Agent string"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without scanning"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for results (JSON format)"
    )

    return parser.parse_args()


def load_wordlist(path: Optional[str]) -> List[str]:
    """Load wordlist from file or return default."""
    if path:
        try:
            with open(path, 'r', errors='ignore') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            print("[*] Using built-in wordlist")

    return DEFAULT_WORDLIST.copy()


def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """Parse header list into dictionary."""
    headers = {}
    if header_list:
        for h in header_list:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name.strip()] = value.strip()
    return headers


def parse_cookies(cookie_str: Optional[str]) -> Dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies = {}
    if cookie_str:
        for pair in cookie_str.split(';'):
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()
    return cookies


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Load wordlist
    wordlist = load_wordlist(args.wordlist)

    # Parse extensions
    extensions = []
    if args.extensions:
        for ext in args.extensions.split(','):
            ext = ext.strip()
            if ext and not ext.startswith('.'):
                ext = '.' + ext
            extensions.append(ext)

    # Parse status codes
    status_codes = [200, 201, 204, 301, 302, 307, 401, 403]
    if args.status_codes:
        status_codes = [int(c.strip()) for c in args.status_codes.split(',')]

    # Parse exclude codes
    exclude_codes = []
    if args.exclude_codes:
        exclude_codes = [int(c.strip()) for c in args.exclude_codes.split(',')]

    # Parse exclude lengths
    exclude_lengths = []
    if args.exclude_length:
        exclude_lengths = [int(l.strip()) for l in args.exclude_length.split(',')]

    # Build configuration
    config = EnumConfig(
        target_url=args.url,
        wordlist=wordlist,
        extensions=extensions,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        status_codes=status_codes,
        exclude_codes=exclude_codes,
        exclude_lengths=exclude_lengths,
        user_agent=args.user_agent,
        headers=parse_headers(args.header),
        cookies=parse_cookies(args.cookie),
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute enumeration
    print(f"[*] Web Directory Enumerator starting...")
    print(f"[*] Target: {config.target_url}")
    print(f"[*] Wordlist: {len(config.wordlist)} entries")
    print(f"[*] Extensions: {config.extensions if config.extensions else 'None'}")

    enumerator = DirectoryEnumerator(config)

    try:
        results = enumerator.enumerate()

        # Display results
        print()
        print("=" * 70)
        print("ENUMERATION RESULTS")
        print("=" * 70)
        print(f"Total requests:   {len(enumerator._generate_paths())}")
        print(f"Interesting:      {len(results)}")
        print()

        if results:
            print(f"{'STATUS':<8} {'SIZE':<10} {'PATH':<40} {'REDIRECT':<20}")
            print("-" * 70)
            for result in sorted(results, key=lambda x: x.status_code):
                redirect = result.redirect_url[:20] if result.redirect_url else "-"
                print(f"{result.status_code:<8} {result.content_length:<10} "
                      f"{result.path:<40} {redirect:<20}")

        # Output to file if requested
        if args.output:
            import json
            output_data = {
                "target": config.target_url,
                "timestamp": datetime.now().isoformat(),
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        enumerator.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
