#!/usr/bin/env python3
"""
Service Fingerprinter - Advanced Service Detection and Version Identification
==============================================================================

A comprehensive service fingerprinting utility that identifies running services,
extracts version information, and detects potential vulnerabilities through
banner grabbing and protocol-specific probes.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized service probing may violate laws and regulations.
"""

import argparse
import re
import socket
import ssl
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Callable
from datetime import datetime
from abc import ABC, abstractmethod


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10
DEFAULT_DELAY_MIN = 0.1
DEFAULT_DELAY_MAX = 0.5


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ServiceInfo:
    """Information about a detected service."""
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    banner: Optional[str] = None
    ssl_enabled: bool = False
    ssl_info: Optional[Dict[str, Any]] = None
    confidence: int = 0  # 0-100
    cpe: Optional[str] = None  # Common Platform Enumeration
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service_name": self.service_name,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
            "banner": self.banner,
            "ssl_enabled": self.ssl_enabled,
            "ssl_info": self.ssl_info,
            "confidence": self.confidence,
            "cpe": self.cpe,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class FingerprintConfig:
    """Configuration for service fingerprinting."""
    target: str = ""
    ports: List[int] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    aggressive: bool = False
    ssl_check: bool = True
    version_intensity: int = 5  # 0-9, higher = more probes
    verbose: bool = False
    plan_mode: bool = False


@dataclass
class ProbeResult:
    """Result of a service probe."""
    matched: bool
    service_name: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    banner: Optional[str] = None
    confidence: int = 0
    extra_info: Optional[str] = None


# =============================================================================
# Service Probes
# =============================================================================

class ServiceProbe(ABC):
    """Abstract base class for service probes."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Probe name."""
        pass

    @property
    @abstractmethod
    def ports(self) -> List[int]:
        """Default ports this probe targets."""
        pass

    @property
    @abstractmethod
    def protocol(self) -> str:
        """Protocol (tcp/udp)."""
        pass

    @abstractmethod
    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Execute the probe."""
        pass

    def _safe_recv(self, sock: socket.socket, size: int = 4096) -> bytes:
        """Safely receive data with timeout handling."""
        try:
            return sock.recv(size)
        except socket.timeout:
            return b""
        except Exception:
            return b""


class HTTPProbe(ServiceProbe):
    """HTTP/HTTPS service detection probe."""

    @property
    def name(self) -> str:
        return "HTTP"

    @property
    def ports(self) -> List[int]:
        return [80, 8080, 8000, 8008, 8443, 443]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Send HTTP request and analyze response."""
        try:
            # Send HTTP HEAD request
            request = b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
            sock.send(request)
            response = self._safe_recv(sock, 4096)

            if not response:
                return ProbeResult(matched=False)

            response_str = response.decode('utf-8', errors='ignore')

            # Check if HTTP response
            if not response_str.startswith('HTTP/'):
                return ProbeResult(matched=False)

            result = ProbeResult(
                matched=True,
                service_name="http",
                banner=response_str[:500],
                confidence=90
            )

            # Extract server header
            server_match = re.search(r'Server:\s*([^\r\n]+)', response_str, re.IGNORECASE)
            if server_match:
                server = server_match.group(1)
                result.product = server
                result.confidence = 95

                # Try to extract version
                version_patterns = [
                    r'([Aa]pache|[Nn]ginx|IIS|[Ll]ighttpd)/(\d+[\d.]*)',
                    r'([A-Za-z]+)/(\d+[\d.]*)',
                ]
                for pattern in version_patterns:
                    ver_match = re.search(pattern, server)
                    if ver_match:
                        result.product = ver_match.group(1)
                        result.version = ver_match.group(2)
                        break

            return result

        except Exception:
            return ProbeResult(matched=False)


class SSHProbe(ServiceProbe):
    """SSH service detection probe."""

    @property
    def name(self) -> str:
        return "SSH"

    @property
    def ports(self) -> List[int]:
        return [22, 2222, 22222]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Receive SSH banner."""
        try:
            # SSH servers send banner immediately
            banner = self._safe_recv(sock, 1024)

            if not banner:
                return ProbeResult(matched=False)

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            if not banner_str.startswith('SSH-'):
                return ProbeResult(matched=False)

            result = ProbeResult(
                matched=True,
                service_name="ssh",
                banner=banner_str,
                confidence=95
            )

            # Parse SSH banner format: SSH-protoversion-softwareversion
            parts = banner_str.split('-', 2)
            if len(parts) >= 3:
                software = parts[2].split()[0] if parts[2] else ""

                # Common patterns
                if 'OpenSSH' in software:
                    result.product = "OpenSSH"
                    ver_match = re.search(r'OpenSSH[_\s]*([\d.p]+)', software)
                    if ver_match:
                        result.version = ver_match.group(1)
                elif 'dropbear' in software.lower():
                    result.product = "Dropbear"
                    ver_match = re.search(r'dropbear[_\s]*([\d.]+)', software, re.I)
                    if ver_match:
                        result.version = ver_match.group(1)
                else:
                    result.product = software.split('_')[0] if '_' in software else software

            return result

        except Exception:
            return ProbeResult(matched=False)


class FTPProbe(ServiceProbe):
    """FTP service detection probe."""

    @property
    def name(self) -> str:
        return "FTP"

    @property
    def ports(self) -> List[int]:
        return [21, 2121]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Receive FTP banner."""
        try:
            banner = self._safe_recv(sock, 1024)

            if not banner:
                return ProbeResult(matched=False)

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            # FTP banner starts with 220
            if not banner_str.startswith('220'):
                return ProbeResult(matched=False)

            result = ProbeResult(
                matched=True,
                service_name="ftp",
                banner=banner_str,
                confidence=90
            )

            # Extract version info
            if 'vsftpd' in banner_str.lower():
                result.product = "vsftpd"
                ver_match = re.search(r'vsftpd\s*([\d.]+)', banner_str, re.I)
                if ver_match:
                    result.version = ver_match.group(1)
            elif 'ProFTPD' in banner_str:
                result.product = "ProFTPD"
                ver_match = re.search(r'ProFTPD\s*([\d.]+)', banner_str)
                if ver_match:
                    result.version = ver_match.group(1)
            elif 'FileZilla' in banner_str:
                result.product = "FileZilla Server"
                ver_match = re.search(r'FileZilla Server\s*([\d.]+)', banner_str)
                if ver_match:
                    result.version = ver_match.group(1)

            return result

        except Exception:
            return ProbeResult(matched=False)


class SMTPProbe(ServiceProbe):
    """SMTP service detection probe."""

    @property
    def name(self) -> str:
        return "SMTP"

    @property
    def ports(self) -> List[int]:
        return [25, 465, 587, 2525]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Receive SMTP banner."""
        try:
            banner = self._safe_recv(sock, 1024)

            if not banner:
                return ProbeResult(matched=False)

            banner_str = banner.decode('utf-8', errors='ignore').strip()

            # SMTP banner starts with 220
            if not banner_str.startswith('220'):
                return ProbeResult(matched=False)

            result = ProbeResult(
                matched=True,
                service_name="smtp",
                banner=banner_str,
                confidence=90
            )

            # Extract MTA info
            if 'Postfix' in banner_str:
                result.product = "Postfix"
            elif 'Sendmail' in banner_str:
                result.product = "Sendmail"
                ver_match = re.search(r'Sendmail\s*([\d./]+)', banner_str)
                if ver_match:
                    result.version = ver_match.group(1)
            elif 'Microsoft' in banner_str or 'Exchange' in banner_str:
                result.product = "Microsoft Exchange"
            elif 'Exim' in banner_str:
                result.product = "Exim"
                ver_match = re.search(r'Exim\s*([\d.]+)', banner_str)
                if ver_match:
                    result.version = ver_match.group(1)

            return result

        except Exception:
            return ProbeResult(matched=False)


class MySQLProbe(ServiceProbe):
    """MySQL service detection probe."""

    @property
    def name(self) -> str:
        return "MySQL"

    @property
    def ports(self) -> List[int]:
        return [3306]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Receive MySQL greeting packet."""
        try:
            banner = self._safe_recv(sock, 1024)

            if not banner or len(banner) < 5:
                return ProbeResult(matched=False)

            # MySQL protocol: first 4 bytes are packet header
            # Byte 5 is protocol version (should be 10 for MySQL 3.21+)
            protocol_version = banner[4]

            if protocol_version != 10 and protocol_version != 9:
                return ProbeResult(matched=False)

            result = ProbeResult(
                matched=True,
                service_name="mysql",
                confidence=90
            )

            # Extract version string (null-terminated after protocol version)
            try:
                version_end = banner.find(b'\x00', 5)
                if version_end > 5:
                    version = banner[5:version_end].decode('utf-8', errors='ignore')
                    result.banner = f"MySQL {version}"
                    result.product = "MySQL"
                    result.version = version

                    # Check for MariaDB
                    if 'MariaDB' in version:
                        result.product = "MariaDB"
                        ver_match = re.search(r'([\d.]+)-MariaDB', version)
                        if ver_match:
                            result.version = ver_match.group(1)
            except Exception:
                pass

            return result

        except Exception:
            return ProbeResult(matched=False)


class RDPProbe(ServiceProbe):
    """RDP service detection probe."""

    @property
    def name(self) -> str:
        return "RDP"

    @property
    def ports(self) -> List[int]:
        return [3389]

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Send RDP connection request."""
        try:
            # RDP connection request (X.224 Connection Request)
            rdp_neg_req = bytes([
                0x03, 0x00,  # TPKT header
                0x00, 0x13,  # Length
                0x0e,        # X.224 length
                0xe0,        # X.224 connection request
                0x00, 0x00,  # DST-REF
                0x00, 0x00,  # SRC-REF
                0x00,        # Class
                0x01,        # Cookie length
                0x00,        # Cookie
                0x08,        # RDP NEG REQ length
                0x00, 0x01,  # Type: RDP_NEG_REQ
                0x00, 0x00,  # Flags
                0x00, 0x00,  # Protocol
            ])

            sock.send(rdp_neg_req)
            response = self._safe_recv(sock, 1024)

            if not response or len(response) < 11:
                return ProbeResult(matched=False)

            # Check for X.224 connection confirm
            if response[5] == 0xd0:  # Connection confirm
                return ProbeResult(
                    matched=True,
                    service_name="rdp",
                    product="Microsoft Remote Desktop",
                    confidence=85,
                    banner="RDP detected"
                )

            return ProbeResult(matched=False)

        except Exception:
            return ProbeResult(matched=False)


class GenericProbe(ServiceProbe):
    """Generic banner grabbing probe."""

    @property
    def name(self) -> str:
        return "Generic"

    @property
    def ports(self) -> List[int]:
        return []  # Applied to any port

    @property
    def protocol(self) -> str:
        return "tcp"

    def probe(self, sock: socket.socket, config: FingerprintConfig) -> ProbeResult:
        """Attempt generic banner grab."""
        try:
            # First try to receive without sending
            sock.settimeout(2.0)
            banner = self._safe_recv(sock, 1024)

            if not banner:
                # Try sending some common probes
                probes = [
                    b"\r\n",
                    b"HELP\r\n",
                    b"\x00",
                ]

                for probe in probes:
                    try:
                        sock.send(probe)
                        banner = self._safe_recv(sock, 1024)
                        if banner:
                            break
                    except Exception:
                        continue

            if not banner:
                return ProbeResult(matched=False)

            banner_str = banner.decode('utf-8', errors='ignore').strip()[:500]

            return ProbeResult(
                matched=True,
                service_name="unknown",
                banner=banner_str,
                confidence=30
            )

        except Exception:
            return ProbeResult(matched=False)


# =============================================================================
# SSL/TLS Detection
# =============================================================================

class SSLDetector:
    """Detect and analyze SSL/TLS on a port."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check_ssl(self, target: str, port: int) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if port is running SSL/TLS and gather certificate info.

        Returns:
            Tuple of (is_ssl, ssl_info_dict)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))

            ssl_sock = context.wrap_socket(sock, server_hostname=target)

            cert = ssl_sock.getpeercert(binary_form=False)
            cipher = ssl_sock.cipher()
            version = ssl_sock.version()

            ssl_info = {
                "version": version,
                "cipher": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
            }

            if cert:
                ssl_info["subject"] = dict(x[0] for x in cert.get('subject', []))
                ssl_info["issuer"] = dict(x[0] for x in cert.get('issuer', []))
                ssl_info["not_before"] = cert.get('notBefore')
                ssl_info["not_after"] = cert.get('notAfter')

            ssl_sock.close()
            return True, ssl_info

        except ssl.SSLError:
            return False, None
        except Exception:
            return False, None


# =============================================================================
# Service Fingerprinter Core
# =============================================================================

class ServiceFingerprinter:
    """
    Main service fingerprinting engine.

    Coordinates probes, manages threading, and aggregates results
    with operational security considerations.
    """

    PROBES: List[type] = [
        HTTPProbe,
        SSHProbe,
        FTPProbe,
        SMTPProbe,
        MySQLProbe,
        RDPProbe,
    ]

    def __init__(self, config: FingerprintConfig):
        """
        Initialize the fingerprinter.

        Args:
            config: FingerprintConfig with scanning parameters
        """
        self.config = config
        self.results: List[ServiceInfo] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._ssl_detector = SSLDetector(config.timeout)

        # Initialize probes
        self._probes = [probe_class() for probe_class in self.PROBES]
        self._generic_probe = GenericProbe()

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _get_probes_for_port(self, port: int) -> List[ServiceProbe]:
        """Get relevant probes for a port."""
        probes = []

        # Add probes that target this port
        for probe in self._probes:
            if port in probe.ports:
                probes.append(probe)

        # Add remaining probes if aggressive mode
        if self.config.aggressive:
            for probe in self._probes:
                if probe not in probes:
                    probes.append(probe)

        return probes

    def _fingerprint_port(self, port: int) -> Optional[ServiceInfo]:
        """
        Fingerprint a single port.

        Args:
            port: Port number to fingerprint

        Returns:
            ServiceInfo or None
        """
        if self._stop_event.is_set():
            return None

        self._apply_jitter()

        # First check SSL
        ssl_enabled = False
        ssl_info = None

        if self.config.ssl_check:
            ssl_enabled, ssl_info = self._ssl_detector.check_ssl(self.config.target, port)

        # Get relevant probes
        probes = self._get_probes_for_port(port)

        best_result: Optional[ProbeResult] = None

        for probe in probes:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target, port))

                # Wrap in SSL if needed
                if ssl_enabled:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)

                result = probe.probe(sock, self.config)
                sock.close()

                if result.matched:
                    if not best_result or result.confidence > best_result.confidence:
                        best_result = result

                    # High confidence match - stop probing
                    if result.confidence >= 90:
                        break

            except Exception as e:
                if self.config.verbose:
                    print(f"[!] Probe {probe.name} failed on port {port}: {e}")
                continue

        # Try generic probe if no match
        if not best_result:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.timeout)
                sock.connect((self.config.target, port))

                if ssl_enabled:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock)

                best_result = self._generic_probe.probe(sock, self.config)
                sock.close()
            except Exception:
                pass

        if best_result and best_result.matched:
            service_name = best_result.service_name or "unknown"
            if ssl_enabled and service_name == "http":
                service_name = "https"

            return ServiceInfo(
                port=port,
                protocol="tcp",
                service_name=service_name,
                version=best_result.version,
                product=best_result.product,
                banner=best_result.banner,
                ssl_enabled=ssl_enabled,
                ssl_info=ssl_info,
                confidence=best_result.confidence,
                extra_info=best_result.extra_info
            )

        return ServiceInfo(
            port=port,
            protocol="tcp",
            service_name="unknown",
            confidence=0
        )

    def fingerprint(self) -> List[ServiceInfo]:
        """
        Execute service fingerprinting.

        Returns:
            List of ServiceInfo objects
        """
        if self.config.verbose:
            print(f"[*] Fingerprinting {len(self.config.ports)} ports on {self.config.target}")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._fingerprint_port, port): port
                      for port in self.config.ports}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.results.append(result)
                            if self.config.verbose and result.confidence > 0:
                                ver_str = f" {result.version}" if result.version else ""
                                print(f"[+] {result.port}/tcp - {result.service_name}"
                                      f"{ver_str} ({result.confidence}%)")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error fingerprinting port {futures[future]}: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the fingerprinter to stop."""
        self._stop_event.set()


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: FingerprintConfig) -> None:
    """
    Display execution plan without performing any actions.

    Args:
        config: FingerprintConfig with planned parameters
    """
    print("""
[PLAN MODE] Tool: service-fingerprinter
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Target:          {config.target}")
    print(f"  Ports:           {len(config.ports)}")
    if config.ports:
        print(f"  Port List:       {config.ports[:10]}{'...' if len(config.ports) > 10 else ''}")
    print()

    print("SCAN CONFIGURATION")
    print("-" * 40)
    print(f"  Threads:           {config.threads}")
    print(f"  Timeout:           {config.timeout}s")
    print(f"  Delay Range:       {config.delay_min}s - {config.delay_max}s")
    print(f"  Aggressive Mode:   {config.aggressive}")
    print(f"  SSL Detection:     {config.ssl_check}")
    print(f"  Version Intensity: {config.version_intensity}/9")
    print()

    print("PROBES TO BE USED")
    print("-" * 40)
    for probe_class in ServiceFingerprinter.PROBES:
        probe = probe_class()
        print(f"  - {probe.name}: targets ports {probe.ports}")
    print(f"  - Generic: fallback banner grabbing")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. For each target port:")
    if config.ssl_check:
        print("     a. Check for SSL/TLS and gather certificate info")
    print("     b. Select relevant probes based on port number")
    print("     c. Execute probes in order of specificity")
    print("     d. Extract service name, version, and banner")
    print("     e. Fall back to generic probe if no match")
    print("  2. Aggregate results in memory")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if len(config.ports) > 50:
        risk_factors.append("Many ports increase connection footprint")
    if config.aggressive:
        risk_factors.append("Aggressive mode sends more probes")
    if config.delay_max < 0.1:
        risk_factors.append("Low delay may trigger rate limiting")

    risk_level = "LOW"
    if len(risk_factors) >= 2:
        risk_level = "MEDIUM"

    print(f"  Risk Level: {risk_level}")
    for factor in risk_factors:
        print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Service-specific probes may be logged by applications")
    print("  - SSL handshakes leave certificate negotiation traces")
    print("  - Banner grabbing attempts may trigger IDS rules")
    print()

    print("=" * 80)
    print("No actions will be taken. Remove --plan flag to execute.")
    print("=" * 80)


# =============================================================================
# Documentation Hooks
# =============================================================================

def get_documentation() -> Dict[str, Any]:
    """
    Return structured documentation for integration with documentation systems.

    Returns:
        Dictionary containing comprehensive tool documentation
    """
    return {
        "name": "service-fingerprinter",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Advanced service detection and version identification tool",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Protocol-specific service probes",
            "Version extraction from banners",
            "SSL/TLS detection and analysis",
            "Configurable probe intensity",
            "In-memory result storage",
            "Planning mode for operation preview"
        ],
        "supported_services": [
            "HTTP/HTTPS", "SSH", "FTP", "SMTP", "MySQL/MariaDB", "RDP"
        ],
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP address or hostname"
            },
            "--ports": {
                "type": "list",
                "required": True,
                "description": "Comma-separated list of ports to fingerprint"
            },
            "--timeout": {
                "type": "float",
                "default": 5.0,
                "description": "Connection timeout in seconds"
            },
            "--threads": {
                "type": "int",
                "default": 10,
                "description": "Number of concurrent threads"
            },
            "--aggressive": {
                "type": "bool",
                "default": False,
                "description": "Try all probes on all ports"
            },
            "--no-ssl": {
                "type": "bool",
                "default": False,
                "description": "Skip SSL/TLS detection"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without scanning"
            }
        },
        "examples": [
            {
                "command": "python tool.py 192.168.1.1 --ports 22,80,443 --plan",
                "description": "Preview fingerprinting operation"
            },
            {
                "command": "python tool.py target.com --ports 22,80,443,3306 --aggressive",
                "description": "Aggressive fingerprint with all probes"
            }
        ]
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Service Fingerprinter - Advanced Service Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 --ports 22,80,443 --plan
  %(prog)s target.com --ports 22,80,443,8080 --aggressive
  %(prog)s 10.0.0.1 --ports 21,22,25,80,443 --verbose

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-P", "--ports",
        required=True,
        help="Comma-separated list of ports to fingerprint"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})"
    )

    parser.add_argument(
        "--delay-min",
        type=float,
        default=DEFAULT_DELAY_MIN,
        help=f"Minimum delay between probes (default: {DEFAULT_DELAY_MIN})"
    )

    parser.add_argument(
        "--delay-max",
        type=float,
        default=DEFAULT_DELAY_MAX,
        help=f"Maximum delay between probes (default: {DEFAULT_DELAY_MAX})"
    )

    parser.add_argument(
        "-a", "--aggressive",
        action="store_true",
        help="Try all probes on all ports"
    )

    parser.add_argument(
        "--no-ssl",
        action="store_true",
        help="Skip SSL/TLS detection"
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


def parse_ports(port_str: str) -> List[int]:
    """Parse comma-separated port list."""
    ports = []
    for part in port_str.split(','):
        try:
            port = int(part.strip())
            if 1 <= port <= 65535:
                ports.append(port)
        except ValueError:
            pass
    return ports


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print("[!] No valid ports specified")
        return 1

    # Build configuration
    config = FingerprintConfig(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        aggressive=args.aggressive,
        ssl_check=not args.no_ssl,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute fingerprinting
    print(f"[*] Service Fingerprinter starting...")
    print(f"[*] Target: {config.target}")
    print(f"[*] Ports: {ports}")

    fingerprinter = ServiceFingerprinter(config)

    try:
        results = fingerprinter.fingerprint()

        # Display results
        print()
        print("=" * 70)
        print("FINGERPRINT RESULTS")
        print("=" * 70)
        print(f"{'PORT':<8} {'SERVICE':<15} {'PRODUCT':<20} {'VERSION':<15} {'SSL':<5}")
        print("-" * 70)

        for result in sorted(results, key=lambda x: x.port):
            if result.confidence > 0:
                ssl_str = "Yes" if result.ssl_enabled else "No"
                product = result.product or "-"
                version = result.version or "-"
                print(f"{result.port:<8} {result.service_name:<15} {product:<20} "
                      f"{version:<15} {ssl_str:<5}")

        # Output to file if requested
        if args.output:
            import json
            output_data = {
                "target": config.target,
                "timestamp": datetime.now().isoformat(),
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Fingerprinting interrupted by user")
        fingerprinter.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
