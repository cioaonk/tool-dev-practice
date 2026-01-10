#!/usr/bin/env python3
"""
Port Scanner - Advanced TCP/UDP Port Scanning Tool
===================================================

A comprehensive port scanning utility with multiple scan techniques,
stealth options, and service detection capabilities.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized port scanning may violate laws and regulations.
"""

import argparse
import socket
import struct
import sys
import time
import random
import threading
import select
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Any
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 50
DEFAULT_DELAY_MIN = 0.0
DEFAULT_DELAY_MAX = 0.05

# Common ports for quick scans
TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
]

# Well-known service ports mapping
SERVICE_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt", 27017: "mongodb"
}


# =============================================================================
# Enums and Data Classes
# =============================================================================

class PortState(Enum):
    """Possible states for a scanned port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class ScanType(Enum):
    """Available scan types."""
    TCP_CONNECT = "connect"
    TCP_SYN = "syn"
    TCP_FIN = "fin"
    TCP_NULL = "null"
    TCP_XMAS = "xmas"
    UDP = "udp"


@dataclass
class PortResult:
    """Result of scanning a single port."""
    port: int
    state: PortState
    protocol: str = "tcp"
    service: Optional[str] = None
    banner: Optional[str] = None
    response_time: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "port": self.port,
            "state": self.state.value,
            "protocol": self.protocol,
            "service": self.service,
            "banner": self.banner,
            "response_time": self.response_time,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ScanConfig:
    """Configuration for port scanning operations."""
    target: str = ""
    ports: List[int] = field(default_factory=list)
    scan_type: ScanType = ScanType.TCP_CONNECT
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    banner_grab: bool = False
    randomize_ports: bool = True
    verbose: bool = False
    plan_mode: bool = False


@dataclass
class ScanReport:
    """Complete scan report for a target."""
    target: str
    resolved_ip: Optional[str] = None
    scan_type: str = ""
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    results: List[PortResult] = field(default_factory=list)

    def get_open_ports(self) -> List[PortResult]:
        """Return only open ports."""
        return [r for r in self.results if r.state == PortState.OPEN]

    def get_filtered_ports(self) -> List[PortResult]:
        """Return filtered ports."""
        return [r for r in self.results if r.state == PortState.FILTERED]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "results": [r.to_dict() for r in self.results]
        }


# =============================================================================
# Port Parsing Utilities
# =============================================================================

def parse_port_specification(spec: str) -> List[int]:
    """
    Parse port specification into list of ports.

    Supports:
    - Single port: "80"
    - Range: "1-1024"
    - List: "22,80,443"
    - Combined: "22,80,443,8000-8100"
    - Keywords: "top20", "top100", "all"

    Args:
        spec: Port specification string

    Returns:
        List of port numbers
    """
    ports: Set[int] = set()

    # Handle keywords
    spec_lower = spec.lower()
    if spec_lower == "top20":
        return TOP_20_PORTS.copy()
    elif spec_lower == "top100":
        return TOP_100_PORTS.copy()
    elif spec_lower == "all":
        return list(range(1, 65536))

    # Parse comma-separated parts
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            # Range specification
            try:
                start, end = part.split("-")
                start_port = int(start.strip())
                end_port = int(end.strip())
                for p in range(start_port, min(end_port + 1, 65536)):
                    if 1 <= p <= 65535:
                        ports.add(p)
            except ValueError:
                pass
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass

    return sorted(list(ports))


def get_service_name(port: int) -> Optional[str]:
    """Get common service name for a port."""
    return SERVICE_PORTS.get(port)


# =============================================================================
# Scan Techniques
# =============================================================================

class ScanTechnique(ABC):
    """Abstract base class for port scanning techniques."""

    @abstractmethod
    def scan_port(self, target: str, port: int, config: ScanConfig) -> PortResult:
        """Scan a single port."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return technique name."""
        pass

    @property
    @abstractmethod
    def requires_root(self) -> bool:
        """Whether this technique requires root privileges."""
        pass


class TCPConnectScan(ScanTechnique):
    """
    TCP Connect scan - Full TCP handshake.

    Most reliable but also most detectable.
    Does not require elevated privileges.
    """

    @property
    def name(self) -> str:
        return "TCP Connect"

    @property
    def requires_root(self) -> bool:
        return False

    def scan_port(self, target: str, port: int, config: ScanConfig) -> PortResult:
        """Perform full TCP connect scan on a port."""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            result = sock.connect_ex((target, port))

            response_time = time.time() - start_time

            if result == 0:
                # Port is open
                banner = None
                if config.banner_grab:
                    banner = self._grab_banner(sock, port)
                sock.close()

                return PortResult(
                    port=port,
                    state=PortState.OPEN,
                    protocol="tcp",
                    service=get_service_name(port),
                    banner=banner,
                    response_time=response_time
                )
            else:
                sock.close()
                # Distinguish between closed and filtered
                if result == 111:  # Connection refused
                    return PortResult(port=port, state=PortState.CLOSED, protocol="tcp")
                else:
                    return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")

        except socket.timeout:
            return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")
        except socket.error:
            return PortResult(port=port, state=PortState.FILTERED, protocol="tcp")

    def _grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            # Send probe based on common services
            probes = {
                80: b"HEAD / HTTP/1.0\r\n\r\n",
                443: b"",  # HTTPS needs TLS
                22: b"",   # SSH sends banner first
                21: b"",   # FTP sends banner first
                25: b"",   # SMTP sends banner first
            }

            probe = probes.get(port, b"")
            if probe:
                sock.send(probe)

            sock.settimeout(2.0)
            banner = sock.recv(1024)
            return banner.decode('utf-8', errors='ignore').strip()[:200]
        except Exception:
            return None


class TCPSYNScan(ScanTechnique):
    """
    TCP SYN scan (Half-open scan).

    Stealthier than connect scan as it doesn't complete the handshake.
    Requires elevated privileges for raw sockets.
    Note: This implementation falls back to connect scan without privileges.
    """

    @property
    def name(self) -> str:
        return "TCP SYN"

    @property
    def requires_root(self) -> bool:
        return True

    def scan_port(self, target: str, port: int, config: ScanConfig) -> PortResult:
        """
        Perform SYN scan on a port.

        Note: Full SYN scan requires raw socket privileges.
        This implementation attempts raw sockets and falls back to connect scan.
        """
        # Attempt raw socket SYN scan
        try:
            return self._raw_syn_scan(target, port, config)
        except (PermissionError, OSError):
            # Fall back to connect scan
            connect_scan = TCPConnectScan()
            result = connect_scan.scan_port(target, port, config)
            result.service = f"{result.service or ''} (fallback)"
            return result

    def _raw_syn_scan(self, target: str, port: int, config: ScanConfig) -> PortResult:
        """Raw socket SYN scan implementation."""
        # This would require raw socket implementation
        # For safety and compatibility, raising to trigger fallback
        raise PermissionError("Raw socket SYN scan requires privileges")


class UDPScan(ScanTechnique):
    """
    UDP scan for UDP services.

    Sends UDP packets and analyzes responses.
    Slower and less reliable than TCP scanning.
    """

    @property
    def name(self) -> str:
        return "UDP"

    @property
    def requires_root(self) -> bool:
        return False

    def scan_port(self, target: str, port: int, config: ScanConfig) -> PortResult:
        """Perform UDP scan on a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(config.timeout)

            # Send empty UDP packet (some services need specific payloads)
            sock.sendto(b"\x00", (target, port))

            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                return PortResult(
                    port=port,
                    state=PortState.OPEN,
                    protocol="udp",
                    service=get_service_name(port),
                    banner=data.decode('utf-8', errors='ignore')[:100] if data else None
                )
            except socket.timeout:
                sock.close()
                # No response could mean open or filtered
                return PortResult(
                    port=port,
                    state=PortState.OPEN_FILTERED,
                    protocol="udp"
                )

        except socket.error as e:
            # ICMP port unreachable means closed
            if "refused" in str(e).lower():
                return PortResult(port=port, state=PortState.CLOSED, protocol="udp")
            return PortResult(port=port, state=PortState.FILTERED, protocol="udp")


# =============================================================================
# Port Scanner Core
# =============================================================================

class PortScanner:
    """
    Main port scanning engine with stealth and operational security features.

    Supports multiple scanning techniques, configurable delays,
    port randomization, and banner grabbing.
    """

    TECHNIQUES: Dict[ScanType, type] = {
        ScanType.TCP_CONNECT: TCPConnectScan,
        ScanType.TCP_SYN: TCPSYNScan,
        ScanType.UDP: UDPScan,
    }

    def __init__(self, config: ScanConfig):
        """
        Initialize the port scanner.

        Args:
            config: ScanConfig object with scanning parameters
        """
        self.config = config
        self.report: Optional[ScanReport] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._technique = self.TECHNIQUES.get(config.scan_type, TCPConnectScan)()

    def _resolve_target(self) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.config.target)
        except socket.gaierror:
            return None

    def _apply_jitter(self) -> None:
        """Apply random delay between port scans."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _scan_single_port(self, port: int) -> Optional[PortResult]:
        """
        Scan a single port.

        Args:
            port: Port number to scan

        Returns:
            PortResult or None if stopped
        """
        if self._stop_event.is_set():
            return None

        self._apply_jitter()

        target_ip = self.report.resolved_ip or self.config.target
        result = self._technique.scan_port(target_ip, port, self.config)

        return result

    def scan(self) -> ScanReport:
        """
        Execute the port scan.

        Returns:
            ScanReport with all results
        """
        # Initialize report
        resolved_ip = self._resolve_target()
        self.report = ScanReport(
            target=self.config.target,
            resolved_ip=resolved_ip,
            scan_type=self.config.scan_type.value,
            start_time=datetime.now()
        )

        if not resolved_ip:
            if self.config.verbose:
                print(f"[!] Could not resolve target: {self.config.target}")
            self.report.end_time = datetime.now()
            return self.report

        # Prepare ports
        ports = self.config.ports.copy()
        if self.config.randomize_ports:
            random.shuffle(ports)

        if self.config.verbose:
            print(f"[*] Scanning {len(ports)} ports on {self.config.target} ({resolved_ip})")
            print(f"[*] Scan type: {self._technique.name}")

        # Execute scan
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._scan_single_port, port): port for port in ports}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.report.results.append(result)
                            if result.state == PortState.OPEN and self.config.verbose:
                                service = result.service or "unknown"
                                print(f"[+] {result.port}/tcp open - {service}")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error scanning port {futures[future]}: {e}")

        self.report.end_time = datetime.now()
        return self.report

    def stop(self) -> None:
        """Signal the scanner to stop."""
        self._stop_event.set()


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: ScanConfig) -> None:
    """
    Display execution plan without performing any actions.

    Args:
        config: ScanConfig with planned parameters
    """
    # Resolve target for display
    try:
        resolved_ip = socket.gethostbyname(config.target)
    except socket.gaierror:
        resolved_ip = "Unable to resolve"

    technique = PortScanner.TECHNIQUES.get(config.scan_type, TCPConnectScan)()

    print("""
[PLAN MODE] Tool: port-scanner
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Target:          {config.target}")
    print(f"  Resolved IP:     {resolved_ip}")
    print(f"  Ports to scan:   {len(config.ports)}")
    print(f"  Port range:      {min(config.ports) if config.ports else 'N/A'} - {max(config.ports) if config.ports else 'N/A'}")
    print()

    print("SCAN CONFIGURATION")
    print("-" * 40)
    print(f"  Scan Type:       {technique.name}")
    print(f"  Requires Root:   {technique.requires_root}")
    print(f"  Threads:         {config.threads}")
    print(f"  Timeout:         {config.timeout}s")
    print(f"  Delay Range:     {config.delay_min}s - {config.delay_max}s")
    print(f"  Randomize Ports: {config.randomize_ports}")
    print(f"  Banner Grab:     {config.banner_grab}")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Resolve target hostname to IP address")
    print(f"  2. Initialize {config.threads} worker threads")
    if config.randomize_ports:
        print("  3. Shuffle port order for stealth")
    print(f"  4. For each of {len(config.ports)} ports:")
    print(f"     - Apply random delay ({config.delay_min}s - {config.delay_max}s)")
    print(f"     - Perform {technique.name} scan")
    if config.banner_grab:
        print("     - Attempt banner grab on open ports")
    print("  5. Aggregate results in memory")
    print()

    print("PORT PREVIEW (first 20)")
    print("-" * 40)
    preview_ports = config.ports[:20]
    for port in preview_ports:
        service = get_service_name(port) or "unknown"
        print(f"  - {port}/tcp ({service})")
    if len(config.ports) > 20:
        print(f"  ... and {len(config.ports) - 20} more ports")
    print()

    # Estimate scan time
    estimated_time = (len(config.ports) * config.timeout) / config.threads
    estimated_time += len(config.ports) * ((config.delay_min + config.delay_max) / 2) / config.threads

    print("TIME ESTIMATE")
    print("-" * 40)
    print(f"  Worst case:      {estimated_time:.1f} seconds")
    print(f"  Typical:         {estimated_time * 0.3:.1f} seconds")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)

    risk_factors = []
    risk_level = "LOW"

    if len(config.ports) > 1000:
        risk_factors.append("Large number of ports increases detection risk")
    if config.threads > 100:
        risk_factors.append("High thread count may trigger rate limiting")
    if config.delay_max < 0.01:
        risk_factors.append("Low delay increases scan speed visibility")
    if config.scan_type == ScanType.TCP_CONNECT:
        risk_factors.append("Connect scans complete full handshake (logged)")

    if len(risk_factors) >= 2:
        risk_level = "MEDIUM"
    if len(risk_factors) >= 3:
        risk_level = "HIGH"

    print(f"  Risk Level: {risk_level}")
    if risk_factors:
        for factor in risk_factors:
            print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Firewall logs will record connection attempts")
    print("  - IDS/IPS may detect port scan patterns")
    print("  - Rate limiting may slow or block the scan")
    if config.scan_type == ScanType.TCP_CONNECT:
        print("  - Application logs may record failed connections")
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
        "name": "port-scanner",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Advanced TCP/UDP port scanning tool with stealth features",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Multiple scan types (Connect, SYN, UDP)",
            "Flexible port specification",
            "Configurable threading and delays",
            "Port randomization for stealth",
            "Banner grabbing capability",
            "Service identification",
            "Planning mode for operation preview"
        ],
        "scan_types": {
            "connect": "Full TCP handshake - most reliable, most detectable",
            "syn": "Half-open scan - stealthier, requires privileges",
            "udp": "UDP port scan - for UDP services"
        },
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP address or hostname"
            },
            "--ports": {
                "type": "string",
                "default": "top20",
                "description": "Port specification (e.g., 80, 1-1024, 22,80,443, top20, top100, all)"
            },
            "--scan-type": {
                "type": "string",
                "default": "connect",
                "choices": ["connect", "syn", "udp"],
                "description": "Type of port scan to perform"
            },
            "--timeout": {
                "type": "float",
                "default": 1.0,
                "description": "Connection timeout in seconds"
            },
            "--threads": {
                "type": "int",
                "default": 50,
                "description": "Number of concurrent threads"
            },
            "--delay-min": {
                "type": "float",
                "default": 0.0,
                "description": "Minimum delay between scans (seconds)"
            },
            "--delay-max": {
                "type": "float",
                "default": 0.05,
                "description": "Maximum delay between scans (seconds)"
            },
            "--banner": {
                "type": "bool",
                "default": False,
                "description": "Attempt to grab service banners"
            },
            "--no-randomize": {
                "type": "bool",
                "default": False,
                "description": "Disable port order randomization"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without scanning"
            },
            "--verbose": {
                "type": "bool",
                "default": False,
                "description": "Enable verbose output"
            }
        },
        "examples": [
            {
                "command": "python tool.py 192.168.1.1 --plan",
                "description": "Preview scan of top 20 ports"
            },
            {
                "command": "python tool.py target.com --ports 1-1024 --threads 100",
                "description": "Fast scan of first 1024 ports"
            },
            {
                "command": "python tool.py 10.0.0.1 --ports top100 --banner --delay-max 1",
                "description": "Stealthy scan with banner grabbing"
            }
        ],
        "opsec_notes": [
            "Connect scans complete full TCP handshake and are logged",
            "Port randomization helps avoid pattern detection",
            "Use delays to reduce scan footprint",
            "Results stored in-memory by default"
        ]
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Port Scanner - Advanced TCP/UDP Port Scanning Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port Specifications:
  Single port:    80
  Range:          1-1024
  List:           22,80,443
  Combined:       22,80,443,8000-8100
  Keywords:       top20, top100, all

Examples:
  %(prog)s 192.168.1.1 --plan
  %(prog)s target.com --ports 1-1024 --threads 100
  %(prog)s 10.0.0.1 --ports top100 --banner --verbose

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-P", "--ports",
        default="top20",
        help="Port specification (default: top20)"
    )

    parser.add_argument(
        "-s", "--scan-type",
        choices=["connect", "syn", "udp"],
        default="connect",
        help="Type of scan (default: connect)"
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
        help=f"Minimum delay between scans (default: {DEFAULT_DELAY_MIN})"
    )

    parser.add_argument(
        "--delay-max",
        type=float,
        default=DEFAULT_DELAY_MAX,
        help=f"Maximum delay between scans (default: {DEFAULT_DELAY_MAX})"
    )

    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Attempt to grab service banners"
    )

    parser.add_argument(
        "--no-randomize",
        action="store_true",
        help="Disable port order randomization"
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


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Parse ports
    ports = parse_port_specification(args.ports)
    if not ports:
        print("[!] No valid ports specified")
        return 1

    # Map scan type
    scan_type_map = {
        "connect": ScanType.TCP_CONNECT,
        "syn": ScanType.TCP_SYN,
        "udp": ScanType.UDP
    }
    scan_type = scan_type_map.get(args.scan_type, ScanType.TCP_CONNECT)

    # Build configuration
    config = ScanConfig(
        target=args.target,
        ports=ports,
        scan_type=scan_type,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        banner_grab=args.banner,
        randomize_ports=not args.no_randomize,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute scan
    print(f"[*] Port Scanner starting...")
    print(f"[*] Target: {config.target}")
    print(f"[*] Ports: {len(config.ports)}")

    scanner = PortScanner(config)

    try:
        report = scanner.scan()

        # Display results
        print()
        print("=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Target:       {report.target}")
        print(f"Resolved IP:  {report.resolved_ip}")
        print(f"Scan Type:    {report.scan_type}")
        print(f"Duration:     {(report.end_time - report.start_time).total_seconds():.2f}s")
        print()

        open_ports = report.get_open_ports()
        filtered_ports = report.get_filtered_ports()

        print(f"Open ports:     {len(open_ports)}")
        print(f"Filtered ports: {len(filtered_ports)}")
        print()

        if open_ports:
            print("OPEN PORTS:")
            print("-" * 60)
            for result in sorted(open_ports, key=lambda x: x.port):
                service = result.service or "unknown"
                banner_str = f" - {result.banner[:50]}..." if result.banner else ""
                print(f"  {result.port}/{result.protocol} open  {service}{banner_str}")

        # Output to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(report.to_dict(), f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
