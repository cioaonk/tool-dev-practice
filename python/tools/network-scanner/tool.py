#!/usr/bin/env python3
"""
Network Scanner - Stealthy Network Discovery Tool
=================================================

A comprehensive network scanning utility designed for authorized penetration testing.
Emphasizes stealth, in-memory operation, and operational security.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized access to computer systems is illegal.
"""

import argparse
import ipaddress
import socket
import struct
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Generator, Any
from datetime import datetime
from abc import ABC, abstractmethod


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 10
DEFAULT_DELAY_MIN = 0.0
DEFAULT_DELAY_MAX = 0.1
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ScanResult:
    """Represents a single host scan result."""
    ip: str
    is_alive: bool
    response_time: Optional[float] = None
    method: str = "unknown"
    hostname: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "ip": self.ip,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "method": self.method,
            "hostname": self.hostname,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ScanConfig:
    """Configuration for network scanning operations."""
    targets: List[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    resolve_hostnames: bool = False
    scan_methods: List[str] = field(default_factory=lambda: ["tcp"])
    tcp_ports: List[int] = field(default_factory=lambda: [80, 443, 22])
    verbose: bool = False
    plan_mode: bool = False


# =============================================================================
# Scanning Techniques
# =============================================================================

class ScanTechnique(ABC):
    """Abstract base class for scan techniques."""

    @abstractmethod
    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Execute the scan against a single IP."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the technique name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return technique description."""
        pass


class TCPConnectScan(ScanTechnique):
    """TCP Connect scan - checks if common ports are open."""

    @property
    def name(self) -> str:
        return "tcp_connect"

    @property
    def description(self) -> str:
        return "TCP Connect scan using socket connections to detect live hosts"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Perform TCP connect scan on specified ports."""
        start_time = time.time()

        for port in config.tcp_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    response_time = time.time() - start_time
                    hostname = None
                    if config.resolve_hostnames:
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except socket.herror:
                            pass

                    return ScanResult(
                        ip=ip,
                        is_alive=True,
                        response_time=response_time,
                        method=f"tcp_connect:{port}",
                        hostname=hostname
                    )
            except socket.error:
                continue

        return ScanResult(ip=ip, is_alive=False, method="tcp_connect")


class ARPScan(ScanTechnique):
    """ARP-based scanning for local network discovery."""

    @property
    def name(self) -> str:
        return "arp"

    @property
    def description(self) -> str:
        return "ARP scan for local network host discovery (requires privileges)"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Perform ARP scan (requires raw socket privileges)."""
        # Note: Full ARP implementation requires raw sockets and elevated privileges
        # This is a placeholder that falls back to TCP scanning
        tcp_scan = TCPConnectScan()
        result = tcp_scan.scan(ip, config)
        result.method = "arp_fallback_tcp"
        return result


class DNSResolutionScan(ScanTechnique):
    """DNS-based host discovery through reverse lookups."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS reverse lookup scan to identify hosts with PTR records"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Perform DNS reverse lookup to detect host."""
        start_time = time.time()

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            response_time = time.time() - start_time

            return ScanResult(
                ip=ip,
                is_alive=True,
                response_time=response_time,
                method="dns_ptr",
                hostname=hostname
            )
        except socket.herror:
            return ScanResult(ip=ip, is_alive=False, method="dns_ptr")


# =============================================================================
# Network Scanner Core
# =============================================================================

class NetworkScanner:
    """
    Main network scanning engine with stealth and operational security features.

    This class coordinates network host discovery using various techniques
    while maintaining operational security through configurable delays,
    randomization, and in-memory result handling.
    """

    TECHNIQUES: Dict[str, type] = {
        "tcp": TCPConnectScan,
        "arp": ARPScan,
        "dns": DNSResolutionScan,
    }

    def __init__(self, config: ScanConfig):
        """
        Initialize the network scanner.

        Args:
            config: ScanConfig object with scanning parameters
        """
        self.config = config
        self.results: List[ScanResult] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def _expand_targets(self) -> Generator[str, None, None]:
        """
        Expand target specifications into individual IP addresses.

        Supports:
        - Single IPs: 192.168.1.1
        - CIDR notation: 192.168.1.0/24
        - Ranges: 192.168.1.1-254

        Yields:
            Individual IP addresses as strings
        """
        for target in self.config.targets:
            try:
                # Try CIDR notation
                if "/" in target:
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        yield str(ip)
                # Try range notation
                elif "-" in target:
                    base, end = target.rsplit(".", 1)[0], target.rsplit(".", 1)[1]
                    if "-" in target.rsplit(".", 1)[1]:
                        start, end = target.rsplit(".", 1)[1].split("-")
                        base = target.rsplit(".", 1)[0]
                        for i in range(int(start), int(end) + 1):
                            yield f"{base}.{i}"
                    else:
                        yield target
                else:
                    # Single IP or hostname
                    yield target
            except ValueError as e:
                if self.config.verbose:
                    print(f"[!] Invalid target specification: {target} - {e}")

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth operations."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _scan_host(self, ip: str) -> Optional[ScanResult]:
        """
        Scan a single host using configured techniques.

        Args:
            ip: Target IP address

        Returns:
            ScanResult if host responds, None if scan was stopped
        """
        if self._stop_event.is_set():
            return None

        self._apply_jitter()

        for method in self.config.scan_methods:
            if method in self.TECHNIQUES:
                technique = self.TECHNIQUES[method]()
                result = technique.scan(ip, self.config)

                if result.is_alive:
                    return result

        # Return negative result
        return ScanResult(ip=ip, is_alive=False, method="all_methods")

    def scan(self) -> List[ScanResult]:
        """
        Execute the network scan.

        Returns:
            List of ScanResult objects for all scanned hosts
        """
        targets = list(self._expand_targets())

        if self.config.verbose:
            print(f"[*] Scanning {len(targets)} hosts with {self.config.threads} threads")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._scan_host, ip): ip for ip in targets}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.results.append(result)
                            if result.is_alive and self.config.verbose:
                                print(f"[+] {result.ip} is alive ({result.method})")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error scanning {futures[future]}: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the scanner to stop operations."""
        self._stop_event.set()

    def get_live_hosts(self) -> List[ScanResult]:
        """Return only hosts that responded."""
        return [r for r in self.results if r.is_alive]


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: ScanConfig) -> None:
    """
    Display execution plan without performing any actions.

    Args:
        config: ScanConfig with planned parameters
    """
    scanner = NetworkScanner(config)
    targets = list(scanner._expand_targets())

    print("""
[PLAN MODE] Tool: network-scanner
================================================================================
""")

    print("OPERATION SUMMARY")
    print("-" * 40)
    print(f"  Target Specification: {', '.join(config.targets)}")
    print(f"  Total IPs to scan:    {len(targets)}")
    print(f"  Scan Methods:         {', '.join(config.scan_methods)}")
    print(f"  TCP Ports:            {config.tcp_ports}")
    print(f"  Threads:              {config.threads}")
    print(f"  Timeout:              {config.timeout}s")
    print(f"  Delay Range:          {config.delay_min}s - {config.delay_max}s")
    print(f"  Resolve Hostnames:    {config.resolve_hostnames}")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Parse and expand target specifications")
    print("  2. Initialize thread pool with {} workers".format(config.threads))
    print("  3. For each target IP:")
    for method in config.scan_methods:
        if method == "tcp":
            print(f"     - Attempt TCP connections to ports {config.tcp_ports}")
        elif method == "arp":
            print("     - Send ARP request (requires privileges)")
        elif method == "dns":
            print("     - Perform reverse DNS lookup")
    print("  4. Apply random delay ({:.2f}s - {:.2f}s) between scans".format(
        config.delay_min, config.delay_max))
    print("  5. Aggregate and report results in-memory")
    print()

    print("TARGET PREVIEW (first 10)")
    print("-" * 40)
    for ip in targets[:10]:
        print(f"  - {ip}")
    if len(targets) > 10:
        print(f"  ... and {len(targets) - 10} more")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)

    # Calculate risk level
    risk_factors = []
    if len(targets) > 100:
        risk_factors.append("Large scan scope")
    if "arp" in config.scan_methods:
        risk_factors.append("ARP scanning may be logged")
    if config.delay_max < 0.1:
        risk_factors.append("Low delay may trigger rate limiting")
    if config.threads > 50:
        risk_factors.append("High thread count increases detection risk")

    risk_level = "LOW"
    if len(risk_factors) >= 2:
        risk_level = "MEDIUM"
    if len(risk_factors) >= 3:
        risk_level = "HIGH"

    print(f"  Risk Level: {risk_level}")
    if risk_factors:
        print("  Risk Factors:")
        for factor in risk_factors:
            print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Network IDS/IPS may detect port scanning patterns")
    print("  - Firewall logs will record connection attempts")
    print("  - Host-based security tools may alert on connection probes")
    print()

    print("OPSEC CONSIDERATIONS")
    print("-" * 40)
    print("  - Results stored in-memory only (no disk artifacts)")
    print("  - Configurable jitter between requests")
    print("  - Uses standard Python sockets (no raw packets without privilege)")
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
        "name": "network-scanner",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Stealthy network host discovery tool for penetration testing",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Multiple scanning techniques (TCP, ARP, DNS)",
            "CIDR and range notation support",
            "Configurable threading and delays",
            "In-memory result storage",
            "Planning mode for operation preview",
            "Hostname resolution option",
        ],
        "arguments": {
            "targets": {
                "type": "list",
                "required": True,
                "description": "Target IPs, CIDR ranges, or hostnames"
            },
            "--timeout": {
                "type": "float",
                "default": 2.0,
                "description": "Connection timeout in seconds"
            },
            "--threads": {
                "type": "int",
                "default": 10,
                "description": "Number of concurrent scanning threads"
            },
            "--methods": {
                "type": "list",
                "default": ["tcp"],
                "choices": ["tcp", "arp", "dns"],
                "description": "Scanning techniques to use"
            },
            "--ports": {
                "type": "list",
                "default": [80, 443, 22],
                "description": "TCP ports for connect scanning"
            },
            "--delay-min": {
                "type": "float",
                "default": 0.0,
                "description": "Minimum delay between scans (seconds)"
            },
            "--delay-max": {
                "type": "float",
                "default": 0.1,
                "description": "Maximum delay between scans (seconds)"
            },
            "--resolve": {
                "type": "bool",
                "default": False,
                "description": "Resolve hostnames for live hosts"
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
                "command": "python tool.py 192.168.1.0/24 --plan",
                "description": "Preview scan of a /24 network"
            },
            {
                "command": "python tool.py 192.168.1.1-50 --methods tcp dns --threads 5",
                "description": "Scan IP range with multiple methods"
            },
            {
                "command": "python tool.py 10.0.0.0/8 --delay-min 1 --delay-max 5 --threads 2",
                "description": "Slow, stealthy scan of large network"
            }
        ],
        "opsec_notes": [
            "Results are kept in memory to minimize disk artifacts",
            "Use --delay flags to reduce detection probability",
            "TCP connect scans are logged by target systems",
            "Consider network position and monitoring capabilities"
        ]
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Stealthy Host Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24 --plan
  %(prog)s 192.168.1.1-254 --methods tcp dns
  %(prog)s 10.0.0.1 10.0.0.2 10.0.0.3 --resolve --verbose

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Target IPs, CIDR ranges, or IP ranges (e.g., 192.168.1.1-254)"
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
        "-m", "--methods",
        nargs="+",
        choices=["tcp", "arp", "dns"],
        default=["tcp"],
        help="Scanning methods to use (default: tcp)"
    )

    parser.add_argument(
        "-P", "--ports",
        nargs="+",
        type=int,
        default=[80, 443, 22],
        help="TCP ports for connect scanning (default: 80 443 22)"
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
        "-r", "--resolve",
        action="store_true",
        help="Resolve hostnames for discovered hosts"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without performing scan"
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

    # Build configuration
    config = ScanConfig(
        targets=args.targets,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        resolve_hostnames=args.resolve,
        scan_methods=args.methods,
        tcp_ports=args.ports,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute scan
    print("[*] Network Scanner starting...")
    print(f"[*] Targets: {', '.join(config.targets)}")

    scanner = NetworkScanner(config)

    try:
        results = scanner.scan()
        live_hosts = scanner.get_live_hosts()

        print()
        print("=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Total hosts scanned: {len(results)}")
        print(f"Live hosts found:    {len(live_hosts)}")
        print()

        if live_hosts:
            print("LIVE HOSTS:")
            print("-" * 60)
            for host in live_hosts:
                hostname_str = f" ({host.hostname})" if host.hostname else ""
                time_str = f" [{host.response_time:.3f}s]" if host.response_time else ""
                print(f"  {host.ip}{hostname_str}{time_str} - {host.method}")

        # Output to file if requested
        if args.output:
            import json
            output_data = {
                "scan_time": datetime.now().isoformat(),
                "config": {
                    "targets": config.targets,
                    "methods": config.scan_methods,
                    "ports": config.tcp_ports
                },
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
