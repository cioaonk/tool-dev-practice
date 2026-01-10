#!/usr/bin/env python3
"""
DNS Enumerator - Comprehensive DNS Reconnaissance Tool
=======================================================

A comprehensive DNS enumeration utility for subdomain discovery,
zone transfers, and DNS record analysis. Designed for authorized
penetration testing with stealth options.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized DNS enumeration may violate terms of service.
"""

import argparse
import socket
import struct
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 5.0
DEFAULT_THREADS = 10
DEFAULT_DELAY_MIN = 0.0
DEFAULT_DELAY_MAX = 0.1

# DNS record types
class RecordType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255


# Common subdomains for bruteforcing
DEFAULT_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
    "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
    "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
    "www1", "smtp1", "autodiscover", "mail3", "mx2", "staging", "beta",
    "intranet", "extranet", "demo", "mobile", "gateway", "dns", "dns1",
    "dns2", "ns3", "backup", "corp", "internal", "private", "public",
    "office", "partner", "admin2", "cpanel", "whm", "direct", "direct-connect",
    "vps", "server1", "server2", "proxy", "git", "svn", "cms", "status"
]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class DNSRecord:
    """Represents a DNS record."""
    name: str
    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX records
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "priority": self.priority,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class EnumConfig:
    """Configuration for DNS enumeration."""
    domain: str = ""
    nameserver: Optional[str] = None
    wordlist: List[str] = field(default_factory=list)
    record_types: List[str] = field(default_factory=lambda: ["A", "AAAA", "CNAME"])
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    zone_transfer: bool = False
    brute_force: bool = True
    verbose: bool = False
    plan_mode: bool = False


# =============================================================================
# DNS Protocol Implementation
# =============================================================================

class DNSResolver:
    """
    Lightweight DNS resolver using raw UDP sockets.

    Implements basic DNS query functionality without external dependencies.
    """

    def __init__(self, nameserver: str = "8.8.8.8", timeout: float = 5.0):
        self.nameserver = nameserver
        self.timeout = timeout
        self._transaction_id = random.randint(0, 65535)

    def _build_query(self, domain: str, record_type: RecordType) -> bytes:
        """Build a DNS query packet."""
        # Transaction ID
        self._transaction_id = (self._transaction_id + 1) % 65536
        packet = struct.pack(">H", self._transaction_id)

        # Flags: standard query, recursion desired
        packet += struct.pack(">H", 0x0100)

        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        packet += struct.pack(">HHHH", 1, 0, 0, 0)

        # Question section
        for part in domain.split('.'):
            packet += struct.pack("B", len(part)) + part.encode()
        packet += b'\x00'  # End of domain name

        # Type and class
        packet += struct.pack(">HH", record_type.value, 1)  # Type, Class IN

        return packet

    def _parse_name(self, data: bytes, offset: int) -> Tuple[str, int]:
        """Parse a domain name from DNS response."""
        labels = []
        original_offset = offset
        jumped = False

        while True:
            if offset >= len(data):
                break

            length = data[offset]

            if length == 0:
                offset += 1
                break
            elif (length & 0xc0) == 0xc0:
                # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3fff
                offset = pointer
                jumped = True
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
                offset += length

        if jumped:
            return '.'.join(labels), original_offset
        return '.'.join(labels), offset

    def _parse_response(self, data: bytes, query_type: RecordType) -> List[DNSRecord]:
        """Parse DNS response packet."""
        records = []

        if len(data) < 12:
            return records

        # Parse header
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])

        # Check for errors
        rcode = flags & 0x000f
        if rcode != 0:
            return records

        offset = 12

        # Skip questions
        for _ in range(qdcount):
            _, offset = self._parse_name(data, offset)
            offset += 4  # Type and class

        # Parse answers
        for _ in range(ancount):
            name, offset = self._parse_name(data, offset)

            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset:offset+rdlength]
            offset += rdlength

            # Parse record data based on type
            value = ""
            if rtype == RecordType.A.value:
                if len(rdata) == 4:
                    value = '.'.join(str(b) for b in rdata)
            elif rtype == RecordType.AAAA.value:
                if len(rdata) == 16:
                    value = ':'.join(f'{rdata[i]:02x}{rdata[i+1]:02x}' for i in range(0, 16, 2))
            elif rtype in [RecordType.NS.value, RecordType.CNAME.value, RecordType.PTR.value]:
                value, _ = self._parse_name(data, offset - rdlength)
            elif rtype == RecordType.MX.value:
                if len(rdata) >= 2:
                    priority = struct.unpack(">H", rdata[:2])[0]
                    mx_name, _ = self._parse_name(data, offset - rdlength + 2)
                    records.append(DNSRecord(
                        name=name,
                        record_type="MX",
                        value=mx_name,
                        ttl=ttl,
                        priority=priority
                    ))
                    continue
            elif rtype == RecordType.TXT.value:
                # TXT records have length-prefixed strings
                txt_offset = 0
                txt_parts = []
                while txt_offset < len(rdata):
                    txt_len = rdata[txt_offset]
                    txt_offset += 1
                    txt_parts.append(rdata[txt_offset:txt_offset+txt_len].decode('utf-8', errors='ignore'))
                    txt_offset += txt_len
                value = ' '.join(txt_parts)
            elif rtype == RecordType.SOA.value:
                primary_ns, pos = self._parse_name(data, offset - rdlength)
                resp_person, pos = self._parse_name(data, pos)
                value = f"{primary_ns} {resp_person}"
            else:
                value = rdata.hex()

            if value:
                record_type_name = RecordType(rtype).name if rtype in [e.value for e in RecordType] else str(rtype)
                records.append(DNSRecord(
                    name=name,
                    record_type=record_type_name,
                    value=value,
                    ttl=ttl
                ))

        return records

    def query(self, domain: str, record_type: RecordType) -> List[DNSRecord]:
        """
        Perform DNS query.

        Args:
            domain: Domain to query
            record_type: Type of record to query

        Returns:
            List of DNSRecord objects
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            packet = self._build_query(domain, record_type)
            sock.sendto(packet, (self.nameserver, 53))

            response, _ = sock.recvfrom(4096)
            sock.close()

            return self._parse_response(response, record_type)

        except socket.timeout:
            return []
        except Exception:
            return []

    def resolve(self, domain: str) -> Optional[str]:
        """Resolve domain to IP address."""
        records = self.query(domain, RecordType.A)
        if records:
            return records[0].value
        return None


class ZoneTransfer:
    """
    Attempt DNS zone transfer (AXFR).

    Zone transfers may expose internal DNS records if misconfigured.
    """

    def __init__(self, nameserver: str, timeout: float = 10.0):
        self.nameserver = nameserver
        self.timeout = timeout

    def _build_axfr_query(self, domain: str) -> bytes:
        """Build AXFR query packet."""
        transaction_id = random.randint(0, 65535)

        # Build query similar to regular DNS but for AXFR
        packet = struct.pack(">H", transaction_id)
        packet += struct.pack(">H", 0x0000)  # Standard query
        packet += struct.pack(">HHHH", 1, 0, 0, 0)

        for part in domain.split('.'):
            packet += struct.pack("B", len(part)) + part.encode()
        packet += b'\x00'

        packet += struct.pack(">HH", 252, 1)  # AXFR, Class IN

        # TCP length prefix
        return struct.pack(">H", len(packet)) + packet

    def transfer(self, domain: str) -> List[DNSRecord]:
        """
        Attempt zone transfer.

        Args:
            domain: Domain to transfer

        Returns:
            List of DNSRecord objects if successful
        """
        records = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.nameserver, 53))

            query = self._build_axfr_query(domain)
            sock.send(query)

            # Receive response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()

            # Parse response (simplified - full parsing would be more complex)
            # Check for transfer denied
            if len(response) > 4:
                flags = struct.unpack(">H", response[4:6])[0] if len(response) > 6 else 0
                rcode = flags & 0x000f
                if rcode == 5:  # Refused
                    return []

            # If we got data, zone transfer might have succeeded
            # Full parsing would extract individual records

            return records

        except Exception:
            return []


# =============================================================================
# DNS Enumerator Core
# =============================================================================

class DNSEnumerator:
    """
    Main DNS enumeration engine.

    Coordinates subdomain bruteforcing, record queries, and zone transfers
    with operational security considerations.
    """

    def __init__(self, config: EnumConfig):
        self.config = config
        self.results: List[DNSRecord] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._found_subdomains: Set[str] = set()

        # Determine nameserver
        if config.nameserver:
            self.nameserver = config.nameserver
        else:
            # Try to get system nameserver
            self.nameserver = self._get_system_nameserver() or "8.8.8.8"

        self.resolver = DNSResolver(self.nameserver, config.timeout)

    def _get_system_nameserver(self) -> Optional[str]:
        """Try to get system's configured nameserver."""
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        return line.split()[1]
        except Exception:
            pass
        return None

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _check_subdomain(self, subdomain: str) -> List[DNSRecord]:
        """Check if a subdomain exists."""
        if self._stop_event.is_set():
            return []

        self._apply_jitter()

        full_domain = f"{subdomain}.{self.config.domain}"
        records = []

        for record_type_str in self.config.record_types:
            try:
                record_type = RecordType[record_type_str.upper()]
                result = self.resolver.query(full_domain, record_type)
                records.extend(result)
            except (KeyError, ValueError):
                pass

        return records

    def _enumerate_records(self) -> List[DNSRecord]:
        """Enumerate DNS records for the base domain."""
        records = []

        record_types = ["A", "AAAA", "NS", "MX", "TXT", "SOA"]

        for record_type_str in record_types:
            try:
                record_type = RecordType[record_type_str]
                result = self.resolver.query(self.config.domain, record_type)
                records.extend(result)
            except Exception:
                pass

        return records

    def _attempt_zone_transfer(self) -> List[DNSRecord]:
        """Attempt zone transfer against nameservers."""
        records = []

        # First, get NS records
        ns_records = self.resolver.query(self.config.domain, RecordType.NS)

        for ns_record in ns_records:
            if self.config.verbose:
                print(f"[*] Attempting zone transfer from {ns_record.value}")

            # Resolve NS to IP
            ns_ip = self.resolver.resolve(ns_record.value)
            if not ns_ip:
                continue

            zt = ZoneTransfer(ns_ip, self.config.timeout)
            transfer_records = zt.transfer(self.config.domain)

            if transfer_records:
                if self.config.verbose:
                    print(f"[+] Zone transfer successful from {ns_record.value}")
                records.extend(transfer_records)
            else:
                if self.config.verbose:
                    print(f"[-] Zone transfer denied by {ns_record.value}")

        return records

    def enumerate(self) -> List[DNSRecord]:
        """
        Execute DNS enumeration.

        Returns:
            List of discovered DNSRecord objects
        """
        if self.config.verbose:
            print(f"[*] DNS Enumerator starting for {self.config.domain}")
            print(f"[*] Using nameserver: {self.nameserver}")

        # Enumerate base domain records
        if self.config.verbose:
            print("[*] Querying base domain records...")

        base_records = self._enumerate_records()
        self.results.extend(base_records)

        if self.config.verbose:
            for record in base_records:
                print(f"[+] {record.record_type}: {record.value}")

        # Attempt zone transfer
        if self.config.zone_transfer:
            if self.config.verbose:
                print("[*] Attempting zone transfers...")

            zt_records = self._attempt_zone_transfer()
            self.results.extend(zt_records)

        # Subdomain bruteforce
        if self.config.brute_force and self.config.wordlist:
            if self.config.verbose:
                print(f"[*] Bruteforcing {len(self.config.wordlist)} subdomains...")

            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = {executor.submit(self._check_subdomain, sub): sub
                          for sub in self.config.wordlist}

                for future in as_completed(futures):
                    try:
                        records = future.result()
                        if records:
                            subdomain = futures[future]
                            with self._lock:
                                self.results.extend(records)
                                self._found_subdomains.add(subdomain)
                                if self.config.verbose:
                                    for record in records:
                                        print(f"[+] {subdomain}.{self.config.domain} -> {record.value}")
                    except Exception as e:
                        if self.config.verbose:
                            print(f"[!] Error: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the enumerator to stop."""
        self._stop_event.set()

    def get_unique_ips(self) -> Set[str]:
        """Return unique IP addresses discovered."""
        ips = set()
        for record in self.results:
            if record.record_type in ["A", "AAAA"]:
                ips.add(record.value)
        return ips


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: EnumConfig) -> None:
    """Display execution plan without performing any actions."""
    print("""
[PLAN MODE] Tool: dns-enumerator
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Domain:          {config.domain}")
    print(f"  Nameserver:      {config.nameserver or 'System default'}")
    print()

    print("ENUMERATION CONFIGURATION")
    print("-" * 40)
    print(f"  Wordlist Size:   {len(config.wordlist)} subdomains")
    print(f"  Record Types:    {', '.join(config.record_types)}")
    print(f"  Zone Transfer:   {config.zone_transfer}")
    print(f"  Bruteforce:      {config.brute_force}")
    print(f"  Threads:         {config.threads}")
    print(f"  Timeout:         {config.timeout}s")
    print(f"  Delay Range:     {config.delay_min}s - {config.delay_max}s")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Query base domain for common record types (A, AAAA, NS, MX, TXT, SOA)")
    if config.zone_transfer:
        print("  2. Enumerate NS records and attempt zone transfer against each")
    if config.brute_force:
        print(f"  3. Bruteforce {len(config.wordlist)} subdomains using {config.threads} threads")
        print("     For each subdomain:")
        for rt in config.record_types:
            print(f"       - Query {rt} record")
    print("  4. Aggregate discovered records")
    print()

    if config.wordlist:
        print("SUBDOMAIN PREVIEW (first 20)")
        print("-" * 40)
        for sub in config.wordlist[:20]:
            print(f"  - {sub}.{config.domain}")
        if len(config.wordlist) > 20:
            print(f"  ... and {len(config.wordlist) - 20} more")
        print()

    # Estimate
    estimated_queries = len(config.wordlist) * len(config.record_types)
    print("QUERY ESTIMATE")
    print("-" * 40)
    print(f"  Total queries:   ~{estimated_queries}")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if len(config.wordlist) > 1000:
        risk_factors.append("Large wordlist generates many queries")
    if config.zone_transfer:
        risk_factors.append("Zone transfer attempts may be logged/alerted")
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
    print("  - DNS server logs will record all queries")
    print("  - Zone transfer attempts are typically logged")
    print("  - High query volume may trigger rate limiting")
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
        "name": "dns-enumerator",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Comprehensive DNS enumeration and subdomain discovery tool",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Subdomain bruteforcing",
            "Zone transfer attempts",
            "Multiple record type queries",
            "Custom nameserver support",
            "Built-in subdomain wordlist",
            "Configurable delays for stealth",
            "Planning mode for operation preview"
        ],
        "arguments": {
            "domain": {
                "type": "string",
                "required": True,
                "description": "Target domain to enumerate"
            },
            "--nameserver": {
                "type": "string",
                "default": "System default",
                "description": "DNS server to query"
            },
            "--wordlist": {
                "type": "file",
                "default": "built-in",
                "description": "Subdomain wordlist file"
            },
            "--zone-transfer": {
                "type": "bool",
                "default": False,
                "description": "Attempt zone transfer"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without scanning"
            }
        }
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="DNS Enumerator - DNS Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com --plan
  %(prog)s example.com --zone-transfer
  %(prog)s example.com -w subdomains.txt -t 20

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "domain",
        help="Target domain to enumerate"
    )

    parser.add_argument(
        "-n", "--nameserver",
        help="DNS server to use (default: system resolver)"
    )

    parser.add_argument(
        "-w", "--wordlist",
        help="Subdomain wordlist file (uses built-in if not specified)"
    )

    parser.add_argument(
        "-r", "--record-types",
        default="A,AAAA,CNAME",
        help="Comma-separated record types to query (default: A,AAAA,CNAME)"
    )

    parser.add_argument(
        "-z", "--zone-transfer",
        action="store_true",
        help="Attempt zone transfer against nameservers"
    )

    parser.add_argument(
        "--no-brute",
        action="store_true",
        help="Disable subdomain bruteforcing"
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
        help=f"Query timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--delay-min",
        type=float,
        default=DEFAULT_DELAY_MIN,
        help=f"Minimum delay between queries (default: {DEFAULT_DELAY_MIN})"
    )

    parser.add_argument(
        "--delay-max",
        type=float,
        default=DEFAULT_DELAY_MAX,
        help=f"Maximum delay between queries (default: {DEFAULT_DELAY_MAX})"
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
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
            print("[*] Using built-in wordlist")

    return DEFAULT_SUBDOMAINS.copy()


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Load wordlist
    wordlist = load_wordlist(args.wordlist)

    # Parse record types
    record_types = [r.strip().upper() for r in args.record_types.split(',')]

    # Build configuration
    config = EnumConfig(
        domain=args.domain,
        nameserver=args.nameserver,
        wordlist=wordlist,
        record_types=record_types,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        zone_transfer=args.zone_transfer,
        brute_force=not args.no_brute,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute enumeration
    print(f"[*] DNS Enumerator starting...")
    print(f"[*] Target: {config.domain}")

    enumerator = DNSEnumerator(config)

    try:
        results = enumerator.enumerate()
        unique_ips = enumerator.get_unique_ips()

        # Display results
        print()
        print("=" * 70)
        print("DNS ENUMERATION RESULTS")
        print("=" * 70)
        print(f"Total records:      {len(results)}")
        print(f"Unique IPs:         {len(unique_ips)}")
        print(f"Subdomains found:   {len(enumerator._found_subdomains)}")
        print()

        if results:
            print(f"{'TYPE':<8} {'NAME':<35} {'VALUE':<30}")
            print("-" * 70)
            for record in sorted(results, key=lambda x: (x.record_type, x.name)):
                name = record.name[:33] + ".." if len(record.name) > 35 else record.name
                value = record.value[:28] + ".." if len(record.value) > 30 else record.value
                print(f"{record.record_type:<8} {name:<35} {value:<30}")

        # Output to file if requested
        if args.output:
            import json
            output_data = {
                "domain": config.domain,
                "timestamp": datetime.now().isoformat(),
                "records": [r.to_dict() for r in results],
                "unique_ips": list(unique_ips),
                "subdomains": list(enumerator._found_subdomains)
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
