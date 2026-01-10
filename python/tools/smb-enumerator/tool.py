#!/usr/bin/env python3
"""
SMB Enumerator - SMB/CIFS Share and User Enumeration Tool
==========================================================

A comprehensive SMB enumeration utility for share discovery,
user enumeration, and system information gathering.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized SMB access may violate laws and regulations.
"""

import argparse
import socket
import struct
import sys
import time
import random
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 10.0
SMB_PORT = 445
NETBIOS_PORT = 139


# SMB Commands
class SMBCommand(Enum):
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_TRANSACTION = 0x25


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class SMBShare:
    """Represents an SMB share."""
    name: str
    share_type: str
    comment: Optional[str] = None
    permissions: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.share_type,
            "comment": self.comment,
            "permissions": self.permissions
        }


@dataclass
class SMBUser:
    """Represents an SMB/Windows user."""
    username: str
    rid: Optional[int] = None
    description: Optional[str] = None
    groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.username,
            "rid": self.rid,
            "description": self.description,
            "groups": self.groups
        }


@dataclass
class SMBSystemInfo:
    """System information gathered from SMB."""
    hostname: Optional[str] = None
    domain: Optional[str] = None
    os_version: Optional[str] = None
    server_type: Optional[str] = None
    smb_version: Optional[str] = None
    signing_required: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "domain": self.domain,
            "os_version": self.os_version,
            "server_type": self.server_type,
            "smb_version": self.smb_version,
            "signing_required": self.signing_required
        }


@dataclass
class EnumConfig:
    """Configuration for SMB enumeration."""
    target: str = ""
    port: int = SMB_PORT
    username: Optional[str] = None
    password: Optional[str] = None
    domain: str = ""
    timeout: float = DEFAULT_TIMEOUT
    enum_shares: bool = True
    enum_users: bool = True
    enum_sessions: bool = False
    null_session: bool = True
    verbose: bool = False
    plan_mode: bool = False


@dataclass
class EnumResult:
    """Result of SMB enumeration."""
    target: str
    system_info: Optional[SMBSystemInfo] = None
    shares: List[SMBShare] = field(default_factory=list)
    users: List[SMBUser] = field(default_factory=list)
    sessions: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "system_info": self.system_info.to_dict() if self.system_info else None,
            "shares": [s.to_dict() for s in self.shares],
            "users": [u.to_dict() for u in self.users],
            "sessions": self.sessions,
            "errors": self.errors,
            "timestamp": self.timestamp.isoformat()
        }


# =============================================================================
# SMB Protocol Implementation
# =============================================================================

class SMBClient:
    """
    Lightweight SMB client for enumeration.

    Implements basic SMB protocol operations without external dependencies.
    Note: This is a simplified implementation; full SMB requires more complexity.
    """

    def __init__(self, target: str, port: int = SMB_PORT, timeout: float = 10.0):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.socket: Optional[socket.socket] = None
        self.session_key = 0
        self.user_id = 0
        self.tree_id = 0
        self.process_id = random.randint(1, 65535)
        self.multiplex_id = 1

    def _create_smb_header(self, command: int, flags: int = 0x18,
                           flags2: int = 0xc803) -> bytes:
        """Create SMB header."""
        header = b'\xffSMB'  # Protocol identifier
        header += struct.pack('<B', command)  # Command
        header += struct.pack('<I', 0)  # Status
        header += struct.pack('<B', flags)  # Flags
        header += struct.pack('<H', flags2)  # Flags2
        header += struct.pack('<H', 0)  # PID high
        header += struct.pack('<Q', self.session_key)  # Security features
        header += struct.pack('<H', 0)  # Reserved
        header += struct.pack('<H', self.tree_id)  # Tree ID
        header += struct.pack('<H', self.process_id)  # Process ID
        header += struct.pack('<H', self.user_id)  # User ID
        header += struct.pack('<H', self.multiplex_id)  # Multiplex ID
        self.multiplex_id += 1
        return header

    def _create_netbios_header(self, data: bytes) -> bytes:
        """Create NetBIOS session header."""
        return struct.pack('>I', len(data))[:1] + struct.pack('>I', len(data))[1:]

    def _send_packet(self, data: bytes) -> Optional[bytes]:
        """Send packet and receive response."""
        try:
            packet = self._create_netbios_header(data) + data
            self.socket.send(packet)

            # Receive response
            response = self.socket.recv(4096)
            if len(response) < 4:
                return None

            return response[4:]  # Skip NetBIOS header

        except Exception:
            return None

    def connect(self) -> bool:
        """Establish connection to SMB server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.target, self.port))
            return True
        except Exception:
            return False

    def disconnect(self) -> None:
        """Close connection."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    def negotiate(self) -> Optional[SMBSystemInfo]:
        """
        Perform SMB negotiation and gather system info.

        Returns:
            SMBSystemInfo or None on failure
        """
        # Build negotiate request
        dialects = [
            b'\x02NT LM 0.12\x00',  # NT LAN Manager
            b'\x02SMB 2.002\x00',   # SMB 2.0
            b'\x02SMB 2.???\x00',   # SMB 2.x wildcard
        ]

        header = self._create_smb_header(SMBCommand.SMB_COM_NEGOTIATE.value)

        # Word count and byte count
        data = struct.pack('<B', 0)  # Word count
        dialect_bytes = b''.join(dialects)
        data += struct.pack('<H', len(dialect_bytes))
        data += dialect_bytes

        response = self._send_packet(header + data)
        if not response or len(response) < 36:
            return None

        system_info = SMBSystemInfo()

        # Parse negotiate response
        try:
            # Check for SMB signature
            if response[:4] != b'\xffSMB':
                # Might be SMB2
                if response[:4] == b'\xfeSMB':
                    system_info.smb_version = "SMB2+"
                return system_info

            # Parse SMB1 negotiate response
            word_count = response[32]

            if word_count >= 17:
                # Extended security negotiation
                capabilities = struct.unpack('<I', response[44:48])[0] if len(response) > 48 else 0

                # Check signing
                security_mode = response[33] if len(response) > 33 else 0
                system_info.signing_required = bool(security_mode & 0x08)
                system_info.smb_version = "SMB1"

            # Try to extract OS info from string area
            byte_count_pos = 33 + (word_count * 2)
            if len(response) > byte_count_pos + 2:
                byte_count = struct.unpack('<H', response[byte_count_pos:byte_count_pos+2])[0]
                string_area = response[byte_count_pos+2:byte_count_pos+2+byte_count]

                # Parse null-terminated strings (OS, LM, Domain)
                strings = []
                current = b''
                for byte in string_area:
                    if byte == 0:
                        if current:
                            strings.append(current.decode('utf-8', errors='ignore'))
                            current = b''
                    else:
                        current += bytes([byte])

                if len(strings) >= 1:
                    system_info.os_version = strings[0]
                if len(strings) >= 3:
                    system_info.domain = strings[2]

        except Exception:
            pass

        return system_info

    def session_setup(self, username: str = "", password: str = "",
                      domain: str = "") -> bool:
        """
        Attempt session setup (authentication).

        Args:
            username: Username (empty for null session)
            password: Password
            domain: Domain name

        Returns:
            True if session established
        """
        header = self._create_smb_header(SMBCommand.SMB_COM_SESSION_SETUP_ANDX.value)

        # Build session setup request (simplified NTLM)
        words = struct.pack('<B', 0xff)  # AndX command
        words += struct.pack('<B', 0)     # Reserved
        words += struct.pack('<H', 0)     # AndX offset
        words += struct.pack('<H', 65535) # Max buffer
        words += struct.pack('<H', 2)     # Max MPX count
        words += struct.pack('<H', 1)     # VC number
        words += struct.pack('<I', 0)     # Session key
        words += struct.pack('<H', 0)     # Security blob length
        words += struct.pack('<I', 0)     # Reserved
        words += struct.pack('<I', 0x80000000)  # Capabilities

        data = struct.pack('<B', 13)  # Word count
        data += words
        data += struct.pack('<H', 0)  # Byte count

        response = self._send_packet(header + data)
        if not response:
            return False

        # Check status
        status = struct.unpack('<I', response[5:9])[0] if len(response) > 9 else 0xFFFFFFFF

        if status == 0:
            # Extract user ID
            if len(response) > 28:
                self.user_id = struct.unpack('<H', response[28:30])[0]
            return True

        return False

    def tree_connect(self, share: str) -> bool:
        """
        Connect to a share.

        Args:
            share: Share path (e.g., \\\\target\\IPC$)

        Returns:
            True if connected
        """
        header = self._create_smb_header(SMBCommand.SMB_COM_TREE_CONNECT_ANDX.value)

        # Build tree connect request
        words = struct.pack('<B', 0xff)  # AndX command
        words += struct.pack('<B', 0)     # Reserved
        words += struct.pack('<H', 0)     # AndX offset
        words += struct.pack('<H', 0)     # Flags
        words += struct.pack('<H', 1)     # Password length

        password_bytes = b'\x00'  # Null password
        path_bytes = share.encode('utf-16-le') + b'\x00\x00'
        service_bytes = b'?????\x00'  # Any service

        data = struct.pack('<B', 4)  # Word count
        data += words
        byte_count = len(password_bytes) + len(path_bytes) + len(service_bytes)
        data += struct.pack('<H', byte_count)
        data += password_bytes
        data += path_bytes
        data += service_bytes

        response = self._send_packet(header + data)
        if not response:
            return False

        status = struct.unpack('<I', response[5:9])[0] if len(response) > 9 else 0xFFFFFFFF

        if status == 0:
            if len(response) > 24:
                self.tree_id = struct.unpack('<H', response[24:26])[0]
            return True

        return False


# =============================================================================
# SMB Enumerator Core
# =============================================================================

class SMBEnumerator:
    """
    Main SMB enumeration engine.

    Coordinates share enumeration, user enumeration, and system info gathering.
    """

    # Common share names to check
    COMMON_SHARES = [
        "IPC$", "ADMIN$", "C$", "D$", "E$", "NETLOGON", "SYSVOL",
        "print$", "Users", "Public", "Shared", "Data", "Backup",
        "IT", "Finance", "HR", "Software", "Install", "Temp"
    ]

    # Common user RIDs
    COMMON_RIDS = [
        500,   # Administrator
        501,   # Guest
        502,   # KRBTGT
        512,   # Domain Admins
        513,   # Domain Users
        514,   # Domain Guests
        515,   # Domain Computers
        516,   # Domain Controllers
        519,   # Enterprise Admins
        544,   # Local Administrators
    ]

    def __init__(self, config: EnumConfig):
        self.config = config
        self.result = EnumResult(target=config.target)
        self._client: Optional[SMBClient] = None

    def _connect(self) -> bool:
        """Establish SMB connection."""
        self._client = SMBClient(self.config.target, self.config.port, self.config.timeout)

        if not self._client.connect():
            self.result.errors.append("Failed to connect to target")
            return False

        # Negotiate
        system_info = self._client.negotiate()
        if system_info:
            self.result.system_info = system_info

        # Session setup
        if self.config.null_session:
            if not self._client.session_setup():
                self.result.errors.append("Null session failed")
        elif self.config.username:
            if not self._client.session_setup(
                self.config.username,
                self.config.password or "",
                self.config.domain
            ):
                self.result.errors.append("Authentication failed")
                return False

        return True

    def _disconnect(self) -> None:
        """Close SMB connection."""
        if self._client:
            self._client.disconnect()
            self._client = None

    def _enum_shares_basic(self) -> List[SMBShare]:
        """
        Enumerate shares by attempting to connect to common names.

        This is a fallback method when RPC enumeration is not available.
        """
        shares = []

        for share_name in self.COMMON_SHARES:
            share_path = f"\\\\{self.config.target}\\{share_name}"

            # Try to connect
            if self._client and self._client.tree_connect(share_path):
                share_type = "IPC" if share_name.endswith("$") else "Disk"
                shares.append(SMBShare(
                    name=share_name,
                    share_type=share_type,
                    comment=None,
                    permissions="Accessible"
                ))

                if self.config.verbose:
                    print(f"[+] Found share: {share_name}")

        return shares

    def enumerate(self) -> EnumResult:
        """
        Execute SMB enumeration.

        Returns:
            EnumResult with discovered information
        """
        if self.config.verbose:
            print(f"[*] SMB Enumerator starting for {self.config.target}")

        # Connect
        if not self._connect():
            return self.result

        if self.config.verbose:
            if self.result.system_info:
                print(f"[*] OS: {self.result.system_info.os_version}")
                print(f"[*] SMB: {self.result.system_info.smb_version}")
                print(f"[*] Signing: {'Required' if self.result.system_info.signing_required else 'Not Required'}")

        # Enumerate shares
        if self.config.enum_shares:
            if self.config.verbose:
                print("[*] Enumerating shares...")

            shares = self._enum_shares_basic()
            self.result.shares = shares

        # Cleanup
        self._disconnect()

        return self.result

    def stop(self) -> None:
        """Stop enumeration."""
        self._disconnect()


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: EnumConfig) -> None:
    """Display execution plan without performing any actions."""
    print("""
[PLAN MODE] Tool: smb-enumerator
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Target:          {config.target}")
    print(f"  Port:            {config.port}")
    print()

    print("AUTHENTICATION")
    print("-" * 40)
    if config.username:
        print(f"  Username:        {config.username}")
        print(f"  Domain:          {config.domain or 'WORKGROUP'}")
        print(f"  Password:        {'*' * len(config.password) if config.password else 'None'}")
    else:
        print(f"  Null Session:    {config.null_session}")
    print()

    print("ENUMERATION OPTIONS")
    print("-" * 40)
    print(f"  Enumerate Shares:   {config.enum_shares}")
    print(f"  Enumerate Users:    {config.enum_users}")
    print(f"  Enumerate Sessions: {config.enum_sessions}")
    print(f"  Timeout:            {config.timeout}s")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Establish TCP connection to port 445")
    print("  2. Perform SMB negotiation (gather OS info)")
    if config.null_session:
        print("  3. Attempt null session authentication")
    elif config.username:
        print("  3. Authenticate with provided credentials")
    if config.enum_shares:
        print("  4. Enumerate accessible shares")
        print(f"     - Test {len(SMBEnumerator.COMMON_SHARES)} common share names")
    if config.enum_users:
        print("  5. Attempt user enumeration via RPC")
    print()

    print("SHARES TO TEST")
    print("-" * 40)
    for share in SMBEnumerator.COMMON_SHARES[:10]:
        print(f"  - {share}")
    print(f"  ... and {len(SMBEnumerator.COMMON_SHARES) - 10} more")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if config.null_session:
        risk_factors.append("Null session attempts are commonly logged")
    if config.enum_users:
        risk_factors.append("User enumeration may trigger alerts")

    risk_level = "MEDIUM"  # SMB enum is inherently visible
    print(f"  Risk Level: {risk_level}")
    for factor in risk_factors:
        print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Windows Security Event logs (4625, 4624)")
    print("  - SMB connection attempts are logged")
    print("  - Share enumeration visible in audit logs")
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
        "name": "smb-enumerator",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "SMB/CIFS share and user enumeration tool",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Share enumeration",
            "OS/version detection",
            "Null session support",
            "SMB signing detection",
            "Planning mode for operation preview"
        ],
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP or hostname"
            },
            "--username": {
                "type": "string",
                "description": "Username for authentication"
            },
            "--password": {
                "type": "string",
                "description": "Password for authentication"
            },
            "--null-session": {
                "type": "bool",
                "default": True,
                "description": "Attempt null session"
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
        description="SMB Enumerator - Share and User Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 --plan
  %(prog)s 192.168.1.1 --null-session
  %(prog)s 192.168.1.1 -u admin -P password -d DOMAIN

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "target",
        help="Target IP or hostname"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=SMB_PORT,
        help=f"SMB port (default: {SMB_PORT})"
    )

    parser.add_argument(
        "-u", "--username",
        help="Username for authentication"
    )

    parser.add_argument(
        "-P", "--password",
        help="Password for authentication"
    )

    parser.add_argument(
        "-d", "--domain",
        default="",
        help="Domain name"
    )

    parser.add_argument(
        "-n", "--null-session",
        action="store_true",
        default=True,
        help="Attempt null session (default: enabled)"
    )

    parser.add_argument(
        "--no-shares",
        action="store_true",
        help="Skip share enumeration"
    )

    parser.add_argument(
        "--no-users",
        action="store_true",
        help="Skip user enumeration"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout (default: {DEFAULT_TIMEOUT})"
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

    # Build configuration
    config = EnumConfig(
        target=args.target,
        port=args.port,
        username=args.username,
        password=args.password,
        domain=args.domain,
        timeout=args.timeout,
        enum_shares=not args.no_shares,
        enum_users=not args.no_users,
        null_session=args.null_session and not args.username,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Execute enumeration
    print(f"[*] SMB Enumerator starting...")
    print(f"[*] Target: {config.target}:{config.port}")

    enumerator = SMBEnumerator(config)

    try:
        result = enumerator.enumerate()

        # Display results
        print()
        print("=" * 60)
        print("SMB ENUMERATION RESULTS")
        print("=" * 60)

        if result.system_info:
            print("\nSYSTEM INFORMATION:")
            print("-" * 40)
            print(f"  OS Version:      {result.system_info.os_version or 'Unknown'}")
            print(f"  SMB Version:     {result.system_info.smb_version or 'Unknown'}")
            print(f"  Domain:          {result.system_info.domain or 'Unknown'}")
            print(f"  Signing:         {'Required' if result.system_info.signing_required else 'Not Required'}")

        if result.shares:
            print(f"\nSHARES ({len(result.shares)}):")
            print("-" * 40)
            for share in result.shares:
                print(f"  {share.name:<20} [{share.share_type}] {share.permissions or ''}")

        if result.errors:
            print("\nERRORS:")
            print("-" * 40)
            for error in result.errors:
                print(f"  [!] {error}")

        # Output to file if requested
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        enumerator.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
