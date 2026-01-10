"""
Integration tests for FTP credential validation against Docker environment.
"""

import pytest
import socket
import sys
import os

# Add tools path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'credential-validator'))

try:
    from tool import FTPValidator, ValidatorConfig, Credential, ValidationResult, Protocol
except ImportError:
    FTPValidator = None
    ValidatorConfig = None
    Credential = None


class TestFTPConnection:
    """Test basic FTP connectivity."""

    def test_ftp_banner(self, ftp_service):
        """Test that FTP server responds with banner."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ftp_service["host"], ftp_service["port"]))

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        assert banner.startswith('220'), f"Expected 220 banner, got: {banner}"
        assert "FTP" in banner or "CPTC11" in banner

    def test_anonymous_login_enabled(self, ftp_service):
        """Test that anonymous login is enabled."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((ftp_service["host"], ftp_service["port"]))

        # Receive banner
        sock.recv(1024)

        # Try anonymous login
        sock.send(b"USER anonymous\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        sock.close()

        # Should get 331 (password required) or 230 (logged in)
        assert response.startswith('331') or response.startswith('230'), \
            f"Expected 331 or 230, got: {response}"


@pytest.mark.skipif(FTPValidator is None, reason="Credential validator tool not available")
class TestFTPCredentialValidation:
    """Test FTP credential validation using the tool."""

    def test_valid_credentials(self, ftp_service):
        """Test validation of valid FTP credentials."""
        validator = FTPValidator()
        config = ValidatorConfig(
            target=ftp_service["host"],
            port=ftp_service["port"],
            timeout=10.0
        )

        credential = Credential(
            username=ftp_service["valid_user"],
            password=ftp_service["valid_pass"]
        )

        result = validator.validate(
            ftp_service["host"],
            ftp_service["port"],
            credential,
            config
        )

        assert result.result == ValidationResult.VALID, \
            f"Expected VALID, got {result.result}: {result.message}"

    def test_invalid_credentials(self, ftp_service):
        """Test validation of invalid FTP credentials."""
        validator = FTPValidator()
        config = ValidatorConfig(
            target=ftp_service["host"],
            port=ftp_service["port"],
            timeout=10.0
        )

        credential = Credential(
            username=ftp_service["invalid_user"],
            password=ftp_service["invalid_pass"]
        )

        result = validator.validate(
            ftp_service["host"],
            ftp_service["port"],
            credential,
            config
        )

        assert result.result == ValidationResult.INVALID, \
            f"Expected INVALID, got {result.result}: {result.message}"

    def test_admin_credentials(self, ftp_service):
        """Test validation of admin FTP credentials."""
        validator = FTPValidator()
        config = ValidatorConfig(
            target=ftp_service["host"],
            port=ftp_service["port"],
            timeout=10.0
        )

        credential = Credential(username="admin", password="admin123")

        result = validator.validate(
            ftp_service["host"],
            ftp_service["port"],
            credential,
            config
        )

        assert result.result == ValidationResult.VALID, \
            f"Expected VALID for admin, got {result.result}: {result.message}"

    def test_backup_credentials(self, ftp_service):
        """Test validation of backup user credentials."""
        validator = FTPValidator()
        config = ValidatorConfig(
            target=ftp_service["host"],
            port=ftp_service["port"],
            timeout=10.0
        )

        credential = Credential(username="backup", password="backup2024")

        result = validator.validate(
            ftp_service["host"],
            ftp_service["port"],
            credential,
            config
        )

        assert result.result == ValidationResult.VALID, \
            f"Expected VALID for backup, got {result.result}: {result.message}"
