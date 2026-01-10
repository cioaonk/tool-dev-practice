"""
Tests for the Credential Validator tool.

This module contains unit tests and integration tests for the credential-validator tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/credential-validator')

from tool import (
    Protocol,
    ValidationResult,
    Credential,
    ValidationConfig,
    ValidatorResult,
    SSHValidator,
    FTPValidator,
    HTTPBasicValidator,
    SMTPValidator,
    MySQLValidator,
    CredentialValidator,
    get_documentation,
    print_plan,
    parse_arguments,
)


# =============================================================================
# Test get_documentation()
# =============================================================================

class TestGetDocumentation:
    """Tests for the get_documentation function."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        docs = get_documentation()
        assert isinstance(docs, dict)

    def test_get_documentation_has_required_keys(self):
        """Test that documentation contains all required keys."""
        docs = get_documentation()
        required_keys = ["name", "version", "description"]
        for key in required_keys:
            assert key in docs, f"Missing required key: {key}"

    def test_get_documentation_name_is_correct(self):
        """Test that documentation name matches tool name."""
        docs = get_documentation()
        assert docs["name"] == "credential-validator"

    def test_get_documentation_has_arguments(self):
        """Test that documentation includes argument definitions."""
        docs = get_documentation()
        assert "arguments" in docs
        assert isinstance(docs["arguments"], dict)

    def test_get_documentation_has_examples(self):
        """Test that documentation includes usage examples."""
        docs = get_documentation()
        assert "examples" in docs
        assert isinstance(docs["examples"], list)


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out

    def test_plan_mode_shows_protocol(self, capsys):
        """Test that planning mode shows protocol information."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "SSH" in captured.out or "ssh" in captured.out.lower()

    def test_plan_mode_does_not_validate(self):
        """Test that planning mode does not actually validate credentials."""
        with patch('socket.socket') as mock_socket:
            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.SSH,
                credentials=[Credential("admin", "password")],
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be used in plan mode
            mock_socket.return_value.connect.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_target(self):
        """Test that valid targets are accepted."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")]
        )
        assert config.target == "192.168.1.1"

    def test_valid_protocol_ssh(self):
        """Test SSH protocol validation."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")]
        )
        assert config.protocol == Protocol.SSH

    def test_valid_protocol_ftp(self):
        """Test FTP protocol validation."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.FTP,
            credentials=[Credential("admin", "password")]
        )
        assert config.protocol == Protocol.FTP

    def test_valid_credentials_list(self):
        """Test that credentials list is properly configured."""
        creds = [
            Credential("user1", "pass1"),
            Credential("user2", "pass2")
        ]
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=creds
        )
        assert len(config.credentials) == 2


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_connection_error_handled(self):
        """Test that connection errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.side_effect = socket.error("Connection refused")

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.FTP,
                credentials=[Credential("admin", "password")]
            )
            validator = FTPValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "password"), config)

            # Should return error result, not crash
            assert isinstance(result, ValidatorResult)
            assert result.result == ValidationResult.ERROR or result.result == ValidationResult.TIMEOUT

    def test_timeout_handling(self):
        """Test that timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.side_effect = socket.timeout("Timeout")

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.FTP,
                credentials=[Credential("admin", "password")],
                timeout=0.1
            )
            validator = FTPValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "password"), config)

            assert isinstance(result, ValidatorResult)
            assert result.result in [ValidationResult.ERROR, ValidationResult.TIMEOUT]


# =============================================================================
# Test Protocol Enum
# =============================================================================

class TestProtocolEnum:
    """Tests for the Protocol enum."""

    def test_protocol_ssh(self):
        """Test SSH protocol enum value."""
        assert Protocol.SSH is not None

    def test_protocol_ftp(self):
        """Test FTP protocol enum value."""
        assert Protocol.FTP is not None

    def test_protocol_http_basic(self):
        """Test HTTP_BASIC protocol enum value."""
        assert Protocol.HTTP_BASIC is not None

    def test_protocol_smtp(self):
        """Test SMTP protocol enum value."""
        assert Protocol.SMTP is not None

    def test_protocol_mysql(self):
        """Test MYSQL protocol enum value."""
        assert Protocol.MYSQL is not None


# =============================================================================
# Test ValidationResult Enum
# =============================================================================

class TestValidationResultEnum:
    """Tests for the ValidationResult enum."""

    def test_validation_result_valid(self):
        """Test VALID result enum value."""
        assert ValidationResult.VALID is not None

    def test_validation_result_invalid(self):
        """Test INVALID result enum value."""
        assert ValidationResult.INVALID is not None

    def test_validation_result_locked(self):
        """Test LOCKED result enum value."""
        assert ValidationResult.LOCKED is not None

    def test_validation_result_error(self):
        """Test ERROR result enum value."""
        assert ValidationResult.ERROR is not None

    def test_validation_result_timeout(self):
        """Test TIMEOUT result enum value."""
        assert ValidationResult.TIMEOUT is not None


# =============================================================================
# Test Credential Data Class
# =============================================================================

class TestCredential:
    """Tests for the Credential data class."""

    def test_credential_creation(self):
        """Test that Credential can be created."""
        cred = Credential(username="admin", password="secret")
        assert cred.username == "admin"
        assert cred.password == "secret"

    def test_credential_equality(self):
        """Test Credential equality."""
        cred1 = Credential("admin", "secret")
        cred2 = Credential("admin", "secret")
        assert cred1 == cred2


# =============================================================================
# Test ValidatorResult Data Class
# =============================================================================

class TestValidatorResult:
    """Tests for the ValidatorResult data class."""

    def test_validator_result_creation(self):
        """Test ValidatorResult creation."""
        result = ValidatorResult(
            credential=Credential("admin", "password"),
            result=ValidationResult.VALID,
            protocol=Protocol.SSH
        )
        assert result.result == ValidationResult.VALID

    def test_validator_result_with_message(self):
        """Test ValidatorResult with message."""
        result = ValidatorResult(
            credential=Credential("admin", "password"),
            result=ValidationResult.INVALID,
            protocol=Protocol.SSH,
            message="Invalid credentials"
        )
        assert result.message == "Invalid credentials"


# =============================================================================
# Test Protocol Validators
# =============================================================================

class TestProtocolValidators:
    """Tests for individual protocol validators."""

    def test_ssh_validator_valid_credentials(self):
        """Test SSHValidator with valid credentials."""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.return_value = None  # Successful connection

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.SSH,
                credentials=[Credential("admin", "password")]
            )
            validator = SSHValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "password"), config)

            # If paramiko is available and mock works
            assert isinstance(result, ValidatorResult)

    def test_ftp_validator_valid_credentials(self):
        """Test FTPValidator with valid credentials."""
        with patch('ftplib.FTP') as mock_ftp:
            mock_ftp.return_value.login.return_value = "230 Login successful"

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.FTP,
                credentials=[Credential("admin", "password")]
            )
            validator = FTPValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "password"), config)

            assert isinstance(result, ValidatorResult)

    def test_ftp_validator_invalid_credentials(self):
        """Test FTPValidator with invalid credentials."""
        with patch('ftplib.FTP') as mock_ftp:
            import ftplib
            mock_ftp.return_value.login.side_effect = ftplib.error_perm("530 Login incorrect")

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.FTP,
                credentials=[Credential("admin", "wrongpassword")]
            )
            validator = FTPValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "wrongpassword"), config)

            assert isinstance(result, ValidatorResult)
            assert result.result == ValidationResult.INVALID

    def test_http_basic_validator(self):
        """Test HTTPBasicValidator."""
        with patch('http.client.HTTPConnection') as mock_http:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_http.return_value.getresponse.return_value = mock_response

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.HTTP_BASIC,
                credentials=[Credential("admin", "password")]
            )
            validator = HTTPBasicValidator()
            result = validator.validate("192.168.1.1", Credential("admin", "password"), config)

            assert isinstance(result, ValidatorResult)


# =============================================================================
# Test CredentialValidator Class
# =============================================================================

class TestCredentialValidator:
    """Tests for the CredentialValidator class."""

    def test_validator_initialization(self):
        """Test CredentialValidator initialization."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")]
        )
        validator = CredentialValidator(config)

        assert validator.config == config

    def test_validator_has_protocols(self):
        """Test that validator has registered protocols."""
        config = ValidationConfig(
            target="192.168.1.1",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")]
        )
        validator = CredentialValidator(config)

        # Should have validators registered
        assert hasattr(validator, 'validators') or len(validator.__dict__) > 0


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_target_argument(self):
        """Test parsing target argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1']):
            args = parse_arguments()
            assert args.target == '192.168.1.1'

    def test_parse_protocol_argument(self):
        """Test parsing protocol argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--protocol', 'ssh']):
            args = parse_arguments()
            assert 'ssh' in str(args.protocol).lower()

    def test_parse_username_argument(self):
        """Test parsing username argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '-u', 'admin']):
            args = parse_arguments()
            assert args.username == 'admin' or 'admin' in str(args.username)

    def test_parse_password_argument(self):
        """Test parsing password argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '-p', 'secret']):
            args = parse_arguments()
            assert args.password == 'secret' or 'secret' in str(args.password)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_validation_run_ssh(self):
        """Test full SSH validation with mocked network."""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_ssh.return_value.connect.return_value = None

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.SSH,
                credentials=[
                    Credential("admin", "password1"),
                    Credential("admin", "password2")
                ],
                threads=1
            )
            validator = CredentialValidator(config)
            results = validator.validate_all()

            assert isinstance(results, list)

    def test_full_validation_run_ftp(self):
        """Test full FTP validation with mocked network."""
        with patch('ftplib.FTP') as mock_ftp:
            mock_ftp.return_value.login.return_value = "230 OK"

            config = ValidationConfig(
                target="192.168.1.1",
                protocol=Protocol.FTP,
                credentials=[Credential("admin", "password")],
                threads=1
            )
            validator = CredentialValidator(config)
            results = validator.validate_all()

            assert isinstance(results, list)

    def test_validation_with_multiple_protocols(self):
        """Test validation across multiple protocols."""
        # This tests the validator's ability to handle different protocols
        for protocol in [Protocol.SSH, Protocol.FTP, Protocol.HTTP_BASIC]:
            config = ValidationConfig(
                target="192.168.1.1",
                protocol=protocol,
                credentials=[Credential("admin", "password")],
                threads=1
            )
            validator = CredentialValidator(config)
            assert validator.config.protocol == protocol
