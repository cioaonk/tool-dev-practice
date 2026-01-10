#!/usr/bin/env python3
"""
Test Suite for Credential Validator
====================================

Comprehensive tests for the credential validation tool including
plan mode, documentation, and mock authentication operations.
"""

import sys
import unittest
from unittest.mock import Mock, MagicMock, patch
from io import StringIO
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tool import (
    Credential,
    ValidationAttempt,
    ValidatorConfig,
    Protocol,
    ValidationResult,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS
)


class TestCredential(unittest.TestCase):
    """Tests for Credential dataclass."""

    def test_credential_creation(self):
        """Test creating a Credential instance."""
        cred = Credential(username="admin", password="password123")

        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.password, "password123")
        self.assertIsNone(cred.domain)

    def test_credential_with_domain(self):
        """Test credential with domain."""
        cred = Credential(
            username="admin",
            password="pass",
            domain="CORP"
        )

        self.assertEqual(cred.domain, "CORP")

    def test_credential_repr(self):
        """Test credential string representation."""
        cred = Credential(username="user", password="pass")
        self.assertIn("user", repr(cred))

    def test_credential_repr_with_domain(self):
        """Test credential repr with domain."""
        cred = Credential(username="user", password="pass", domain="DOMAIN")
        repr_str = repr(cred)

        self.assertIn("DOMAIN", repr_str)
        self.assertIn("user", repr_str)

    def test_credential_clear(self):
        """Test secure credential clearing."""
        cred = Credential(username="admin", password="secret")
        cred.clear()

        # Should be overwritten with x's
        self.assertNotEqual(cred.username, "admin")
        self.assertNotEqual(cred.password, "secret")


class TestValidationAttempt(unittest.TestCase):
    """Tests for ValidationAttempt dataclass."""

    def test_attempt_creation(self):
        """Test creating a ValidationAttempt."""
        cred = Credential(username="admin", password="password")
        attempt = ValidationAttempt(
            credential=cred,
            protocol=Protocol.SSH,
            target="192.168.1.100",
            result=ValidationResult.VALID
        )

        self.assertEqual(attempt.protocol, Protocol.SSH)
        self.assertEqual(attempt.result, ValidationResult.VALID)

    def test_attempt_to_dict(self):
        """Test serialization to dictionary."""
        cred = Credential(username="admin", password="pass")
        attempt = ValidationAttempt(
            credential=cred,
            protocol=Protocol.FTP,
            target="ftp.example.com",
            result=ValidationResult.INVALID,
            message="Invalid credentials"
        )

        data = attempt.to_dict()

        self.assertIn("username", data)
        self.assertIn("protocol", data)
        self.assertEqual(data["result"], "invalid")


class TestValidatorConfig(unittest.TestCase):
    """Tests for ValidatorConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = ValidatorConfig()

        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.threads, DEFAULT_THREADS)
        self.assertEqual(config.plan_mode, False)
        self.assertEqual(config.protocol, Protocol.SSH)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        creds = [
            Credential("admin", "pass1"),
            Credential("root", "pass2")
        ]

        config = ValidatorConfig(
            target="192.168.1.100",
            port=22,
            protocol=Protocol.SSH,
            credentials=creds,
            plan_mode=True
        )

        self.assertEqual(config.target, "192.168.1.100")
        self.assertEqual(len(config.credentials), 2)
        self.assertTrue(config.plan_mode)


class TestProtocol(unittest.TestCase):
    """Tests for Protocol enum."""

    def test_protocol_values(self):
        """Test protocol enum values."""
        self.assertEqual(Protocol.SSH.value, "ssh")
        self.assertEqual(Protocol.FTP.value, "ftp")
        self.assertEqual(Protocol.HTTP_BASIC.value, "http-basic")

    def test_all_protocols_defined(self):
        """Test all expected protocols are defined."""
        expected = ["ssh", "ftp", "http-basic", "http-form", "smtp", "mysql"]

        protocol_values = [p.value for p in Protocol]

        for exp in expected:
            self.assertIn(exp, protocol_values)


class TestValidationResult(unittest.TestCase):
    """Tests for ValidationResult enum."""

    def test_result_values(self):
        """Test validation result values."""
        self.assertEqual(ValidationResult.VALID.value, "valid")
        self.assertEqual(ValidationResult.INVALID.value, "invalid")
        self.assertEqual(ValidationResult.LOCKED.value, "locked")
        self.assertEqual(ValidationResult.ERROR.value, "error")


class TestDocumentation(unittest.TestCase):
    """Tests for tool documentation."""

    def test_get_documentation_returns_dict(self):
        """Test that get_documentation returns a dictionary."""
        doc = get_documentation()
        self.assertIsInstance(doc, dict)

    def test_documentation_has_required_fields(self):
        """Test that documentation has all required fields."""
        doc = get_documentation()

        required_fields = ["name", "description", "usage"]
        for field in required_fields:
            self.assertIn(field, doc, f"Missing required field: {field}")

    def test_documentation_lists_protocols(self):
        """Test documentation lists supported protocols."""
        doc = get_documentation()

        # Should mention protocols somewhere
        doc_str = str(doc).lower()
        self.assertTrue("ssh" in doc_str or "protocol" in doc_str)


class TestArgumentParser(unittest.TestCase):
    """Tests for argument parser."""

    def test_parser_creation(self):
        """Test parser can be created."""
        parser = create_argument_parser()
        self.assertIsNotNone(parser)

    def test_parser_has_plan_flag(self):
        """Test parser has --plan flag."""
        parser = create_argument_parser()

        plan_found = False
        for action in parser._actions:
            if '--plan' in action.option_strings or '-p' in action.option_strings:
                plan_found = True
                break

        self.assertTrue(plan_found, "Parser should have --plan flag")

    def test_parser_target_argument(self):
        """Test parser has target argument."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--target', '192.168.1.1',
            '--username', 'admin',
            '--password', 'pass'
        ])

        self.assertEqual(args.target, '192.168.1.1')

    def test_parser_protocol_argument(self):
        """Test parser accepts protocol argument."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--target', '192.168.1.1',
            '--protocol', 'ssh',
            '--username', 'admin',
            '--password', 'pass'
        ])

        self.assertEqual(args.protocol, 'ssh')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = ValidatorConfig(
            target="192.168.1.100",
            protocol=Protocol.SSH,
            credentials=[Credential("admin", "password")],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertTrue(len(output) > 0)

    def test_plan_mode_shows_target(self):
        """Test that plan output shows target."""
        config = ValidatorConfig(
            target="192.168.1.100",
            credentials=[Credential("admin", "pass")],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        self.assertIn("192.168.1.100", output)

    def test_plan_mode_masks_passwords(self):
        """Test that plan mode masks passwords."""
        config = ValidatorConfig(
            target="192.168.1.100",
            credentials=[Credential("admin", "supersecretpassword")],
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        # Should not contain plaintext password
        self.assertNotIn("supersecretpassword", output)

    def test_plan_mode_shows_credential_count(self):
        """Test that plan shows number of credentials."""
        creds = [
            Credential("admin", "pass1"),
            Credential("root", "pass2"),
            Credential("user", "pass3")
        ]

        config = ValidatorConfig(
            target="192.168.1.100",
            credentials=creds,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        # Should show credential count
        self.assertTrue("3" in output or "credential" in output.lower())


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_target_error(self):
        """Test error handling for missing target."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args(['--username', 'admin'])


# =============================================================================
# Test Fixtures
# =============================================================================

class CredentialValidatorFixtures:
    """Test fixtures for credential validator."""

    # Common username/password combinations
    CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("root", "toor"),
        ("administrator", "administrator"),
        ("test", "test"),
        ("user", "user123")
    ]

    # Protocol default ports
    DEFAULT_PORTS = {
        Protocol.SSH: 22,
        Protocol.FTP: 21,
        Protocol.HTTP_BASIC: 80,
        Protocol.SMTP: 25,
        Protocol.MYSQL: 3306
    }

    @classmethod
    def get_credentials(cls, count: int = 5):
        """Get test credentials."""
        return [Credential(u, p) for u, p in cls.CREDENTIALS[:count]]

    @classmethod
    def get_mock_validator_response(cls, success: bool):
        """Get a mock validator response."""
        if success:
            return ValidationResult.VALID
        return ValidationResult.INVALID


if __name__ == '__main__':
    unittest.main(verbosity=2)
