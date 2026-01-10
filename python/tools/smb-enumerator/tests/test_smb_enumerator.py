#!/usr/bin/env python3
"""
Test Suite for SMB Enumerator
==============================

Comprehensive tests for the SMB enumeration tool including
plan mode, documentation, and mock SMB operations.
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
    SMBShare,
    SMBUser,
    SMBSystemInfo,
    EnumConfig,
    EnumResult,
    SMBClient,
    SMBCommand,
    get_documentation,
    create_argument_parser,
    print_plan,
    DEFAULT_TIMEOUT,
    SMB_PORT,
    NETBIOS_PORT
)


class TestSMBShare(unittest.TestCase):
    """Tests for SMBShare dataclass."""

    def test_share_creation(self):
        """Test creating an SMBShare instance."""
        share = SMBShare(
            name="ADMIN$",
            share_type="Disk",
            comment="Remote Admin"
        )

        self.assertEqual(share.name, "ADMIN$")
        self.assertEqual(share.share_type, "Disk")
        self.assertEqual(share.comment, "Remote Admin")

    def test_share_to_dict(self):
        """Test serialization to dictionary."""
        share = SMBShare(
            name="C$",
            share_type="Disk",
            comment="Default share",
            permissions="READ"
        )

        data = share.to_dict()

        self.assertIn("name", data)
        self.assertIn("type", data)
        self.assertEqual(data["permissions"], "READ")


class TestSMBUser(unittest.TestCase):
    """Tests for SMBUser dataclass."""

    def test_user_creation(self):
        """Test creating an SMBUser instance."""
        user = SMBUser(
            username="Administrator",
            rid=500,
            description="Built-in administrator account"
        )

        self.assertEqual(user.username, "Administrator")
        self.assertEqual(user.rid, 500)

    def test_user_with_groups(self):
        """Test user with groups."""
        user = SMBUser(
            username="admin",
            rid=1001,
            groups=["Domain Admins", "Administrators"]
        )

        self.assertEqual(len(user.groups), 2)
        self.assertIn("Domain Admins", user.groups)

    def test_user_to_dict(self):
        """Test serialization to dictionary."""
        user = SMBUser(
            username="guest",
            rid=501,
            groups=["Guests"]
        )

        data = user.to_dict()

        self.assertIn("username", data)
        self.assertIn("rid", data)
        self.assertEqual(len(data["groups"]), 1)


class TestSMBSystemInfo(unittest.TestCase):
    """Tests for SMBSystemInfo dataclass."""

    def test_system_info_creation(self):
        """Test creating SMBSystemInfo instance."""
        info = SMBSystemInfo(
            hostname="DC01",
            domain="CORP.LOCAL",
            os_version="Windows Server 2019"
        )

        self.assertEqual(info.hostname, "DC01")
        self.assertEqual(info.domain, "CORP.LOCAL")

    def test_system_info_to_dict(self):
        """Test serialization to dictionary."""
        info = SMBSystemInfo(
            hostname="SRV01",
            domain="EXAMPLE",
            smb_version="SMB 3.0",
            signing_required=True
        )

        data = info.to_dict()

        self.assertIn("hostname", data)
        self.assertTrue(data["signing_required"])


class TestEnumConfig(unittest.TestCase):
    """Tests for EnumConfig dataclass."""

    def test_config_defaults(self):
        """Test default configuration values."""
        config = EnumConfig()

        self.assertEqual(config.port, SMB_PORT)
        self.assertEqual(config.timeout, DEFAULT_TIMEOUT)
        self.assertEqual(config.plan_mode, False)
        self.assertTrue(config.null_session)

    def test_config_custom_values(self):
        """Test custom configuration values."""
        config = EnumConfig(
            target="192.168.1.100",
            username="admin",
            password="password",
            domain="CORP",
            enum_shares=True,
            enum_users=True,
            plan_mode=True
        )

        self.assertEqual(config.target, "192.168.1.100")
        self.assertEqual(config.username, "admin")
        self.assertTrue(config.plan_mode)


class TestEnumResult(unittest.TestCase):
    """Tests for EnumResult dataclass."""

    def test_result_creation(self):
        """Test creating EnumResult instance."""
        result = EnumResult(target="192.168.1.100")

        self.assertEqual(result.target, "192.168.1.100")
        self.assertEqual(len(result.shares), 0)
        self.assertEqual(len(result.users), 0)

    def test_result_with_data(self):
        """Test result with enumerated data."""
        shares = [
            SMBShare("ADMIN$", "Disk"),
            SMBShare("C$", "Disk")
        ]
        users = [SMBUser("Administrator", 500)]

        result = EnumResult(
            target="192.168.1.100",
            shares=shares,
            users=users
        )

        self.assertEqual(len(result.shares), 2)
        self.assertEqual(len(result.users), 1)

    def test_result_to_dict(self):
        """Test serialization to dictionary."""
        result = EnumResult(
            target="10.0.0.1",
            system_info=SMBSystemInfo(hostname="SERVER01")
        )

        data = result.to_dict()

        self.assertIn("target", data)
        self.assertIn("system_info", data)


class TestSMBCommand(unittest.TestCase):
    """Tests for SMBCommand enum."""

    def test_command_values(self):
        """Test SMB command values."""
        self.assertEqual(SMBCommand.SMB_COM_NEGOTIATE.value, 0x72)
        self.assertEqual(SMBCommand.SMB_COM_SESSION_SETUP_ANDX.value, 0x73)


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

    def test_documentation_name(self):
        """Test documentation name."""
        doc = get_documentation()
        self.assertIn("smb", doc["name"].lower())


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
        args = parser.parse_args(['--target', '192.168.1.100'])

        self.assertEqual(args.target, '192.168.1.100')

    def test_parser_credential_arguments(self):
        """Test parser accepts credentials."""
        parser = create_argument_parser()
        args = parser.parse_args([
            '--target', '192.168.1.100',
            '--username', 'admin',
            '--password', 'pass',
            '--domain', 'CORP'
        ])

        self.assertEqual(args.username, 'admin')
        self.assertEqual(args.domain, 'CORP')


class TestPlanMode(unittest.TestCase):
    """Tests for plan mode functionality."""

    def test_print_plan_produces_output(self):
        """Test that print_plan produces output."""
        config = EnumConfig(
            target="192.168.1.100",
            enum_shares=True,
            enum_users=True,
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
        config = EnumConfig(
            target="192.168.1.100",
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

    def test_plan_mode_shows_enumeration_options(self):
        """Test that plan shows enumeration options."""
        config = EnumConfig(
            target="192.168.1.100",
            enum_shares=True,
            enum_users=True,
            null_session=True,
            plan_mode=True
        )

        captured = StringIO()
        sys.stdout = captured
        try:
            print_plan(config)
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue().lower()
        # Should mention what will be enumerated
        self.assertTrue("share" in output or "user" in output or "enumerat" in output)


class TestConstants(unittest.TestCase):
    """Tests for module constants."""

    def test_smb_port(self):
        """Test SMB port constant."""
        self.assertEqual(SMB_PORT, 445)

    def test_netbios_port(self):
        """Test NetBIOS port constant."""
        self.assertEqual(NETBIOS_PORT, 139)


class TestInputValidation(unittest.TestCase):
    """Tests for input validation."""

    def test_missing_target_error(self):
        """Test error handling for missing target."""
        parser = create_argument_parser()

        with self.assertRaises(SystemExit):
            parser.parse_args([])


# =============================================================================
# Test Fixtures
# =============================================================================

class SMBEnumeratorFixtures:
    """Test fixtures for SMB enumerator."""

    # Common shares
    SHARES = [
        SMBShare("ADMIN$", "Disk", "Remote Admin"),
        SMBShare("C$", "Disk", "Default share"),
        SMBShare("IPC$", "IPC", "Remote IPC"),
        SMBShare("NETLOGON", "Disk", "Logon server share"),
        SMBShare("SYSVOL", "Disk", "Logon server share"),
        SMBShare("Public", "Disk", "Public share", "READ/WRITE")
    ]

    # Common users
    USERS = [
        SMBUser("Administrator", 500, "Built-in administrator"),
        SMBUser("Guest", 501, "Built-in guest account"),
        SMBUser("krbtgt", 502, "Key Distribution Center"),
        SMBUser("admin", 1001, "Domain admin", ["Domain Admins"])
    ]

    @classmethod
    def get_shares(cls, count: int = 3):
        """Get test shares."""
        return cls.SHARES[:count]

    @classmethod
    def get_users(cls, count: int = 2):
        """Get test users."""
        return cls.USERS[:count]


if __name__ == '__main__':
    unittest.main(verbosity=2)
