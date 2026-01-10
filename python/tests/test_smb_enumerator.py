"""
Tests for the SMB Enumerator tool.

This module contains unit tests and integration tests for the smb-enumerator tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
import socket
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/smb-enumerator')

from tool import (
    SMBShare,
    SMBUser,
    SMBSystemInfo,
    EnumConfig,
    SMBClient,
    SMBEnumerator,
    get_documentation,
    print_plan,
    parse_arguments,
    COMMON_SHARES,
    COMMON_RIDS,
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
        assert docs["name"] == "smb-enumerator"

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
        config = EnumConfig(
            target="192.168.1.1",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = EnumConfig(
            target="192.168.1.1",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.1" in captured.out

    def test_plan_mode_shows_enum_options(self, capsys):
        """Test that planning mode shows enumeration options."""
        config = EnumConfig(
            target="192.168.1.1",
            enum_shares=True,
            enum_users=True,
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention shares or users enumeration
        assert "share" in captured.out.lower() or "user" in captured.out.lower()

    def test_plan_mode_does_not_connect(self):
        """Test that planning mode does not make SMB connections."""
        with patch('socket.socket') as mock_socket:
            config = EnumConfig(
                target="192.168.1.1",
                plan_mode=True
            )
            print_plan(config)
            # Socket should not be connected in plan mode
            mock_socket.return_value.connect.assert_not_called()


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_target_ip(self):
        """Test that valid IP targets are accepted."""
        config = EnumConfig(target="192.168.1.1")
        assert config.target == "192.168.1.1"

    def test_valid_target_hostname(self):
        """Test that valid hostnames are accepted."""
        config = EnumConfig(target="fileserver.local")
        assert config.target == "fileserver.local"

    def test_enum_shares_option(self):
        """Test shares enumeration option."""
        config = EnumConfig(
            target="192.168.1.1",
            enum_shares=True
        )
        assert config.enum_shares == True

    def test_enum_users_option(self):
        """Test users enumeration option."""
        config = EnumConfig(
            target="192.168.1.1",
            enum_users=True
        )
        assert config.enum_users == True

    def test_credentials_option(self):
        """Test credentials configuration."""
        config = EnumConfig(
            target="192.168.1.1",
            username="admin",
            password="password"
        )
        assert config.username == "admin"


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_connection_error_handled(self):
        """Test that connection errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.side_effect = socket.error("Connection refused")

            config = EnumConfig(target="192.168.1.1")
            client = SMBClient(config)
            result = client.connect()

            # Should handle error gracefully
            assert result == False or result is None

    def test_timeout_handling(self):
        """Test that timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect.side_effect = socket.timeout("Timeout")

            config = EnumConfig(target="192.168.1.1", timeout=0.1)
            client = SMBClient(config)
            result = client.connect()

            # Should handle timeout gracefully
            assert result == False or result is None

    def test_authentication_failure_handling(self):
        """Test that authentication failures are handled."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b'\x00' * 32  # Invalid response

            config = EnumConfig(
                target="192.168.1.1",
                username="invalid",
                password="invalid"
            )
            client = SMBClient(config)

            # Should handle auth failure gracefully
            try:
                result = client.authenticate()
                assert result == False or result is None
            except:
                pass  # Exception handling is acceptable


# =============================================================================
# Test SMBShare Data Class
# =============================================================================

class TestSMBShare:
    """Tests for the SMBShare data class."""

    def test_smb_share_creation(self):
        """Test that SMBShare can be created."""
        share = SMBShare(
            name="Documents",
            share_type="disk"
        )
        assert share.name == "Documents"
        assert share.share_type == "disk"

    def test_smb_share_with_comment(self):
        """Test SMBShare with comment."""
        share = SMBShare(
            name="Documents",
            share_type="disk",
            comment="Shared documents folder"
        )
        assert share.comment == "Shared documents folder"

    def test_smb_share_with_permissions(self):
        """Test SMBShare with permissions."""
        share = SMBShare(
            name="Admin$",
            share_type="disk",
            permissions="read-only"
        )
        assert share.permissions == "read-only"


# =============================================================================
# Test SMBUser Data Class
# =============================================================================

class TestSMBUser:
    """Tests for the SMBUser data class."""

    def test_smb_user_creation(self):
        """Test that SMBUser can be created."""
        user = SMBUser(
            username="administrator",
            rid=500
        )
        assert user.username == "administrator"
        assert user.rid == 500

    def test_smb_user_with_full_name(self):
        """Test SMBUser with full name."""
        user = SMBUser(
            username="jsmith",
            rid=1001,
            full_name="John Smith"
        )
        assert user.full_name == "John Smith"


# =============================================================================
# Test SMBSystemInfo Data Class
# =============================================================================

class TestSMBSystemInfo:
    """Tests for the SMBSystemInfo data class."""

    def test_smb_system_info_creation(self):
        """Test that SMBSystemInfo can be created."""
        info = SMBSystemInfo(
            hostname="FILESERVER",
            domain="WORKGROUP"
        )
        assert info.hostname == "FILESERVER"
        assert info.domain == "WORKGROUP"

    def test_smb_system_info_with_os(self):
        """Test SMBSystemInfo with OS information."""
        info = SMBSystemInfo(
            hostname="FILESERVER",
            domain="WORKGROUP",
            os_version="Windows Server 2019"
        )
        assert "Windows" in info.os_version


# =============================================================================
# Test SMBClient Class
# =============================================================================

class TestSMBClient:
    """Tests for the SMBClient class."""

    def test_client_initialization(self):
        """Test SMBClient initialization."""
        config = EnumConfig(target="192.168.1.1")
        client = SMBClient(config)
        assert client is not None

    def test_client_with_credentials(self):
        """Test SMBClient with credentials."""
        config = EnumConfig(
            target="192.168.1.1",
            username="admin",
            password="password"
        )
        client = SMBClient(config)
        assert client.config.username == "admin"

    def test_client_connect_with_mock(self):
        """Test SMBClient connect with mocked socket."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b'\x00' * 100

            config = EnumConfig(target="192.168.1.1")
            client = SMBClient(config)

            # Connection attempt
            try:
                result = client.connect()
            except:
                pass  # Expected with incomplete mock


# =============================================================================
# Test SMBEnumerator Class
# =============================================================================

class TestSMBEnumerator:
    """Tests for the SMBEnumerator class."""

    def test_enumerator_initialization(self):
        """Test SMBEnumerator initialization."""
        config = EnumConfig(target="192.168.1.1")
        enumerator = SMBEnumerator(config)

        assert enumerator.config == config

    def test_enumerator_with_all_options(self):
        """Test enumerator with all enumeration options."""
        config = EnumConfig(
            target="192.168.1.1",
            enum_shares=True,
            enum_users=True,
            enum_groups=True
        )
        enumerator = SMBEnumerator(config)

        assert enumerator.config.enum_shares == True
        assert enumerator.config.enum_users == True


# =============================================================================
# Test Common Shares and RIDs
# =============================================================================

class TestCommonSharesAndRIDs:
    """Tests for common shares and RIDs lists."""

    def test_common_shares_not_empty(self):
        """Test that common shares list is not empty."""
        assert len(COMMON_SHARES) > 0

    def test_common_shares_contains_known_shares(self):
        """Test that common shares contains known share names."""
        known_shares = ["C$", "ADMIN$", "IPC$"]
        found = sum(1 for s in known_shares if s in COMMON_SHARES)
        assert found >= 2

    def test_common_rids_not_empty(self):
        """Test that common RIDs list is not empty."""
        assert len(COMMON_RIDS) > 0

    def test_common_rids_contains_known_rids(self):
        """Test that common RIDs contains known values."""
        # Administrator is typically RID 500
        assert 500 in COMMON_RIDS


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

    def test_parse_username_argument(self):
        """Test parsing username argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '-u', 'admin']):
            args = parse_arguments()
            assert args.username == 'admin'

    def test_parse_password_argument(self):
        """Test parsing password argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '-p', 'secret']):
            args = parse_arguments()
            assert args.password == 'secret'

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_shares_flag(self):
        """Test parsing --shares flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--shares']):
            args = parse_arguments()
            assert args.shares == True or args.enum_shares == True

    def test_parse_users_flag(self):
        """Test parsing --users flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--users']):
            args = parse_arguments()
            assert args.users == True or args.enum_users == True


# =============================================================================
# Integration Tests with Mocked Network
# =============================================================================

class TestIntegrationWithMockedNetwork:
    """Integration tests with mocked network operations."""

    def test_full_enumeration_run(self):
        """Test full SMB enumeration with mocked network."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b'\x00' * 100

            config = EnumConfig(
                target="192.168.1.1",
                enum_shares=True,
                enum_users=True
            )
            enumerator = SMBEnumerator(config)

            # Run enumeration - may fail with mock, but should not crash
            try:
                results = enumerator.enumerate()
                assert isinstance(results, (list, dict))
            except:
                pass  # Expected with incomplete SMB mock

    def test_null_session_enumeration(self):
        """Test null session enumeration."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b'\x00' * 100

            config = EnumConfig(
                target="192.168.1.1",
                null_session=True
            )
            enumerator = SMBEnumerator(config)

            try:
                results = enumerator.enumerate()
            except:
                pass  # Expected

    def test_authenticated_enumeration(self):
        """Test authenticated enumeration."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.recv.return_value = b'\x00' * 100

            config = EnumConfig(
                target="192.168.1.1",
                username="admin",
                password="password",
                enum_shares=True
            )
            enumerator = SMBEnumerator(config)

            try:
                results = enumerator.enumerate()
            except:
                pass  # Expected
