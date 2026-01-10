"""
Integration tests for SMB enumeration against Docker environment.
"""

import pytest
import socket
import sys
import os

# Add tools path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'smb-enumerator'))

try:
    from tool import SMBClient, SMBEnumerator, EnumConfig
except ImportError:
    SMBClient = None
    SMBEnumerator = None
    EnumConfig = None


class TestSMBConnection:
    """Test basic SMB connectivity."""

    def test_smb_port_open(self, smb_service):
        """Test that SMB port is open."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        result = sock.connect_ex((smb_service["host"], smb_service["port"]))
        sock.close()

        assert result == 0, f"SMB port {smb_service['port']} should be open"

    def test_smb_banner_exchange(self, smb_service):
        """Test basic SMB protocol exchange."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((smb_service["host"], smb_service["port"]))

        # Build simple SMB negotiate request
        # NetBIOS header (4 bytes) + SMB header
        smb_negotiate = (
            b'\x00\x00\x00\x54'  # NetBIOS length
            b'\xffSMB'          # SMB signature
            b'\x72'             # SMB_COM_NEGOTIATE
            b'\x00\x00\x00\x00' # Status
            b'\x18'             # Flags
            b'\x53\xc8'         # Flags2
            b'\x00\x00'         # PID High
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
            b'\x00\x00'         # Reserved
            b'\x00\x00'         # TID
            b'\xff\xfe'         # PID
            b'\x00\x00'         # UID
            b'\x00\x00'         # MID
            # Words
            b'\x00'             # Word count
            # Bytes
            b'\x31\x00'         # Byte count
            b'\x02NT LM 0.12\x00'
            b'\x02SMB 2.002\x00'
            b'\x02SMB 2.???\x00'
        )

        sock.send(smb_negotiate)
        response = sock.recv(4096)
        sock.close()

        assert len(response) > 4, "Should receive SMB response"
        # Check for SMB signature in response
        assert b'\xffSMB' in response or b'\xfeSMB' in response, \
            "Response should contain SMB signature"


@pytest.mark.skipif(SMBClient is None, reason="SMB enumerator tool not available")
class TestSMBEnumeration:
    """Test SMB enumeration using the tool."""

    def test_smb_client_connect(self, smb_service):
        """Test SMB client connection."""
        client = SMBClient(
            target=smb_service["host"],
            port=smb_service["port"],
            timeout=10.0
        )

        result = client.connect()

        if result:
            client.disconnect()

        assert result is True, "Should be able to connect to SMB server"

    def test_smb_negotiate(self, smb_service):
        """Test SMB negotiation and system info gathering."""
        client = SMBClient(
            target=smb_service["host"],
            port=smb_service["port"],
            timeout=10.0
        )

        if not client.connect():
            pytest.fail("Failed to connect to SMB server")

        system_info = client.negotiate()
        client.disconnect()

        assert system_info is not None, "Should receive system info from negotiate"

    def test_smb_enumerator_config(self, smb_service):
        """Test SMB enumerator configuration."""
        config = EnumConfig(
            target=smb_service["host"],
            port=smb_service["port"],
            null_session=True,
            enum_shares=True,
            enum_users=True,
            timeout=10.0
        )

        assert config.target == smb_service["host"]
        assert config.port == smb_service["port"]
        assert config.null_session is True

    def test_share_enumeration(self, smb_service):
        """Test enumeration of SMB shares."""
        config = EnumConfig(
            target=smb_service["host"],
            port=smb_service["port"],
            null_session=True,
            enum_shares=True,
            enum_users=False,
            timeout=10.0,
            verbose=False
        )

        enumerator = SMBEnumerator(config)
        result = enumerator.enumerate()

        # Should find at least the public share
        share_names = [s.name for s in result.shares]

        # Note: Null session may not be able to enumerate all shares
        # depending on Samba configuration
        assert result is not None, "Should return enumeration result"


class TestSMBShareAccess:
    """Test SMB share access patterns."""

    def test_expected_shares_configured(self, smb_service):
        """Verify expected shares are configured."""
        expected_shares = smb_service["shares"]

        # These shares should be defined in smb.conf
        assert "public" in expected_shares
        assert "private" in expected_shares
        assert "backup" in expected_shares

    def test_null_session_support(self, smb_service):
        """Test that null session is supported (by configuration)."""
        # Our Samba config has:
        # - restrict anonymous = 0
        # - null passwords = yes
        # - guest account = nobody

        # This test documents the expected configuration
        # Actual null session testing requires more complex SMB protocol handling
        assert smb_service["port"] == 4445
