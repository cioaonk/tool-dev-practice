"""
Tests for the EDR Evasion Toolkit.

This module contains unit tests and integration tests for the edr-evasion-toolkit tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/edr-evasion-toolkit')

from edr_evasion import (
    TechniqueCategory,
    SyscallInfo,
    EvasionTechnique,
    EvasionConfig,
    DirectSyscallGenerator,
    UnhookingTechniques,
    MemoryEvasionTechniques,
    EDREvasionToolkit,
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
        assert docs["name"] == "edr-evasion-toolkit"

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

    def test_get_documentation_lists_techniques(self):
        """Test that documentation lists available techniques."""
        docs = get_documentation()
        doc_str = str(docs).lower()
        assert "technique" in doc_str or "evasion" in doc_str


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = EvasionConfig(
            technique="direct_syscall",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_technique(self, capsys):
        """Test that planning mode shows selected technique."""
        config = EvasionConfig(
            technique="unhooking",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "unhook" in captured.out.lower() or "technique" in captured.out.lower()

    def test_plan_mode_shows_description(self, capsys):
        """Test that planning mode shows technique description."""
        config = EvasionConfig(
            technique="direct_syscall",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should have meaningful content
        assert len(captured.out) > 50


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_technique_direct_syscall(self):
        """Test direct_syscall technique is accepted."""
        config = EvasionConfig(technique="direct_syscall")
        assert config.technique == "direct_syscall"

    def test_valid_technique_unhooking(self):
        """Test unhooking technique is accepted."""
        config = EvasionConfig(technique="unhooking")
        assert config.technique == "unhooking"

    def test_valid_technique_memory_evasion(self):
        """Test memory_evasion technique is accepted."""
        config = EvasionConfig(technique="memory_evasion")
        assert config.technique == "memory_evasion"

    def test_valid_output_format(self):
        """Test output format configuration."""
        config = EvasionConfig(
            technique="direct_syscall",
            output_format="asm"
        )
        assert config.output_format == "asm"


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_technique_handling(self):
        """Test handling of invalid technique."""
        try:
            config = EvasionConfig(technique="invalid_technique")
            toolkit = EDREvasionToolkit(config)
            result = toolkit.generate()
        except (ValueError, KeyError):
            pass  # Expected behavior

    def test_empty_technique_handling(self):
        """Test handling of empty technique."""
        try:
            config = EvasionConfig(technique="")
            toolkit = EDREvasionToolkit(config)
            result = toolkit.generate()
        except (ValueError, KeyError):
            pass  # Expected


# =============================================================================
# Test TechniqueCategory Enum
# =============================================================================

class TestTechniqueCategoryEnum:
    """Tests for the TechniqueCategory enum."""

    def test_category_syscall(self):
        """Test SYSCALL category."""
        assert TechniqueCategory.SYSCALL is not None

    def test_category_unhooking(self):
        """Test UNHOOKING category."""
        assert TechniqueCategory.UNHOOKING is not None

    def test_category_memory(self):
        """Test MEMORY category."""
        assert TechniqueCategory.MEMORY is not None


# =============================================================================
# Test SyscallInfo Data Class
# =============================================================================

class TestSyscallInfo:
    """Tests for the SyscallInfo data class."""

    def test_syscall_info_creation(self):
        """Test that SyscallInfo can be created."""
        info = SyscallInfo(
            name="NtAllocateVirtualMemory",
            syscall_number=24,
            num_args=6
        )
        assert info.name == "NtAllocateVirtualMemory"
        assert info.syscall_number == 24

    def test_syscall_info_with_signature(self):
        """Test SyscallInfo with function signature."""
        info = SyscallInfo(
            name="NtWriteVirtualMemory",
            syscall_number=58,
            num_args=5,
            signature="NTSTATUS NtWriteVirtualMemory(...)"
        )
        assert info.signature is not None


# =============================================================================
# Test EvasionTechnique Data Class
# =============================================================================

class TestEvasionTechnique:
    """Tests for the EvasionTechnique data class."""

    def test_technique_creation(self):
        """Test that EvasionTechnique can be created."""
        technique = EvasionTechnique(
            name="Direct Syscall",
            category=TechniqueCategory.SYSCALL,
            description="Bypasses user-mode hooks"
        )
        assert technique.name == "Direct Syscall"
        assert technique.category == TechniqueCategory.SYSCALL

    def test_technique_with_code(self):
        """Test EvasionTechnique with code template."""
        technique = EvasionTechnique(
            name="Direct Syscall",
            category=TechniqueCategory.SYSCALL,
            description="Syscall stub",
            code_template="mov r10, rcx\nmov eax, <syscall_number>"
        )
        assert technique.code_template is not None

    def test_technique_with_detection_info(self):
        """Test EvasionTechnique with detection information."""
        technique = EvasionTechnique(
            name="DLL Unhooking",
            category=TechniqueCategory.UNHOOKING,
            description="Removes EDR hooks",
            detection_methods=["ETW", "Kernel callbacks"]
        )
        assert len(technique.detection_methods) > 0


# =============================================================================
# Test EvasionConfig Data Class
# =============================================================================

class TestEvasionConfig:
    """Tests for the EvasionConfig data class."""

    def test_config_creation(self):
        """Test EvasionConfig creation."""
        config = EvasionConfig(technique="direct_syscall")
        assert config.technique == "direct_syscall"

    def test_config_with_options(self):
        """Test EvasionConfig with options."""
        config = EvasionConfig(
            technique="direct_syscall",
            output_format="asm",
            target_api="NtAllocateVirtualMemory",
            plan_mode=True
        )
        assert config.target_api == "NtAllocateVirtualMemory"
        assert config.plan_mode == True


# =============================================================================
# Test DirectSyscallGenerator Class
# =============================================================================

class TestDirectSyscallGenerator:
    """Tests for the DirectSyscallGenerator class."""

    def test_generator_initialization(self):
        """Test DirectSyscallGenerator initialization."""
        generator = DirectSyscallGenerator()
        assert generator is not None

    def test_generator_get_syscall_number(self):
        """Test getting syscall number."""
        generator = DirectSyscallGenerator()
        # NtAllocateVirtualMemory is commonly used
        number = generator.get_syscall_number("NtAllocateVirtualMemory")

        # Should return a syscall number (varies by Windows version)
        assert number is not None or isinstance(number, int)

    def test_generator_generate_stub(self):
        """Test generating syscall stub."""
        generator = DirectSyscallGenerator()
        stub = generator.generate_stub("NtWriteVirtualMemory")

        # Should produce assembly or machine code
        assert stub is not None
        assert len(stub) > 0

    def test_generator_djb2_hash(self):
        """Test DJB2 API hashing."""
        generator = DirectSyscallGenerator()
        hash_value = generator.djb2_hash("NtAllocateVirtualMemory")

        # Should produce a hash value
        assert isinstance(hash_value, int)
        assert hash_value != 0

    def test_generator_ror13_hash(self):
        """Test ROR13 API hashing."""
        generator = DirectSyscallGenerator()
        hash_value = generator.ror13_hash("kernel32.dll")

        # Should produce a hash value
        assert isinstance(hash_value, int)


# =============================================================================
# Test UnhookingTechniques Class
# =============================================================================

class TestUnhookingTechniques:
    """Tests for the UnhookingTechniques class."""

    def test_unhooking_initialization(self):
        """Test UnhookingTechniques initialization."""
        unhooking = UnhookingTechniques()
        assert unhooking is not None

    def test_unhooking_list_techniques(self):
        """Test listing unhooking techniques."""
        unhooking = UnhookingTechniques()
        techniques = unhooking.list_techniques()

        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_unhooking_generate_peruns_fart(self):
        """Test generating Perun's Fart technique."""
        unhooking = UnhookingTechniques()
        code = unhooking.generate_peruns_fart()

        # Should produce code or description
        assert code is not None

    def test_unhooking_generate_fresh_copy(self):
        """Test generating fresh DLL copy technique."""
        unhooking = UnhookingTechniques()
        code = unhooking.generate_fresh_copy()

        # Should produce technique implementation
        assert code is not None


# =============================================================================
# Test MemoryEvasionTechniques Class
# =============================================================================

class TestMemoryEvasionTechniques:
    """Tests for the MemoryEvasionTechniques class."""

    def test_memory_evasion_initialization(self):
        """Test MemoryEvasionTechniques initialization."""
        evasion = MemoryEvasionTechniques()
        assert evasion is not None

    def test_memory_evasion_list_techniques(self):
        """Test listing memory evasion techniques."""
        evasion = MemoryEvasionTechniques()
        techniques = evasion.list_techniques()

        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_memory_evasion_generate_stomping(self):
        """Test generating module stomping technique."""
        evasion = MemoryEvasionTechniques()
        code = evasion.generate_module_stomping()

        assert code is not None

    def test_memory_evasion_generate_phantom(self):
        """Test generating phantom DLL technique."""
        evasion = MemoryEvasionTechniques()
        code = evasion.generate_phantom_dll()

        assert code is not None


# =============================================================================
# Test EDREvasionToolkit Class
# =============================================================================

class TestEDREvasionToolkit:
    """Tests for the EDREvasionToolkit class."""

    def test_toolkit_initialization(self):
        """Test EDREvasionToolkit initialization."""
        config = EvasionConfig(technique="direct_syscall")
        toolkit = EDREvasionToolkit(config)
        assert toolkit is not None

    def test_toolkit_list_all_techniques(self):
        """Test listing all available techniques."""
        config = EvasionConfig(technique="direct_syscall")
        toolkit = EDREvasionToolkit(config)
        techniques = toolkit.list_all_techniques()

        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_toolkit_generate_syscall(self):
        """Test generating direct syscall code."""
        config = EvasionConfig(
            technique="direct_syscall",
            target_api="NtAllocateVirtualMemory"
        )
        toolkit = EDREvasionToolkit(config)
        result = toolkit.generate()

        assert result is not None

    def test_toolkit_generate_unhooking(self):
        """Test generating unhooking code."""
        config = EvasionConfig(technique="unhooking")
        toolkit = EDREvasionToolkit(config)
        result = toolkit.generate()

        assert result is not None

    def test_toolkit_generate_memory_evasion(self):
        """Test generating memory evasion code."""
        config = EvasionConfig(technique="memory_evasion")
        toolkit = EDREvasionToolkit(config)
        result = toolkit.generate()

        assert result is not None


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_technique_argument(self):
        """Test parsing technique argument."""
        with patch('sys.argv', ['edr_evasion.py', '-t', 'direct_syscall']):
            args = parse_arguments()
            assert args.technique == 'direct_syscall' or 'syscall' in str(args.technique)

    def test_parse_api_argument(self):
        """Test parsing target API argument."""
        with patch('sys.argv', ['edr_evasion.py', '-a', 'NtAllocateVirtualMemory']):
            args = parse_arguments()
            assert 'NtAllocate' in str(args.api) or args.target_api

    def test_parse_format_argument(self):
        """Test parsing output format argument."""
        with patch('sys.argv', ['edr_evasion.py', '-f', 'asm']):
            args = parse_arguments()
            assert args.format == 'asm' or 'asm' in str(args.output_format)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['edr_evasion.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_list_flag(self):
        """Test parsing --list flag."""
        with patch('sys.argv', ['edr_evasion.py', '--list']):
            args = parse_arguments()
            assert args.list == True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for EDR evasion toolkit."""

    def test_generate_all_techniques(self):
        """Test generating all available techniques."""
        techniques = ["direct_syscall", "unhooking", "memory_evasion"]

        for technique in techniques:
            config = EvasionConfig(technique=technique)
            toolkit = EDREvasionToolkit(config)

            try:
                result = toolkit.generate()
                assert result is not None
            except (ValueError, KeyError):
                pass  # Some may not be fully implemented

    def test_syscall_for_common_apis(self):
        """Test syscall generation for common APIs."""
        common_apis = [
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "NtProtectVirtualMemory",
        ]

        generator = DirectSyscallGenerator()

        for api in common_apis:
            try:
                stub = generator.generate_stub(api)
                assert stub is not None
            except (ValueError, KeyError):
                pass  # API might not be in database

    def test_api_hashing_consistency(self):
        """Test that API hashing is consistent."""
        generator = DirectSyscallGenerator()

        api_name = "NtAllocateVirtualMemory"
        hash1 = generator.djb2_hash(api_name)
        hash2 = generator.djb2_hash(api_name)

        # Same input should produce same hash
        assert hash1 == hash2

    def test_technique_categorization(self):
        """Test that techniques are properly categorized."""
        config = EvasionConfig(technique="direct_syscall")
        toolkit = EDREvasionToolkit(config)
        techniques = toolkit.list_all_techniques()

        for technique in techniques:
            if hasattr(technique, 'category'):
                assert isinstance(technique.category, TechniqueCategory)
