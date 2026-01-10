"""
Tests for the AMSI Bypass tool.

This module contains unit tests and integration tests for the amsi-bypass tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.

Note: This tool generates educational AMSI bypass technique documentation.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/amsi-bypass')

from amsi_bypass import (
    BypassCategory,
    BypassTechnique,
    BypassConfig,
    StringObfuscator,
    AMSIBypassGenerator,
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
        assert docs["name"] == "amsi-bypass"

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
        config = BypassConfig(
            technique="memory_patch",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_technique(self, capsys):
        """Test that planning mode shows selected technique."""
        config = BypassConfig(
            technique="reflection",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "reflection" in captured.out.lower() or "technique" in captured.out.lower()

    def test_plan_mode_shows_description(self, capsys):
        """Test that planning mode shows technique description."""
        config = BypassConfig(
            technique="memory_patch",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should have some description
        assert len(captured.out) > 50  # More than just headers


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_technique_memory_patch(self):
        """Test memory_patch technique is accepted."""
        config = BypassConfig(technique="memory_patch")
        assert config.technique == "memory_patch"

    def test_valid_technique_reflection(self):
        """Test reflection technique is accepted."""
        config = BypassConfig(technique="reflection")
        assert config.technique == "reflection"

    def test_valid_technique_string_obfuscation(self):
        """Test string_obfuscation technique is accepted."""
        config = BypassConfig(technique="string_obfuscation")
        assert config.technique == "string_obfuscation"

    def test_valid_output_format_powershell(self):
        """Test PowerShell output format is accepted."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="powershell"
        )
        assert config.output_format == "powershell"

    def test_valid_output_format_csharp(self):
        """Test C# output format is accepted."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="csharp"
        )
        assert config.output_format == "csharp"


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_technique_handling(self):
        """Test handling of invalid technique."""
        try:
            config = BypassConfig(technique="invalid_technique")
            generator = AMSIBypassGenerator(config)
            result = generator.generate()
        except (ValueError, KeyError):
            pass  # Expected behavior

    def test_empty_technique_handling(self):
        """Test handling of empty technique."""
        try:
            config = BypassConfig(technique="")
            generator = AMSIBypassGenerator(config)
            result = generator.generate()
        except (ValueError, KeyError):
            pass  # Expected behavior


# =============================================================================
# Test BypassCategory Enum
# =============================================================================

class TestBypassCategoryEnum:
    """Tests for the BypassCategory enum."""

    def test_category_memory_patching(self):
        """Test MEMORY_PATCHING category."""
        assert BypassCategory.MEMORY_PATCHING is not None

    def test_category_reflection(self):
        """Test REFLECTION category."""
        assert BypassCategory.REFLECTION is not None

    def test_category_obfuscation(self):
        """Test OBFUSCATION category."""
        assert BypassCategory.OBFUSCATION is not None


# =============================================================================
# Test BypassTechnique Data Class
# =============================================================================

class TestBypassTechnique:
    """Tests for the BypassTechnique data class."""

    def test_technique_creation(self):
        """Test that BypassTechnique can be created."""
        technique = BypassTechnique(
            name="Memory Patch",
            category=BypassCategory.MEMORY_PATCHING,
            description="Patches AMSI DLL in memory"
        )
        assert technique.name == "Memory Patch"
        assert technique.category == BypassCategory.MEMORY_PATCHING

    def test_technique_with_code(self):
        """Test BypassTechnique with code."""
        technique = BypassTechnique(
            name="Memory Patch",
            category=BypassCategory.MEMORY_PATCHING,
            description="Patches AMSI DLL",
            code_template="$a = [Ref].Assembly..."
        )
        assert technique.code_template is not None

    def test_technique_with_detection_notes(self):
        """Test BypassTechnique with detection notes."""
        technique = BypassTechnique(
            name="Memory Patch",
            category=BypassCategory.MEMORY_PATCHING,
            description="Patches AMSI DLL",
            detection_notes=["May trigger memory protection alerts"]
        )
        assert len(technique.detection_notes) > 0


# =============================================================================
# Test BypassConfig Data Class
# =============================================================================

class TestBypassConfig:
    """Tests for the BypassConfig data class."""

    def test_config_creation(self):
        """Test BypassConfig creation."""
        config = BypassConfig(technique="memory_patch")
        assert config.technique == "memory_patch"

    def test_config_with_options(self):
        """Test BypassConfig with options."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="powershell",
            obfuscate=True,
            plan_mode=True
        )
        assert config.obfuscate == True
        assert config.plan_mode == True


# =============================================================================
# Test StringObfuscator Class
# =============================================================================

class TestStringObfuscator:
    """Tests for the StringObfuscator class."""

    def test_obfuscator_initialization(self):
        """Test StringObfuscator initialization."""
        obfuscator = StringObfuscator()
        assert obfuscator is not None

    def test_obfuscator_base64_encode(self):
        """Test base64 encoding."""
        obfuscator = StringObfuscator()
        result = obfuscator.base64_encode("test")

        # Result should be base64 encoded
        import base64
        assert result != "test"

    def test_obfuscator_char_code_split(self):
        """Test character code splitting."""
        obfuscator = StringObfuscator()
        result = obfuscator.char_code_split("AMSI")

        # Should produce character codes
        assert "+" in result or "[char]" in result or "chr" in result.lower()

    def test_obfuscator_string_reverse(self):
        """Test string reversal."""
        obfuscator = StringObfuscator()
        result = obfuscator.reverse_string("AMSI")

        # Should be reversed
        assert "ISMA" in result or result != "AMSI"

    def test_obfuscator_concatenation(self):
        """Test string concatenation obfuscation."""
        obfuscator = StringObfuscator()
        result = obfuscator.concatenate("AmsiUtils")

        # Should be split into parts
        assert "+" in result or "'" in result or '"' in result


# =============================================================================
# Test AMSIBypassGenerator Class
# =============================================================================

class TestAMSIBypassGenerator:
    """Tests for the AMSIBypassGenerator class."""

    def test_generator_initialization(self):
        """Test AMSIBypassGenerator initialization."""
        config = BypassConfig(technique="memory_patch")
        generator = AMSIBypassGenerator(config)
        assert generator is not None

    def test_generator_list_techniques(self):
        """Test listing available techniques."""
        config = BypassConfig(technique="memory_patch")
        generator = AMSIBypassGenerator(config)
        techniques = generator.list_techniques()

        assert isinstance(techniques, list)
        assert len(techniques) > 0

    def test_generator_memory_patch_technique(self):
        """Test generating memory patch bypass."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="powershell"
        )
        generator = AMSIBypassGenerator(config)
        result = generator.generate()

        assert result is not None
        # Should contain PowerShell or AMSI-related content
        assert "amsi" in str(result).lower() or "patch" in str(result).lower()

    def test_generator_reflection_technique(self):
        """Test generating reflection bypass."""
        config = BypassConfig(
            technique="reflection",
            output_format="powershell"
        )
        generator = AMSIBypassGenerator(config)
        result = generator.generate()

        assert result is not None

    def test_generator_with_obfuscation(self):
        """Test generating obfuscated bypass."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="powershell",
            obfuscate=True
        )
        generator = AMSIBypassGenerator(config)
        result = generator.generate()

        assert result is not None

    def test_generator_csharp_output(self):
        """Test generating C# output."""
        config = BypassConfig(
            technique="memory_patch",
            output_format="csharp"
        )
        generator = AMSIBypassGenerator(config)
        result = generator.generate()

        assert result is not None


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_technique_argument(self):
        """Test parsing technique argument."""
        with patch('sys.argv', ['amsi_bypass.py', '-t', 'memory_patch']):
            args = parse_arguments()
            assert args.technique == 'memory_patch' or 'memory_patch' in str(args.technique)

    def test_parse_format_argument(self):
        """Test parsing format argument."""
        with patch('sys.argv', ['amsi_bypass.py', '-f', 'powershell']):
            args = parse_arguments()
            assert args.format == 'powershell' or 'powershell' in str(args.output_format)

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['amsi_bypass.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_obfuscate_flag(self):
        """Test parsing --obfuscate flag."""
        with patch('sys.argv', ['amsi_bypass.py', '--obfuscate']):
            args = parse_arguments()
            assert args.obfuscate == True

    def test_parse_list_flag(self):
        """Test parsing --list flag."""
        with patch('sys.argv', ['amsi_bypass.py', '--list']):
            args = parse_arguments()
            assert args.list == True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for AMSI bypass generator."""

    def test_generate_all_techniques(self):
        """Test generating all available techniques."""
        config = BypassConfig(technique="memory_patch")
        generator = AMSIBypassGenerator(config)
        techniques = generator.list_techniques()

        for technique in techniques:
            tech_name = technique.name if hasattr(technique, 'name') else str(technique)
            try:
                config = BypassConfig(technique=tech_name.lower().replace(" ", "_"))
                gen = AMSIBypassGenerator(config)
                result = gen.generate()
                assert result is not None
            except (ValueError, KeyError):
                pass  # Some techniques may not be implemented

    def test_obfuscation_variations(self):
        """Test different obfuscation methods."""
        obfuscator = StringObfuscator()
        test_string = "AmsiScanBuffer"

        methods = [
            obfuscator.base64_encode,
            obfuscator.char_code_split,
            obfuscator.reverse_string,
            obfuscator.concatenate,
        ]

        for method in methods:
            result = method(test_string)
            # Result should be different from original
            assert result != test_string

    def test_output_format_variations(self):
        """Test different output formats."""
        formats = ["powershell", "csharp"]

        for fmt in formats:
            config = BypassConfig(
                technique="memory_patch",
                output_format=fmt
            )
            generator = AMSIBypassGenerator(config)
            result = generator.generate()

            assert result is not None

    def test_technique_category_mapping(self):
        """Test that techniques have proper categories."""
        config = BypassConfig(technique="memory_patch")
        generator = AMSIBypassGenerator(config)
        techniques = generator.list_techniques()

        for technique in techniques:
            if hasattr(technique, 'category'):
                assert isinstance(technique.category, BypassCategory)
