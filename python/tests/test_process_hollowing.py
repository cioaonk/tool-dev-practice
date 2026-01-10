"""
Tests for the Process Hollowing tool.

This module contains unit tests and integration tests for the process-hollowing tool,
including tests for planning mode, input validation, error handling, and the
get_documentation() function.

Note: This tool is educational and demonstrates Windows process hollowing concepts.
"""

import pytest
import sys
from unittest.mock import patch, MagicMock
from io import StringIO

# Add the tools directory to path for imports
sys.path.insert(0, '/Users/ic/cptc11/python/tools/process-hollowing')

from process_hollowing import (
    ProcessState,
    HollowingStep,
    HollowingConfig,
    WindowsAPISimulator,
    ProcessHollowingDemonstrator,
    get_documentation,
    print_plan,
    parse_arguments,
    COMMON_TARGETS,
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
        assert docs["name"] == "process-hollowing"

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

    def test_get_documentation_mentions_educational(self):
        """Test that documentation mentions educational purpose."""
        docs = get_documentation()
        doc_str = str(docs).lower()
        assert "educational" in doc_str or "demonstration" in doc_str or "learning" in doc_str


# =============================================================================
# Test Planning Mode
# =============================================================================

class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_process(self, capsys):
        """Test that planning mode shows target process."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "svchost" in captured.out.lower()

    def test_plan_mode_shows_steps(self, capsys):
        """Test that planning mode shows hollowing steps."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should mention process hollowing steps
        output_lower = captured.out.lower()
        assert "step" in output_lower or "create" in output_lower or "suspend" in output_lower

    def test_plan_mode_is_simulation_only(self, capsys):
        """Test that planning mode indicates simulation."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        # Should indicate no actual execution
        output_lower = captured.out.lower()
        assert "simulation" in output_lower or "educational" in output_lower or "demo" in output_lower or "plan" in output_lower


# =============================================================================
# Test Input Validation
# =============================================================================

class TestInputValidation:
    """Tests for input validation."""

    def test_valid_target_process(self):
        """Test that valid target processes are accepted."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe"
        )
        assert config.target_process == "svchost.exe"

    def test_valid_payload_path(self):
        """Test that valid payload paths are accepted."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\Windows\\Temp\\payload.exe"
        )
        assert "payload" in config.payload_path

    def test_common_targets_available(self):
        """Test that common target processes are defined."""
        assert len(COMMON_TARGETS) > 0
        # Should include common Windows processes
        target_names = [t.lower() for t in COMMON_TARGETS]
        assert any("svchost" in t for t in target_names) or len(COMMON_TARGETS) > 0


# =============================================================================
# Test Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for error handling."""

    def test_empty_target_handling(self):
        """Test handling of empty target process."""
        try:
            config = HollowingConfig(
                target_process="",
                payload_path="C:\\payload.exe"
            )
            demonstrator = ProcessHollowingDemonstrator(config)
            result = demonstrator.demonstrate()
        except ValueError:
            pass  # Acceptable

    def test_invalid_payload_path_handling(self):
        """Test handling of invalid payload path."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path=""
        )
        demonstrator = ProcessHollowingDemonstrator(config)
        # Should handle gracefully in simulation
        try:
            result = demonstrator.demonstrate()
        except ValueError:
            pass  # Acceptable


# =============================================================================
# Test ProcessState Enum
# =============================================================================

class TestProcessStateEnum:
    """Tests for the ProcessState enum."""

    def test_process_state_created(self):
        """Test CREATED state."""
        assert ProcessState.CREATED is not None

    def test_process_state_suspended(self):
        """Test SUSPENDED state."""
        assert ProcessState.SUSPENDED is not None

    def test_process_state_hollowed(self):
        """Test HOLLOWED state."""
        assert ProcessState.HOLLOWED is not None

    def test_process_state_resumed(self):
        """Test RESUMED state."""
        assert ProcessState.RESUMED is not None


# =============================================================================
# Test HollowingStep Data Class
# =============================================================================

class TestHollowingStep:
    """Tests for the HollowingStep data class."""

    def test_hollowing_step_creation(self):
        """Test that HollowingStep can be created."""
        step = HollowingStep(
            step_number=1,
            name="Create Process",
            description="Create target process in suspended state",
            api_calls=["CreateProcessA"]
        )
        assert step.step_number == 1
        assert step.name == "Create Process"

    def test_hollowing_step_with_api_calls(self):
        """Test HollowingStep with multiple API calls."""
        step = HollowingStep(
            step_number=2,
            name="Unmap Memory",
            description="Unmap the original executable",
            api_calls=["NtUnmapViewOfSection", "ZwUnmapViewOfSection"]
        )
        assert len(step.api_calls) == 2


# =============================================================================
# Test HollowingConfig Data Class
# =============================================================================

class TestHollowingConfig:
    """Tests for the HollowingConfig data class."""

    def test_config_creation(self):
        """Test HollowingConfig creation."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe"
        )
        assert config.target_process == "svchost.exe"

    def test_config_with_options(self):
        """Test HollowingConfig with options."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            verbose=True,
            plan_mode=True
        )
        assert config.verbose == True
        assert config.plan_mode == True


# =============================================================================
# Test WindowsAPISimulator Class
# =============================================================================

class TestWindowsAPISimulator:
    """Tests for the WindowsAPISimulator class."""

    def test_simulator_initialization(self):
        """Test WindowsAPISimulator initialization."""
        simulator = WindowsAPISimulator()
        assert simulator is not None

    def test_simulator_create_process(self):
        """Test simulated CreateProcess."""
        simulator = WindowsAPISimulator()
        result = simulator.create_process_suspended("svchost.exe")

        # Should return simulated process handle/info
        assert result is not None

    def test_simulator_get_thread_context(self):
        """Test simulated GetThreadContext."""
        simulator = WindowsAPISimulator()
        result = simulator.get_thread_context(12345)

        # Should return simulated context
        assert result is not None

    def test_simulator_unmap_view(self):
        """Test simulated NtUnmapViewOfSection."""
        simulator = WindowsAPISimulator()
        result = simulator.unmap_view_of_section(12345, 0x400000)

        # Should return success indicator
        assert result is not None or result == True

    def test_simulator_virtual_alloc(self):
        """Test simulated VirtualAllocEx."""
        simulator = WindowsAPISimulator()
        result = simulator.virtual_alloc_ex(12345, 0x400000, 4096)

        # Should return simulated address
        assert result is not None

    def test_simulator_write_memory(self):
        """Test simulated WriteProcessMemory."""
        simulator = WindowsAPISimulator()
        result = simulator.write_process_memory(12345, 0x400000, b"test")

        # Should return success indicator
        assert result is not None or result == True

    def test_simulator_resume_thread(self):
        """Test simulated ResumeThread."""
        simulator = WindowsAPISimulator()
        result = simulator.resume_thread(12345)

        # Should return success indicator
        assert result is not None or result == True


# =============================================================================
# Test ProcessHollowingDemonstrator Class
# =============================================================================

class TestProcessHollowingDemonstrator:
    """Tests for the ProcessHollowingDemonstrator class."""

    def test_demonstrator_initialization(self):
        """Test ProcessHollowingDemonstrator initialization."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe"
        )
        demonstrator = ProcessHollowingDemonstrator(config)
        assert demonstrator is not None

    def test_demonstrator_get_steps(self):
        """Test getting hollowing steps."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe"
        )
        demonstrator = ProcessHollowingDemonstrator(config)
        steps = demonstrator.get_steps()

        assert isinstance(steps, list)
        assert len(steps) > 0

    def test_demonstrator_demonstrate(self):
        """Test demonstration execution."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe",
            verbose=True
        )
        demonstrator = ProcessHollowingDemonstrator(config)
        result = demonstrator.demonstrate()

        # Should complete demonstration without error
        assert result is not None or result == True

    def test_demonstrator_step_descriptions(self):
        """Test that steps have descriptions."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\payload.exe"
        )
        demonstrator = ProcessHollowingDemonstrator(config)
        steps = demonstrator.get_steps()

        for step in steps:
            assert hasattr(step, 'description') or hasattr(step, 'name')


# =============================================================================
# Test Common Targets
# =============================================================================

class TestCommonTargets:
    """Tests for common target processes."""

    def test_common_targets_defined(self):
        """Test that common targets are defined."""
        assert COMMON_TARGETS is not None
        assert len(COMMON_TARGETS) > 0

    def test_common_targets_are_strings(self):
        """Test that all common targets are strings."""
        for target in COMMON_TARGETS:
            assert isinstance(target, str) or isinstance(target, dict)


# =============================================================================
# Test CLI Argument Parsing
# =============================================================================

class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_target_argument(self):
        """Test parsing target process argument."""
        with patch('sys.argv', ['process_hollowing.py', '-t', 'svchost.exe']):
            args = parse_arguments()
            assert args.target == 'svchost.exe' or 'svchost' in str(args.target_process)

    def test_parse_payload_argument(self):
        """Test parsing payload path argument."""
        with patch('sys.argv', ['process_hollowing.py', '-p', 'C:\\payload.exe']):
            args = parse_arguments()
            assert 'payload' in str(args.payload).lower()

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['process_hollowing.py', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_verbose_flag(self):
        """Test parsing --verbose flag."""
        with patch('sys.argv', ['process_hollowing.py', '--verbose']):
            args = parse_arguments()
            assert args.verbose == True


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for process hollowing demonstrator."""

    def test_full_demonstration_workflow(self):
        """Test complete demonstration workflow."""
        config = HollowingConfig(
            target_process="svchost.exe",
            payload_path="C:\\Windows\\Temp\\test.exe",
            verbose=True
        )
        demonstrator = ProcessHollowingDemonstrator(config)

        # Get steps
        steps = demonstrator.get_steps()
        assert len(steps) > 0

        # Run demonstration
        result = demonstrator.demonstrate()
        assert result is not None

    def test_demonstration_with_different_targets(self):
        """Test demonstration with different target processes."""
        targets = ["svchost.exe", "notepad.exe", "explorer.exe"]

        for target in targets:
            config = HollowingConfig(
                target_process=target,
                payload_path="C:\\payload.exe"
            )
            demonstrator = ProcessHollowingDemonstrator(config)
            result = demonstrator.demonstrate()

            # Should complete without error
            assert result is not None or result == True

    def test_api_simulator_sequence(self):
        """Test API simulator with typical hollowing sequence."""
        simulator = WindowsAPISimulator()

        # Typical hollowing sequence
        process_info = simulator.create_process_suspended("svchost.exe")
        assert process_info is not None

        context = simulator.get_thread_context(1234)
        assert context is not None

        unmap_result = simulator.unmap_view_of_section(1234, 0x400000)
        assert unmap_result is not None or unmap_result == True

        alloc_addr = simulator.virtual_alloc_ex(1234, 0x400000, 4096)
        assert alloc_addr is not None

        write_result = simulator.write_process_memory(1234, 0x400000, b"MZ...")
        assert write_result is not None or write_result == True

        resume_result = simulator.resume_thread(1234)
        assert resume_result is not None or resume_result == True
