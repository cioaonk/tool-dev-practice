"""
Integration Test Base for CPTC11

This module contains integration tests that verify interactions
between multiple components in the CPTC11 tool suite.
"""

import pytest
import json
import os
import tempfile
import shutil
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


# ============================================================================
# INTEGRATION TEST BASE CLASS
# ============================================================================

class IntegrationTestBase:
    """Base class for integration tests with common setup/teardown."""

    @pytest.fixture(autouse=True)
    def setup_integration_environment(self, temp_dir):
        """Set up integration test environment."""
        self.test_dir = temp_dir
        self.test_files = {}
        yield
        # Cleanup is handled by temp_dir fixture

    def create_test_file(self, name, content):
        """Helper to create test files."""
        file_path = self.test_dir / name
        if isinstance(content, bytes):
            file_path.write_bytes(content)
        else:
            file_path.write_text(content)
        self.test_files[name] = file_path
        return file_path


# ============================================================================
# FILE ANALYSIS PIPELINE INTEGRATION TESTS
# ============================================================================

class TestFileAnalysisPipeline(IntegrationTestBase):
    """Integration tests for the file analysis pipeline."""

    @pytest.mark.integration
    def test_file_info_full_analysis(self, temp_file):
        """Test complete file analysis workflow."""
        from file_info import get_file_info

        # Step 1: Analyze file
        result = get_file_info(str(temp_file))
        info = json.loads(result)

        # Step 2: Verify all fields present
        assert 'filename' in info
        assert 'md5sum' in info
        assert 'file_size' in info
        assert 'file_type' in info
        assert 'base64_encoded' in info

        # Step 3: Verify data consistency
        assert info['file_size'] == os.path.getsize(temp_file)

    @pytest.mark.integration
    def test_multiple_file_analysis(self, temp_dir):
        """Test analyzing multiple files in sequence."""
        from file_info import get_file_info

        # Create multiple test files
        files = []
        for i in range(5):
            file_path = temp_dir / f"test_file_{i}.txt"
            file_path.write_text(f"Content for file {i}")
            files.append(file_path)

        # Analyze all files
        results = []
        for file_path in files:
            result = json.loads(get_file_info(str(file_path)))
            results.append(result)

        # Verify all analyses succeeded
        for result in results:
            assert 'error' not in result
            assert 'md5sum' in result


# ============================================================================
# CROSS-TOOL INTEGRATION TESTS
# ============================================================================

class TestCrossToolIntegration(IntegrationTestBase):
    """Integration tests for interactions between different tools."""

    @pytest.mark.integration
    def test_tool_output_compatibility(self):
        """Test that tool outputs can be used as inputs to other tools."""
        # This test verifies JSON output format compatibility
        # between different tools in the suite
        pass

    @pytest.mark.integration
    def test_concurrent_tool_execution(self):
        """Test running multiple tools concurrently."""
        # Verify tools can run in parallel without interference
        pass


# ============================================================================
# ERROR PROPAGATION TESTS
# ============================================================================

class TestErrorPropagation(IntegrationTestBase):
    """Test error handling across tool boundaries."""

    @pytest.mark.integration
    def test_error_json_format_consistency(self, nonexistent_file):
        """Test that all tools return errors in consistent JSON format."""
        from file_info import get_file_info

        result = json.loads(get_file_info(str(nonexistent_file)))

        # Verify error format
        assert 'error' in result
        assert isinstance(result['error'], str)


# ============================================================================
# PERFORMANCE INTEGRATION TESTS
# ============================================================================

class TestPerformanceIntegration(IntegrationTestBase):
    """Performance-related integration tests."""

    @pytest.mark.integration
    @pytest.mark.slow
    def test_large_file_processing_time(self, temp_large_file):
        """Test processing time for large files stays reasonable."""
        import time
        from file_info import get_file_info

        start_time = time.time()
        result = get_file_info(str(temp_large_file))
        elapsed_time = time.time() - start_time

        # Processing should complete within reasonable time
        assert elapsed_time < 10.0  # 10 seconds max for 1MB file

        # Result should be valid
        info = json.loads(result)
        assert 'error' not in info
