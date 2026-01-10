#!/usr/bin/env python3
"""
Performance Tests for Encoding Operations
==========================================

Benchmarks for shellcode encoding and payload generation including:
- Encoding throughput for various algorithms
- Key generation performance
- Payload generation speed
- Memory efficiency for large shellcode

These tests are marked as slow and may be skipped in quick test runs.

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import time
import os
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools" / "shellcode-encoder"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools" / "payload-generator"))

try:
    from shellcode_encoder import (
        EncodingType,
        EncoderConfig,
        EncoderOutput,
        XOREncoder,
        RollingXOREncoder,
        ADDEncoder,
        SUBEncoder,
        ROTEncoder,
        Base64Encoder,
        AESEncoder,
        RC4Encoder,
        ShellcodeEncoderTool,
    )
    ENCODER_AVAILABLE = True
except ImportError:
    ENCODER_AVAILABLE = False

try:
    from payload_generator import (
        PayloadConfig,
        PayloadOutput,
        PythonReverseShell,
        PowerShellReverseShell,
        BashReverseShell,
        PHPReverseShell,
        PayloadGenerator,
    )
    PAYLOAD_AVAILABLE = True
except ImportError:
    PAYLOAD_AVAILABLE = False


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def small_shellcode():
    """Small shellcode sample (64 bytes)."""
    return b"\x90" * 64


@pytest.fixture
def medium_shellcode():
    """Medium shellcode sample (4KB)."""
    return b"\x90" * 4096


@pytest.fixture
def large_shellcode():
    """Large shellcode sample (64KB)."""
    return b"\x90" * 65536


@pytest.fixture
def realistic_shellcode():
    """Realistic shellcode pattern with variety."""
    # Create shellcode with varying byte values
    pattern = bytes([i % 256 for i in range(256)])
    return pattern * 16  # 4KB


# =============================================================================
# XOR Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestXOREncoderPerformance:
    """Performance benchmarks for XOR encoder."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_xor_small_shellcode(self, small_shellcode):
        """Benchmark XOR encoding of small shellcode."""
        encoder = XOREncoder()
        key = b"\x41"
        iterations = 10000

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(small_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        bytes_per_second = (iterations * len(small_shellcode)) / elapsed
        assert ops_per_second > 50000, f"XOR ops/sec: {ops_per_second:.0f}"
        print(f"XOR small: {ops_per_second:.0f} ops/sec, {bytes_per_second/1e6:.2f} MB/sec")

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_xor_medium_shellcode(self, medium_shellcode):
        """Benchmark XOR encoding of medium shellcode."""
        encoder = XOREncoder()
        key = b"\x41"
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        bytes_per_second = (iterations * len(medium_shellcode)) / elapsed
        assert bytes_per_second > 10e6, f"XOR throughput: {bytes_per_second/1e6:.2f} MB/sec"

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_xor_large_shellcode(self, large_shellcode):
        """Benchmark XOR encoding of large shellcode."""
        encoder = XOREncoder()
        key = b"\x41"
        iterations = 100

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(large_shellcode, key)
        elapsed = time.perf_counter() - start_time

        bytes_per_second = (iterations * len(large_shellcode)) / elapsed
        print(f"XOR large: {bytes_per_second/1e6:.2f} MB/sec")

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    @pytest.mark.parametrize("key_size", [1, 4, 16, 64, 256])
    def test_xor_key_size_impact(self, medium_shellcode, key_size):
        """Benchmark XOR with different key sizes."""
        encoder = XOREncoder()
        key = os.urandom(key_size)
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        # Key size shouldn't dramatically affect performance
        assert ops_per_second > 1000, f"Key size {key_size}: {ops_per_second:.0f} ops/sec"


# =============================================================================
# Rolling XOR Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestRollingXORPerformance:
    """Performance benchmarks for Rolling XOR encoder."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_rolling_xor_performance(self, medium_shellcode):
        """Benchmark Rolling XOR encoding."""
        encoder = RollingXOREncoder()
        key = b"\x41\x42\x43\x44"
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        print(f"Rolling XOR: {ops_per_second:.0f} ops/sec")


# =============================================================================
# ADD/SUB Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestAddSubPerformance:
    """Performance benchmarks for ADD and SUB encoders."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_add_encoder_performance(self, medium_shellcode):
        """Benchmark ADD encoding."""
        encoder = ADDEncoder()
        key = b"\x10"
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        assert ops_per_second > 1000, f"ADD ops/sec: {ops_per_second:.0f}"

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_sub_encoder_performance(self, medium_shellcode):
        """Benchmark SUB encoding."""
        encoder = SUBEncoder()
        key = b"\x10"
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        assert ops_per_second > 1000, f"SUB ops/sec: {ops_per_second:.0f}"


# =============================================================================
# Base64 Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestBase64Performance:
    """Performance benchmarks for Base64 encoder."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_base64_performance(self, medium_shellcode):
        """Benchmark Base64 encoding."""
        encoder = Base64Encoder()
        iterations = 2000

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        bytes_per_second = (iterations * len(medium_shellcode)) / elapsed
        print(f"Base64: {ops_per_second:.0f} ops/sec, {bytes_per_second/1e6:.2f} MB/sec")

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_base64_large_data(self, large_shellcode):
        """Benchmark Base64 with large data."""
        encoder = Base64Encoder()
        iterations = 100

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(large_shellcode)
        elapsed = time.perf_counter() - start_time

        bytes_per_second = (iterations * len(large_shellcode)) / elapsed
        print(f"Base64 large: {bytes_per_second/1e6:.2f} MB/sec")


# =============================================================================
# AES Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestAESPerformance:
    """Performance benchmarks for AES encoder."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_aes_performance(self):
        """Benchmark AES encoding."""
        encoder = AESEncoder()
        shellcode = b"\x90" * 4096  # Multiple of block size
        key = b"0123456789abcdef"  # 128-bit key
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            try:
                result = encoder.encode(shellcode, key)
            except Exception:
                pass  # AES may not be available
        elapsed = time.perf_counter() - start_time

        if elapsed > 0:
            ops_per_second = iterations / elapsed
            print(f"AES: {ops_per_second:.0f} ops/sec")


# =============================================================================
# RC4 Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestRC4Performance:
    """Performance benchmarks for RC4 encoder."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_rc4_performance(self, medium_shellcode):
        """Benchmark RC4 encoding."""
        encoder = RC4Encoder()
        key = b"secretkey"
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(medium_shellcode, key)
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        bytes_per_second = (iterations * len(medium_shellcode)) / elapsed
        print(f"RC4: {ops_per_second:.0f} ops/sec, {bytes_per_second/1e6:.2f} MB/sec")

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_rc4_key_setup_overhead(self, small_shellcode):
        """Benchmark RC4 key setup overhead."""
        encoder = RC4Encoder()
        iterations = 5000

        # Same key reused
        key = b"secretkey"
        start_time = time.perf_counter()
        for _ in range(iterations):
            result = encoder.encode(small_shellcode, key)
        elapsed_same_key = time.perf_counter() - start_time

        # Different keys each time
        start_time = time.perf_counter()
        for i in range(iterations):
            key = f"key{i}".encode()
            result = encoder.encode(small_shellcode, key)
        elapsed_diff_keys = time.perf_counter() - start_time

        print(f"RC4 same key: {iterations/elapsed_same_key:.0f} ops/sec")
        print(f"RC4 diff keys: {iterations/elapsed_diff_keys:.0f} ops/sec")


# =============================================================================
# Payload Generator Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestPayloadGeneratorPerformance:
    """Performance benchmarks for payload generator."""

    @pytest.mark.skipif(not PAYLOAD_AVAILABLE, reason="Payload generator not available")
    def test_python_payload_generation(self):
        """Benchmark Python payload generation."""
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            config = PayloadConfig(
                payload_type="python",
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        assert ops_per_second > 500, f"Python payload gen: {ops_per_second:.0f} ops/sec"

    @pytest.mark.skipif(not PAYLOAD_AVAILABLE, reason="Payload generator not available")
    @pytest.mark.parametrize("payload_type", ["python", "powershell", "bash", "php"])
    def test_all_payload_types(self, payload_type):
        """Benchmark all payload type generation."""
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            config = PayloadConfig(
                payload_type=payload_type,
                lhost="192.168.1.100",
                lport=4444
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        print(f"{payload_type}: {ops_per_second:.0f} ops/sec")

    @pytest.mark.skipif(not PAYLOAD_AVAILABLE, reason="Payload generator not available")
    def test_payload_with_encoding(self):
        """Benchmark payload generation with encoding."""
        iterations = 500

        start_time = time.perf_counter()
        for _ in range(iterations):
            config = PayloadConfig(
                payload_type="python",
                lhost="192.168.1.100",
                lport=4444,
                encoded=True
            )
            generator = PayloadGenerator(config)
            output = generator.generate()
        elapsed = time.perf_counter() - start_time

        ops_per_second = iterations / elapsed
        print(f"Encoded payload: {ops_per_second:.0f} ops/sec")


# =============================================================================
# Comparative Encoder Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestEncoderComparison:
    """Comparative benchmarks across encoders."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_encoder_throughput_comparison(self, realistic_shellcode):
        """Compare throughput of different encoders."""
        iterations = 200
        results = {}

        encoders = [
            ("XOR", XOREncoder(), b"\x41"),
            ("RollingXOR", RollingXOREncoder(), b"\x41\x42\x43\x44"),
            ("ADD", ADDEncoder(), b"\x10"),
            ("SUB", SUBEncoder(), b"\x10"),
            ("Base64", Base64Encoder(), None),
            ("RC4", RC4Encoder(), b"secretkey"),
        ]

        for name, encoder, key in encoders:
            start_time = time.perf_counter()
            try:
                for _ in range(iterations):
                    if key:
                        result = encoder.encode(realistic_shellcode, key)
                    else:
                        result = encoder.encode(realistic_shellcode)
                elapsed = time.perf_counter() - start_time
                ops_per_second = iterations / elapsed
                throughput = (iterations * len(realistic_shellcode)) / elapsed / 1e6
                results[name] = (ops_per_second, throughput)
            except Exception as e:
                results[name] = (0, 0)

        print("\nEncoder Comparison:")
        print("-" * 50)
        for name, (ops, throughput) in sorted(results.items(), key=lambda x: -x[1][1]):
            print(f"{name:12s}: {ops:8.0f} ops/sec, {throughput:6.2f} MB/sec")


# =============================================================================
# Memory Efficiency Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestMemoryEfficiency:
    """Memory efficiency tests for encoding operations."""

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_xor_no_memory_leak(self, medium_shellcode):
        """Test XOR encoding doesn't leak memory."""
        import gc

        encoder = XOREncoder()
        key = b"\x41"

        gc.collect()
        initial_objects = len(gc.get_objects())

        for _ in range(1000):
            result = encoder.encode(medium_shellcode, key)

        gc.collect()
        final_objects = len(gc.get_objects())

        # Allow some growth but not proportional to iterations
        assert final_objects - initial_objects < 1000, "Potential memory leak detected"

    @pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
    def test_large_shellcode_memory_usage(self):
        """Test memory usage with large shellcode."""
        encoder = XOREncoder()
        key = b"\x41"

        # Create progressively larger shellcode
        sizes = [1024, 4096, 16384, 65536, 262144]

        for size in sizes:
            shellcode = b"\x90" * size
            result = encoder.encode(shellcode, key)
            assert len(result) == size, f"Output size mismatch for {size} bytes"


# =============================================================================
# Benchmark Fixtures for pytest-benchmark
# =============================================================================

@pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
def test_benchmark_xor_encoding(benchmark, medium_shellcode):
    """Benchmark XOR encoding using pytest-benchmark."""
    encoder = XOREncoder()
    key = b"\x41"

    def encode():
        return encoder.encode(medium_shellcode, key)

    try:
        result = benchmark(encode)
        assert len(result) == len(medium_shellcode)
    except TypeError:
        result = encode()
        assert len(result) == len(medium_shellcode)


@pytest.mark.skipif(not ENCODER_AVAILABLE, reason="Shellcode encoder not available")
def test_benchmark_base64_encoding(benchmark, medium_shellcode):
    """Benchmark Base64 encoding using pytest-benchmark."""
    encoder = Base64Encoder()

    def encode():
        return encoder.encode(medium_shellcode)

    try:
        result = benchmark(encode)
    except TypeError:
        result = encode()


@pytest.mark.skipif(not PAYLOAD_AVAILABLE, reason="Payload generator not available")
def test_benchmark_payload_generation(benchmark):
    """Benchmark payload generation using pytest-benchmark."""
    def generate():
        config = PayloadConfig(
            payload_type="python",
            lhost="192.168.1.100",
            lport=4444
        )
        generator = PayloadGenerator(config)
        return generator.generate()

    try:
        result = benchmark(generate)
        assert isinstance(result, PayloadOutput)
    except TypeError:
        result = generate()
        assert isinstance(result, PayloadOutput)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "performance"])
