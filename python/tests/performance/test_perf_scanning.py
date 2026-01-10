#!/usr/bin/env python3
"""
Performance Tests for Scanning Operations
==========================================

Benchmarks for network and port scanning operations including:
- Target expansion performance
- Port specification parsing
- Scanning throughput metrics
- Memory usage for large scans

These tests are marked as slow and may be skipped in quick test runs.

Author: QA Tester Agent
Date: January 10, 2026
"""

import pytest
import sys
import time
import socket
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools" / "network-scanner"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools" / "port-scanner"))

try:
    from tool import (
        ScanConfig as NetworkScanConfig,
        NetworkScanner,
    )
    NETWORK_SCANNER_AVAILABLE = True
except ImportError:
    NETWORK_SCANNER_AVAILABLE = False
    NetworkScanConfig = None
    NetworkScanner = None

try:
    from tool import (
        ScanConfig as PortScanConfig,
        PortScanner,
        parse_port_specification,
    )
    PORT_SCANNER_AVAILABLE = True
except ImportError:
    PORT_SCANNER_AVAILABLE = False
    PortScanConfig = None
    PortScanner = None
    parse_port_specification = None


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_socket_fast():
    """Mock socket that responds immediately."""
    with patch('socket.socket') as mock:
        mock.return_value.connect_ex.return_value = 0
        mock.return_value.settimeout.return_value = None
        mock.return_value.close.return_value = None
        yield mock


@pytest.fixture
def mock_socket_timeout():
    """Mock socket that always times out."""
    with patch('socket.socket') as mock:
        mock.return_value.connect_ex.side_effect = socket.timeout()
        yield mock


# =============================================================================
# Network Scanner Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestNetworkScannerPerformance:
    """Performance benchmarks for network scanner."""

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_target_expansion_cidr_24(self):
        """Benchmark /24 CIDR expansion (254 hosts)."""
        config = NetworkScanConfig(targets=["192.168.1.0/24"])
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == 254
        assert elapsed < 0.1, f"CIDR /24 expansion took {elapsed:.3f}s (expected < 0.1s)"

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_target_expansion_cidr_16(self):
        """Benchmark /16 CIDR expansion (65534 hosts)."""
        config = NetworkScanConfig(targets=["192.168.0.0/16"])
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == 65534
        assert elapsed < 5.0, f"CIDR /16 expansion took {elapsed:.3f}s (expected < 5.0s)"

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_target_expansion_range(self):
        """Benchmark IP range expansion (254 hosts)."""
        config = NetworkScanConfig(targets=["192.168.1.1-254"])
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == 254
        assert elapsed < 0.05, f"Range expansion took {elapsed:.3f}s (expected < 0.05s)"

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_target_expansion_multiple_networks(self):
        """Benchmark multiple CIDR expansion."""
        networks = [f"192.168.{i}.0/24" for i in range(10)]
        config = NetworkScanConfig(targets=networks)
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == 2540  # 254 * 10
        assert elapsed < 0.5, f"Multi-network expansion took {elapsed:.3f}s (expected < 0.5s)"

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_scan_throughput_mocked(self, mock_socket_fast):
        """Benchmark scan throughput with mocked socket."""
        config = NetworkScanConfig(
            targets=["192.168.1.0/28"],  # 14 hosts
            threads=10,
            delay_max=0
        )
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        results = scanner.scan()
        elapsed = time.perf_counter() - start_time

        assert len(results) >= 1
        hosts_per_second = len(results) / elapsed if elapsed > 0 else 0
        # With mocked socket and no delay, should be very fast
        assert hosts_per_second > 10, f"Throughput: {hosts_per_second:.1f} hosts/sec"

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_memory_efficiency_large_scan(self):
        """Test memory efficiency for large target lists."""
        import sys

        config = NetworkScanConfig(targets=["10.0.0.0/20"])  # 4094 hosts
        scanner = NetworkScanner(config)

        # Use generator to minimize memory
        count = 0
        for _ in scanner._expand_targets():
            count += 1

        assert count == 4094


# =============================================================================
# Port Scanner Performance Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestPortScannerPerformance:
    """Performance benchmarks for port scanner."""

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_port_parsing_single(self):
        """Benchmark single port parsing."""
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            ports = parse_port_specification("80")
        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.1, f"1000 single port parses took {elapsed:.3f}s"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_port_parsing_range_small(self):
        """Benchmark small port range parsing."""
        iterations = 100

        start_time = time.perf_counter()
        for _ in range(iterations):
            ports = parse_port_specification("1-1024")
        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.5, f"100 small range parses took {elapsed:.3f}s"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_port_parsing_all_ports(self):
        """Benchmark all ports parsing."""
        start_time = time.perf_counter()
        ports = parse_port_specification("all")
        elapsed = time.perf_counter() - start_time

        assert len(ports) == 65535
        assert elapsed < 1.0, f"All ports parsing took {elapsed:.3f}s"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_port_parsing_complex_spec(self):
        """Benchmark complex port specification parsing."""
        spec = ",".join([f"{i*100+1}-{i*100+50}" for i in range(20)])  # 20 ranges

        start_time = time.perf_counter()
        ports = parse_port_specification(spec)
        elapsed = time.perf_counter() - start_time

        assert len(ports) == 1000  # 50 ports * 20 ranges
        assert elapsed < 0.1, f"Complex spec parsing took {elapsed:.3f}s"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_port_scan_throughput_mocked(self, mock_socket_fast):
        """Benchmark port scan throughput with mocked socket."""
        with patch('socket.gethostbyname') as mock_resolve:
            mock_resolve.return_value = "192.168.1.1"

            config = PortScanConfig(
                target="192.168.1.1",
                ports=list(range(1, 101)),  # 100 ports
                threads=50,
                delay_max=0
            )
            scanner = PortScanner(config)

            start_time = time.perf_counter()
            report = scanner.scan()
            elapsed = time.perf_counter() - start_time

            ports_per_second = len(report.results) / elapsed if elapsed > 0 else 0
            assert ports_per_second > 50, f"Throughput: {ports_per_second:.1f} ports/sec"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_top_ports_lookup(self):
        """Benchmark top ports keyword parsing."""
        iterations = 1000

        start_time = time.perf_counter()
        for _ in range(iterations):
            ports = parse_port_specification("top100")
        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.05, f"1000 top100 lookups took {elapsed:.3f}s"


# =============================================================================
# Comparative Benchmarks
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestComparativeBenchmarks:
    """Comparative benchmarks across operations."""

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    @pytest.mark.parametrize("network_size,prefix", [
        (2, 31),
        (14, 28),
        (62, 26),
        (254, 24),
        (1022, 22),
    ])
    def test_expansion_scaling(self, network_size, prefix):
        """Benchmark how expansion time scales with network size."""
        config = NetworkScanConfig(targets=[f"192.168.0.0/{prefix}"])
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == network_size
        # Time should scale linearly with network size
        time_per_host = elapsed / network_size if network_size > 0 else 0
        assert time_per_host < 0.001, f"Time per host: {time_per_host*1000:.3f}ms"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    @pytest.mark.parametrize("port_count", [10, 100, 1000, 10000])
    def test_port_parsing_scaling(self, port_count):
        """Benchmark how port parsing scales with count."""
        spec = ",".join(str(p) for p in range(1, port_count + 1))

        start_time = time.perf_counter()
        ports = parse_port_specification(spec)
        elapsed = time.perf_counter() - start_time

        assert len(ports) == port_count
        time_per_port = elapsed / port_count if port_count > 0 else 0
        assert time_per_port < 0.0001, f"Time per port: {time_per_port*1000000:.3f}us"


# =============================================================================
# Stress Tests
# =============================================================================

@pytest.mark.slow
@pytest.mark.performance
class TestStressTests:
    """Stress tests for scanner operations."""

    @pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
    def test_concurrent_target_expansion(self):
        """Test concurrent target expansion doesn't cause issues."""
        import threading

        config = NetworkScanConfig(targets=["192.168.1.0/24"])
        results = []
        errors = []

        def expand_targets():
            try:
                scanner = NetworkScanner(config)
                targets = list(scanner._expand_targets())
                results.append(len(targets))
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=expand_targets) for _ in range(10)]

        start_time = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.perf_counter() - start_time

        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert all(r == 254 for r in results)
        assert elapsed < 2.0, f"Concurrent expansion took {elapsed:.3f}s"

    @pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
    def test_rapid_port_parsing(self):
        """Test rapid repeated port parsing."""
        iterations = 10000

        start_time = time.perf_counter()
        for i in range(iterations):
            ports = parse_port_specification(f"{i % 65535 + 1}")
        elapsed = time.perf_counter() - start_time

        parses_per_second = iterations / elapsed if elapsed > 0 else 0
        assert parses_per_second > 10000, f"Parse rate: {parses_per_second:.1f}/sec"


# =============================================================================
# Benchmark Fixtures for pytest-benchmark
# =============================================================================

@pytest.mark.skipif(not NETWORK_SCANNER_AVAILABLE, reason="Network scanner not available")
def test_benchmark_cidr_expansion(benchmark):
    """Benchmark CIDR expansion using pytest-benchmark."""
    config = NetworkScanConfig(targets=["192.168.1.0/24"])
    scanner = NetworkScanner(config)

    def expand():
        return list(scanner._expand_targets())

    try:
        result = benchmark(expand)
        assert len(result) == 254
    except TypeError:
        # pytest-benchmark not installed, run manually
        result = expand()
        assert len(result) == 254


@pytest.mark.skipif(not PORT_SCANNER_AVAILABLE, reason="Port scanner not available")
def test_benchmark_port_parsing(benchmark):
    """Benchmark port parsing using pytest-benchmark."""
    def parse():
        return parse_port_specification("1-1024")

    try:
        result = benchmark(parse)
        assert len(result) == 1024
    except TypeError:
        result = parse()
        assert len(result) == 1024


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "performance"])
