# QA Testing Infrastructure and Practices for CPTC11

## Module Overview

**Purpose:** This module provides comprehensive training on the quality assurance testing infrastructure and practices used in the CPTC11 security toolkit. Understanding these testing practices is essential for all developers contributing to the project and operators who need to validate tool functionality.

**Learning Objectives:**
- Understand the unique challenges of testing offensive security tools
- Navigate the CPTC11 test infrastructure and configuration
- Write effective unit, integration, fuzz, and security tests
- Use mock classes to safely test network operations
- Run the test suite and interpret results

**Prerequisites:**
- Python 3.8+ experience
- Basic understanding of pytest
- Familiarity with offensive security concepts

**Estimated Duration:** 4-6 hours

---

## Section 1: Testing Security Tools

### 1.1 Unique Challenges of Testing Offensive Tools

Testing offensive security tools presents challenges that differ significantly from testing conventional software. Understanding these challenges is fundamental to developing effective test strategies that ensure reliability without creating safety risks.

**Challenge 1: Dual-Use Nature of Functionality**

Offensive tools are designed to probe, enumerate, and sometimes exploit systems. The very functionality we need to test could cause harm if executed against production systems. A network scanner test that accidentally scans the corporate network could trigger security alerts, cause service disruptions, or violate acceptable use policies. Similarly, a credential validator test that attempts authentication against real services could lock out legitimate users or create audit log entries that complicate incident response.

This dual-use nature requires careful isolation of test environments. Unlike a web application where testing against a staging environment is straightforward, security tools often target infrastructure components that may not have obvious staging equivalents. A DNS enumerator test needs a DNS server to query, but using public DNS servers introduces variability and potential policy violations.

**Challenge 2: Environment Sensitivity**

Offensive tools interact deeply with system resources including network interfaces, raw sockets, process memory, and privileged kernel features. Test results can vary dramatically based on the execution environment. A port scanner might behave differently on Windows versus Linux due to socket implementation differences. Tests that pass on a developer workstation might fail in CI/CD containers due to network namespace restrictions or missing privileges.

This sensitivity extends to timing-related behaviors. Network operations depend on latency, packet loss, and system load. A test that passes reliably on a fast machine might exhibit race conditions or timeouts on slower CI runners. Property-based tests using fuzzing can uncover timing-dependent bugs that only manifest under specific conditions.

**Challenge 3: Validation Complexity**

Determining whether an offensive tool produced correct output is often non-trivial. When a port scanner reports a port as "filtered," how do we validate that classification without access to the firewall rules? When a service fingerprinter identifies a service version, verification might require manual inspection or access to the target system's actual configuration.

This validation complexity is compounded by the adversarial nature of the tools' targets. Services may respond differently based on perceived reconnaissance activity. Anti-scan mechanisms, rate limiting, and honeypots can all affect tool behavior in ways that are difficult to reproduce consistently in tests.

**Challenge 4: Safety in Automation**

Test suites run automatically in CI/CD pipelines, often without human oversight. An improperly configured test could repeatedly attempt to scan external hosts, generate malicious payloads, or perform other actions that create legal or ethical liability. Even tests that are safe in isolation might cause problems when run in parallel or at scale.

The automation requirement also means tests must be deterministic and isolated. A test that modifies global state or leaves network connections open can cause cascading failures in subsequent tests. Cleanup procedures must be robust enough to handle test failures without leaving the system in an inconsistent state.

### 1.2 Mock vs Live Testing Considerations

The testing strategy for offensive tools must balance between mocked tests that provide safety and speed, and live tests that validate real-world functionality.

**When to Use Mocks:**

Mocks are appropriate when testing logic that does not fundamentally depend on network interaction. Input validation, data parsing, configuration handling, and output formatting can all be tested effectively with mocks. The CPTC11 test suite uses mocks extensively for:

- Socket operations that would otherwise require network access
- DNS resolution that would query real DNS servers
- HTTP responses that would require running web servers
- Authentication flows that would require credential databases

Mocks provide predictable behavior, fast execution, and complete isolation. A mocked socket can simulate any response pattern including errors, timeouts, and partial data. This enables testing error handling paths that would be difficult or impossible to trigger with real network operations.

**When to Require Live Testing:**

Some functionality cannot be adequately validated without real network interaction. Protocol implementations may have subtle bugs that only manifest with actual network stacks. Timing-dependent behaviors like connection pooling, keep-alive handling, and retry logic often work differently with mocked versus real connections.

The CPTC11 suite uses Docker-based integration tests for this purpose. These tests run against containerized services that provide consistent, controlled targets. The Docker environment includes vulnerable web applications, FTP servers, SMB shares, and other services specifically configured for testing.

**Hybrid Approaches:**

Many CPTC11 tests use a hybrid approach where the tool's network layer is mocked but the application logic runs normally. This validates that the tool correctly interprets responses and produces appropriate output without requiring network access. Integration tests then validate the network layer separately.

### 1.3 Safety in Test Design

Test safety is a first-order concern in CPTC11 development. The following principles guide test design:

**Principle 1: Default to Isolation**

Tests should not interact with any system outside the test environment unless explicitly configured to do so. Network operations default to mocked implementations. File operations use temporary directories that are cleaned up after each test. No test should require network connectivity to pass.

**Principle 2: Fail Closed**

When test environment configuration is ambiguous, tests should skip rather than proceed with potentially unsafe operations. The Docker integration tests check for container availability before attempting any network operations. If containers are not running, tests skip with a clear message rather than attempting to connect to localhost ports that might be bound to other services.

**Principle 3: Explicit Danger Markers**

Tests that perform potentially dangerous operations are explicitly marked. The `@pytest.mark.integration` marker indicates tests that make real network connections. The `@pytest.mark.requires_root` marker indicates tests that need elevated privileges. CI/CD pipelines can selectively enable or disable these test categories based on the execution environment.

**Principle 4: No Persistent Side Effects**

Tests must not create persistent changes to the system or network. Temporary files are cleaned up. Mock patches are scoped appropriately. Docker containers are stateless and can be reset between test runs. A failed test should not leave artifacts that affect subsequent tests or other system users.

---

## Section 2: CPTC11 Test Infrastructure

### 2.1 pytest Configuration

The CPTC11 test suite uses pytest with configurations defined in two files: `pytest.ini` for pytest-specific settings and `pyproject.toml` for broader project configuration including test settings.

**pytest.ini Configuration:**

```ini
[pytest]
# Test discovery patterns
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*

# Output configuration
addopts =
    -v
    --tb=short
    --strict-markers
    -ra

# Markers for categorizing tests
markers =
    unit: Unit tests for individual functions
    integration: Integration tests for component interactions
    regression: Regression tests for bug fixes
    slow: Tests that take longer to execute
    smoke: Quick smoke tests for basic functionality

# Logging configuration
log_cli = true
log_cli_level = INFO
```

The `--strict-markers` option ensures that all markers used in tests are explicitly registered, preventing typos in marker names from silently creating uncategorized tests.

**pyproject.toml Test Configuration:**

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = [
    "-v",
    "--strict-markers",
    "--tb=short",
]
markers = [
    "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    "integration: marks tests as integration tests",
    "fuzz: marks tests as fuzz tests",
    "security: marks tests as security-focused",
]

[tool.coverage.run]
source = ["tools", "tui"]
branch = true
omit = [
    "tests/*",
    "*/__pycache__/*",
    "*/test_*.py",
]
```

### 2.2 Test Markers

CPTC11 uses a comprehensive marker system to categorize tests and enable selective execution:

| Marker | Purpose | Example Usage |
|--------|---------|---------------|
| `@pytest.mark.unit` | Individual function tests | `test_parse_port_specification` |
| `@pytest.mark.integration` | Component interaction tests | `test_full_scan_with_docker` |
| `@pytest.mark.fuzz` | Property-based fuzz tests | `test_arbitrary_input_handling` |
| `@pytest.mark.security` | Input sanitization tests | `test_command_injection_blocked` |
| `@pytest.mark.slow` | Long-running tests | `test_cidr_16_expansion` |
| `@pytest.mark.smoke` | Quick validation tests | `test_basic_connectivity` |
| `@pytest.mark.regression` | Bug fix verification | `test_regression_issue_001` |
| `@pytest.mark.edge_case` | Boundary condition tests | `test_port_65535` |
| `@pytest.mark.network` | Requires network access | `test_dns_resolution` |
| `@pytest.mark.requires_root` | Needs elevated privileges | `test_raw_socket_scan` |

**Automatic Marker Assignment:**

The `conftest.py` includes logic to automatically assign markers based on test location:

```python
def pytest_collection_modifyitems(config, items):
    for item in items:
        if "edge_cases" in str(item.fspath):
            item.add_marker(pytest.mark.edge_case)
        if "fuzz" in str(item.fspath):
            item.add_marker(pytest.mark.fuzz)
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
```

### 2.3 Fixtures (conftest.py)

The central `conftest.py` provides fixtures used across all test modules. Key fixture categories include:

**Temporary File Fixtures:**

```python
@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    temp_path = tempfile.mkdtemp(prefix="cptc11_test_")
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)

@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file with sample content."""
    file_path = temp_dir / "test_file.txt"
    file_path.write_text("Hello, World!")
    yield file_path
```

**Network Edge Case Fixtures:**

```python
@pytest.fixture
def boundary_ports():
    """Return boundary port values for testing."""
    return {
        "min_valid": 1,
        "max_valid": 65535,
        "below_min": 0,
        "above_max": 65536,
        "well_known_max": 1023,
        "registered_min": 1024,
    }

@pytest.fixture
def sample_cidr_ranges():
    """Return sample CIDR ranges for testing."""
    return [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.168.1.0/24",
    ]
```

**Credential Test Fixtures:**

```python
@pytest.fixture
def special_character_credentials():
    """Return credentials with special characters for testing."""
    return [
        ("admin", "P@$$w0rd!"),
        ("user'name", "pass\"word"),
        ("user;drop", "pass|pipe"),
        ("admin\x00user", "pass\x00word"),
    ]
```

**Hypothesis Profile Configuration:**

```python
def pytest_configure(config):
    from hypothesis import settings, Verbosity, Phase

    settings.register_profile(
        "ci",
        max_examples=50,
        deadline=5000,
        suppress_health_check=[],
        verbosity=Verbosity.normal,
    )

    settings.register_profile(
        "dev",
        max_examples=100,
        deadline=2000,
    )

    settings.register_profile(
        "thorough",
        max_examples=500,
        deadline=10000,
    )

    profile_name = os.environ.get("HYPOTHESIS_PROFILE", "dev")
    settings.load_profile(profile_name)
```

### 2.4 Test Directory Structure

```
tests/
    __init__.py
    conftest.py                    # Central fixtures
    test_template.py               # Template for new tests
    test_network_scanner.py        # Unit tests
    test_port_scanner.py
    test_*.py

    edge_cases/
        __init__.py
        test_edge_network_inputs.py
        test_edge_port_inputs.py
        test_edge_credential_inputs.py

    fuzz/
        __init__.py
        test_fuzz_network_inputs.py
        test_fuzz_port_inputs.py
        test_fuzz_url_inputs.py

    integration/
        __init__.py
        test_integration_base.py

    docker_integration/
        __init__.py
        conftest.py                 # Docker-specific fixtures
        test_web_enumeration.py
        test_ftp_credentials.py
        test_dns_enumeration.py
        test_smb_enumeration.py

    security/
        __init__.py
        test_input_sanitization.py
        test_safe_defaults.py

    performance/
        __init__.py
        test_perf_scanning.py
        test_perf_encoding.py
```

---

## Section 3: Test Categories Explained

### 3.1 Unit Tests - Isolation and Mocking

Unit tests focus on individual functions and classes in isolation. They use mocks to replace external dependencies, ensuring tests are fast, deterministic, and do not require network access.

**Example: Testing Port Specification Parsing**

```python
class TestPortSpecificationParsing:
    """Tests for port specification parsing."""

    def test_parse_single_port(self):
        """Test parsing a single port."""
        ports = parse_port_specification("80")
        assert 80 in ports

    def test_parse_port_range(self):
        """Test parsing a port range."""
        ports = parse_port_specification("80-83")
        assert set(ports) == {80, 81, 82, 83}

    def test_parse_comma_separated_ports(self):
        """Test parsing comma-separated ports."""
        ports = parse_port_specification("80,443,8080")
        assert set(ports) == {80, 443, 8080}

    def test_parse_mixed_specification(self):
        """Test parsing mixed port specifications."""
        ports = parse_port_specification("80,443,8000-8002")
        assert set(ports) == {80, 443, 8000, 8001, 8002}
```

**Example: Testing with Mocked Socket**

```python
def test_tcp_connect_scan_open_port(self):
    """Test TCPConnectScan with open port."""
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.connect_ex.return_value = 0

        config = ScanConfig(target="192.168.1.1", ports=[80])
        technique = TCPConnectScan()
        result = technique.scan("192.168.1.1", 80, config)

        assert result.state == PortState.OPEN
```

### 3.2 Integration Tests - Docker Environment

Integration tests validate component interactions using real network operations against Docker containers.

**Docker Service Configuration:**

```python
DOCKER_SERVICES = {
    "vulnerable-web": {"host": "localhost", "port": 8080, "protocol": "tcp"},
    "ftp-server": {"host": "localhost", "port": 2121, "protocol": "tcp"},
    "smtp-server": {"host": "localhost", "port": 2525, "protocol": "tcp"},
    "dns-server": {"host": "localhost", "port": 5353, "protocol": "udp"},
    "smb-server": {"host": "localhost", "port": 4445, "protocol": "tcp"},
}
```

**Service Availability Fixtures:**

```python
@pytest.fixture(scope="session")
def docker_available():
    """Session-scoped fixture to check Docker availability."""
    if os.environ.get("SKIP_DOCKER_TESTS"):
        pytest.skip("SKIP_DOCKER_TESTS environment variable set")

    if not is_docker_running():
        pytest.skip("Docker daemon is not running")

    if not are_containers_running():
        pytest.skip("CPTC11 Docker containers are not running")

    return True

@pytest.fixture(scope="module")
def web_service(docker_available, docker_host):
    """Fixture for web service connection details."""
    service = DOCKER_SERVICES["vulnerable-web"]
    host = docker_host
    port = service["port"]

    if not check_port(host, port):
        pytest.skip(f"Web service not available at {host}:{port}")

    return {"host": host, "port": port, "url": f"http://{host}:{port}"}
```

**Example Integration Test:**

```python
@pytest.mark.skipif(DirectoryEnumerator is None, reason="Tool not available")
class TestWebDirectoryEnumeration:
    """Test web enumeration against vulnerable-web container."""

    def test_enumerate_known_paths(self, web_service):
        """Test enumeration of known vulnerable paths."""
        known_paths = ["admin", "login.php", "robots.txt", "api", "config"]

        config = EnumConfig(
            target_url=web_service["url"],
            wordlist=known_paths,
            extensions=[],
            timeout=10.0,
            threads=5,
            status_codes=[200, 301, 302, 401, 403]
        )

        enumerator = DirectoryEnumerator(config)
        results = enumerator.enumerate()

        found_paths = [r.path for r in results]
        assert len(found_paths) > 0, "Should find at least one known path"
```

### 3.3 Fuzz Tests - Hypothesis Property-Based Testing

Fuzz tests use the Hypothesis library to generate random inputs and discover edge cases that might not be anticipated by manual test case design.

**Custom Strategies for Network Inputs:**

```python
from hypothesis import strategies as st

# Strategy for valid IPv4 addresses as strings
ipv4_octet = st.integers(min_value=0, max_value=255)
valid_ipv4 = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet
)

# Strategy for valid CIDR notation
cidr_prefix = st.integers(min_value=0, max_value=32)
valid_cidr = st.builds(
    lambda ip, prefix: f"{ip}/{prefix}",
    valid_ipv4, cidr_prefix
)

# Strategy for malformed inputs
fuzzy_ipv4 = st.one_of(
    st.builds(lambda a, b, c, d, e: f"{a}.{b}.{c}.{d}.{e}",
              ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet, ipv4_octet),
    st.builds(lambda a, b, c: f"{a}.{b}.{c}",
              ipv4_octet, ipv4_octet, ipv4_octet),
    st.just("..."),
    st.just("192..1.1"),
)
```

**Example Fuzz Test:**

```python
@pytest.mark.fuzz
class TestNetworkInputFuzzing:
    """Fuzz tests for network input parsing."""

    @given(ip=valid_ipv4)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_ipv4_parsing_never_crashes(self, ip: str):
        """Valid IPv4 addresses should never cause crashes."""
        assert is_valid_ip(ip), f"Generated invalid IP: {ip}"

        if NETWORK_SCANNER_AVAILABLE:
            results = list(expand_targets_safe([ip]))
            assert len(results) <= 1

    @given(arbitrary=arbitrary_network_input)
    @settings(max_examples=1000)
    def test_arbitrary_input_does_not_crash(self, arbitrary: str):
        """Arbitrary input should never crash the network parser."""
        try:
            results = list(expand_targets_safe([arbitrary]))
            for ip in results:
                assert is_valid_ip(ip)
        except (ValueError, TypeError, AttributeError):
            pass  # Controlled exceptions are acceptable
```

### 3.4 Security Tests - Input Sanitization

Security tests verify that tools properly sanitize user input and resist injection attacks.

**Injection Payload Collections:**

```python
COMMAND_INJECTION_PAYLOADS = [
    "; ls",
    "| cat /etc/passwd",
    "& whoami",
    "&& id",
    "`id`",
    "$(whoami)",
    "${USER}",
    "\nls\n",
]

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT * FROM users--",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
```

**Example Security Test:**

```python
@pytest.mark.security
class TestNetworkScannerInjection:
    """Test network scanner for injection vulnerabilities."""

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_in_target(self, payload):
        """Command injection payloads in target should not execute."""
        config = self.ScanConfig(targets=[payload])
        scanner = self.NetworkScanner(config)

        try:
            targets = list(scanner._expand_targets())
            for target in targets:
                assert "root:" not in target.lower()
                assert "uid=" not in target.lower()
        except (ValueError, TypeError):
            pass  # Acceptable to reject malicious input
```

### 3.5 Performance Tests - Benchmarking

Performance tests measure execution time and resource usage for critical operations.

**Example Performance Tests:**

```python
@pytest.mark.slow
@pytest.mark.performance
class TestNetworkScannerPerformance:
    """Performance benchmarks for network scanner."""

    def test_target_expansion_cidr_24(self):
        """Benchmark /24 CIDR expansion (254 hosts)."""
        config = NetworkScanConfig(targets=["192.168.1.0/24"])
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        targets = list(scanner._expand_targets())
        elapsed = time.perf_counter() - start_time

        assert len(targets) == 254
        assert elapsed < 0.1, f"CIDR /24 expansion took {elapsed:.3f}s"

    def test_scan_throughput_mocked(self, mock_socket_fast):
        """Benchmark scan throughput with mocked socket."""
        config = NetworkScanConfig(
            targets=["192.168.1.0/28"],
            threads=10,
            delay_max=0
        )
        scanner = NetworkScanner(config)

        start_time = time.perf_counter()
        results = scanner.scan()
        elapsed = time.perf_counter() - start_time

        hosts_per_second = len(results) / elapsed if elapsed > 0 else 0
        assert hosts_per_second > 10, f"Throughput: {hosts_per_second:.1f}/sec"
```

---

## Section 4: Writing Tests for Security Tools

### 4.1 Testing Dataclasses

CPTC11 tools use Python dataclasses for configuration and results. Testing these requires validating both construction and serialization.

**Example: Testing ScanResult Dataclass**

```python
class TestScanResult:
    """Tests for the ScanResult data class."""

    def test_scan_result_creation(self):
        """Test that ScanResult can be created with required fields."""
        result = ScanResult(ip="192.168.1.1", is_alive=True)
        assert result.ip == "192.168.1.1"
        assert result.is_alive == True

    def test_scan_result_to_dict(self):
        """Test that ScanResult can be converted to dictionary."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=0.1,
            method="tcp_connect",
            hostname="host.example.com"
        )
        result_dict = result.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["ip"] == "192.168.1.1"
        assert result_dict["response_time"] == 0.1

    def test_scan_result_default_values(self):
        """Test ScanResult default values."""
        result = ScanResult(ip="192.168.1.1", is_alive=False)
        assert result.response_time is None
        assert result.method == "unknown"
        assert result.hostname is None
        assert isinstance(result.timestamp, datetime)
```

### 4.2 Testing CLI Arguments

CLI argument parsing tests verify that tools correctly interpret command-line inputs.

**Example: Testing Argument Parsing**

```python
class TestCLIArgumentParsing:
    """Tests for CLI argument parsing."""

    def test_parse_single_target(self):
        """Test parsing a single target argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1']):
            args = parse_arguments()
            assert args.targets == ['192.168.1.1']

    def test_parse_plan_flag(self):
        """Test parsing --plan flag."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--plan']):
            args = parse_arguments()
            assert args.plan == True

    def test_parse_timeout_argument(self):
        """Test parsing --timeout argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--timeout', '5.0']):
            args = parse_arguments()
            assert args.timeout == 5.0

    def test_parse_methods_argument(self):
        """Test parsing --methods argument."""
        with patch('sys.argv', ['tool.py', '192.168.1.1', '--methods', 'tcp', 'dns']):
            args = parse_arguments()
            assert 'tcp' in args.methods
            assert 'dns' in args.methods
```

### 4.3 Testing Plan Mode

Plan mode is a critical safety feature that shows what a tool would do without executing. Tests must verify both the output format and that no actual operations occur.

**Example: Testing Plan Mode**

```python
class TestPlanningMode:
    """Tests for the planning mode (--plan flag)."""

    def test_plan_mode_outputs_plan_header(self, capsys):
        """Test that planning mode outputs the PLAN MODE header."""
        config = ScanConfig(
            targets=["192.168.1.1"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "[PLAN MODE]" in captured.out

    def test_plan_mode_shows_target_info(self, capsys):
        """Test that planning mode shows target information."""
        config = ScanConfig(
            targets=["192.168.1.0/24"],
            plan_mode=True
        )
        print_plan(config)
        captured = capsys.readouterr()
        assert "192.168.1.0/24" in captured.out
        assert "Target Specification" in captured.out

    def test_plan_mode_does_not_perform_scan(self):
        """Test that planning mode does not actually perform scans."""
        with patch('socket.socket') as mock_socket:
            config = ScanConfig(
                targets=["192.168.1.1"],
                plan_mode=True
            )
            print_plan(config)
            mock_socket.return_value.connect_ex.assert_not_called()

    def test_plan_mode_shows_risk_assessment(self, capsys):
        """Test that planning mode includes risk assessment."""
        config = ScanConfig(targets=["192.168.1.1"], plan_mode=True)
        print_plan(config)
        captured = capsys.readouterr()
        assert "RISK ASSESSMENT" in captured.out
```

### 4.4 Testing Network Operations (with Mocks)

Network operations require careful mocking to test various scenarios safely.

**Example: Testing Error Handling**

```python
class TestErrorHandling:
    """Tests for error handling."""

    def test_socket_error_handled(self):
        """Test that socket errors are handled gracefully."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.error("Connection failed")

            config = ScanConfig(targets=["192.168.1.1"], tcp_ports=[80])
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_dns_resolution_error_handled(self):
        """Test that DNS resolution errors are handled gracefully."""
        with patch('socket.gethostbyaddr') as mock_dns:
            mock_dns.side_effect = socket.herror("DNS lookup failed")

            config = ScanConfig(targets=["192.168.1.1"])
            technique = DNSResolutionScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False

    def test_timeout_handling(self):
        """Test that connection timeouts are handled properly."""
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout("Timeout")

            config = ScanConfig(targets=["192.168.1.1"], timeout=0.1)
            technique = TCPConnectScan()
            result = technique.scan("192.168.1.1", config)

            assert isinstance(result, ScanResult)
            assert result.is_alive == False
```

### 4.5 Testing Output Formats

Tools often support multiple output formats. Tests should verify each format produces valid output.

**Example: Testing JSON Output**

```python
def test_results_to_json(self):
    """Test that results can be serialized to JSON."""
    results = [
        ScanResult(ip="192.168.1.1", is_alive=True, method="tcp"),
        ScanResult(ip="192.168.1.2", is_alive=False, method="tcp"),
    ]

    json_output = json.dumps([r.to_dict() for r in results])
    parsed = json.loads(json_output)

    assert len(parsed) == 2
    assert parsed[0]["ip"] == "192.168.1.1"
    assert parsed[0]["is_alive"] == True
```

---

## Section 5: Mock Classes Reference

### 5.1 MockSocket Usage

The `MockSocket` pattern is used extensively for testing network operations without actual network access.

**Basic Socket Mocking:**

```python
def test_port_open(self):
    """Test detection of open port."""
    with patch('socket.socket') as mock_socket:
        # Configure mock for successful connection
        mock_socket.return_value.connect_ex.return_value = 0

        result = scan_port("192.168.1.1", 80)
        assert result == "open"

def test_port_closed(self):
    """Test detection of closed port."""
    with patch('socket.socket') as mock_socket:
        # Configure mock for connection refused
        mock_socket.return_value.connect_ex.return_value = 111

        result = scan_port("192.168.1.1", 80)
        assert result == "closed"
```

**Simulating Timeouts:**

```python
def test_port_timeout(self):
    """Test handling of connection timeout."""
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.connect_ex.side_effect = socket.timeout()

        result = scan_port("192.168.1.1", 80)
        assert result == "filtered"
```

**Simulating Data Reception:**

```python
def test_banner_grab(self):
    """Test banner grabbing."""
    with patch('socket.socket') as mock_socket:
        mock_socket.return_value.connect_ex.return_value = 0
        mock_socket.return_value.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

        banner = grab_banner("192.168.1.1", 22)
        assert "OpenSSH" in banner
```

### 5.2 MockHTTPResponse Usage

HTTP response mocking enables testing of web-related functionality.

**Basic HTTP Mocking:**

```python
def test_http_200_response(self):
    """Test handling of successful HTTP response."""
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.read.return_value = b"<html>Success</html>"

    with patch('http.client.HTTPConnection') as mock_conn:
        mock_conn.return_value.getresponse.return_value = mock_response

        result = check_url("http://example.com/path")
        assert result.status_code == 200
```

**Simulating Error Responses:**

```python
def test_http_404_response(self):
    """Test handling of 404 response."""
    mock_response = MagicMock()
    mock_response.status = 404
    mock_response.read.return_value = b"Not Found"

    with patch('http.client.HTTPConnection') as mock_conn:
        mock_conn.return_value.getresponse.return_value = mock_response

        result = check_url("http://example.com/missing")
        assert result.status_code == 404
        assert result.exists == False
```

### 5.3 MockDNSResponse Usage

DNS mocking allows testing of enumeration and resolution functionality.

**Mocking DNS Resolution:**

```python
def test_dns_forward_lookup(self):
    """Test forward DNS lookup."""
    with patch('socket.gethostbyname') as mock_dns:
        mock_dns.return_value = "93.184.216.34"

        result = resolve_hostname("example.com")
        assert result == "93.184.216.34"

def test_dns_reverse_lookup(self):
    """Test reverse DNS lookup."""
    with patch('socket.gethostbyaddr') as mock_dns:
        mock_dns.return_value = ("host.example.com", [], ["192.168.1.1"])

        result = reverse_lookup("192.168.1.1")
        assert result == "host.example.com"

def test_dns_resolution_failure(self):
    """Test handling of DNS resolution failure."""
    with patch('socket.gethostbyname') as mock_dns:
        mock_dns.side_effect = socket.gaierror("Name resolution failed")

        result = resolve_hostname("nonexistent.invalid")
        assert result is None
```

### 5.4 MockSMBClient Usage

SMB mocking enables testing of share enumeration without real SMB servers.

**Mocking SMB Share Enumeration:**

```python
def test_smb_share_enumeration(self):
    """Test SMB share enumeration."""
    mock_shares = [
        {"name": "public", "type": "DISKTREE"},
        {"name": "private", "type": "DISKTREE"},
        {"name": "IPC$", "type": "IPC"},
    ]

    with patch('smb.SMBConnection.SMBConnection') as mock_smb:
        mock_smb.return_value.listShares.return_value = mock_shares

        config = SMBConfig(target="192.168.1.1")
        enumerator = SMBEnumerator(config)
        shares = enumerator.list_shares()

        assert len(shares) == 3
        assert any(s["name"] == "public" for s in shares)

def test_smb_authentication_failure(self):
    """Test handling of SMB authentication failure."""
    with patch('smb.SMBConnection.SMBConnection') as mock_smb:
        mock_smb.return_value.connect.side_effect = Exception("Auth failed")

        config = SMBConfig(
            target="192.168.1.1",
            username="invalid",
            password="wrong"
        )
        enumerator = SMBEnumerator(config)

        with pytest.raises(AuthenticationError):
            enumerator.connect()
```

---

## Section 6: Running the Test Suite

### 6.1 Makefile Commands

The CPTC11 Python project includes a Makefile with convenient test targets:

```bash
# Run all tests
make test

# Run unit tests only (excludes integration, fuzz, and slow tests)
make test-unit

# Run fuzz tests only
make test-fuzz

# Run integration tests only
make test-integration

# Run fast tests (excludes slow tests)
make test-fast

# Run tests with coverage report
make coverage

# Run all checks (lint and test)
make check-all
```

**Direct pytest Usage:**

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_network_scanner.py -v

# Run tests matching pattern
python -m pytest tests/ -v -k "test_plan_mode"

# Run tests with specific marker
python -m pytest tests/ -v -m "security"

# Exclude slow tests
python -m pytest tests/ -v -m "not slow"

# Run with specific Hypothesis profile
HYPOTHESIS_PROFILE=thorough python -m pytest tests/fuzz/ -v
```

### 6.2 Coverage Reports

Coverage reports help identify untested code paths:

```bash
# Generate coverage report
make coverage

# Or directly:
python -m pytest tests/ -v --cov=tools --cov=tui --cov-report=term-missing --cov-report=html
```

**Interpreting Coverage Output:**

```
Name                          Stmts   Miss Branch BrPart  Cover   Missing
-------------------------------------------------------------------------
tools/network-scanner/tool.py   245     12     48      3    94%    156-159, 312
tools/port-scanner/tool.py      198      8     36      2    95%    89-92
-------------------------------------------------------------------------
TOTAL                           443     20     84      5    94%
```

The HTML report in `htmlcov/` provides line-by-line coverage visualization.

### 6.3 CI/CD Integration

The test suite integrates with CI/CD pipelines through the `check-all` target:

```yaml
# Example GitHub Actions workflow
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          cd python
          make install-test
      - name: Run lint and tests
        run: |
          cd python
          make check-all
```

**Environment Variables for CI:**

```bash
# Skip Docker-based integration tests
export SKIP_DOCKER_TESTS=1

# Use CI Hypothesis profile (fewer examples, longer deadlines)
export HYPOTHESIS_PROFILE=ci

# Enable verbose output
export PYTEST_ADDOPTS="-v --tb=long"
```

---

## Section 7: Hands-On Labs

### Lab 1: Writing Unit Tests

**Objective:** Create a comprehensive unit test module for a simple IP validation function.

**Scenario:** You have been given a function `is_valid_target()` that validates IP addresses and CIDR ranges. Write tests to verify its correctness.

**Task Instructions:**

1. Create a new test file at `tests/test_target_validation.py`
2. Implement tests for the following cases:
   - Valid single IPv4 addresses
   - Valid CIDR notation
   - Invalid IP addresses (out of range, wrong format)
   - Invalid CIDR prefixes
   - Empty strings and None values
   - Edge cases (0.0.0.0, 255.255.255.255, /0, /32)

**Starter Code:**

```python
"""Tests for target validation."""
import pytest

# TODO: Import the function under test
# from tool import is_valid_target

class TestValidTargets:
    """Positive test cases for valid targets."""

    @pytest.mark.unit
    def test_valid_single_ipv4(self):
        """Test that standard IPv4 addresses are accepted."""
        # TODO: Implement
        pass

    @pytest.mark.unit
    def test_valid_cidr_24(self):
        """Test that /24 CIDR notation is accepted."""
        # TODO: Implement
        pass


class TestInvalidTargets:
    """Negative test cases for invalid targets."""

    @pytest.mark.unit
    def test_invalid_octet_range(self):
        """Test that octets > 255 are rejected."""
        # TODO: Implement
        pass


class TestEdgeCases:
    """Edge case tests."""

    @pytest.mark.unit
    @pytest.mark.edge_case
    def test_broadcast_address(self):
        """Test handling of broadcast address."""
        # TODO: Implement
        pass
```

**Hints:**

- Use `pytest.mark.parametrize` for testing multiple similar inputs
- Consider using fixtures from `conftest.py` for common test data
- Remember to test both the happy path and error conditions

**Validation Criteria:**

- [ ] All tests pass
- [ ] Tests use appropriate markers
- [ ] Tests include docstrings explaining purpose
- [ ] Edge cases are covered
- [ ] Tests are independent (no shared state)

---

### Lab 2: Creating Fuzz Tests

**Objective:** Write property-based fuzz tests using Hypothesis to discover edge cases in port parsing.

**Scenario:** The `parse_port_specification()` function accepts various port specification formats. Use Hypothesis to generate random inputs and verify the function never crashes and always produces valid results.

**Task Instructions:**

1. Create a new test file at `tests/fuzz/test_fuzz_port_parsing.py`
2. Define Hypothesis strategies for:
   - Valid port numbers (1-65535)
   - Valid port ranges (e.g., "1-100")
   - Malformed port specifications
   - Arbitrary string inputs
3. Write property tests that verify:
   - Valid inputs produce valid port lists
   - Invalid inputs do not crash the parser
   - Output ports are always within valid range

**Starter Code:**

```python
"""Fuzz tests for port parsing."""
import pytest
from hypothesis import given, settings, strategies as st

# TODO: Import parse_port_specification

# Strategy for valid port numbers
valid_port = st.integers(min_value=1, max_value=65535)

# TODO: Define more strategies

@pytest.mark.fuzz
class TestPortParsingFuzz:
    """Fuzz tests for port specification parsing."""

    @given(port=valid_port)
    @settings(max_examples=200)
    def test_single_port_never_crashes(self, port):
        """Single valid port should never cause crash."""
        # TODO: Implement
        pass

    @given(start=valid_port, end=valid_port)
    @settings(max_examples=200)
    def test_port_range_produces_valid_ports(self, start, end):
        """Port ranges should produce valid port numbers."""
        # TODO: Implement
        pass

    @given(arbitrary=st.text(max_size=100))
    @settings(max_examples=500)
    def test_arbitrary_input_does_not_crash(self, arbitrary):
        """Arbitrary text should not crash the parser."""
        # TODO: Implement
        pass
```

**Hints:**

- Use `assume()` to filter out invalid test cases in property tests
- The `st.one_of()` strategy can combine multiple strategies
- Use `@settings(max_examples=N)` to control test iterations

**Validation Criteria:**

- [ ] Tests discover at least one edge case not covered by unit tests
- [ ] Tests use appropriate Hypothesis strategies
- [ ] No uncaught exceptions from arbitrary input
- [ ] Tests run within reasonable time limits

---

### Lab 3: Integration Testing with Docker

**Objective:** Write integration tests that validate tool functionality against Docker-based test services.

**Scenario:** You need to verify that the FTP credential validator correctly identifies valid and invalid credentials against a running FTP server.

**Task Instructions:**

1. Create a new test file at `tests/docker_integration/test_ftp_validation.py`
2. Use the `ftp_service` fixture from the docker conftest
3. Write tests that:
   - Connect to the FTP service
   - Verify valid credentials are accepted
   - Verify invalid credentials are rejected
   - Test connection timeout handling

**Starter Code:**

```python
"""Integration tests for FTP credential validation."""
import pytest

# TODO: Import FTP-related classes

@pytest.mark.integration
class TestFTPCredentialValidation:
    """Test FTP credential validation against Docker FTP server."""

    def test_valid_credentials_accepted(self, ftp_service):
        """Test that valid credentials authenticate successfully."""
        # ftp_service provides:
        #   host, port, valid_user, valid_pass, invalid_user, invalid_pass
        # TODO: Implement
        pass

    def test_invalid_credentials_rejected(self, ftp_service):
        """Test that invalid credentials are rejected."""
        # TODO: Implement
        pass

    def test_invalid_username_rejected(self, ftp_service):
        """Test that invalid username is rejected."""
        # TODO: Implement
        pass

    def test_connection_timeout(self, ftp_service):
        """Test handling of connection timeout."""
        # TODO: Implement with very short timeout
        pass
```

**Environment Setup:**

Before running integration tests, ensure Docker containers are running:

```bash
# From the project root
docker-compose up -d

# Verify containers are running
docker ps --filter "label=cptc11.role"
```

**Hints:**

- Use `pytest.skip()` if Docker services are unavailable
- Integration tests should have longer timeouts than unit tests
- Clean up any connections in test teardown

**Validation Criteria:**

- [ ] Tests skip gracefully when Docker is not available
- [ ] Tests use service fixtures correctly
- [ ] All credential scenarios are tested
- [ ] Tests clean up connections properly

---

## Quick Reference Card

### Common pytest Commands

| Command | Description |
|---------|-------------|
| `pytest` | Run all tests |
| `pytest -v` | Verbose output |
| `pytest -k "pattern"` | Run matching tests |
| `pytest -m marker` | Run marked tests |
| `pytest -x` | Stop on first failure |
| `pytest --pdb` | Debug on failure |
| `pytest --lf` | Run last failed |
| `pytest --cov` | With coverage |

### Test Markers Quick Reference

| Marker | Usage |
|--------|-------|
| `@pytest.mark.unit` | Unit tests |
| `@pytest.mark.integration` | Integration tests |
| `@pytest.mark.fuzz` | Hypothesis tests |
| `@pytest.mark.security` | Security tests |
| `@pytest.mark.slow` | Long-running tests |
| `@pytest.mark.skip(reason="...")` | Skip test |
| `@pytest.mark.skipif(cond)` | Conditional skip |
| `@pytest.mark.parametrize` | Multiple inputs |

### Hypothesis Profiles

| Profile | Examples | Deadline | Use Case |
|---------|----------|----------|----------|
| `fast` | 10 | 1000ms | Quick local check |
| `dev` | 100 | 2000ms | Development |
| `ci` | 50 | 5000ms | CI pipelines |
| `thorough` | 500 | 10000ms | Release validation |

Set profile: `HYPOTHESIS_PROFILE=ci pytest`

---

## Assessment Questions

1. Why is it important to use mocks when testing network operations in security tools?

2. Explain the difference between `@pytest.mark.integration` and `@pytest.mark.fuzz` tests.

3. What is the purpose of the `--plan` flag in CPTC11 tools, and how should it be tested?

4. Describe three types of injection attacks that should be tested in security tools.

5. How does the CPTC11 test infrastructure handle tests that require Docker containers?

---

## Summary

This module covered the comprehensive QA testing infrastructure and practices used in CPTC11:

- **Testing Challenges:** Understanding the unique difficulties of testing offensive security tools
- **Infrastructure:** Navigating pytest configuration, markers, and fixtures
- **Test Categories:** Writing unit, integration, fuzz, security, and performance tests
- **Mock Classes:** Using mocks to safely test network operations
- **Execution:** Running tests via Makefile commands and interpreting results

Effective testing of security tools requires balancing safety with thoroughness. By following the patterns and practices outlined in this module, you can contribute high-quality, well-tested code to the CPTC11 project while minimizing risk.

---

**Module Version:** 1.0
**Last Updated:** January 2026
**Author:** Training Development Team
