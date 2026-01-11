# Offensive Security Tooling Development

## A Comprehensive Curriculum for Building Professional-Grade Penetration Testing Tools

**Version:** 1.0
**Target Audience:** Intermediate to Advanced Security Practitioners
**Prerequisites:** Python fundamentals, basic networking concepts, familiarity with penetration testing methodologies
**Estimated Study Time:** 40-60 hours

---

## Table of Contents

1. [Introduction to Offensive Tool Development](#1-introduction-to-offensive-tool-development)
2. [Development Environment Setup](#2-development-environment-setup)
3. [Tool Architecture Patterns](#3-tool-architecture-patterns)
4. [Building Your First Reconnaissance Tool](#4-building-your-first-reconnaissance-tool)
5. [Advanced Techniques](#5-advanced-techniques)
6. [Case Studies](#6-case-studies)

---

## 1. Introduction to Offensive Tool Development

### 1.1 Philosophy of Tool Development for Penetration Testing

The art of developing offensive security tools transcends mere programming. It requires a deep understanding of systems, networks, adversary tradecraft, and the delicate balance between capability and responsibility. When we build tools for penetration testing, we are creating instruments that simulate real-world attack scenarios, enabling organizations to identify and remediate vulnerabilities before malicious actors exploit them.

Professional offensive tool development adheres to several core philosophical principles:

**Purpose-Driven Design:** Every tool should solve a specific operational problem. The best offensive tools emerge from real engagement needs rather than theoretical exercises. Before writing a single line of code, articulate the precise operational gap your tool addresses. Ask yourself: What can this tool do that existing tools cannot? What operational advantage does it provide? How does it fit into a broader methodology?

**Reliability Over Features:** In the heat of an engagement, a simple tool that works reliably is infinitely more valuable than a feature-rich tool that behaves unpredictably. Operators must trust their tools completely. This means extensive testing, graceful error handling, and predictable behavior across diverse environments. A network scanner that crashes on malformed input is worse than useless--it is a liability that may compromise your position.

**Operational Security by Design:** Security tools should protect the operator as much as they enable operations. This principle manifests in design decisions like in-memory result storage, configurable network timing, minimal disk artifacts, and clear documentation of detection vectors. A well-designed tool makes operational security the default, not an afterthought.

**Extensibility and Modularity:** The threat landscape evolves continuously. Tools built with extensibility in mind can adapt to new requirements without complete rewrites. Abstract base classes, plugin architectures, and clean interfaces enable rapid capability development while maintaining stability in core functionality.

**Transparency and Education:** The best offensive tools teach their users. Clear documentation, meaningful output, and the `--plan` flag pattern (which we will explore extensively) transform tools from black boxes into educational instruments. Operators who understand what their tools do are more effective than those who merely execute commands.

### 1.2 Ethics and Legal Considerations

The development and use of offensive security tools carries profound ethical and legal responsibilities. These tools possess dual-use potential--the same capabilities that enable legitimate security testing can facilitate malicious activity. As tool developers, we must internalize several critical principles:

**Authorization is Non-Negotiable:** Every tool in this curriculum includes explicit warnings about authorized use. This is not merely legal protection--it reflects a fundamental ethical boundary. Tools should be designed to remind operators of their responsibilities, through warning banners, documentation, and operational safeguards.

**Scope Awareness:** Well-designed tools help operators stay within authorized scope. Features like explicit target specification, planning modes that preview actions, and clear logging of activities support disciplined operations. A tool that makes it easy to accidentally expand beyond scope is poorly designed.

**Responsible Disclosure:** When your tools reveal vulnerabilities, you inherit responsibility for how that information is handled. Build tools that produce actionable, well-documented findings that enable remediation. Consider how your tool's output might be misused and design accordingly.

**Legal Framework Understanding:** Security testing occurs within a complex legal framework that varies by jurisdiction. Tool developers should understand concepts like the Computer Fraud and Abuse Act (CFAA), authorization requirements, and international considerations. While tools themselves are generally legal to develop, their misuse is not. Include appropriate legal disclaimers and warnings.

**Community Responsibility:** The security community benefits from shared tools and knowledge, but this sharing must be balanced against potential harm. Consider whether public release serves the defensive community more than it enables attackers. Many excellent tools remain private precisely because their public release would cause more harm than good.

### 1.3 The Offensive Security Mindset

Developing effective offensive tools requires adopting the adversarial mindset--thinking like an attacker while maintaining the ethics of a defender. This cognitive framework shapes every design decision:

**Assume Detection:** Modern defensive technologies are sophisticated and improving rapidly. Design tools assuming they will be detected eventually. This means building in stealth features, understanding detection mechanisms, and documenting what defenders will see. The question is not whether detection is possible, but how long you can operate before detection occurs.

**Embrace Constraints:** Real engagements impose constraints: limited time windows, network restrictions, endpoint protections, and operational security requirements. Tools designed for unconstrained environments fail in practice. Embrace these constraints during development--they drive creative solutions and practical capabilities.

**Think in Kill Chains:** Individual tools are components of larger operational sequences. A network scanner feeds results to a port scanner, which identifies services for the fingerprinter, which reveals vulnerabilities for exploitation. Design tools to integrate seamlessly, with consistent interfaces and machine-readable outputs.

**Prioritize Reliability:** An engagement is not the time to debug tools. Comprehensive testing, including edge cases and failure scenarios, separates professional tools from hobbyist scripts. When tools encounter errors, they should fail gracefully with informative messages, not crash spectacularly or worse, continue silently with incorrect results.

**Document Everything:** Future you (and your teammates) will thank present you for clear documentation. Document not just how to use the tool, but why design decisions were made, what detection vectors exist, and what limitations apply. This documentation is as valuable as the code itself.

---

## 2. Development Environment Setup

### 2.1 Python Environment Configuration

Python serves as the primary language for offensive tool development due to its rich standard library, extensive third-party ecosystem, and rapid development cycle. This section establishes a professional development environment.

#### 2.1.1 Python Version Requirements

```bash
# Verify Python version (3.8+ required, 3.10+ recommended)
python3 --version

# Install Python 3.10+ via pyenv for version management
curl https://pyenv.run | bash

# Add to shell configuration (~/.bashrc or ~/.zshrc)
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

# Install specific Python version
pyenv install 3.11.0
pyenv global 3.11.0
```

#### 2.1.2 Virtual Environment Setup

Isolate project dependencies using virtual environments:

```bash
# Create project directory
mkdir -p ~/projects/offensive-tools
cd ~/projects/offensive-tools

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

#### 2.1.3 Core Dependencies

Create a `requirements.txt` file with essential libraries:

```text
# Core libraries
dataclasses-json>=0.5.7
typing-extensions>=4.0.0

# Networking
dnspython>=2.3.0
impacket>=0.10.0
requests>=2.28.0
urllib3>=1.26.0

# Concurrency
aiohttp>=3.8.0

# Encoding/Crypto
pycryptodome>=3.17.0

# Testing
pytest>=7.0.0
pytest-cov>=4.0.0
hypothesis>=6.0.0

# Code quality
ruff>=0.1.0
mypy>=1.0.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

### 2.2 Go Development Setup

Go provides performance advantages for network-intensive tools and produces easily distributable static binaries. The CPTC11 framework includes Go ports of all Phase 1 tools.

#### 2.2.1 Go Installation

```bash
# Download Go (1.19+ required)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz

# Extract to /usr/local
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz

# Add to PATH (~/.bashrc or ~/.zshrc)
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Verify installation
go version
```

#### 2.2.2 Project Structure for Go Tools

```
golang/
|-- go.mod
|-- go.sum
|-- tools/
|   |-- network-scanner/
|   |   |-- scanner.go
|   |   |-- scanner_test.go
|   |-- port-scanner/
|   |   |-- scanner.go
```

Initialize Go modules:

```bash
cd golang
go mod init cptc11
go mod tidy
```

### 2.3 IDE and Editor Configuration

#### 2.3.1 Visual Studio Code Configuration

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.formatting.provider": "none",
    "editor.formatOnSave": true,
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff"
    },
    "editor.rulers": [100],
    "files.trimTrailingWhitespace": true,
    "go.formatTool": "gofmt",
    "go.lintTool": "golangci-lint"
}
```

#### 2.3.2 Recommended Extensions

- Python: ms-python.python
- Pylance: ms-python.vscode-pylance
- Ruff: charliermarsh.ruff
- Go: golang.go

### 2.4 Linting and Code Quality

#### 2.4.1 Ruff Configuration

Create `pyproject.toml`:

```toml
[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "B", "A", "C4", "SIM"]
ignore = ["E501"]  # Line length handled separately

[tool.ruff.format]
quote-style = "double"
indent-style = "space"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
addopts = "-v --tb=short"

[tool.mypy]
python_version = "3.10"
warn_return_any = true
warn_unused_configs = true
```

#### 2.4.2 Makefile for Automation

```makefile
.PHONY: lint lint-fix test coverage clean

lint:
	ruff check .
	ruff format --check .

lint-fix:
	ruff check --fix .
	ruff format .

test:
	python -m pytest tests/ -v

test-fast:
	python -m pytest tests/ -v -m "not slow"

coverage:
	python -m pytest tests/ --cov=tools --cov-report=html --cov-report=term-missing

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov
```

---

## 3. Tool Architecture Patterns

This section examines the architectural patterns employed throughout the CPTC11 toolkit. These patterns represent battle-tested approaches to building maintainable, extensible, and operationally secure offensive tools.

### 3.1 The CPTC11 Tool Architecture Pattern

Every tool in the framework follows a consistent architectural blueprint:

```
+------------------------------------------------------------------+
|                        TOOL ARCHITECTURE                          |
+------------------------------------------------------------------+
|                                                                   |
|  +------------------+     +------------------+                    |
|  |   CLI Layer      |     |  Config Layer    |                   |
|  |  (argparse)      |---->|  (dataclasses)   |                   |
|  +------------------+     +------------------+                    |
|                                   |                               |
|                                   v                               |
|                          +------------------+                     |
|                          |   Core Engine    |                     |
|                          |  (Main Class)    |                     |
|                          +------------------+                     |
|                                   |                               |
|                    +--------------+--------------+                |
|                    |              |              |                 |
|                    v              v              v                 |
|            +----------+   +----------+   +----------+            |
|            |Technique |   |Technique |   |Technique |            |
|            |    A     |   |    B     |   |    C     |            |
|            +----------+   +----------+   +----------+            |
|                    |              |              |                 |
|                    +--------------+--------------+                |
|                                   |                               |
|                                   v                               |
|                          +------------------+                     |
|                          |  Result Layer    |                     |
|                          |  (dataclasses)   |                     |
|                          +------------------+                     |
|                                   |                               |
|                    +--------------+--------------+                |
|                    |              |              |                 |
|                    v              v              v                 |
|              [Console]      [JSON File]    [In-Memory]            |
|                                                                   |
+------------------------------------------------------------------+
```

### 3.2 Abstract Base Classes for Extensibility

Abstract base classes define contracts that concrete implementations must fulfill. This pattern enables:

- Consistent interfaces across similar components
- Easy addition of new techniques without modifying core code
- Clear documentation of expected behavior

**Example: ScanTechnique Abstract Base Class**

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ScanResult:
    """Represents a single scan result."""
    target: str
    is_successful: bool
    data: Dict[str, Any] = None
    error: str = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        return {
            "target": self.target,
            "is_successful": self.is_successful,
            "data": self.data,
            "error": self.error
        }


class ScanTechnique(ABC):
    """
    Abstract base class for scan techniques.

    All scanning techniques must implement this interface,
    ensuring consistent behavior across the toolkit.
    """

    @abstractmethod
    def scan(self, target: str, config: "ScanConfig") -> ScanResult:
        """
        Execute the scan against a single target.

        Args:
            target: The target specification (IP, hostname, etc.)
            config: Configuration object with scan parameters

        Returns:
            ScanResult containing scan outcome
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the human-readable technique name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return technique description for documentation."""
        pass

    @property
    def requires_privileges(self) -> bool:
        """Whether this technique requires elevated privileges."""
        return False


class TCPConnectScan(ScanTechnique):
    """TCP Connect scan implementation."""

    @property
    def name(self) -> str:
        return "tcp_connect"

    @property
    def description(self) -> str:
        return "Full TCP handshake scan - reliable but logged"

    def scan(self, target: str, config: "ScanConfig") -> ScanResult:
        # Implementation here
        pass


class ARPScan(ScanTechnique):
    """ARP-based local network scan."""

    @property
    def name(self) -> str:
        return "arp"

    @property
    def description(self) -> str:
        return "ARP scan for local network discovery"

    @property
    def requires_privileges(self) -> bool:
        return True  # ARP requires raw socket access

    def scan(self, target: str, config: "ScanConfig") -> ScanResult:
        # Implementation here
        pass
```

### 3.3 Dataclasses for Configuration and Results

Dataclasses provide clean, type-hinted structures for configuration and results:

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class ScanMethod(Enum):
    """Available scanning methods."""
    TCP = "tcp"
    ARP = "arp"
    DNS = "dns"


@dataclass
class ScanConfig:
    """
    Configuration for scanning operations.

    Centralizes all configuration options with sensible defaults
    and type hints for IDE support and validation.
    """
    # Required parameters
    targets: List[str] = field(default_factory=list)

    # Timing and performance
    timeout: float = 2.0
    threads: int = 10
    delay_min: float = 0.0
    delay_max: float = 0.1

    # Scan behavior
    scan_methods: List[ScanMethod] = field(
        default_factory=lambda: [ScanMethod.TCP]
    )
    tcp_ports: List[int] = field(
        default_factory=lambda: [80, 443, 22]
    )
    resolve_hostnames: bool = False

    # Output control
    verbose: bool = False
    plan_mode: bool = False

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of errors.

        Returns:
            Empty list if valid, list of error messages otherwise
        """
        errors = []

        if not self.targets:
            errors.append("No targets specified")

        if self.timeout <= 0:
            errors.append("Timeout must be positive")

        if self.threads < 1:
            errors.append("Thread count must be at least 1")

        if self.delay_min > self.delay_max:
            errors.append("delay_min cannot exceed delay_max")

        return errors


@dataclass
class HostResult:
    """Result for a single host scan."""
    ip: str
    is_alive: bool
    response_time: Optional[float] = None
    method: str = "unknown"
    hostname: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "ip": self.ip,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "method": self.method,
            "hostname": self.hostname,
            "timestamp": self.timestamp.isoformat()
        }
```

### 3.4 The `--plan` Flag Pattern

The `--plan` flag is perhaps the most important operational pattern in the toolkit. It enables operators to preview exactly what a tool will do before execution:

```
+------------------------------------------------------------------+
|                     PLAN MODE EXECUTION FLOW                      |
+------------------------------------------------------------------+
|                                                                   |
|    User invokes: python tool.py 192.168.1.0/24 --plan            |
|                                                                   |
|                          +                                        |
|                          |                                        |
|                          v                                        |
|                  +---------------+                                |
|                  | Parse CLI     |                                |
|                  | Arguments     |                                |
|                  +---------------+                                |
|                          |                                        |
|                          v                                        |
|                  +---------------+                                |
|                  | Build Config  |                                |
|                  | Object        |                                |
|                  +---------------+                                |
|                          |                                        |
|                          v                                        |
|                  +---------------+                                |
|               +--| plan_mode?    |--+                             |
|               |  +---------------+  |                             |
|               |                     |                             |
|          [True]                [False]                            |
|               |                     |                             |
|               v                     v                             |
|      +----------------+    +----------------+                     |
|      | print_plan()   |    | Execute scan   |                     |
|      | - Show targets |    | - Network ops  |                     |
|      | - Show actions |    | - Return data  |                     |
|      | - Risk assess  |    +----------------+                     |
|      | - NO NETWORK   |                                           |
|      +----------------+                                           |
|               |                                                   |
|               v                                                   |
|      +----------------+                                           |
|      | Exit with      |                                           |
|      | status 0       |                                           |
|      +----------------+                                           |
|                                                                   |
+------------------------------------------------------------------+
```

**Implementation Pattern:**

```python
def print_plan(config: ScanConfig) -> None:
    """
    Display execution plan without performing any network operations.

    This function provides operators with complete visibility into
    what the tool will do when executed, enabling informed decisions
    and operational security.
    """
    # Calculate derived information
    scanner = NetworkScanner(config)
    targets = list(scanner._expand_targets())

    print("""
[PLAN MODE] Tool: network-scanner
================================================================================
""")

    # Operation Summary
    print("OPERATION SUMMARY")
    print("-" * 40)
    print(f"  Target Specification: {', '.join(config.targets)}")
    print(f"  Total IPs to scan:    {len(targets)}")
    print(f"  Scan Methods:         {', '.join(m.value for m in config.scan_methods)}")
    print(f"  TCP Ports:            {config.tcp_ports}")
    print(f"  Threads:              {config.threads}")
    print(f"  Timeout:              {config.timeout}s")
    print()

    # Actions Preview
    print("ACTIONS TO BE PERFORMED")
    print("-" * 40)
    print("  1. Parse and expand target specifications")
    print(f"  2. Initialize thread pool with {config.threads} workers")
    print("  3. For each target IP:")
    for method in config.scan_methods:
        if method == ScanMethod.TCP:
            print(f"     - Attempt TCP connections to ports {config.tcp_ports}")
        elif method == ScanMethod.ARP:
            print("     - Send ARP request (requires privileges)")
    print(f"  4. Apply random delay ({config.delay_min}s - {config.delay_max}s)")
    print("  5. Aggregate results in-memory")
    print()

    # Target Preview
    print("TARGET PREVIEW (first 10)")
    print("-" * 40)
    for ip in targets[:10]:
        print(f"  - {ip}")
    if len(targets) > 10:
        print(f"  ... and {len(targets) - 10} more")
    print()

    # Risk Assessment
    print("RISK ASSESSMENT")
    print("-" * 40)
    risk_factors = []

    if len(targets) > 100:
        risk_factors.append("Large scan scope may trigger alerts")
    if config.delay_max < 0.1:
        risk_factors.append("Low delay increases detection probability")
    if config.threads > 50:
        risk_factors.append("High thread count visible in network logs")

    risk_level = "LOW"
    if len(risk_factors) >= 2:
        risk_level = "MEDIUM"
    if len(risk_factors) >= 3:
        risk_level = "HIGH"

    print(f"  Risk Level: {risk_level}")
    for factor in risk_factors:
        print(f"    - {factor}")
    print()

    # Detection Vectors
    print("DETECTION VECTORS")
    print("-" * 40)
    print("  - Network IDS/IPS may detect port scanning patterns")
    print("  - Firewall logs will record connection attempts")
    print("  - Host-based security tools may alert on probes")
    print()

    print("=" * 80)
    print("No actions will be taken. Remove --plan flag to execute.")
    print("=" * 80)
```

### 3.5 The `get_documentation()` Hook Pattern

Every tool implements a documentation hook that returns structured metadata:

```python
def get_documentation() -> Dict[str, Any]:
    """
    Return structured documentation for integration with documentation systems.

    This function enables:
    - Automated documentation generation
    - TUI integration for tool discovery
    - Programmatic tool chaining based on capabilities

    Returns:
        Dictionary containing comprehensive tool metadata
    """
    return {
        "name": "network-scanner",
        "version": "1.0.0",
        "category": "reconnaissance",
        "description": "Stealthy network host discovery tool for penetration testing",
        "author": "Offensive Security Toolsmith",
        "license": "Authorized security testing only",

        "features": [
            "Multiple scanning techniques (TCP, ARP, DNS)",
            "CIDR and range notation support",
            "Configurable threading and delays",
            "In-memory result storage",
            "Planning mode for operation preview"
        ],

        "arguments": {
            "targets": {
                "type": "list",
                "required": True,
                "description": "Target IPs, CIDR ranges, or hostnames"
            },
            "--timeout": {
                "type": "float",
                "default": 2.0,
                "description": "Connection timeout in seconds"
            },
            "--threads": {
                "type": "int",
                "default": 10,
                "description": "Number of concurrent scanning threads"
            },
            "--plan": {
                "type": "bool",
                "default": False,
                "description": "Show execution plan without scanning"
            }
        },

        "examples": [
            {
                "command": "python tool.py 192.168.1.0/24 --plan",
                "description": "Preview scan of a /24 network"
            },
            {
                "command": "python tool.py 10.0.0.1-50 --methods tcp dns",
                "description": "Scan IP range with multiple methods"
            }
        ],

        "opsec_notes": [
            "Results are kept in memory to minimize disk artifacts",
            "Use --delay flags to reduce detection probability",
            "TCP connect scans are logged by target systems"
        ]
    }
```

### 3.6 JSON Output for Tool Chaining

All tools support JSON output for programmatic integration:

```python
import json
from typing import List


def output_results(results: List[HostResult], output_file: str = None) -> None:
    """
    Output results in JSON format for tool chaining.

    Args:
        results: List of scan results
        output_file: Optional file path for output
    """
    output_data = {
        "scan_time": datetime.now().isoformat(),
        "total_results": len(results),
        "live_hosts": len([r for r in results if r.is_alive]),
        "results": [r.to_dict() for r in results]
    }

    json_output = json.dumps(output_data, indent=2)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(json_output)
    else:
        print(json_output)
```

Tool chaining example:

```bash
# Scan network, extract live hosts, scan ports on live hosts
python network-scanner/tool.py 192.168.1.0/24 -o hosts.json
cat hosts.json | jq -r '.results[] | select(.is_alive) | .ip' | \
    xargs -I {} python port-scanner/tool.py {} --ports top100 -o {}_ports.json
```

---

## 4. Building Your First Reconnaissance Tool

This section provides a complete walkthrough of building a network scanner from scratch, applying all architectural patterns discussed previously.

### 4.1 Requirements Gathering

Before writing code, document clear requirements:

**Functional Requirements:**
1. Discover live hosts on a network segment
2. Support multiple input formats (single IP, CIDR, ranges)
3. Implement multiple discovery techniques (TCP, ARP, DNS)
4. Report results with timing information
5. Support JSON output for automation

**Non-Functional Requirements:**
1. Configurable timing for stealth operations
2. In-memory result storage (no disk artifacts)
3. Graceful error handling
4. Planning mode for operation preview
5. Documentation hook for integration

**Operational Requirements:**
1. Thread-safe concurrent scanning
2. Interruptible via keyboard (Ctrl+C)
3. Progress indication for large scans

### 4.2 Design Decisions

**Architecture Decision Record:**

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Python 3.10+ | Rich networking libraries, rapid development |
| Concurrency | ThreadPoolExecutor | I/O-bound operations, simpler than asyncio |
| Configuration | Dataclasses | Type safety, IDE support, clean defaults |
| Techniques | Abstract base class | Easy extension for new methods |
| CLI | argparse | Standard library, no dependencies |

### 4.3 Implementation

#### Step 1: Project Structure

```
network-scanner/
|-- tool.py          # Main implementation
|-- README.md        # Tool documentation
|-- tests/
    |-- test_scanner.py
```

#### Step 2: Constants and Configuration

```python
#!/usr/bin/env python3
"""
Network Scanner - Stealthy Network Discovery Tool
==================================================

A comprehensive network scanning utility designed for authorized penetration testing.
Emphasizes stealth, in-memory operation, and operational security.

Author: Offensive Security Toolsmith
Version: 1.0.0
License: For authorized security testing only

WARNING: This tool is intended for authorized security assessments only.
Unauthorized access to computer systems is illegal.
"""

import argparse
import ipaddress
import socket
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Generator, Any
from datetime import datetime
from abc import ABC, abstractmethod


# Configuration Constants
DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 10
DEFAULT_DELAY_MIN = 0.0
DEFAULT_DELAY_MAX = 0.1
```

#### Step 3: Data Classes

```python
@dataclass
class ScanResult:
    """Represents a single host scan result."""
    ip: str
    is_alive: bool
    response_time: Optional[float] = None
    method: str = "unknown"
    hostname: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "ip": self.ip,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "method": self.method,
            "hostname": self.hostname,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ScanConfig:
    """Configuration for network scanning operations."""
    targets: List[str] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    threads: int = DEFAULT_THREADS
    delay_min: float = DEFAULT_DELAY_MIN
    delay_max: float = DEFAULT_DELAY_MAX
    resolve_hostnames: bool = False
    scan_methods: List[str] = field(default_factory=lambda: ["tcp"])
    tcp_ports: List[int] = field(default_factory=lambda: [80, 443, 22])
    verbose: bool = False
    plan_mode: bool = False
```

#### Step 4: Scan Techniques (Abstract Pattern)

```python
class ScanTechnique(ABC):
    """Abstract base class for scan techniques."""

    @abstractmethod
    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Execute the scan against a single IP."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the technique name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return technique description."""
        pass


class TCPConnectScan(ScanTechnique):
    """TCP Connect scan - checks if common ports are open."""

    @property
    def name(self) -> str:
        return "tcp_connect"

    @property
    def description(self) -> str:
        return "TCP Connect scan using socket connections to detect live hosts"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Perform TCP connect scan on specified ports."""
        start_time = time.time()

        for port in config.tcp_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    response_time = time.time() - start_time
                    hostname = None
                    if config.resolve_hostnames:
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                        except socket.herror:
                            pass

                    return ScanResult(
                        ip=ip,
                        is_alive=True,
                        response_time=response_time,
                        method=f"tcp_connect:{port}",
                        hostname=hostname
                    )
            except socket.error:
                continue

        return ScanResult(ip=ip, is_alive=False, method="tcp_connect")


class DNSResolutionScan(ScanTechnique):
    """DNS-based host discovery through reverse lookups."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS reverse lookup scan to identify hosts with PTR records"

    def scan(self, ip: str, config: ScanConfig) -> ScanResult:
        """Perform DNS reverse lookup to detect host."""
        start_time = time.time()

        try:
            hostname = socket.gethostbyaddr(ip)[0]
            response_time = time.time() - start_time

            return ScanResult(
                ip=ip,
                is_alive=True,
                response_time=response_time,
                method="dns_ptr",
                hostname=hostname
            )
        except socket.herror:
            return ScanResult(ip=ip, is_alive=False, method="dns_ptr")
```

#### Step 5: Core Scanner Engine

```python
class NetworkScanner:
    """
    Main network scanning engine with stealth and operational security features.
    """

    TECHNIQUES: Dict[str, type] = {
        "tcp": TCPConnectScan,
        "dns": DNSResolutionScan,
    }

    def __init__(self, config: ScanConfig):
        """Initialize the network scanner."""
        self.config = config
        self.results: List[ScanResult] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def _expand_targets(self) -> Generator[str, None, None]:
        """
        Expand target specifications into individual IP addresses.

        Supports:
        - Single IPs: 192.168.1.1
        - CIDR notation: 192.168.1.0/24
        - Ranges: 192.168.1.1-254
        """
        for target in self.config.targets:
            try:
                if "/" in target:
                    # CIDR notation
                    network = ipaddress.ip_network(target, strict=False)
                    for ip in network.hosts():
                        yield str(ip)
                elif "-" in target:
                    # Range notation
                    base = target.rsplit(".", 1)[0]
                    range_part = target.rsplit(".", 1)[1]
                    if "-" in range_part:
                        start, end = range_part.split("-")
                        for i in range(int(start), int(end) + 1):
                            yield f"{base}.{i}"
                    else:
                        yield target
                else:
                    yield target
            except ValueError as e:
                if self.config.verbose:
                    print(f"[!] Invalid target: {target} - {e}")

    def _apply_jitter(self) -> None:
        """Apply random delay for stealth operations."""
        if self.config.delay_max > 0:
            delay = random.uniform(self.config.delay_min, self.config.delay_max)
            time.sleep(delay)

    def _scan_host(self, ip: str) -> Optional[ScanResult]:
        """Scan a single host using configured techniques."""
        if self._stop_event.is_set():
            return None

        self._apply_jitter()

        for method in self.config.scan_methods:
            if method in self.TECHNIQUES:
                technique = self.TECHNIQUES[method]()
                result = technique.scan(ip, self.config)

                if result.is_alive:
                    return result

        return ScanResult(ip=ip, is_alive=False, method="all_methods")

    def scan(self) -> List[ScanResult]:
        """Execute the network scan."""
        targets = list(self._expand_targets())

        if self.config.verbose:
            print(f"[*] Scanning {len(targets)} hosts with {self.config.threads} threads")

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self._scan_host, ip): ip for ip in targets}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self.results.append(result)
                            if result.is_alive and self.config.verbose:
                                print(f"[+] {result.ip} is alive ({result.method})")
                except Exception as e:
                    if self.config.verbose:
                        print(f"[!] Error scanning {futures[future]}: {e}")

        return self.results

    def stop(self) -> None:
        """Signal the scanner to stop operations."""
        self._stop_event.set()

    def get_live_hosts(self) -> List[ScanResult]:
        """Return only hosts that responded."""
        return [r for r in self.results if r.is_alive]
```

#### Step 6: CLI Interface and Main Entry Point

```python
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Network Scanner - Stealthy Host Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24 --plan
  %(prog)s 192.168.1.1-254 --methods tcp dns
  %(prog)s 10.0.0.1 10.0.0.2 --resolve --verbose

WARNING: Use only for authorized security testing.
        """
    )

    parser.add_argument("targets", nargs="+",
                        help="Target IPs, CIDR ranges, or IP ranges")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-T", "--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-m", "--methods", nargs="+", choices=["tcp", "dns"],
                        default=["tcp"], help="Scanning methods to use")
    parser.add_argument("-P", "--ports", nargs="+", type=int, default=[80, 443, 22],
                        help="TCP ports for connect scanning")
    parser.add_argument("--delay-min", type=float, default=DEFAULT_DELAY_MIN,
                        help="Minimum delay between scans")
    parser.add_argument("--delay-max", type=float, default=DEFAULT_DELAY_MAX,
                        help="Maximum delay between scans")
    parser.add_argument("-r", "--resolve", action="store_true",
                        help="Resolve hostnames for discovered hosts")
    parser.add_argument("-p", "--plan", action="store_true",
                        help="Show execution plan without performing scan")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = parse_arguments()

    config = ScanConfig(
        targets=args.targets,
        timeout=args.timeout,
        threads=args.threads,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        resolve_hostnames=args.resolve,
        scan_methods=args.methods,
        tcp_ports=args.ports,
        verbose=args.verbose,
        plan_mode=args.plan
    )

    if config.plan_mode:
        print_plan(config)
        return 0

    print("[*] Network Scanner starting...")
    scanner = NetworkScanner(config)

    try:
        results = scanner.scan()
        live_hosts = scanner.get_live_hosts()

        print(f"\n{'=' * 60}")
        print("SCAN RESULTS")
        print(f"{'=' * 60}")
        print(f"Total hosts scanned: {len(results)}")
        print(f"Live hosts found:    {len(live_hosts)}")

        if live_hosts:
            print("\nLIVE HOSTS:")
            print("-" * 60)
            for host in live_hosts:
                hostname_str = f" ({host.hostname})" if host.hostname else ""
                print(f"  {host.ip}{hostname_str} - {host.method}")

        if args.output:
            import json
            output_data = {
                "scan_time": datetime.now().isoformat(),
                "config": {"targets": config.targets, "methods": config.scan_methods},
                "results": [r.to_dict() for r in results]
            }
            with open(args.output, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.stop()
        return 130


if __name__ == "__main__":
    sys.exit(main())
```

### 4.4 Testing Strategies

#### Unit Tests

```python
# tests/test_scanner.py
import pytest
from unittest.mock import Mock, patch
from tool import (
    ScanConfig, ScanResult, NetworkScanner,
    TCPConnectScan, parse_port_specification
)


class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScanConfig()
        assert config.timeout == 2.0
        assert config.threads == 10
        assert config.scan_methods == ["tcp"]

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ScanConfig(
            targets=["192.168.1.0/24"],
            timeout=5.0,
            threads=20
        )
        assert config.targets == ["192.168.1.0/24"]
        assert config.timeout == 5.0


class TestTargetExpansion:
    """Tests for target expansion functionality."""

    def test_single_ip(self):
        """Test single IP expansion."""
        config = ScanConfig(targets=["192.168.1.1"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert targets == ["192.168.1.1"]

    def test_cidr_expansion(self):
        """Test CIDR notation expansion."""
        config = ScanConfig(targets=["192.168.1.0/30"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        # /30 has 2 usable hosts
        assert len(targets) == 2
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_range_expansion(self):
        """Test range notation expansion."""
        config = ScanConfig(targets=["192.168.1.1-3"])
        scanner = NetworkScanner(config)
        targets = list(scanner._expand_targets())
        assert targets == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = ScanResult(
            ip="192.168.1.1",
            is_alive=True,
            response_time=0.025,
            method="tcp_connect:80"
        )
        d = result.to_dict()
        assert d["ip"] == "192.168.1.1"
        assert d["is_alive"] is True
        assert d["method"] == "tcp_connect:80"


class TestTCPConnectScan:
    """Tests for TCP Connect scan technique."""

    @patch('socket.socket')
    def test_open_port(self, mock_socket_class):
        """Test detection of open port."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 0

        config = ScanConfig(tcp_ports=[80])
        technique = TCPConnectScan()
        result = technique.scan("192.168.1.1", config)

        assert result.is_alive is True
        assert "tcp_connect" in result.method

    @patch('socket.socket')
    def test_closed_port(self, mock_socket_class):
        """Test detection of closed port."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect_ex.return_value = 111  # Connection refused

        config = ScanConfig(tcp_ports=[80])
        technique = TCPConnectScan()
        result = technique.scan("192.168.1.1", config)

        assert result.is_alive is False
```

### 4.5 Documentation

Every tool includes a README.md:

```markdown
# Network Scanner

Stealthy network host discovery tool for penetration testing.

## Features

- Multiple scanning techniques (TCP, DNS)
- CIDR and range notation support
- Configurable threading and delays
- In-memory result storage
- Planning mode for operation preview

## Usage

    python tool.py <targets> [options]

## Examples

    # Preview scan without execution
    python tool.py 192.168.1.0/24 --plan

    # Scan with multiple methods
    python tool.py 192.168.1.1-254 --methods tcp dns

    # Stealthy scan with delays
    python tool.py 10.0.0.0/24 --delay-min 1 --delay-max 5 --threads 2

## OPSEC Notes

- Results stored in-memory only
- Use --delay flags to reduce detection probability
- TCP connect scans are logged by target systems
```

---

## 5. Advanced Techniques

### 5.1 Threading and Concurrency

Effective offensive tools must balance performance with stealth. The CPTC11 framework employs several concurrency patterns:

#### ThreadPoolExecutor for I/O-Bound Operations

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


class ConcurrentScanner:
    """Scanner with thread-safe result collection."""

    def __init__(self, config):
        self.config = config
        self.results = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def scan_target(self, target: str) -> Optional[Result]:
        """Scan a single target (called from thread pool)."""
        if self._stop_event.is_set():
            return None

        # Perform scan...
        result = self._do_scan(target)

        # Thread-safe result collection
        with self._lock:
            self.results.append(result)

        return result

    def scan_all(self, targets: List[str]) -> List[Result]:
        """Scan all targets with concurrent execution."""
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            # Submit all tasks
            futures = {
                executor.submit(self.scan_target, t): t
                for t in targets
            }

            # Process results as they complete
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=self.config.timeout * 2)
                except TimeoutError:
                    target = futures[future]
                    self._handle_timeout(target)
                except Exception as e:
                    self._handle_error(futures[future], e)

        return self.results

    def stop(self):
        """Signal all threads to stop."""
        self._stop_event.set()
```

#### Rate Limiting with Jitter

```python
import random
import time


class RateLimitedOperations:
    """Operations with configurable rate limiting."""

    def __init__(self, delay_min: float, delay_max: float):
        self.delay_min = delay_min
        self.delay_max = delay_max

    def apply_jitter(self) -> None:
        """Apply random delay between operations."""
        if self.delay_max > 0:
            delay = random.uniform(self.delay_min, self.delay_max)
            time.sleep(delay)

    def execute_with_backoff(self, operation, max_retries: int = 3):
        """Execute operation with exponential backoff on failure."""
        for attempt in range(max_retries):
            try:
                return operation()
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time)
```

### 5.2 Error Handling Patterns

Robust error handling is critical for operational reliability:

```python
from enum import Enum
from typing import Union


class OperationStatus(Enum):
    """Possible operation outcomes."""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    UNREACHABLE = "unreachable"
    ERROR = "error"


@dataclass
class OperationResult:
    """Result with detailed error information."""
    status: OperationStatus
    data: Optional[Any] = None
    error_message: Optional[str] = None
    error_code: Optional[int] = None


class RobustOperation:
    """Operation with comprehensive error handling."""

    def execute(self, target: str) -> OperationResult:
        """Execute operation with structured error handling."""
        try:
            result = self._perform_operation(target)
            return OperationResult(
                status=OperationStatus.SUCCESS,
                data=result
            )
        except socket.timeout:
            return OperationResult(
                status=OperationStatus.TIMEOUT,
                error_message=f"Connection timed out: {target}"
            )
        except ConnectionRefusedError:
            return OperationResult(
                status=OperationStatus.REFUSED,
                error_message=f"Connection refused: {target}"
            )
        except OSError as e:
            if e.errno == errno.ENETUNREACH:
                return OperationResult(
                    status=OperationStatus.UNREACHABLE,
                    error_message=f"Network unreachable: {target}",
                    error_code=e.errno
                )
            return OperationResult(
                status=OperationStatus.ERROR,
                error_message=str(e),
                error_code=e.errno
            )
        except Exception as e:
            return OperationResult(
                status=OperationStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}"
            )
```

### 5.3 Operational Security Considerations

#### In-Memory Operations

```python
class SecureResultStorage:
    """In-memory storage with secure cleanup."""

    def __init__(self):
        self._results = []
        self._lock = threading.Lock()

    def add(self, result: Result) -> None:
        """Add result to secure storage."""
        with self._lock:
            self._results.append(result)

    def get_all(self) -> List[Result]:
        """Get all results (returns copy)."""
        with self._lock:
            return self._results.copy()

    def clear(self) -> None:
        """Securely clear all results."""
        with self._lock:
            # Overwrite data before clearing
            for i in range(len(self._results)):
                self._results[i] = None
            self._results.clear()

    def __del__(self):
        """Ensure cleanup on destruction."""
        self.clear()
```

#### Credential Handling

```python
@dataclass
class Credential:
    """Secure credential container."""
    username: str
    password: str
    domain: Optional[str] = None

    def clear(self) -> None:
        """Securely overwrite credential data."""
        self.username = "x" * len(self.username)
        self.password = "x" * len(self.password)
        if self.domain:
            self.domain = "x" * len(self.domain)

    def __repr__(self) -> str:
        """Prevent accidental password exposure in logs."""
        domain_str = f"{self.domain}\\" if self.domain else ""
        return f"{domain_str}{self.username}:********"
```

### 5.4 Stealth and Evasion in Tool Design

Tools should minimize their detection footprint:

```python
class StealthConfig:
    """Configuration for stealth operations."""

    # Timing controls
    delay_min: float = 0.5
    delay_max: float = 2.0

    # Traffic shaping
    randomize_order: bool = True
    max_concurrent: int = 3

    # Identification masking
    user_agent_rotation: bool = True
    source_port_randomization: bool = True


class StealthyOperations:
    """Operations optimized for stealth."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ]

    def __init__(self, config: StealthConfig):
        self.config = config

    def get_random_user_agent(self) -> str:
        """Return random user agent string."""
        return random.choice(self.USER_AGENTS)

    def randomize_target_order(self, targets: List[str]) -> List[str]:
        """Randomize target order to avoid sequential patterns."""
        shuffled = targets.copy()
        random.shuffle(shuffled)
        return shuffled

    def create_socket_with_random_source(self) -> socket.socket:
        """Create socket with randomized source port."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to random high port
        sock.bind(('', random.randint(49152, 65535)))
        return sock
```

---

## 6. Case Studies

### 6.1 Network Scanner Architecture Breakdown

The network scanner demonstrates the full CPTC11 architecture pattern:

```
+------------------------------------------------------------------+
|                    NETWORK SCANNER ARCHITECTURE                   |
+------------------------------------------------------------------+
|                                                                   |
|  CLI Layer (argparse)                                             |
|  +------------------------------------------------------------+  |
|  | parse_arguments() -> Namespace                              |  |
|  | - Defines all command-line options                          |  |
|  | - Handles --plan flag routing                               |  |
|  +------------------------------------------------------------+  |
|                               |                                   |
|                               v                                   |
|  Configuration Layer (dataclass)                                  |
|  +------------------------------------------------------------+  |
|  | ScanConfig                                                  |  |
|  | - targets: List[str]                                        |  |
|  | - timeout, threads, delays                                  |  |
|  | - scan_methods: List[str]                                   |  |
|  | - plan_mode: bool                                           |  |
|  +------------------------------------------------------------+  |
|                               |                                   |
|              +----------------+----------------+                   |
|              |                                 |                   |
|              v                                 v                   |
|  +-------------------+              +-------------------+         |
|  | print_plan()      |              | NetworkScanner    |         |
|  | - Preview actions |              | - Executes scan   |         |
|  | - Risk assessment |              | - Thread pool     |         |
|  | - NO NETWORK OPS  |              | - Result collect  |         |
|  +-------------------+              +-------------------+         |
|                                                |                   |
|                                                v                   |
|  Technique Layer (abstract base class)                            |
|  +------------------------------------------------------------+  |
|  | ScanTechnique (ABC)                                         |  |
|  |   +-- TCPConnectScan   (full TCP handshake)                |  |
|  |   +-- ARPScan          (local network, requires privs)      |  |
|  |   +-- DNSResolutionScan (reverse DNS lookups)               |  |
|  +------------------------------------------------------------+  |
|                               |                                   |
|                               v                                   |
|  Result Layer (dataclass)                                         |
|  +------------------------------------------------------------+  |
|  | ScanResult                                                  |  |
|  | - ip, is_alive, response_time                               |  |
|  | - method, hostname, timestamp                               |  |
|  | - to_dict() for JSON serialization                          |  |
|  +------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

**Key Design Decisions:**

1. **Target Expansion:** Supports CIDR (/24), ranges (1-254), and individual IPs through the `_expand_targets()` generator, enabling memory-efficient iteration over large target sets.

2. **Technique Registry:** The `TECHNIQUES` dictionary maps method names to classes, enabling runtime technique selection without conditional logic in the scanner core.

3. **Thread Safety:** The `_lock` protects result collection, while `_stop_event` enables graceful cancellation across all worker threads.

4. **Jitter Application:** Random delays applied before each scan reduce temporal patterns that IDS systems detect.

### 6.2 Credential Validator Design Decisions

The credential validator showcases protocol abstraction and secure data handling:

```
+------------------------------------------------------------------+
|                 CREDENTIAL VALIDATOR ARCHITECTURE                 |
+------------------------------------------------------------------+
|                                                                   |
|  Protocol Abstraction                                             |
|  +------------------------------------------------------------+  |
|  | ProtocolValidator (ABC)                                     |  |
|  |   @property name -> str                                     |  |
|  |   @property default_port -> int                             |  |
|  |   validate(target, port, credential, config) -> Result     |  |
|  +------------------------------------------------------------+  |
|              |                                                    |
|              +-- SSHValidator (port 22)                          |
|              +-- FTPValidator (port 21)                          |
|              +-- HTTPBasicValidator (port 80/443)                |
|              +-- HTTPFormValidator (port 80/443)                 |
|              +-- SMTPValidator (port 25)                         |
|              +-- MySQLValidator (port 3306)                      |
|                                                                   |
|  Credential Security                                              |
|  +------------------------------------------------------------+  |
|  | @dataclass Credential                                       |  |
|  |   username: str                                             |  |
|  |   password: str                                             |  |
|  |   domain: Optional[str]                                     |  |
|  |                                                             |  |
|  |   def clear(self):                                          |  |
|  |       # Overwrite sensitive data                            |  |
|  |       self.password = "x" * len(self.password)              |  |
|  |                                                             |  |
|  |   def __repr__(self):                                       |  |
|  |       # Never expose password in logs                       |  |
|  |       return f"{self.username}:********"                    |  |
|  +------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

**Security-First Design:**

1. **Password Masking:** The `__repr__` method ensures passwords never appear in logs, stack traces, or debug output.

2. **Secure Cleanup:** The `clear()` method overwrites sensitive data before garbage collection, reducing memory exposure windows.

3. **Stop on Success:** The `stop_on_success` option prevents unnecessary authentication attempts after finding valid credentials, reducing detection risk and account lockout probability.

4. **Lockout Awareness:** Planning mode warns about lockout risks based on credential count and delay settings.

### 6.3 EDR Evasion Toolkit Complexity Management

The EDR evasion toolkit demonstrates how to organize complex, multi-technique tools:

```
+------------------------------------------------------------------+
|               EDR EVASION TOOLKIT ORGANIZATION                    |
+------------------------------------------------------------------+
|                                                                   |
|  Technique Categories (Enum)                                      |
|  +------------------------------------------------------------+  |
|  | TechniqueCategory                                           |  |
|  |   DIRECT_SYSCALLS     - Bypass user-mode hooks              |  |
|  |   UNHOOKING           - Remove EDR hooks                    |  |
|  |   MEMORY_EVASION      - Hide in memory                      |  |
|  |   API_HASHING         - Avoid string detection              |  |
|  |   CALLBACK_MANIPULATION - Kernel callbacks                   |  |
|  |   ETW_BYPASS          - Event tracing bypass                |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Technique Definition (dataclass)                                 |
|  +------------------------------------------------------------+  |
|  | EvasionTechnique                                            |  |
|  |   name: str                                                 |  |
|  |   category: TechniqueCategory                               |  |
|  |   description: str                                          |  |
|  |   code_concept: str        # Educational pseudocode         |  |
|  |   detection_methods: List  # How defenders detect           |  |
|  |   mitigations: List        # Defensive countermeasures      |  |
|  |   mitre_technique: str     # ATT&CK mapping                 |  |
|  |   risk_level: RiskLevel                                     |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  Component Classes                                                |
|  +------------------------------------------------------------+  |
|  | DirectSyscallGenerator                                      |  |
|  |   - Generates x64/x86 syscall stubs                         |  |
|  |   - Maintains syscall number database                       |  |
|  |   - Documents which EDRs hook which calls                   |  |
|  +------------------------------------------------------------+  |
|  | UnhookingTechniques                                         |  |
|  |   - Full DLL unhooking concepts                             |  |
|  |   - Syscall stub restoration                                |  |
|  |   - Perun's Fart technique                                  |  |
|  +------------------------------------------------------------+  |
|  | MemoryEvasionTechniques                                     |  |
|  |   - Module stomping                                         |  |
|  |   - Sleep encryption                                        |  |
|  |   - No-RWX approaches                                       |  |
|  +------------------------------------------------------------+  |
|  | APIHashingTechniques                                        |  |
|  |   - DJB2 hash generation                                    |  |
|  |   - ROR13 hash generation                                   |  |
|  |   - Hash table creation                                     |  |
|  +------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

**Educational Focus:**

This toolkit emphasizes concepts over implementation. Each technique includes:

1. **Code Concept:** Pseudocode explaining the approach
2. **Detection Methods:** How defenders identify the technique
3. **Mitigations:** Defensive countermeasures
4. **MITRE Mapping:** ATT&CK technique identifiers

This approach ensures the tool educates operators about both offensive capabilities and defensive awareness.

---

## Appendix A: Complete Tool Inventory

The CPTC11 framework includes 15 Python tools organized by operational phase:

| Tool | Category | Key Patterns Demonstrated |
|------|----------|---------------------------|
| network-scanner | Reconnaissance | Target expansion, technique abstraction |
| port-scanner | Reconnaissance | Port parsing, banner grabbing |
| service-fingerprinter | Reconnaissance | Service identification |
| web-directory-enumerator | Web Testing | Wordlist processing |
| credential-validator | Credential Ops | Protocol abstraction, secure credential handling |
| dns-enumerator | Reconnaissance | DNS record types |
| smb-enumerator | Network Utils | SMB protocol handling |
| http-request-tool | Network Utils | HTTP client patterns |
| hash-cracker | Credential Ops | Algorithm selection |
| reverse-shell-handler | Post-Exploitation | Multi-listener management |
| payload-generator | Exploitation | Template pattern |
| process-hollowing | Evasion | Windows internals |
| amsi-bypass | Evasion | Security product interaction |
| shellcode-encoder | Exploitation | Encoding chains |
| edr-evasion-toolkit | Evasion | Technique organization |

---

## Appendix B: Quick Reference Card

### Standard CLI Patterns

```bash
# All tools support these common flags:
--plan       # Preview execution without action
--verbose    # Detailed output
--output     # JSON output file
--help       # Usage information

# Example usage pattern:
python tool.py <targets> [options]
python tool.py 192.168.1.0/24 --plan  # Always preview first
```

### Dataclass Template

```python
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class ToolConfig:
    """Standard configuration template."""
    targets: List[str] = field(default_factory=list)
    timeout: float = 2.0
    threads: int = 10
    verbose: bool = False
    plan_mode: bool = False


@dataclass
class ToolResult:
    """Standard result template."""
    target: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "success": self.success,
            "data": self.data,
            "timestamp": self.timestamp.isoformat()
        }
```

### Abstract Technique Template

```python
from abc import ABC, abstractmethod


class Technique(ABC):
    """Standard technique template."""

    @abstractmethod
    def execute(self, target: str, config: ToolConfig) -> ToolResult:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass
```

---

## Conclusion

This curriculum has presented a comprehensive framework for developing professional-grade offensive security tools. The architectural patterns demonstrated here--abstract base classes, dataclass configurations, the `--plan` flag pattern, and documentation hooks--represent battle-tested approaches that balance capability with responsibility.

Remember: the tools we build reflect our values as security professionals. Build tools that educate, document their impacts, and respect the ethical boundaries of our profession.

---

**Document Information**

- **Created:** 2026-01-10
- **Author:** Offensive Security Training Specialist
- **Version:** 1.0
- **Word Count:** Approximately 5,800 words (body content)
- **Target Audience:** Intermediate to Advanced Security Practitioners

**DISCLAIMER:** This curriculum is intended for authorized security testing, penetration testing engagements, and educational purposes only. The techniques and tools described herein should only be used with proper authorization. Unauthorized access to computer systems is illegal.
