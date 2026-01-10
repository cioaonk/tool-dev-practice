# CPTC11 Security Framework

A multi-agent developed penetration testing toolkit built for comprehensive security assessments and authorized red team operations.

## Description

The CPTC11 Security Framework is an advanced penetration testing toolkit developed through a coordinated multi-agent system. This project demonstrates the collaborative capabilities of specialized AI agents working together to create a comprehensive security assessment platform.

The framework provides:
- A complete suite of reconnaissance, exploitation, and post-exploitation tools
- Cross-platform support through Python implementations with Golang ports
- A modern Terminal User Interface (TUI) for streamlined tool management
- Comprehensive testing including property-based fuzzing
- Extensive documentation and operational security considerations

**DISCLAIMER**: This toolkit is intended solely for authorized security testing, penetration testing engagements, and educational purposes. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical.

## Features

- **15 Python Security Tools** - Complete toolkit covering reconnaissance through post-exploitation
- **10 Golang Conversions** - High-performance cross-platform ports of Phase 1 tools
- **Full TUI Interface** - Textual-based terminal UI for tool management and execution
- **Comprehensive Test Suite** - Unit tests, integration tests, and Hypothesis-based fuzz testing
- **Planning Mode** - All tools support `--plan` flag to preview actions without execution
- **In-Memory Operations** - Results stored in memory to minimize disk artifacts
- **JSON Output Support** - Machine-readable output for tool chaining and automation
- **Documentation Hooks** - Built-in documentation accessible via `get_documentation()` functions

## Directory Structure

```
/Users/ic/cptc11/
|-- README.md                           # This file
|-- .gitignore                          # Git ignore rules
|-- conversion_log.txt                  # Python-to-Golang conversion tracking
|
|-- python/                             # Python source code
|   |-- pyproject.toml                  # Project configuration (ruff, pytest, coverage)
|   |-- Makefile                        # Build automation (lint, test, coverage)
|   |-- requirements-test.txt           # Test dependencies
|   |-- run_tui.py                      # TUI launcher script
|   |-- LINTING.md                      # Linting documentation
|   |
|   |-- tools/                          # Security tools (15 total)
|   |   |-- network-scanner/            # Phase 1: Reconnaissance
|   |   |-- port-scanner/
|   |   |-- service-fingerprinter/
|   |   |-- web-directory-enumerator/
|   |   |-- credential-validator/
|   |   |-- dns-enumerator/
|   |   |-- smb-enumerator/
|   |   |-- http-request-tool/
|   |   |-- hash-cracker/
|   |   |-- reverse-shell-handler/
|   |   |-- payload-generator/          # Phase 2: Advanced
|   |   |-- process-hollowing/
|   |   |-- amsi-bypass/
|   |   |-- shellcode-encoder/
|   |   |-- edr-evasion-toolkit/
|   |   |-- environment/                # Environment setup utilities
|   |
|   |-- tui/                            # Terminal User Interface
|   |   |-- app.py                      # Main TUI application
|   |   |-- __main__.py                 # Module entry point
|   |   |-- screens/                    # TUI screens (dashboard, tool_config)
|   |   |-- widgets/                    # TUI widgets (tool_panel, output_viewer, status_bar)
|   |   |-- visualizers/                # Attack visualization components
|   |   |-- styles/                     # TCSS stylesheets
|   |   |-- utils/                      # Helper utilities
|   |
|   |-- tests/                          # Test suite
|   |   |-- conftest.py                 # Pytest fixtures
|   |   |-- pytest.ini                  # Pytest configuration
|   |   |-- fuzz/                       # Fuzz tests (Hypothesis)
|   |   |   |-- test_fuzz_url_inputs.py
|   |   |   |-- test_fuzz_port_inputs.py
|   |   |   |-- test_fuzz_network_inputs.py
|   |   |-- integration/                # Integration tests
|
|-- golang/                             # Golang conversions
|   |-- file_info.go                    # Utility conversion
|   |-- tools/                          # Converted tools (10 total)
|       |-- network-scanner/scanner.go
|       |-- port-scanner/scanner.go
|       |-- service-fingerprinter/fingerprinter.go
|       |-- web-directory-enumerator/enumerator.go
|       |-- credential-validator/validator.go
|       |-- dns-enumerator/enumerator.go
|       |-- smb-enumerator/enumerator.go
|       |-- http-request-tool/httptool.go
|       |-- hash-cracker/cracker.go
|       |-- reverse-shell-handler/handler.go
|
|-- agent_reports/                      # Multi-agent coordination reports
|   |-- PROJECT_STATUS.md               # Master status dashboard
|   |-- converter_report.md             # Python-to-Golang agent reports
|   |-- toolsmith_report.md             # Offensive toolsmith agent reports
|   |-- qa_report.md                    # QA tester agent reports
|   |-- tui_report.md                   # TUI developer agent reports
|
|-- .claude/                            # Agent configurations
    |-- agents/                         # Individual agent configs
        |-- python-to-golang-converter.md
        |-- offensive-security-toolsmith.md
        |-- project-coordinator.md
        |-- qa-tester.md
        |-- ux-tui-developer.md
        |-- usage-reporter.md
```

## Tools List

### Phase 1: Core Security Tools

| Tool | Category | Description | Golang Port |
|------|----------|-------------|-------------|
| **network-scanner** | Reconnaissance | Multi-method network host discovery (TCP, ARP, DNS) with CIDR support | Yes |
| **port-scanner** | Reconnaissance | Configurable port scanner with service detection | Yes |
| **service-fingerprinter** | Reconnaissance | Service and version identification through banner grabbing | Yes |
| **web-directory-enumerator** | Web Testing | Directory and file enumeration with wordlist support | Yes |
| **credential-validator** | Credential Ops | Credential validation against multiple protocols | Yes |
| **dns-enumerator** | Reconnaissance | DNS record enumeration and zone transfer testing | Yes |
| **smb-enumerator** | Network Utils | SMB share and user enumeration | Yes |
| **http-request-tool** | Network Utils | Flexible HTTP client for manual testing | Yes |
| **hash-cracker** | Credential Ops | Multi-algorithm hash cracking with wordlist support | Yes |
| **reverse-shell-handler** | Post-Exploitation | Multi-listener reverse shell handler | Yes |

### Phase 2: Advanced Offensive Tools

| Tool | Category | Description | Golang Port |
|------|----------|-------------|-------------|
| **payload-generator** | Exploitation | Modular payload generator (reverse/bind/web shells) | Planned |
| **process-hollowing** | Evasion | Process hollowing implementation for code injection | Planned |
| **amsi-bypass** | Evasion | AMSI bypass techniques for Windows environments | Planned |
| **shellcode-encoder** | Exploitation | Shellcode encoding and obfuscation | Planned |
| **edr-evasion-toolkit** | Evasion | EDR/AV evasion techniques and testing | Planned |

## Installation

### Prerequisites

- Python 3.8 or higher
- Go 1.19 or higher (for Golang tools)
- pip package manager

### Quick Start

```bash
# Clone the repository
git clone https://github.com/cioaonk/tool-dev-practice.git
cd cptc11

# Install Python dependencies
cd python
pip install -r requirements-test.txt

# Install TUI dependencies
pip install textual>=0.40.0 rich>=13.0.0

# (Optional) Build Golang tools
cd ../golang/tools/network-scanner
go build -o scanner scanner.go
```

### Development Installation

```bash
cd python

# Install all dependencies including dev tools
make install

# Or manually
pip install -e .
pip install -r requirements-test.txt
```

## Usage

### Python Tools

Each tool supports a consistent CLI interface:

```bash
# Basic usage
python python/tools/network-scanner/tool.py 192.168.1.0/24

# Planning mode - preview actions without execution
python python/tools/network-scanner/tool.py 192.168.1.0/24 --plan

# Verbose output
python python/tools/network-scanner/tool.py 192.168.1.0/24 -v

# JSON output for automation
python python/tools/network-scanner/tool.py 192.168.1.0/24 --json

# Get tool documentation
python python/tools/network-scanner/tool.py --doc
```

### Common Tool Examples

```bash
# Network scanning
python python/tools/network-scanner/tool.py 10.0.0.0/24 --methods tcp,dns --threads 20

# Port scanning
python python/tools/port-scanner/tool.py 192.168.1.1 --ports 1-1000 --fast

# Web directory enumeration
python python/tools/web-directory-enumerator/tool.py https://target.com --wordlist common.txt

# Payload generation (review plan first)
python python/tools/payload-generator/payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --plan

# Hash cracking
python python/tools/hash-cracker/tool.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
```

### Golang Tools

```bash
# Build and run network scanner
cd golang/tools/network-scanner
go build -o scanner scanner.go
./scanner 192.168.1.0/24 --plan
./scanner 192.168.1.1-254 -m tcp,dns -T 10
```

## Testing

### Running Tests

```bash
cd python

# Run all tests
make test
# or
python -m pytest tests/ -v

# Run unit tests only (fast)
make test-unit

# Run fuzz tests with statistics
make test-fuzz
# or
python -m pytest tests/fuzz/ -v -m "fuzz" --hypothesis-show-statistics

# Run integration tests
make test-integration

# Run fast tests (excluding slow)
make test-fast

# Run with coverage report
make coverage
# or
python -m pytest tests/ -v --cov=tools --cov=tui --cov-report=term-missing --cov-report=html
```

### Test Markers

Tests are organized with pytest markers:

```bash
# Run only smoke tests
pytest -m smoke

# Run security-focused tests
pytest -m security

# Exclude slow tests
pytest -m "not slow"

# Run regression tests
pytest -m regression
```

### Linting

```bash
cd python

# Check for issues
make lint

# Auto-fix issues and format
make lint-fix

# CI-friendly check (returns non-zero on issues)
make lint-check

# Format only
make format
```

## TUI

The framework includes a full-featured Terminal User Interface built with Textual.

### Launching the TUI

```bash
cd python

# Run with dependency check
python run_tui.py

# Or run directly
python -m tui
```

### TUI Features

- **Dashboard View**: Overview of all available tools
- **Tool Panel**: Browse and select tools by category
- **Output Viewer**: Real-time tool output with color-coded log levels
- **Attack Visualizer**: Visual representation of attack progress
- **Configuration Screen**: Parameter configuration for each tool
- **Keyboard Shortcuts**:
  - `q` or `Ctrl+Q`: Quit
  - `h`: Toggle help
  - `r`: Refresh display
  - `c`: Clear output
  - `Ctrl+D`: Toggle dark mode

### TUI Dependencies

```bash
pip install textual>=0.40.0 rich>=13.0.0
```

## Contributing

This project was developed using a multi-agent coordination system with specialized AI agents:

- **Project Coordinator Agent**: Task orchestration and reporting
- **Offensive Tool Toolsmith Agent**: Security tool development
- **Python-to-Golang Agent**: Cross-platform conversions
- **QA Tester Agent**: Test development and execution
- **UX TUI Developer Agent**: Terminal interface development
- **Documentation Agent**: Technical documentation

### Agent-Driven Development

The project follows an agent-driven development model where:

1. Tasks are coordinated through the Project Coordinator
2. Specialized agents handle domain-specific work
3. Progress is tracked via periodic reports in `agent_reports/`
4. Cross-agent dependencies are managed through coordination notes

### Manual Contributions

When contributing manually:

1. Follow the existing code style (enforced by ruff)
2. Include tests for new functionality
3. Support planning mode (`--plan`) for all tools
4. Implement `get_documentation()` hooks
5. Update relevant documentation
6. Ensure CI checks pass (`make check-all`)

## Operational Security Considerations

- All tools support planning mode to preview actions
- Results are stored in-memory by default to minimize disk artifacts
- Configurable delays and jitter for stealth operations
- JSON output for automated integration
- Each tool documents its detection vectors

## License

MIT License

Copyright (c) 2026 CPTC11 Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

**IMPORTANT**: This toolkit is provided for authorized security testing only. Always obtain proper written authorization before conducting any security assessments. The authors are not responsible for any misuse of this software.
