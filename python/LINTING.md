# CPTC11 Python Linting Standards

This document describes the linting configuration and standards for the CPTC11 Python codebase.

## Overview

We use **Ruff** as our primary linting tool. Ruff is a fast Python linter written in Rust that combines the functionality of multiple tools (flake8, isort, pyupgrade, and more) into a single, unified tool.

## Quick Start

```bash
# Install ruff
pip install ruff

# Run linter
make lint

# Auto-fix issues
make lint-fix

# Check formatting
make format-check

# Format code
make format
```

## Enabled Rule Categories

The following rule categories are enabled in our configuration:

| Code | Category | Description |
|------|----------|-------------|
| E | pycodestyle errors | Style errors |
| W | pycodestyle warnings | Style warnings |
| F | Pyflakes | Logical errors, undefined names |
| I | isort | Import sorting |
| N | pep8-naming | Naming conventions |
| B | flake8-bugbear | Common bugs and design problems |
| C4 | flake8-comprehensions | Comprehension improvements |
| S | flake8-bandit | Security issues |
| UP | pyupgrade | Python version upgrades |
| SIM | flake8-simplify | Code simplification |
| TID | flake8-tidy-imports | Import hygiene |
| RUF | Ruff-specific | Ruff's own rules |

## Ignored Rules

Some rules are intentionally ignored for our security tooling context:

### Security Tool Exceptions
- **S104**: Binding to all interfaces (intentional for network tools)
- **S105/S106/S107**: Hardcoded passwords (false positives in credential testing tools)
- **S311**: Pseudo-random generators (acceptable for jitter/delays)
- **S603/S607**: Subprocess calls (necessary for some tools)

### General Exceptions
- **E501**: Line length (handled by formatter)
- **S101**: Assert in tests (valid for test code)
- **B008**: Function calls in defaults (used in dataclasses)

## Per-File Ignores

Different files have different requirements:

### Test Files
Test files (`tests/**/*.py`, `test_*.py`) are allowed:
- Assertions (`S101`)
- Magic values (`PLR2004`)
- `assert False` (`B011`)

### Tool Files
Tool files in the `tools/` directory have relaxed security rules since they are intentionally security-focused tools.

## Code Style Standards

### Imports
```python
# Standard library imports first
import os
import sys

# Third-party imports
import pytest
from hypothesis import given

# Local imports
from tools.network_scanner import NetworkScanner
```

### Line Length
- Maximum line length: 100 characters
- Ruff formatter will handle line wrapping automatically

### Quotes
- Use double quotes for strings: `"string"`
- Single quotes are acceptable for dict keys and short strings

### Naming Conventions
- Functions and variables: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private methods/variables: `_leading_underscore`

### Type Hints
Recommended but not enforced:
```python
def process_target(target: str, timeout: float = 1.0) -> bool:
    ...
```

## Running Lint Checks

### Local Development
```bash
# See all issues
make lint

# Auto-fix what can be fixed
make lint-fix

# Just check (CI mode)
make lint-check
```

### Pre-commit (Recommended)
Add to your workflow:
```bash
# Before committing
make lint-fix

# Or just check
make lint-check
```

### CI/CD Integration
The `lint-check` target returns non-zero on errors, suitable for CI:
```yaml
# Example GitHub Actions
- name: Lint
  run: make lint-check
```

## Common Issues and Fixes

### Import Sorting
```bash
# Before (wrong)
from typing import List
import os

# After (correct - ruff will fix)
import os
from typing import List
```

### Unused Imports
```python
# Ruff will flag and can auto-remove unused imports
import json  # F401: unused import
```

### Security Issues
```python
# S105: Hardcoded password - ignore in credential tools
password = "admin123"  # noqa: S105
```

### f-string vs format
```python
# Before
"Hello {}".format(name)

# After (UP032)
f"Hello {name}"
```

## Suppressing Warnings

### Single Line
```python
x = eval(user_input)  # noqa: S307
```

### Specific Rule
```python
password = "test"  # noqa: S105
```

### Multiple Rules
```python
result = eval(data)  # noqa: S307, S102
```

### File-Level
Add to the top of the file:
```python
# ruff: noqa: S105
```

## Configuration

All configuration is in `pyproject.toml`. Key sections:

```toml
[tool.ruff]
target-version = "py38"
line-length = 100

[tool.ruff.lint]
select = ["E", "W", "F", ...]
ignore = ["E501", ...]
```

## IDE Integration

### VS Code
Install the "Ruff" extension and add to settings:
```json
{
    "editor.formatOnSave": true,
    "[python]": {
        "editor.defaultFormatter": "charliermarsh.ruff"
    }
}
```

### PyCharm
Use the Ruff plugin or configure as external tool.

## Updating Rules

To add or modify rules:
1. Edit `pyproject.toml`
2. Run `make lint` to verify
3. Run `make lint-fix` to apply changes
4. Update this document if adding new exceptions

## Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [Ruff Rules Reference](https://docs.astral.sh/ruff/rules/)
- [pyproject.toml Configuration](https://docs.astral.sh/ruff/configuration/)
