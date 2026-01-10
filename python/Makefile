# CPTC11 Python Project Makefile
# =================================
# This Makefile provides convenient targets for linting, testing, and development

.PHONY: help lint lint-fix lint-check format test test-unit test-fuzz test-integration coverage clean install

# Default target
help:
	@echo "CPTC11 Python Project - Available Targets"
	@echo "=========================================="
	@echo ""
	@echo "Linting:"
	@echo "  lint          - Run ruff linter and show all issues"
	@echo "  lint-fix      - Run ruff linter and auto-fix issues"
	@echo "  lint-check    - Run ruff linter in check mode (CI-friendly)"
	@echo "  format        - Format code with ruff formatter"
	@echo "  format-check  - Check code formatting without changes"
	@echo ""
	@echo "Testing:"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-fuzz     - Run fuzz tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-fast     - Run tests excluding slow tests"
	@echo "  coverage      - Run tests with coverage report"
	@echo ""
	@echo "Development:"
	@echo "  install       - Install development dependencies"
	@echo "  install-test  - Install test dependencies"
	@echo "  clean         - Remove build artifacts and caches"
	@echo "  check-all     - Run lint-check and test (for CI)"
	@echo ""

# =============================================================================
# Linting Targets
# =============================================================================

# Run ruff linter and show all issues
lint:
	@echo "Running ruff linter..."
	ruff check . --output-format=text
	@echo ""
	@echo "Running ruff format check..."
	ruff format --check --diff .

# Run ruff linter and auto-fix issues
lint-fix:
	@echo "Running ruff linter with auto-fix..."
	ruff check . --fix
	@echo ""
	@echo "Running ruff formatter..."
	ruff format .
	@echo "Done! Fixed issues and formatted code."

# Run ruff linter in check mode (returns non-zero on issues)
lint-check:
	@echo "Running ruff linter (check mode)..."
	ruff check . --output-format=github
	ruff format --check .

# Format code with ruff
format:
	@echo "Formatting code with ruff..."
	ruff format .
	@echo "Done!"

# Check code formatting without making changes
format-check:
	@echo "Checking code format..."
	ruff format --check --diff .

# =============================================================================
# Testing Targets
# =============================================================================

# Run all tests
test:
	@echo "Running all tests..."
	python -m pytest tests/ -v

# Run unit tests only (excluding integration and fuzz)
test-unit:
	@echo "Running unit tests..."
	python -m pytest tests/ -v -m "not integration and not fuzz and not slow"

# Run fuzz tests only
test-fuzz:
	@echo "Running fuzz tests..."
	python -m pytest tests/fuzz/ -v -m "fuzz" --hypothesis-show-statistics

# Run integration tests only
test-integration:
	@echo "Running integration tests..."
	python -m pytest tests/integration/ -v -m "integration"

# Run tests excluding slow tests
test-fast:
	@echo "Running fast tests..."
	python -m pytest tests/ -v -m "not slow"

# Run tests with coverage report
coverage:
	@echo "Running tests with coverage..."
	python -m pytest tests/ -v --cov=tools --cov=tui --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "Coverage report generated in htmlcov/"

# =============================================================================
# Development Targets
# =============================================================================

# Install development dependencies
install:
	pip install -e .
	pip install -r requirements-test.txt

# Install test dependencies only
install-test:
	pip install -r requirements-test.txt

# Remove build artifacts and caches
clean:
	@echo "Cleaning build artifacts..."
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf htmlcov
	rm -rf .coverage
	rm -rf *.egg-info
	rm -rf build
	rm -rf dist
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@echo "Done!"

# Run all checks (for CI)
check-all: lint-check test
	@echo "All checks passed!"

# =============================================================================
# Quick Shortcuts
# =============================================================================

# Alias for common operations
l: lint
lf: lint-fix
t: test
c: coverage
