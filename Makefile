# CPTC11 Development Makefile
# ============================
# This Makefile provides convenient commands that mirror the CI/CD workflows.
# Use these commands locally before pushing to ensure CI passes.

.PHONY: help install test test-unit test-integration test-fuzz lint lint-fix format build-go vet-go clean

# Default target
help:
	@echo "CPTC11 Development Commands"
	@echo "==========================="
	@echo ""
	@echo "Python Commands:"
	@echo "  make install          - Install Python dependencies"
	@echo "  make test             - Run all Python tests (excluding fuzz)"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-integration - Run integration tests"
	@echo "  make test-fuzz        - Run fuzz tests (5 minute limit)"
	@echo "  make test-coverage    - Run tests with coverage report"
	@echo "  make lint             - Run ruff linter"
	@echo "  make lint-fix         - Fix auto-fixable lint issues"
	@echo "  make format           - Format code with ruff"
	@echo "  make format-check     - Check code formatting"
	@echo ""
	@echo "Go Commands:"
	@echo "  make build-go         - Build all Go files"
	@echo "  make vet-go           - Run go vet on all Go files"
	@echo "  make fmt-go           - Format Go code"
	@echo "  make fmt-go-check     - Check Go formatting"
	@echo ""
	@echo "CI Commands (mirror GitHub Actions):"
	@echo "  make ci               - Run full CI suite locally"
	@echo "  make ci-python        - Run Python CI checks"
	@echo "  make ci-go            - Run Go CI checks"
	@echo ""
	@echo "Other:"
	@echo "  make clean            - Remove build artifacts"

# =============================================================================
# Python Commands
# =============================================================================

# Install Python test dependencies
install:
	cd python && pip install -r requirements-test.txt

# Run all tests (excluding slow fuzz tests)
test:
	cd python && pytest tests/ \
		--ignore=tests/fuzz/ \
		-v \
		--tb=short \
		--timeout=60

# Run unit tests only
test-unit:
	cd python && pytest tests/ \
		--ignore=tests/fuzz/ \
		--ignore=tests/integration/ \
		-v \
		--tb=short \
		--timeout=60

# Run integration tests
test-integration:
	cd python && pytest tests/integration/ \
		-v \
		--tb=short \
		--timeout=120 \
		-m "integration"

# Run fuzz tests with 5 minute limit
test-fuzz:
	cd python && timeout 300 pytest tests/fuzz/ \
		-v \
		--tb=short \
		-m "fuzz" \
		--timeout=300 \
		|| true

# Run tests with coverage report
test-coverage:
	cd python && pytest tests/ \
		--ignore=tests/fuzz/ \
		--cov=tools \
		--cov=tui \
		--cov-report=html \
		--cov-report=term-missing \
		-v \
		--tb=short

# Run ruff linter
lint:
	cd python && ruff check .

# Fix auto-fixable lint issues
lint-fix:
	cd python && ruff check --fix .

# Format code with ruff
format:
	cd python && ruff format .

# Check code formatting
format-check:
	cd python && ruff format --check .

# =============================================================================
# Go Commands
# =============================================================================

# Build all Go files
build-go:
	@echo "Building Go files..."
	cd golang && go build -v -o file_info file_info.go
	@for dir in golang/tools/*/; do \
		if [ -d "$$dir" ]; then \
			tool_name=$$(basename "$$dir"); \
			echo "Building $$tool_name..."; \
			for gofile in $$dir*.go; do \
				if [ -f "$$gofile" ]; then \
					go build -v -o "$$dir$$tool_name" "$$gofile" 2>/dev/null || true; \
				fi \
			done \
		fi \
	done
	@echo "Build complete!"

# Run go vet on all Go files
vet-go:
	@echo "Running go vet..."
	cd golang && go vet file_info.go
	@for gofile in golang/tools/*/*.go; do \
		if [ -f "$$gofile" ]; then \
			echo "Vetting: $$gofile"; \
			go vet "$$gofile" || exit 1; \
		fi \
	done
	@echo "go vet passed!"

# Format Go code
fmt-go:
	cd golang && gofmt -w .

# Check Go formatting
fmt-go-check:
	@unformatted=$$(cd golang && gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo "Go formatting OK!"

# =============================================================================
# CI Commands (mirror GitHub Actions)
# =============================================================================

# Run full CI suite locally
ci: ci-python ci-go
	@echo ""
	@echo "=================================="
	@echo "All CI checks passed!"
	@echo "=================================="

# Run Python CI checks
ci-python: lint format-check test test-coverage
	@echo "Python CI checks passed!"

# Run Go CI checks
ci-go: build-go vet-go fmt-go-check
	@echo "Go CI checks passed!"

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf python/.pytest_cache
	rm -rf python/.coverage
	rm -rf python/htmlcov
	rm -rf python/.hypothesis
	rm -rf python/__pycache__
	rm -rf python/**/__pycache__
	rm -rf golang/file_info
	rm -rf golang/tools/*/network-scanner
	rm -rf golang/tools/*/port-scanner
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete!"
