# CPTC11 CI/CD Pipelines

This document describes the GitHub Actions workflows used in the CPTC11 Security Testing Toolkit project.

## Overview

The CI/CD pipeline consists of several workflows that handle testing, linting, security scanning, building, and releasing the project components.

```
+------------------+     +------------------+     +------------------+
|    tests.yml     |     |    lint.yml      |     |  go-build.yml    |
| (Python Tests)   |     | (Code Quality)   |     |  (Go Compile)    |
+------------------+     +------------------+     +------------------+
         |                       |                       |
         v                       v                       v
+------------------+     +------------------+     +------------------+
| security-scan.yml|     | docker-build.yml |     |network-validation|
| (Vuln Scanning)  |     | (Container Build)|     |  (.imn Files)    |
+------------------+     +------------------+     +------------------+
         |                       |                       |
         +----------+------------+-----------+-----------+
                    |                        |
                    v                        v
            +------------------+     +------------------+
            |   release.yml    |     | Branch Protection|
            | (Create Release) |     |   (Requires CI)  |
            +------------------+     +------------------+
```

## Workflows

### 1. Tests (`tests.yml`)

**Purpose:** Runs the Python test suite including unit tests, integration tests, and fuzz tests.

**Triggers:**
- Push to `main` or `master` branches
- Pull requests targeting `main` or `master`

**Jobs:**
| Job | Description | Timeout |
|-----|-------------|---------|
| `test` | Run pytest with coverage | 15 min |
| `lint` | Run ruff linting | 5 min |
| `fuzz` | Run Hypothesis fuzz tests | 20 min |
| `ci-success` | Aggregate job status | - |

**Key Features:**
- Coverage reporting with `pytest-cov`
- Hypothesis-based property testing
- Dependency caching for faster builds
- Concurrent run cancellation

**Required Secrets:** None

---

### 2. Lint (`lint.yml`)

**Purpose:** Provides fast feedback on code style and formatting issues.

**Triggers:**
- Push to `main`/`master` (Python files only)
- Pull requests (Python files only)

**Jobs:**
| Job | Description | Timeout |
|-----|-------------|---------|
| `ruff` | Code linting and format check | 5 min |
| `security-lint` | Security-focused linting (S rules) | 5 min |

**Configuration:** Uses `python/pyproject.toml` for ruff settings.

**Local Fix Commands:**
```bash
cd python
ruff format .        # Fix formatting
ruff check --fix .   # Fix linting issues
```

---

### 3. Go Build (`go-build.yml`)

**Purpose:** Compiles and validates all Go code in the `golang/` directory.

**Triggers:**
- Push to `main`/`master` (Go files only)
- Pull requests (Go files only)

**Jobs:**
| Job | Description | Timeout |
|-----|-------------|---------|
| `build` | Compile all Go files | 10 min |
| `vet` | Static analysis with `go vet` | 5 min |
| `fmt` | Format checking with `gofmt` | 5 min |
| `security` | Static analysis with `staticcheck` | 5 min |
| `go-ci-success` | Aggregate job status | - |

**Local Fix Commands:**
```bash
cd golang
gofmt -w .           # Fix formatting
go vet ./...         # Run static analysis
```

---

### 4. Security Scan (`security-scan.yml`)

**Purpose:** Identifies security vulnerabilities in code and dependencies.

**Triggers:**
- Push to `main`/`master`
- Pull requests
- Weekly schedule (Mondays 9 AM UTC)
- Manual dispatch

**Jobs:**
| Job | Description | Tools |
|-----|-------------|-------|
| `bandit` | Python static security analysis | bandit |
| `dependency-scan` | Dependency vulnerability check | pip-audit |
| `gosec` | Go security analysis | gosec |
| `secret-scan` | Secret detection in code | truffleHog |
| `security-summary` | Aggregate results | - |

**Artifacts Generated:**
- `bandit-results.json` - Bandit findings
- `pip-audit-results.json` - Dependency vulnerabilities
- `gosec-results.json` - Go security findings
- `trufflehog-results.json` - Detected secrets

**Note:** This project contains intentional security testing tools that may trigger findings.

---

### 5. Docker Build (`docker-build.yml`)

**Purpose:** Builds and tests Docker containers for the test lab environment.

**Triggers:**
- Push to `main`/`master` (Docker files only)
- Pull requests (Docker files only)
- Manual dispatch

**Jobs:**
| Job | Container | Description |
|-----|-----------|-------------|
| `build-vulnerable-web` | vulnerable-web | Intentionally vulnerable web app |
| `build-ftp-server` | ftp-server | FTP credential testing |
| `build-smtp-server` | smtp-server | SMTP testing server |
| `docker-summary` | - | Build results summary |

**Features:**
- Docker Buildx for efficient builds
- Trivy security scanning
- Health check verification
- GitHub Actions cache

**Warning:** These containers are intentionally insecure for testing purposes.

---

### 6. Release (`release.yml`)

**Purpose:** Creates GitHub releases with compiled artifacts.

**Triggers:**
- Push of version tags (`v*`)
- Manual dispatch with version input

**Jobs:**
| Job | Description |
|-----|-------------|
| `build-go` | Cross-compile Go binaries |
| `build-python` | Package Python tools |
| `build-networks` | Package network files |
| `create-release` | Create GitHub release |

**Build Matrix (Go):**
| OS | Architecture |
|----|--------------|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64 |

**Release Artifacts:**
- `cptc11-go-{os}-{arch}.tar.gz` / `.zip`
- `cptc11-python-tools.tar.gz`
- `cptc11-networks.tar.gz`

**Creating a Release:**
```bash
git tag v1.0.0
git push origin v1.0.0
```

---

### 7. Network Validation (`network-validation.yml`)

**Purpose:** Validates IMUNES/CORE network topology files.

**Triggers:**
- Push to `main`/`master` (network files only)
- Pull requests (network files only)
- Manual dispatch

**Jobs:**
| Job | Description |
|-----|-------------|
| `validate-networks` | Syntax and configuration validation |
| `generate-docs` | Network inventory documentation |

**Validation Checks:**
- Syntax correctness
- Node configuration completeness
- Link connectivity
- IP address validity
- Brace balancing

**Artifacts:**
- `network-inventory.md` - Auto-generated network documentation

---

## Branch Protection Recommendations

For production use, configure branch protection rules:

1. **Required status checks:**
   - `CI Success` (from tests.yml)
   - `Go CI Success` (from go-build.yml)
   - `Ruff Linting` (from lint.yml)

2. **Additional settings:**
   - Require pull request reviews
   - Dismiss stale reviews on new commits
   - Require conversation resolution

---

## Workflow Dependencies

```yaml
# Required Python packages (python/requirements-test.txt)
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.0.0
pytest-timeout>=2.0.0
hypothesis>=6.0.0
ruff>=0.1.0
bandit>=1.7.0
safety>=2.3.0
pip-audit>=2.6.0
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHON_VERSION` | 3.10 | Python version for workflows |
| `GO_VERSION` | 1.21 | Go version for workflows |
| `HYPOTHESIS_PROFILE` | ci | Hypothesis profile for fuzz tests |

---

## Troubleshooting

### Tests failing locally but passing in CI

1. Ensure Python version matches (`python --version`)
2. Install all test dependencies: `pip install -r python/requirements-test.txt`
3. Run with the same pytest options as CI

### Go build failures

1. Check Go version: `go version`
2. Go files are standalone (no `go.mod`) - build individually
3. Some tools may have OS-specific code

### Docker build failures

Docker containers may fail if configuration files are missing:
- `docker/vulnerable-web/apache/*`
- `docker/ftp-server/vsftpd.conf`
- `docker/smtp-server/postfix/*`

### Security scan false positives

This repository contains security testing tools. Expected findings include:
- Hardcoded test credentials (intentional)
- Network scanning code
- Shell command execution

---

## Manual Workflow Triggers

All workflows support manual triggering via GitHub Actions UI:

1. Go to **Actions** tab
2. Select the workflow
3. Click **Run workflow**
4. Select branch and input parameters (if applicable)

---

## Adding New Workflows

When adding new workflows:

1. Place YAML file in `.github/workflows/`
2. Follow naming convention: `{purpose}.yml`
3. Include comprehensive header comments
4. Use consistent job structure:
   - Checkout step
   - Setup steps (runtime, dependencies)
   - Main steps
   - Summary step
5. Add concurrency group to cancel duplicate runs
6. Set appropriate timeouts
7. Update this README

---

## Support

For CI/CD issues:
1. Check the Actions tab for detailed logs
2. Review this documentation
3. Ensure all required files exist
4. Verify branch protection settings

---

*Last updated: Auto-generated by CI/CD Integrator*
