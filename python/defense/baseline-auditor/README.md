# Baseline Auditor

A defensive security tool for file integrity monitoring, process baseline comparison, and network port monitoring.

## Overview

Baseline Auditor creates a snapshot of your system's critical files, running processes, and network listeners, then compares future states against this baseline to detect unauthorized changes.

## Features

- **File Integrity Monitoring**: SHA256 hash verification
- **Permission Tracking**: Detect permission changes
- **Process Baseline**: Monitor for unexpected processes
- **Network Monitoring**: Track listening ports
- **Severity-Based Alerting**: Critical, High, Medium, Low

## Installation

```bash
# No external dependencies required
python3 tool.py --help
```

## Usage

### Planning Mode

```bash
python tool.py --plan --mode create --paths /etc
python tool.py --plan --mode audit --baseline baseline.json
```

### Create Baseline

```bash
# Create baseline from /etc directory
python tool.py --mode create --paths /etc --baseline baseline.json

# Multiple paths
python tool.py --mode create --paths /etc,/bin,/usr/bin --baseline system.json
```

### Audit Against Baseline

```bash
# Run audit
python tool.py --mode audit --baseline baseline.json

# JSON output
python tool.py --mode audit --baseline baseline.json --output json
```

## Severity Levels

| Severity | Description |
|----------|-------------|
| CRITICAL | Changes to /etc/passwd, /etc/shadow, sudoers, SSH config |
| HIGH | Changes to files in /etc, /bin, /sbin, /usr/bin |
| MEDIUM | Changes to other monitored files, new processes |
| LOW | Missing expected items |

## API Usage

```python
from tool import BaselineManager, BaselineAuditor, get_documentation

# Create baseline
manager = BaselineManager()
baseline = manager.create_baseline(['/etc'])
manager.save_baseline(baseline, 'baseline.json')

# Audit
baseline = manager.load_baseline('baseline.json')
auditor = BaselineAuditor(baseline)
result = auditor.audit()

for v in result.violations:
    print(f"[{v.severity}] {v.description}")
```

## Exit Codes

- `0`: No critical/high violations
- `1`: Critical or high violations detected

## Legal Notice

For authorized security monitoring only.
