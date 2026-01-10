# Log Analyzer

A defensive security tool for parsing and analyzing security logs to detect suspicious patterns and anomalies.

## Overview

Log Analyzer is designed to help security teams identify potential threats by analyzing various log formats and applying detection rules to find indicators of attack or compromise.

## Features

- **Multi-format Support**: Parse syslog, auth.log, Apache, and Nginx logs
- **Auto-detection**: Automatically detect log format from content
- **Attack Detection**: Built-in rules for common attack patterns
- **Statistical Analysis**: Generate metrics and insights from log data
- **Flexible Output**: Text or JSON output formats
- **Planning Mode**: Preview analysis actions before execution

## Installation

```bash
# No external dependencies required - uses Python standard library
python3 tool.py --help
```

## Usage

### Planning Mode

Always review the execution plan before running analysis:

```bash
python tool.py --plan -f /var/log/auth.log
```

### Basic Analysis

```bash
# Analyze auth logs
python tool.py -f /var/log/auth.log --format auth

# Analyze web server logs
python tool.py -f /var/log/apache2/access.log --format apache

# Analyze multiple files
python tool.py -f /var/log/syslog -f /var/log/auth.log
```

### JSON Output

```bash
python tool.py -f /var/log/auth.log --output json > report.json
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| BRUTE_FORCE_DETECTION | HIGH | Detects 5+ failed logins from same IP within 5 minutes |
| PASSWORD_SPRAY_DETECTION | CRITICAL | Detects attacks against 10+ unique users from same IP |
| SUSPICIOUS_USER_AGENT | MEDIUM | Detects known malicious tools and scanners |
| SQL_INJECTION_ATTEMPT | HIGH | Detects SQL injection patterns in requests |
| PATH_TRAVERSAL_ATTEMPT | HIGH | Detects directory traversal attacks |
| PRIVILEGE_ESCALATION | MEDIUM | Detects suspicious privilege-related commands |

## Supported Log Formats

### Syslog
Standard syslog format: `Mon DD HH:MM:SS hostname process[pid]: message`

### Auth Log
Authentication logs (Linux auth.log, secure): Extends syslog with auth-specific parsing

### Apache/Nginx
Combined Log Format: `IP - user [timestamp] "request" status size "referer" "user-agent"`

## Output

### Text Format

```
============================================================
  LOG ANALYSIS REPORT
============================================================

Summary: Analyzed 1523 log entries. Found 3 alerts: 0 critical, 2 high, 1 medium severity.

------------------------------------------------------------
  ALERTS
------------------------------------------------------------

[HIGH] BRUTE_FORCE_DETECTION
  Description: Brute force attack detected from 192.168.1.100: 15 failed attempts in 5 minutes
  Time: 2024-01-15 10:23:45
  Source IPs: 192.168.1.100
  Recommendation: Block the source IP and investigate affected accounts
```

### JSON Format

Structured JSON output suitable for SIEM integration or further processing.

## Integration

### With SIEM Systems

```bash
# Generate JSON for SIEM ingestion
python tool.py -f /var/log/*.log --output json | send-to-siem.sh
```

### Scheduled Analysis

```bash
# Add to crontab for hourly analysis
0 * * * * /path/to/tool.py -f /var/log/auth.log --output json -q >> /var/log/security-alerts.json
```

## API Usage

```python
from tool import LogAnalyzer, get_documentation

# Get tool documentation
docs = get_documentation()

# Create analyzer instance
analyzer = LogAnalyzer()

# Parse log content
with open('/var/log/auth.log') as f:
    entries = analyzer.parse_logs(f.read(), log_format='auth')

# Run analysis
result = analyzer.analyze(entries)

# Access alerts
for alert in result.alerts:
    print(f"[{alert.severity}] {alert.rule_name}: {alert.description}")
```

## Exit Codes

- `0`: Analysis completed, no critical/high alerts
- `1`: Analysis completed with critical or high severity alerts (or error)

## Legal Notice

This tool is intended for authorized security monitoring and incident response activities only. Ensure you have proper authorization before analyzing logs from systems you do not own or manage.

## Author

Defensive Security Toolsmith
