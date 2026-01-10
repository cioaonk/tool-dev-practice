# IOC Scanner

A defensive security tool for scanning files, processes, and network connections for Indicators of Compromise (IOCs).

## Overview

IOC Scanner helps security teams detect potential threats by comparing system artifacts against known threat indicators. It supports multiple IOC types and scanning modes.

## Features

- **File Scanning**: Hash calculation and comparison, filename matching, content analysis
- **Network Scanning**: Monitor active connections against known malicious IPs/domains
- **Process Scanning**: Check running processes against IOC database
- **Multiple IOC Types**: IPs, domains, hashes (MD5/SHA1/SHA256), URLs, filenames
- **Flexible Input**: JSON and CSV IOC file formats
- **Planning Mode**: Preview scan operations before execution

## Installation

```bash
# No external dependencies required - uses Python standard library
python3 tool.py --help
```

## Usage

### Planning Mode

Always review the execution plan first:

```bash
python tool.py --plan --scan-type file --target /home/user
```

### File Scanning

```bash
# Scan directory with built-in IOCs
python tool.py --scan-type file --target /var/log

# Scan with custom IOC file
python tool.py --scan-type file --target /opt/apps --ioc-file threats.json

# Scan with multiple IOC files
python tool.py --scan-type file --target /home --ioc-file ips.csv --ioc-file hashes.json
```

### Network Scanning

```bash
# Scan active network connections
python tool.py --scan-type network --ioc-file known_bad_ips.json
```

### Process Scanning

```bash
# Scan running processes
python tool.py --scan-type process --ioc-file malware_names.json
```

### Full System Scan

```bash
# Run all scan types
python tool.py --scan-type all --target /home --output json > report.json
```

## IOC File Formats

### JSON Format

```json
{
  "iocs": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "description": "Known C2 server",
      "severity": "HIGH",
      "tags": ["apt", "c2"]
    },
    {
      "type": "hash_sha256",
      "value": "abc123...",
      "description": "Malware sample",
      "severity": "CRITICAL"
    },
    {
      "type": "domain",
      "value": "malware.example.com",
      "description": "Phishing domain",
      "severity": "MEDIUM"
    }
  ]
}
```

### CSV Format

Simple one-value-per-line format (specify type with --ioc-type):

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
d41d8cd98f00b204e9800998ecf8427e
# Comments start with #
```

## Supported IOC Types

| Type | Description | Example |
|------|-------------|---------|
| ip | IPv4/IPv6 addresses | 192.168.1.100 |
| domain | Domain names | malware.example.com |
| hash_md5 | MD5 file hashes | d41d8cd98f00b204e9800998ecf8427e |
| hash_sha1 | SHA1 file hashes | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| hash_sha256 | SHA256 file hashes | e3b0c44298fc1c149... |
| url | Full URLs | http://malware.com/payload |
| filename | File names | mimikatz.exe |
| email | Email addresses | attacker@malicious.com |

## Output Formats

### Text Format (default)

```
============================================================
  IOC SCAN REPORT
============================================================

Scan Type: file
Target: /home/user
Duration: 2.34 seconds
Matches Found: 2

------------------------------------------------------------
  MATCHES
------------------------------------------------------------

[CRITICAL] HASH_SHA256: abc123...
  Location: /home/user/downloads/suspicious.exe
  Context: File hash match
  Description: Known ransomware sample

[HIGH] IP: 192.168.1.100
  Location: /home/user/config.txt
  Context: ...connection_string=192.168.1.100:4444...
  Description: Known C2 server
```

### JSON Format

```bash
python tool.py --scan-type file --target /home --output json
```

## API Usage

```python
from tool import IOCScanner, IOC, get_documentation

# Get documentation
docs = get_documentation()

# Create scanner
scanner = IOCScanner()

# Add custom IOCs
scanner.db.add_ioc(IOC(
    ioc_type="ip",
    value="10.0.0.1",
    description="Internal test",
    severity="LOW"
))

# Load from file
scanner.load_iocs("threats.json")

# Scan files
result = scanner.scan_files("/var/log")

# Check results
for match in result.matches:
    print(f"{match.ioc.severity}: {match.ioc.value} found at {match.location}")
```

## Exit Codes

- `0`: Scan completed, no critical/high severity matches
- `1`: Scan completed with critical or high severity matches (or error)

## Performance Notes

- Large directories may take time to scan
- Binary files are automatically skipped for content scanning
- Files larger than 50MB are skipped by default
- Hash calculation is performed on all files

## Integration

### With SIEM Systems

```bash
# Generate JSON for SIEM ingestion
python tool.py --scan-type all --target /home --output json | send-to-siem.sh
```

### Scheduled Scanning

```bash
# Add to crontab for daily scans
0 2 * * * /path/to/tool.py --scan-type file --target /opt -q --output json >> /var/log/ioc-scans.json
```

## Legal Notice

This tool is intended for authorized security scanning and incident response activities only. Ensure you have proper authorization before scanning systems you do not own or manage.

## Author

Defensive Security Toolsmith
