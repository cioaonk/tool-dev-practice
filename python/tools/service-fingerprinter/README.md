# Service Fingerprinter

Advanced service detection and version identification tool for authorized penetration testing.

## Overview

This tool performs deep service fingerprinting to identify running services, extract version information, and detect SSL/TLS configurations. Uses protocol-specific probes for accurate identification with configurable intensity levels.

## Features

- **Protocol-Specific Probes**: Targeted probes for HTTP, SSH, FTP, SMTP, MySQL, RDP
- **Version Extraction**: Parses banners to extract product and version information
- **SSL/TLS Analysis**: Detects encrypted services and extracts certificate details
- **Confidence Scoring**: Results include confidence percentages
- **Banner Grabbing**: Collects raw service banners for analysis
- **In-Memory Storage**: Minimal disk artifacts by default

## Supported Services

| Service | Default Ports | Detection Method |
|---------|--------------|------------------|
| HTTP/HTTPS | 80, 443, 8080 | Server header analysis |
| SSH | 22, 2222 | Banner parsing |
| FTP | 21, 2121 | Welcome banner analysis |
| SMTP | 25, 465, 587 | MTA identification |
| MySQL/MariaDB | 3306 | Protocol packet parsing |
| RDP | 3389 | X.224 handshake |

## Installation

No external dependencies required. Uses Python 3.6+ standard library.

```bash
python3 --version
chmod +x tool.py
```

## Usage

### Basic Usage

```bash
# Fingerprint specific ports
python3 tool.py 192.168.1.1 --ports 22,80,443

# Preview operation
python3 tool.py target.com --ports 22,80,443,3306 --plan
```

### Advanced Options

```bash
# Aggressive mode - try all probes on all ports
python3 tool.py 192.168.1.1 --ports 22,80,8080 --aggressive

# Increase timeout for slow services
python3 tool.py target.com --ports 22,80 --timeout 10

# Skip SSL detection
python3 tool.py 10.0.0.1 --ports 80,8080 --no-ssl

# Save results to file
python3 tool.py target.com --ports 22,80,443 --output results.json
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| target | - | Required | Target IP or hostname |
| --ports | -P | Required | Comma-separated port list |
| --timeout | -t | 5.0 | Connection timeout (seconds) |
| --threads | -T | 10 | Concurrent threads |
| --delay-min | - | 0.1 | Minimum delay between probes |
| --delay-max | - | 0.5 | Maximum delay between probes |
| --aggressive | -a | False | Try all probes on all ports |
| --no-ssl | - | False | Skip SSL/TLS detection |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | None | Output file (JSON) |

## Output Format

### Console Output
```
[*] Service Fingerprinter starting...
[*] Target: 192.168.1.1
[*] Ports: [22, 80, 443]
[+] 22/tcp - ssh OpenSSH 8.2p1 (95%)
[+] 80/tcp - http Apache 2.4.41 (95%)
[+] 443/tcp - https nginx 1.18.0 (95%)

======================================================================
FINGERPRINT RESULTS
======================================================================
PORT     SERVICE         PRODUCT              VERSION         SSL
----------------------------------------------------------------------
22       ssh             OpenSSH              8.2p1           No
80       http            Apache               2.4.41          No
443      https           nginx                1.18.0          Yes
```

### JSON Output
```json
{
  "target": "192.168.1.1",
  "timestamp": "2024-01-15T10:30:00.000000",
  "results": [
    {
      "port": 22,
      "protocol": "tcp",
      "service_name": "ssh",
      "version": "8.2p1",
      "product": "OpenSSH",
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1",
      "ssl_enabled": false,
      "confidence": 95
    }
  ]
}
```

## Programmatic Usage

```python
from tool import ServiceFingerprinter, FingerprintConfig

# Create configuration
config = FingerprintConfig(
    target="192.168.1.1",
    ports=[22, 80, 443, 3306],
    timeout=5.0,
    threads=5,
    aggressive=True
)

# Run fingerprinter
fingerprinter = ServiceFingerprinter(config)
results = fingerprinter.fingerprint()

# Process results
for result in results:
    if result.confidence > 50:
        print(f"{result.port}: {result.service_name} {result.version}")
```

## Operational Security Notes

1. **Probe Signatures**: Service probes may be detected by IDS/IPS systems
2. **SSL Handshakes**: Certificate negotiation leaves traces
3. **Logging**: Applications may log connection attempts and probes
4. **Delays**: Use delay options to reduce scan footprint

## Version History

- **1.0.0**: Initial release with support for common services
