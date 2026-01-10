# Network Scanner

A stealthy network host discovery tool for authorized penetration testing.

## Overview

This tool performs network reconnaissance by discovering live hosts using various scanning techniques. Designed with operational security in mind, it minimizes disk artifacts and provides configurable delays for stealth operations.

## Features

- **Multiple Scanning Techniques**: TCP connect, ARP, DNS reverse lookup
- **Flexible Targeting**: Supports single IPs, CIDR notation, and IP ranges
- **Stealth Options**: Configurable delays and jitter between scans
- **In-Memory Operation**: Results stored in memory, minimal disk footprint
- **Planning Mode**: Preview operations before execution
- **Threaded Execution**: Configurable concurrent scanning

## Installation

No external dependencies required. Uses Python 3.6+ standard library.

```bash
# Verify Python version
python3 --version

# Make executable
chmod +x tool.py
```

## Usage

### Basic Usage

```bash
# Scan a single IP
python3 tool.py 192.168.1.1

# Scan a network range (CIDR)
python3 tool.py 192.168.1.0/24

# Scan an IP range
python3 tool.py 192.168.1.1-50
```

### Planning Mode

Always preview your scan before execution:

```bash
python3 tool.py 192.168.1.0/24 --plan
```

### Advanced Options

```bash
# Multiple methods with custom ports
python3 tool.py 10.0.0.0/24 --methods tcp dns --ports 22 80 443 8080

# Slow and stealthy scan
python3 tool.py 172.16.0.0/16 --delay-min 2 --delay-max 10 --threads 2

# With hostname resolution and verbose output
python3 tool.py 192.168.1.0/24 --resolve --verbose

# Save results to file
python3 tool.py 192.168.1.0/24 --output results.json
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| targets | - | Required | Target IPs, CIDR ranges, or IP ranges |
| --timeout | -t | 2.0 | Connection timeout in seconds |
| --threads | -T | 10 | Number of concurrent threads |
| --methods | -m | tcp | Scanning methods (tcp, arp, dns) |
| --ports | -P | 80,443,22 | TCP ports for connect scanning |
| --delay-min | - | 0.0 | Minimum delay between scans |
| --delay-max | - | 0.1 | Maximum delay between scans |
| --resolve | -r | False | Resolve hostnames |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | None | Output file (JSON) |

## Scanning Methods

### TCP Connect Scan (tcp)
Attempts TCP connections to specified ports. Most reliable but also most detectable.

### ARP Scan (arp)
Sends ARP requests for local network discovery. Requires elevated privileges for full functionality.

### DNS Reverse Lookup (dns)
Performs reverse DNS lookups to identify hosts with PTR records. Quiet but may miss hosts without DNS entries.

## Operational Security Notes

1. **Logging**: TCP connect scans are logged by target systems
2. **IDS Detection**: Scanning patterns may trigger network intrusion detection
3. **Stealth**: Use `--delay-min` and `--delay-max` for slower, less detectable scans
4. **Threads**: Lower thread counts reduce detection probability
5. **Memory**: Results are stored in-memory only unless `--output` is specified

## Output Format

### Console Output
```
[*] Network Scanner starting...
[*] Targets: 192.168.1.0/24
[+] 192.168.1.1 is alive (tcp_connect:80)
[+] 192.168.1.10 is alive (tcp_connect:22)

============================================================
SCAN RESULTS
============================================================
Total hosts scanned: 254
Live hosts found:    2

LIVE HOSTS:
------------------------------------------------------------
  192.168.1.1 [0.023s] - tcp_connect:80
  192.168.1.10 (server.local) [0.015s] - tcp_connect:22
```

### JSON Output
```json
{
  "scan_time": "2024-01-15T10:30:00.000000",
  "config": {
    "targets": ["192.168.1.0/24"],
    "methods": ["tcp"],
    "ports": [80, 443, 22]
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "is_alive": true,
      "response_time": 0.023,
      "method": "tcp_connect:80",
      "hostname": null,
      "timestamp": "2024-01-15T10:30:05.123456"
    }
  ]
}
```

## Programmatic Usage

```python
from tool import NetworkScanner, ScanConfig

# Create configuration
config = ScanConfig(
    targets=["192.168.1.0/24"],
    timeout=2.0,
    threads=5,
    scan_methods=["tcp", "dns"],
    tcp_ports=[22, 80, 443],
    resolve_hostnames=True
)

# Initialize and run scanner
scanner = NetworkScanner(config)
results = scanner.scan()

# Process results
for result in scanner.get_live_hosts():
    print(f"Found: {result.ip} - {result.hostname}")
```

## Legal Notice

This tool is provided for authorized security testing and educational purposes only. Unauthorized network scanning may violate laws and regulations. Always obtain proper authorization before scanning any network.

## Version History

- **1.0.0**: Initial release with TCP, ARP, and DNS scanning capabilities
