# Port Scanner

Advanced TCP/UDP port scanning tool with stealth features for authorized penetration testing.

## Overview

This tool performs comprehensive port scanning with multiple techniques, configurable threading, stealth options, and service identification capabilities. Designed for operational security with in-memory result storage and configurable delays.

## Features

- **Multiple Scan Types**: TCP Connect, TCP SYN (half-open), UDP
- **Flexible Port Specification**: Single ports, ranges, lists, and predefined sets
- **Stealth Operations**: Port randomization, configurable delays
- **Service Detection**: Automatic service identification for common ports
- **Banner Grabbing**: Optional service banner collection
- **In-Memory Storage**: Minimal disk artifacts
- **Planning Mode**: Preview operations before execution

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
# Scan default top 20 ports
python3 tool.py 192.168.1.1

# Scan specific ports
python3 tool.py target.com --ports 22,80,443

# Scan port range
python3 tool.py 10.0.0.1 --ports 1-1024
```

### Planning Mode

Preview scan before execution:

```bash
python3 tool.py 192.168.1.1 --ports top100 --plan
```

### Advanced Options

```bash
# Fast scan with high thread count
python3 tool.py target.com --ports 1-65535 --threads 200

# Stealthy scan with delays
python3 tool.py 192.168.1.1 --delay-min 1 --delay-max 5 --threads 5

# Banner grabbing
python3 tool.py 10.0.0.1 --ports top100 --banner --verbose

# UDP scan
python3 tool.py target.com --scan-type udp --ports 53,67,68,123,161
```

## Port Specifications

| Format | Example | Description |
|--------|---------|-------------|
| Single | `80` | Single port |
| Range | `1-1024` | Port range |
| List | `22,80,443` | Comma-separated list |
| Combined | `22,80,8000-8100` | Mixed specification |
| top20 | `--ports top20` | 20 most common ports |
| top100 | `--ports top100` | 100 most common ports |
| all | `--ports all` | All 65535 ports |

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| target | - | Required | Target IP or hostname |
| --ports | -P | top20 | Port specification |
| --scan-type | -s | connect | Scan type (connect, syn, udp) |
| --timeout | -t | 1.0 | Connection timeout (seconds) |
| --threads | -T | 50 | Concurrent threads |
| --delay-min | - | 0.0 | Minimum delay between scans |
| --delay-max | - | 0.05 | Maximum delay between scans |
| --banner | -b | False | Grab service banners |
| --no-randomize | - | False | Disable port randomization |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | None | Output file (JSON) |

## Scan Types

### TCP Connect (connect)
- Completes full TCP three-way handshake
- Most reliable detection method
- Does not require elevated privileges
- Most detectable - leaves full connection logs

### TCP SYN (syn)
- Half-open scanning technique
- Sends SYN, waits for SYN/ACK or RST
- Requires root/admin privileges for raw sockets
- Stealthier - doesn't complete connection
- Note: Falls back to connect scan without privileges

### UDP (udp)
- Sends UDP packets and analyzes responses
- Slower and less reliable than TCP
- Essential for UDP-only services
- ICMP responses indicate closed ports

## Operational Security Notes

1. **Port Randomization**: Enabled by default to avoid sequential scan patterns
2. **Delays**: Use `--delay-min` and `--delay-max` for slower, stealthier scans
3. **Threads**: Lower thread counts reduce detection probability
4. **Connect Scans**: Complete handshakes are logged by target systems
5. **In-Memory**: Results stored in memory unless `--output` specified

## Output Format

### Console Output
```
[*] Port Scanner starting...
[*] Target: 192.168.1.1
[*] Ports: 100
[*] Scanning 100 ports on 192.168.1.1 (192.168.1.1)
[*] Scan type: TCP Connect
[+] 22/tcp open - ssh
[+] 80/tcp open - http
[+] 443/tcp open - https

============================================================
SCAN RESULTS
============================================================
Target:       192.168.1.1
Resolved IP:  192.168.1.1
Scan Type:    connect
Duration:     3.45s

Open ports:     3
Filtered ports: 12

OPEN PORTS:
------------------------------------------------------------
  22/tcp open  ssh
  80/tcp open  http
  443/tcp open https
```

### JSON Output
```json
{
  "target": "192.168.1.1",
  "resolved_ip": "192.168.1.1",
  "scan_type": "connect",
  "start_time": "2024-01-15T10:30:00.000000",
  "end_time": "2024-01-15T10:30:03.450000",
  "results": [
    {
      "port": 22,
      "state": "open",
      "protocol": "tcp",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_8.2p1",
      "response_time": 0.015,
      "timestamp": "2024-01-15T10:30:01.123456"
    }
  ]
}
```

## Programmatic Usage

```python
from tool import PortScanner, ScanConfig, ScanType, parse_port_specification

# Parse port specification
ports = parse_port_specification("22,80,443,8000-8100")

# Create configuration
config = ScanConfig(
    target="192.168.1.1",
    ports=ports,
    scan_type=ScanType.TCP_CONNECT,
    threads=20,
    banner_grab=True,
    randomize_ports=True
)

# Initialize and run scanner
scanner = PortScanner(config)
report = scanner.scan()

# Process results
for result in report.get_open_ports():
    print(f"Open: {result.port}/{result.protocol} - {result.service}")
```

## Legal Notice

This tool is provided for authorized security testing and educational purposes only. Unauthorized port scanning may violate computer crime laws. Always obtain proper written authorization before scanning any system.

## Version History

- **1.0.0**: Initial release with TCP Connect, SYN, and UDP scanning capabilities
