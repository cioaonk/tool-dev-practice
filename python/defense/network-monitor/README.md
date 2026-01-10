# Network Monitor

A defensive security tool for monitoring network connections and detecting suspicious network activity.

## Overview

Network Monitor provides real-time visibility into network connections on a system, applying detection rules to identify potential security threats such as connections to suspicious ports, data exfiltration, and command-and-control activity.

## Features

- **Connection Monitoring**: Track all TCP/UDP connections
- **Process Mapping**: Map connections to processes (when available)
- **Suspicious Port Detection**: Alert on connections to known malicious ports
- **Connection Counting**: Detect processes with abnormal connection counts
- **External Connection Tracking**: Monitor connections leaving the network
- **Listener Detection**: Identify unauthorized listening services
- **DNS Tunneling Detection**: Detect potential DNS-based exfiltration
- **Continuous Monitoring**: Run in daemon mode with configurable intervals

## Installation

```bash
# No external dependencies required - uses Python standard library
python3 tool.py --help
```

## Usage

### Planning Mode

Always review what the tool will do first:

```bash
python tool.py --plan
```

### Single Snapshot

```bash
# Basic monitoring
python tool.py

# Show all connections
python tool.py --show-all

# JSON output
python tool.py --output json
```

### Continuous Monitoring

```bash
# Monitor every 30 seconds
python tool.py --continuous

# Custom interval (60 seconds)
python tool.py --continuous --interval 60

# Quiet mode with JSON output for logging
python tool.py --continuous --interval 30 --quiet --output json >> network.log
```

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| SUSPICIOUS_PORT | HIGH | Connections to known malicious ports (4444, 31337, etc.) |
| HIGH_CONNECTION_COUNT | MEDIUM | Process with 50+ active connections |
| EXTERNAL_CONNECTIONS | LOW | Large number of external IP connections |
| UNUSUAL_LISTENERS | MEDIUM | Services listening on non-standard ports |
| DNS_TUNNELING | HIGH | High DNS query rate indicating tunneling |

### Suspicious Ports

The following ports trigger HIGH severity alerts:

| Port | Description |
|------|-------------|
| 4444 | Metasploit default |
| 5555 | Common RAT port |
| 6666/6667 | IRC/backdoor |
| 31337 | Elite/backdoor |
| 12345 | NetBus trojan |
| 9001/9050/9150 | Tor |

## Output Formats

### Text Format (default)

```
============================================================
  NETWORK MONITOR REPORT
============================================================

Timestamp: 2024-01-15 10:23:45
Duration: 0.45 seconds
Total Connections: 127
Alerts Generated: 2

------------------------------------------------------------
  ALERTS
------------------------------------------------------------

[HIGH] SUSPICIOUS_PORT
  Connections to suspicious port 4444 (Metasploit default): 2 connection(s)
  Recommendation: Investigate the process making these connections
  Sample connections:
    tcp 192.168.1.50:45123 -> 10.0.0.5:4444 (ESTABLISHED)
      Process: suspicious.exe

[MEDIUM] UNUSUAL_LISTENERS
  Found 3 unusual listening ports
  Recommendation: Verify all listening services are authorized
```

### JSON Format

```bash
python tool.py --output json
```

Returns structured JSON with all connection data and alerts.

## API Usage

```python
from tool import NetworkMonitor, get_documentation

# Get documentation
docs = get_documentation()

# Create monitor
monitor = NetworkMonitor()

# Get plan
print(monitor.get_plan(continuous=False, interval=30, output_format='text'))

# Run monitoring
result = monitor.monitor()

# Check alerts
for alert in result.alerts:
    print(f"[{alert.severity}] {alert.rule_name}: {alert.description}")

# Access statistics
print(f"Total connections: {result.total_connections}")
print(f"Established: {result.statistics['established_count']}")
```

## Statistics Provided

- **By Protocol**: TCP/UDP connection counts
- **By State**: ESTABLISHED, LISTEN, TIME_WAIT, etc.
- **By Process**: Top processes by connection count
- **Listening Ports**: All ports in LISTEN state
- **External IPs**: Count of unique external IP addresses

## Exit Codes

- `0`: Monitoring completed, no critical/high severity alerts
- `1`: Critical or high severity alerts detected (or error)

## Integration

### SIEM Integration

```bash
# Generate JSON for SIEM
python tool.py --output json | send-to-siem.sh

# Continuous logging
python tool.py --continuous --quiet --output json >> /var/log/network-monitor.json
```

### Alerting

```bash
#!/bin/bash
# alert-on-threats.sh
result=$(python tool.py --output json --quiet)
alerts=$(echo "$result" | jq '.alert_count')
if [ "$alerts" -gt 0 ]; then
    echo "$result" | mail -s "Network Alert" security@company.com
fi
```

### Scheduled Monitoring

```bash
# Crontab entry for hourly checks
0 * * * * /path/to/tool.py --quiet --output json >> /var/log/network-hourly.json
```

## Platform Support

- **macOS**: Full support via netstat and lsof
- **Linux**: Full support via netstat and lsof
- **Windows**: Limited support (netstat only)

## Performance

- Single snapshot: < 1 second
- Continuous mode: Configurable interval (minimum 10s recommended)
- Memory: Minimal (stores current connections only)

## Limitations

- Requires appropriate permissions to enumerate all connections
- Process mapping requires lsof (may need elevated privileges)
- Windows support is limited compared to Unix systems

## Legal Notice

This tool is intended for authorized security monitoring on systems you own or manage. Ensure you have proper authorization before deploying network monitoring solutions.

## Author

Defensive Security Toolsmith
