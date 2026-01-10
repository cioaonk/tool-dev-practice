# SMB Enumerator

SMB/CIFS share and system enumeration tool for authorized penetration testing.

## Overview

This tool performs SMB enumeration including share discovery, OS fingerprinting, and null session testing. Uses raw socket implementation for minimal dependencies.

## Features

- **Share Enumeration**: Discover accessible shares
- **OS Detection**: Extract Windows version information
- **SMB Version Detection**: Identify SMB1/SMB2/SMB3
- **Signing Detection**: Check if SMB signing is required
- **Null Session Testing**: Attempt anonymous access
- **Authentication Support**: Use credentials for authenticated enum

## Usage

### Basic Usage

```bash
# Null session enumeration
python3 tool.py 192.168.1.1

# Preview operation
python3 tool.py 192.168.1.1 --plan

# Authenticated enumeration
python3 tool.py 192.168.1.1 -u admin -P password -d DOMAIN
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| target | - | Required | Target IP or hostname |
| --port | - | 445 | SMB port |
| --username | -u | - | Username |
| --password | -P | - | Password |
| --domain | -d | - | Domain name |
| --null-session | -n | True | Attempt null session |
| --no-shares | - | False | Skip share enum |
| --timeout | - | 10.0 | Connection timeout |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | - | Output file (JSON) |

## Output Format

```
[*] SMB Enumerator starting...
[*] Target: 192.168.1.1:445

============================================================
SMB ENUMERATION RESULTS
============================================================

SYSTEM INFORMATION:
----------------------------------------
  OS Version:      Windows Server 2019
  SMB Version:     SMB2+
  Domain:          CORP
  Signing:         Not Required

SHARES (5):
----------------------------------------
  IPC$                 [IPC] Accessible
  ADMIN$               [Disk] Accessible
  C$                   [Disk] Accessible
  NETLOGON             [Disk] Accessible
  SYSVOL               [Disk] Accessible
```

## Operational Security Notes

1. **Event Logging**: Windows logs SMB connections (Event IDs 4624, 4625)
2. **Null Sessions**: Anonymous access attempts are typically logged
3. **Share Access**: Each share access generates log entries

## Version History

- **1.0.0**: Initial release with share enumeration
