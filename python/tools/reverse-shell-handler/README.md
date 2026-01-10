# Reverse Shell Handler

Multi-protocol reverse shell listener for authorized penetration testing.

## Overview

This tool provides a reverse shell handler for receiving incoming shell connections during authorized security assessments. Supports SSL/TLS encryption and includes payload generation for various platforms.

## Features

- **TCP Handler**: Receive reverse shell connections
- **SSL/TLS**: Encrypted communications option
- **Multi-Session**: Handle multiple concurrent sessions
- **Payload Generator**: Ready-to-use payloads for various platforms
- **Session Management**: Background and resume sessions
- **In-Memory**: No disk artifacts for session data

## IMPORTANT WARNING

This tool is for AUTHORIZED security testing only. Unauthorized access to computer systems is ILLEGAL. Only use this tool:
- On systems you own
- With explicit written authorization
- During approved penetration tests

## Usage

### Basic Handler

```bash
# Start listener on port 4444
python3 tool.py -l 4444

# With SSL
python3 tool.py -l 443 --ssl

# Preview operation
python3 tool.py -l 4444 --plan
```

### Payload Generation

```bash
# Show payloads for your IP
python3 tool.py --payloads -H 10.0.0.1 -l 4444
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| --host | -H | 0.0.0.0 | Listen address |
| --port | -l | 4444 | Listen port |
| --ssl | -s | False | Enable SSL/TLS |
| --ssl-cert | - | - | SSL certificate |
| --ssl-key | - | - | SSL private key |
| --multi | -m | False | Multi-session mode |
| --timeout | -t | 300 | Session timeout |
| --payloads | - | False | Show payloads |
| --plan | -p | False | Show execution plan |

## Interactive Commands

While in a session:
- `background` - Return to handler (keep session alive)
- `exit` - Close session

## Generated Payloads

| Language | Description |
|----------|-------------|
| bash | Standard bash reverse shell |
| bash_b64 | Base64-encoded bash |
| python | Python one-liner |
| netcat | Netcat with -e flag |
| netcat_no_e | Netcat without -e (using FIFO) |
| php | PHP reverse shell |
| perl | Perl reverse shell |
| ruby | Ruby reverse shell |
| powershell | PowerShell reverse shell |

## Output Format

```
================================================================================
  REVERSE SHELL HANDLER
================================================================================

[*] Handler listening on 0.0.0.0:4444
[*] Waiting for connection...

[+] Connection from 192.168.1.100:54321
[+] Session ID: 1

[*] Interacting with session 1 (192.168.1.100:54321)
[*] Type 'background' to return to handler, 'exit' to close session

$ whoami
user
$ hostname
target-machine
```

## Operational Security Notes

1. **Visibility**: Listening ports are visible in network scans
2. **Logging**: Traffic may be logged by network monitoring
3. **Detection**: Shell traffic patterns may trigger alerts
4. **SSL**: Use encryption when possible to avoid inspection

## Version History

- **1.0.0**: Initial release with TCP handling and payload generation
