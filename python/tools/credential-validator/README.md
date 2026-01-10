# Credential Validator

Multi-protocol credential validation tool for authorized penetration testing.

## Overview

This tool validates credentials against various authentication services including FTP, HTTP, SMTP, and more. Features in-memory credential handling, configurable delays to avoid lockouts, and operational security considerations.

## Features

- **Multi-Protocol Support**: SSH, FTP, HTTP Basic, HTTP Form, SMTP, MySQL
- **In-Memory Handling**: Credentials never written to disk
- **Lockout Awareness**: Configurable delays between attempts
- **Stop on Success**: Option to halt after finding valid credentials
- **Credential Clearing**: Secure memory clearing after completion
- **Planning Mode**: Preview operations before execution

## Supported Protocols

| Protocol | Default Port | Status |
|----------|-------------|--------|
| FTP | 21 | Full support |
| HTTP Basic | 80/443 | Full support |
| HTTP Form | 80/443 | Full support |
| SMTP | 25 | Full support |
| SSH | 22 | Framework (needs paramiko) |
| MySQL | 3306 | Framework (needs protocol impl) |

## Installation

No external dependencies for basic functionality.

```bash
python3 --version
chmod +x tool.py
```

## Usage

### Basic Usage

```bash
# Test single credential against FTP
python3 tool.py 192.168.1.1 --protocol ftp -u admin -P password123

# Preview operation
python3 tool.py target.com --protocol http-basic -u admin -P admin --plan

# Use credential file
python3 tool.py 10.0.0.1 --protocol smtp -c credentials.txt
```

### Credential Input Methods

```bash
# Single credential
python3 tool.py target --protocol ftp -u user -P pass

# Credential file (user:pass format)
python3 tool.py target --protocol ftp -c creds.txt

# Username list + password list (cartesian product)
python3 tool.py target --protocol ftp -U users.txt -W passwords.txt
```

### HTTP Authentication

```bash
# Basic Auth
python3 tool.py target.com --protocol http-basic --http-path /admin -c creds.txt

# Form Auth with custom fields
python3 tool.py target.com --protocol http-form \
    --http-path /login.php \
    --http-user-field email \
    --http-pass-field passwd \
    --http-success "Welcome" \
    -c creds.txt
```

## Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| target | - | Required | Target host or IP |
| --protocol | - | Required | Protocol (ftp, http-basic, etc.) |
| --port | - | Auto | Target port |
| --credentials | -c | - | Credential file |
| --username | -u | - | Single username |
| --password | -P | - | Single password |
| --userlist | -U | - | Username list file |
| --passlist | -W | - | Password list file |
| --threads | -t | 5 | Concurrent threads |
| --timeout | - | 10.0 | Connection timeout |
| --delay-min | - | 0.5 | Minimum delay |
| --delay-max | - | 2.0 | Maximum delay |
| --stop-on-success | - | False | Stop on valid cred |
| --plan | -p | False | Show execution plan |
| --verbose | -v | False | Verbose output |
| --output | -o | - | Output file (JSON) |

### HTTP-Specific Options

| Argument | Default | Description |
|----------|---------|-------------|
| --http-path | /login | Authentication path |
| --http-method | POST | HTTP method |
| --http-user-field | username | Form field for username |
| --http-pass-field | password | Form field for password |
| --http-success | - | String indicating success |
| --http-failure | - | String indicating failure |

## Credential File Format

```
admin:password123
root:toor
user:user123
```

## Output Format

### Console Output
```
[*] Credential Validator starting...
[*] Target: 192.168.1.1
[*] Protocol: ftp
[*] Credentials: 3
[+] admin - valid
[-] root - invalid
[-] user - invalid

============================================================
VALIDATION RESULTS
============================================================
Total tested:    3
Valid:           1
Invalid:         2
Errors:          0

VALID CREDENTIALS:
------------------------------------------------------------
  [+] admin:password123
```

## Programmatic Usage

```python
from tool import CredentialValidator, ValidatorConfig, Credential, Protocol

# Create credentials
creds = [
    Credential("admin", "password123"),
    Credential("root", "toor"),
]

# Configure validator
config = ValidatorConfig(
    target="192.168.1.1",
    protocol=Protocol.FTP,
    credentials=creds,
    stop_on_success=True,
    verbose=True
)

# Run validation
validator = CredentialValidator(config)
results = validator.validate()

# Get valid credentials
for result in validator.get_valid_credentials():
    print(f"Valid: {result.credential.username}")

# Clear credentials from memory
for cred in creds:
    cred.clear()
```

## Operational Security Notes

1. **Account Lockout**: Use appropriate delays to avoid triggering lockout policies
2. **Logging**: All authentication attempts will be logged by target systems
3. **Memory Handling**: Credentials are cleared from memory after validation
4. **Rate Limiting**: Low thread counts reduce detection probability
5. **Planning Mode**: Always preview operations in sensitive environments

## Version History

- **1.0.0**: Initial release with FTP, HTTP, SMTP support
