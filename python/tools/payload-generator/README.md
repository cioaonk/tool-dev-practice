# Payload Generator

A modular payload generator for penetration testing that creates reverse shells, bind shells, and web shells in various programming languages.

## DISCLAIMER

**This tool is for authorized security testing and educational purposes only. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical.**

## Features

- **Multiple Payload Types**: Reverse shells, bind shells, web shells
- **Multi-Language Support**: Python, PowerShell, Bash, PHP
- **Encoding Options**: Base64, Hex encoding for delivery
- **Obfuscation Levels**: 0-3 levels of payload obfuscation
- **Planning Mode**: Preview what will be generated without execution
- **JSON Output**: Machine-readable output for integration
- **Documentation Hooks**: Built-in documentation for agent integration

## Installation

No additional dependencies required - uses Python standard library only.

```bash
# Make executable
chmod +x payload_generator.py
```

## Usage

### Basic Usage

```bash
# Generate a Python reverse shell
python payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --lport 4444

# Generate a PowerShell reverse shell with base64 encoding
python payload_generator.py --type reverse_shell --lang powershell --lhost 10.0.0.1 --encoding base64

# Generate an obfuscated PHP web shell
python payload_generator.py --type web_shell --lang php --obfuscate 2
```

### Planning Mode

Always use planning mode first to understand what will be generated:

```bash
python payload_generator.py --type reverse_shell --lang bash --lhost 10.0.0.1 --plan
```

Output:
```
[PLAN MODE] Tool: payload-generator
==================================================

Configuration:
  Payload Type: reverse_shell
  Language: bash
  Target Host (LHOST): 10.0.0.1
  Target Port (LPORT): 4444
  ...

Actions to be performed:
  1. Load bash reverse_shell template
  2. Substitute connection parameters (LHOST/LPORT)
  3. Output generated payload to stdout

Detection Considerations:
  - /dev/tcp access monitoring
  - Outbound connection from shell process
  ...
```

### List Available Payloads

```bash
python payload_generator.py --list
```

### JSON Output

```bash
python payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --json
```

### Get Documentation

```bash
python payload_generator.py --doc
python payload_generator.py --doc --json  # JSON format
```

## Command Line Arguments

| Argument | Short | Description | Required |
|----------|-------|-------------|----------|
| `--type` | `-t` | Payload type (reverse_shell, bind_shell, web_shell) | Yes |
| `--lang` | `-l` | Target language (python, powershell, bash, php) | Yes |
| `--lhost` | | Listener host IP address | For reverse shells |
| `--lport` | | Listener port (default: 4444) | No |
| `--encoding` | `-e` | Output encoding (base64, hex) | No |
| `--obfuscate` | `-o` | Obfuscation level 0-3 | No |
| `--platform` | | Target platform (linux, windows, cross) | No |
| `--plan` | `-p` | Show execution plan only | No |
| `--list` | | List available payloads | No |
| `--json` | `-j` | JSON output format | No |
| `--doc` | | Show documentation | No |

## Supported Payloads

### Reverse Shells
- Python - Cross-platform, requires Python interpreter
- PowerShell - Windows, may trigger AMSI
- Bash - Linux/Unix with /dev/tcp support
- PHP - Web server context

### Bind Shells
- Python - Binds to port and waits for connection

### Web Shells
- PHP - Simple command execution shells

## Obfuscation Levels

- **Level 0**: No obfuscation, clean readable code
- **Level 1**: Basic string manipulation, variable obfuscation
- **Level 2**: Additional encoding and splitting
- **Level 3**: Advanced obfuscation techniques

## Integration

### As a Module

```python
from payload_generator import PayloadGenerator, PayloadConfig

generator = PayloadGenerator()

config = PayloadConfig(
    payload_type="reverse_shell",
    language="python",
    lhost="10.0.0.1",
    lport=4444,
    obfuscation_level=1
)

result = generator.generate(config)
print(result.payload)
```

### Documentation Hook

```python
from payload_generator import get_documentation

docs = get_documentation()
print(docs['supported_payloads'])
```

## Operational Security Considerations

1. **Test in isolated environments** before deployment
2. **Review detection vectors** output for each payload
3. **Consider encoding** for command-line delivery
4. **Use obfuscation** appropriately for the engagement
5. **Document all payload usage** for reporting

## Detection Vectors

Each payload includes detection considerations. Common vectors include:
- Network connection monitoring
- Process behavior analysis
- Script block logging (PowerShell)
- AMSI scanning (Windows)
- Web application firewalls

## Contributing

When adding new payloads:
1. Extend the `PayloadTemplate` abstract base class
2. Implement `generate()`, `get_notes()`, and `get_detection_vectors()`
3. Register in the `PayloadGenerator.templates` dictionary
4. Update documentation

## License

For authorized security testing only. See main project license.
