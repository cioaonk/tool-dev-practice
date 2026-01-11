# CPTC11 Master Tool Cheatsheet

Comprehensive quick-reference guide for all 20 CPTC11 security tools.

---

## Table of Contents

1. [Quick Reference Table - All Tools](#quick-reference-table---all-tools)
2. [Offensive Tools (15)](#offensive-tools-15)
   - [Reconnaissance Tools](#reconnaissance-tools)
   - [Credential Operations](#credential-operations)
   - [Network Utilities](#network-utilities)
   - [Exploitation Tools](#exploitation-tools)
   - [Post-Exploitation Tools](#post-exploitation-tools)
   - [Evasion Tools](#evasion-tools)
3. [Defensive Tools (5)](#defensive-tools-5)
4. [Tool Chaining Quick Reference](#tool-chaining-quick-reference)
5. [Port Reference Tables](#port-reference-tables)
6. [Default Credentials Table](#default-credentials-table)
7. [Output Parsing One-Liners](#output-parsing-one-liners)
8. [Environment Quick Setup](#environment-quick-setup)

---

## Quick Reference Table - All Tools

### Offensive Tools (15)

| # | Tool | Category | One-Line Description |
|---|------|----------|---------------------|
| 1 | network-scanner | Reconnaissance | Multi-method network host discovery with CIDR support |
| 2 | port-scanner | Reconnaissance | TCP/UDP port scanning with service detection |
| 3 | service-fingerprinter | Reconnaissance | Service version identification via banner grabbing |
| 4 | web-directory-enumerator | Web Testing | Directory and file discovery with wordlist support |
| 5 | dns-enumerator | Reconnaissance | DNS record enumeration and zone transfer testing |
| 6 | smb-enumerator | Network Utils | SMB share discovery and system enumeration |
| 7 | http-request-tool | Network Utils | Flexible HTTP client for endpoint testing |
| 8 | credential-validator | Credential Ops | Multi-protocol credential testing (FTP, HTTP, SMTP) |
| 9 | hash-cracker | Credential Ops | Offline hash cracking with dictionary/bruteforce |
| 10 | reverse-shell-handler | Post-Exploitation | Multi-session reverse shell listener |
| 11 | payload-generator | Exploitation | Modular payload creation for multiple languages |
| 12 | process-hollowing | Evasion | Process hollowing technique demonstrator |
| 13 | amsi-bypass | Evasion | AMSI bypass generation with obfuscation |
| 14 | shellcode-encoder | Exploitation | Shellcode encoding and format conversion |
| 15 | edr-evasion-toolkit | Evasion | EDR bypass techniques and syscall generation |

### Defensive Tools (5)

| # | Tool | Category | One-Line Description |
|---|------|----------|---------------------|
| 16 | network-monitor | Detection | Real-time network connection monitoring |
| 17 | baseline-auditor | Integrity | File integrity and process baseline comparison |
| 18 | ioc-scanner | Detection | IOC-based file, process, and network scanning |
| 19 | log-analyzer | Analysis | Security log parsing and attack pattern detection |
| 20 | honeypot-detector | Recon/Defense | Honeypot identification via behavioral analysis |

---

## Offensive Tools (15)

---

### Reconnaissance Tools

---

#### 1. Network Scanner

**Category:** Reconnaissance
**Primary Use:** Discover live hosts on a network using TCP, ARP, or DNS methods.

**Basic Syntax:**
```bash
python3 tool.py <targets> [options]
```

**Common Command Examples:**
```bash
# Scan a /24 network with default settings
python3 tool.py 192.168.1.0/24

# Multi-method scan with custom ports
python3 tool.py 10.0.0.0/24 --methods tcp dns --ports 22 80 443 8080

# Slow stealth scan
python3 tool.py 172.16.0.0/16 --delay-min 2 --delay-max 10 --threads 2
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--timeout` | `-t` | 2.0 | Connection timeout (seconds) |
| `--threads` | `-T` | 10 | Concurrent threads |
| `--methods` | `-m` | tcp | Scan methods: tcp, arp, dns |
| `--ports` | `-P` | 80,443,22 | TCP ports for connect scan |
| `--delay-min` | - | 0.0 | Min delay between scans |
| `--delay-max` | - | 0.1 | Max delay between scans |
| `--resolve` | `-r` | False | Resolve hostnames |
| `--plan` | `-p` | False | Preview execution plan |
| `--verbose` | `-v` | False | Verbose output |
| `--output` | `-o` | None | Output file (JSON) |

**Output Format Notes:**
- Default: Console text with live host listing
- JSON: Includes scan_time, config, and results array
- Results contain: ip, is_alive, response_time, method, hostname, timestamp

---

#### 2. Port Scanner

**Category:** Reconnaissance
**Primary Use:** Enumerate open ports and identify running services on target hosts.

**Basic Syntax:**
```bash
python3 tool.py <target> [options]
```

**Common Command Examples:**
```bash
# Quick scan of top 20 ports
python3 tool.py 192.168.1.1

# Full port range with high concurrency
python3 tool.py target.com --ports 1-65535 --threads 200

# Stealth scan with banner grabbing
python3 tool.py 10.0.0.1 --ports top100 --banner --delay-min 1 --delay-max 5 --threads 5
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ports` | `-P` | top20 | Port spec: single, range, list, top20, top100, all |
| `--scan-type` | `-s` | connect | Type: connect, syn, udp |
| `--timeout` | `-t` | 1.0 | Connection timeout |
| `--threads` | `-T` | 50 | Concurrent threads |
| `--banner` | `-b` | False | Grab service banners |
| `--no-randomize` | - | False | Disable port randomization |
| `--delay-min` | - | 0.0 | Min delay between scans |
| `--delay-max` | - | 0.05 | Max delay between scans |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | None | Output file (JSON) |

**Port Specification Formats:**
```
Single:   80
Range:    1-1024
List:     22,80,443
Combined: 22,80,8000-8100
Presets:  top20, top100, all
```

**Output Format Notes:**
- Console shows port/protocol/state/service table
- JSON includes target, resolved_ip, scan_type, start/end times, results array
- Results contain: port, state, protocol, service, banner, response_time

---

#### 3. Service Fingerprinter

**Category:** Reconnaissance
**Primary Use:** Identify service versions and SSL/TLS configurations on open ports.

**Basic Syntax:**
```bash
python3 tool.py <target> --ports <ports> [options]
```

**Common Command Examples:**
```bash
# Basic fingerprinting
python3 tool.py 192.168.1.1 --ports 22,80,443

# Aggressive mode - all probes
python3 tool.py target.com --ports 22,80,8080 --aggressive

# Extended timeout for slow services
python3 tool.py 10.0.0.1 --ports 22,80 --timeout 10
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ports` | `-P` | Required | Comma-separated port list |
| `--timeout` | `-t` | 5.0 | Connection timeout |
| `--threads` | `-T` | 10 | Concurrent threads |
| `--aggressive` | `-a` | False | Try all probes on all ports |
| `--no-ssl` | - | False | Skip SSL/TLS detection |
| `--delay-min` | - | 0.1 | Min delay between probes |
| `--delay-max` | - | 0.5 | Max delay between probes |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | None | Output file (JSON) |

**Supported Services:**

| Service | Default Ports | Detection Method |
|---------|--------------|------------------|
| HTTP/HTTPS | 80, 443, 8080 | Server header analysis |
| SSH | 22, 2222 | Banner parsing |
| FTP | 21, 2121 | Welcome banner |
| SMTP | 25, 465, 587 | MTA identification |
| MySQL | 3306 | Protocol parsing |
| RDP | 3389 | X.224 handshake |

**Output Format Notes:**
- Console shows PORT/SERVICE/PRODUCT/VERSION/SSL table
- JSON includes target, timestamp, and results with confidence scores (0-100)

---

#### 4. Web Directory Enumerator

**Category:** Web Testing
**Primary Use:** Discover hidden directories and files on web servers.

**Basic Syntax:**
```bash
python3 tool.py <url> [options]
```

**Common Command Examples:**
```bash
# Use built-in wordlist
python3 tool.py http://target.com

# Custom wordlist with extensions
python3 tool.py http://target.com -w /path/to/wordlist.txt -x php,html,txt

# Authenticated enumeration
python3 tool.py http://target.com -c "session=abc123" -H "Authorization: Bearer token"
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--wordlist` | `-w` | built-in | Path to wordlist file |
| `--extensions` | `-x` | None | Extensions to append |
| `--threads` | `-t` | 10 | Concurrent threads |
| `--timeout` | - | 10.0 | Request timeout |
| `--status-codes` | `-s` | 200,201,204,301,302,307,401,403 | Codes to report |
| `--exclude-codes` | `-e` | None | Codes to exclude |
| `--exclude-length` | - | None | Content lengths to exclude |
| `--header` | `-H` | None | Custom header (repeatable) |
| `--cookie` | `-c` | None | Cookies to include |
| `--user-agent` | `-a` | Mozilla/5.0... | Custom User-Agent |
| `--delay-min` | - | 0.0 | Min delay between requests |
| `--delay-max` | - | 0.1 | Max delay between requests |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | None | Output file (JSON) |

**Output Format Notes:**
- Console shows STATUS/SIZE/PATH/REDIRECT table
- Built-in soft 404 detection via baseline calibration

---

#### 5. DNS Enumerator

**Category:** Reconnaissance
**Primary Use:** Enumerate DNS records and attempt zone transfers for subdomain discovery.

**Basic Syntax:**
```bash
python3 tool.py <domain> [options]
```

**Common Command Examples:**
```bash
# Basic enumeration with built-in wordlist
python3 tool.py example.com

# Zone transfer attempt
python3 tool.py example.com --zone-transfer

# Specific record types with custom nameserver
python3 tool.py example.com -r A,MX,TXT -n 8.8.4.4
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--nameserver` | `-n` | System | DNS server to use |
| `--wordlist` | `-w` | built-in | Subdomain wordlist |
| `--record-types` | `-r` | A,AAAA,CNAME | Record types to query |
| `--zone-transfer` | `-z` | False | Attempt zone transfer (AXFR) |
| `--no-brute` | - | False | Disable bruteforcing |
| `--threads` | `-t` | 10 | Concurrent threads |
| `--timeout` | - | 5.0 | Query timeout |
| `--delay-min` | - | 0.0 | Min delay between queries |
| `--delay-max` | - | 0.1 | Max delay between queries |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | None | Output file (JSON) |

**Record Types:**
```
A, AAAA, NS, MX, TXT, SOA, CNAME
```

**Output Format Notes:**
- Console shows TYPE/NAME/VALUE table
- Summary includes total records, unique IPs, subdomains found

---

### Credential Operations

---

#### 6. Credential Validator

**Category:** Credential Operations
**Primary Use:** Test credentials against multiple authentication protocols.

**Basic Syntax:**
```bash
python3 tool.py <target> --protocol <protocol> [options]
```

**Common Command Examples:**
```bash
# Single credential against FTP
python3 tool.py 192.168.1.1 --protocol ftp -u admin -P password123

# Credential file against SMTP
python3 tool.py target.com --protocol smtp -c credentials.txt

# HTTP form authentication
python3 tool.py target.com --protocol http-form --http-path /login.php --http-user-field email --http-pass-field passwd --http-success "Welcome" -c creds.txt
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--protocol` | - | Required | Protocol: ftp, http-basic, http-form, smtp, ssh, mysql |
| `--port` | - | Auto | Target port |
| `--credentials` | `-c` | - | Credential file (user:pass format) |
| `--username` | `-u` | - | Single username |
| `--password` | `-P` | - | Single password |
| `--userlist` | `-U` | - | Username list file |
| `--passlist` | `-W` | - | Password list file |
| `--threads` | `-t` | 5 | Concurrent threads |
| `--timeout` | - | 10.0 | Connection timeout |
| `--delay-min` | - | 0.5 | Min delay (lockout avoidance) |
| `--delay-max` | - | 2.0 | Max delay |
| `--stop-on-success` | - | False | Stop on valid cred |
| `--plan` | `-p` | False | Preview execution plan |

**HTTP-Specific Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--http-path` | /login | Authentication path |
| `--http-method` | POST | HTTP method |
| `--http-user-field` | username | Form username field |
| `--http-pass-field` | password | Form password field |
| `--http-success` | - | Success indicator string |
| `--http-failure` | - | Failure indicator string |

**Supported Protocols:**

| Protocol | Default Port | Notes |
|----------|-------------|-------|
| ftp | 21 | Full support |
| http-basic | 80/443 | Full support |
| http-form | 80/443 | Full support |
| smtp | 25 | Full support |
| ssh | 22 | Requires paramiko |
| mysql | 3306 | Framework only |

---

#### 7. Hash Cracker

**Category:** Credential Operations
**Primary Use:** Crack password hashes using dictionary or bruteforce attacks.

**Basic Syntax:**
```bash
python3 tool.py <hash> [options]
# or
python3 tool.py -f <hashfile> [options]
```

**Common Command Examples:**
```bash
# Dictionary attack on single hash
python3 tool.py 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# Hash file with mutation rules
python3 tool.py -f hashes.txt -w rockyou.txt -r capitalize,append_numbers

# Bruteforce attack
python3 tool.py HASH -b -c alphanumeric --min-length 4 --max-length 8
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `hash` | - | - | Single hash to crack |
| `--file` | `-f` | - | File containing hashes |
| `--wordlist` | `-w` | - | Dictionary file |
| `--type` | `-t` | auto | Hash type (auto-detected) |
| `--rules` | `-r` | - | Mutation rules |
| `--bruteforce` | `-b` | False | Enable bruteforce |
| `--charset` | `-c` | lowercase | Bruteforce charset |
| `--min-length` | - | 1 | Minimum length |
| `--max-length` | - | 6 | Maximum length |
| `--threads` | `-T` | 4 | Thread count |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | - | Output file |

**Supported Hash Types:**

| Algorithm | Length | Auto-Detection |
|-----------|--------|----------------|
| MD5 | 32 | Yes |
| SHA1 | 40 | Yes |
| SHA256 | 64 | Yes |
| SHA512 | 128 | Yes |
| NTLM | 32 | Format-based |

**Available Rules:**

| Rule | Effect |
|------|--------|
| capitalize | password -> Password |
| uppercase | password -> PASSWORD |
| reverse | password -> drowssap |
| append_numbers | password -> password0-99 |
| append_year | password -> password2020-2026 |
| leet | password -> p4ssw0rd |

**Hash File Format:**
```
# Plain hash per line
5f4dcc3b5aa765d61d8327deb882cf99

# username:hash format
admin:e10adc3949ba59abbe56e057f20f883e
```

---

### Network Utilities

---

#### 8. SMB Enumerator

**Category:** Network Utilities
**Primary Use:** Enumerate SMB shares, OS information, and test null sessions.

**Basic Syntax:**
```bash
python3 tool.py <target> [options]
```

**Common Command Examples:**
```bash
# Null session enumeration
python3 tool.py 192.168.1.1

# Authenticated enumeration
python3 tool.py 192.168.1.1 -u admin -P password -d DOMAIN

# Skip share enumeration
python3 tool.py 10.0.0.1 --no-shares
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | - | 445 | SMB port |
| `--username` | `-u` | - | Username |
| `--password` | `-P` | - | Password |
| `--domain` | `-d` | - | Domain name |
| `--null-session` | `-n` | True | Attempt null session |
| `--no-shares` | - | False | Skip share enumeration |
| `--timeout` | - | 10.0 | Connection timeout |
| `--plan` | `-p` | False | Preview execution plan |
| `--verbose` | `-v` | False | Verbose output |
| `--output` | `-o` | - | Output file (JSON) |

**Output Information:**
- OS Version
- SMB Version (SMB1/SMB2/SMB3)
- Domain name
- Signing requirements
- Share listing with types and access

---

#### 9. HTTP Request Tool

**Category:** Network Utilities
**Primary Use:** Craft custom HTTP requests for security testing and API interaction.

**Basic Syntax:**
```bash
python3 tool.py <url> [options]
```

**Common Command Examples:**
```bash
# Simple GET request
python3 tool.py http://target.com

# POST with JSON data
python3 tool.py http://target.com/api -X POST -d '{"key":"value"}'

# With auth header, follow redirects, skip SSL
python3 tool.py https://target.com -H "Authorization: Bearer token" -L -k
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--method` | `-X` | GET | HTTP method |
| `--header` | `-H` | - | Custom header (repeatable) |
| `--data` | `-d` | - | Request body |
| `--data-file` | `-f` | - | File containing body |
| `--follow-redirects` | `-L` | False | Follow redirects |
| `--insecure` | `-k` | False | Skip SSL verification |
| `--timeout` | - | 30.0 | Request timeout |
| `--raw` | `-r` | False | Raw output (body only) |
| `--plan` | `-p` | False | Preview execution plan |
| `--output` | `-o` | - | Save body to file |

**Output Includes:**
- Response status code and message
- Response time
- Response headers
- SSL certificate details (for HTTPS)
- Response body

---

### Post-Exploitation Tools

---

#### 10. Reverse Shell Handler

**Category:** Post-Exploitation
**Primary Use:** Receive and manage incoming reverse shell connections.

**Basic Syntax:**
```bash
python3 tool.py -l <port> [options]
```

**Common Command Examples:**
```bash
# Start listener on port 4444
python3 tool.py -l 4444

# SSL-encrypted listener
python3 tool.py -l 443 --ssl

# Show payload options
python3 tool.py --payloads -H 10.0.0.1 -l 4444
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--host` | `-H` | 0.0.0.0 | Listen address |
| `--port` | `-l` | 4444 | Listen port |
| `--ssl` | `-s` | False | Enable SSL/TLS |
| `--ssl-cert` | - | - | SSL certificate file |
| `--ssl-key` | - | - | SSL private key file |
| `--multi` | `-m` | False | Multi-session mode |
| `--timeout` | `-t` | 300 | Session timeout |
| `--payloads` | - | False | Show payload examples |
| `--plan` | `-p` | False | Preview execution plan |

**Generated Payload Types:**

| Type | Description |
|------|-------------|
| bash | Standard bash reverse shell |
| bash_b64 | Base64-encoded bash |
| python | Python one-liner |
| netcat | Netcat with -e flag |
| netcat_no_e | Netcat using FIFO |
| php | PHP reverse shell |
| perl | Perl reverse shell |
| ruby | Ruby reverse shell |
| powershell | PowerShell reverse shell |

**Interactive Commands:**
```
background  - Return to handler (keep session)
exit        - Close session
```

---

### Exploitation Tools

---

#### 11. Payload Generator

**Category:** Exploitation
**Primary Use:** Generate reverse shells, bind shells, and web shells in multiple languages.

**Basic Syntax:**
```bash
python3 payload_generator.py --type <type> --lang <lang> [options]
```

**Common Command Examples:**
```bash
# Python reverse shell
python3 payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --lport 4444

# Obfuscated PowerShell with base64
python3 payload_generator.py --type reverse_shell --lang powershell --lhost 10.0.0.1 --encoding base64 --obfuscate 2

# PHP web shell
python3 payload_generator.py --type web_shell --lang php --obfuscate 1
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--type` | `-t` | Required | reverse_shell, bind_shell, web_shell |
| `--lang` | `-l` | Required | python, powershell, bash, php |
| `--lhost` | - | Required* | Listener host IP |
| `--lport` | - | 4444 | Listener port |
| `--encoding` | `-e` | None | base64, hex |
| `--obfuscate` | `-o` | 0 | Obfuscation level 0-3 |
| `--platform` | - | cross | linux, windows, cross |
| `--plan` | `-p` | False | Preview plan |
| `--list` | - | False | List available payloads |
| `--json` | `-j` | False | JSON output |

**Obfuscation Levels:**

| Level | Description |
|-------|-------------|
| 0 | No obfuscation |
| 1 | Basic string manipulation |
| 2 | Variable obfuscation + encoding |
| 3 | Advanced techniques |

---

#### 12. Shellcode Encoder

**Category:** Exploitation
**Primary Use:** Encode shellcode to evade signature-based detection.

**Basic Syntax:**
```bash
python3 shellcode_encoder.py --input <file|hex> --encoding <encoder> [options]
```

**Common Command Examples:**
```bash
# XOR encode from file
python3 shellcode_encoder.py --input shellcode.bin --encoding xor

# RC4 with Python output format
python3 shellcode_encoder.py --input sc.bin --encoding rc4 --format python

# Chain multiple encoders
python3 shellcode_encoder.py --input sc.bin --chain xor,add,rot
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--input` | `-i` | Required | Input file or hex string |
| `--encoding` | `-e` | Required | Encoding type |
| `--key` | `-k` | Auto | Encryption key (hex) |
| `--iterations` | `-n` | 1 | Encoding iterations |
| `--format` | `-f` | raw | Output format |
| `--chain` | - | - | Chain encoders (comma-sep) |
| `--null-free` | - | False | Ensure no null bytes |
| `--bad-chars` | - | - | Bad chars to avoid (hex) |
| `--output` | `-o` | - | Output file |
| `--analyze` | `-a` | False | Analyze shellcode |
| `--plan` | `-p` | False | Preview plan |
| `--list` | `-l` | False | List encoders |

**Available Encoders:**

| Encoder | Key Size | Description |
|---------|----------|-------------|
| xor | 1+ bytes | Simple XOR encoding |
| xor_rolling | 1 byte | Rolling XOR with changing key |
| add | 1 byte | ADD encoding (SUB to decode) |
| rot | 1 byte | ROT/Caesar cipher |
| rc4 | Variable | RC4 stream cipher |
| base64 | N/A | Base64 encoding |

**Output Formats:**

| Format | Description |
|--------|-------------|
| raw | Raw hex string |
| hex | Escaped hex (\x format) |
| c_array | C unsigned char array |
| python | Python bytes literal |
| powershell | PowerShell byte array |
| csharp | C# byte array |

---

### Evasion Tools

---

#### 13. Process Hollowing (Demonstrator)

**Category:** Evasion
**Primary Use:** Educational demonstration of process hollowing techniques.

**Basic Syntax:**
```bash
python3 process_hollowing.py --target <process> [options]
```

**Common Command Examples:**
```bash
# Plan hollowing svchost.exe
python3 process_hollowing.py --target svchost.exe --plan

# Run educational demonstration
python3 process_hollowing.py --target svchost.exe --demo

# List common targets
python3 process_hollowing.py --list-targets
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | `-t` | - | Target process name |
| `--payload` | - | - | Payload source path |
| `--platform` | - | windows_x64 | windows_x86, windows_x64 |
| `--plan` | `-p` | False | Show execution plan |
| `--demo` | `-d` | False | Educational demonstration |
| `--list-targets` | - | False | List common targets |
| `--detection-guide` | - | False | Show detection guidance |
| `--step` | - | - | Explain specific step (1-8) |
| `--ppid-spoof` | - | False | Include PPID spoofing |
| `--block-dlls` | - | False | Include DLL blocking |
| `--json` | `-j` | False | JSON output |

**Common Target Processes:**

| Process | Typical Parent | Notes |
|---------|---------------|-------|
| svchost.exe | services.exe | Multiple instances normal |
| RuntimeBroker.exe | svchost.exe | Modern Windows |
| notepad.exe | explorer.exe | GUI expected |

**MITRE ATT&CK:** T1055.012 - Process Injection: Process Hollowing

---

#### 14. AMSI Bypass Generator

**Category:** Evasion
**Primary Use:** Generate AMSI bypass techniques for Windows environments.

**Basic Syntax:**
```bash
python3 amsi_bypass.py --technique <technique> [options]
```

**Common Command Examples:**
```bash
# List available techniques
python3 amsi_bypass.py --list

# Generate basic bypass
python3 amsi_bypass.py --technique force_amsi_error

# Obfuscated with base64 for -enc delivery
python3 amsi_bypass.py --technique amsi_scan_buffer_patch --obfuscate 2 --base64

# Multi-technique chain
python3 amsi_bypass.py --chain
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--technique` | `-t` | - | Bypass technique |
| `--obfuscate` | `-o` | 0 | Obfuscation level 0-3 |
| `--base64` | `-b` | False | Base64 for -enc delivery |
| `--plan` | `-p` | False | Show plan only |
| `--list` | `-l` | False | List techniques |
| `--chain` | - | False | Multi-technique chain |
| `--category` | `-c` | - | Filter by category |
| `--json` | `-j` | False | JSON output |

**Available Techniques:**

| Technique | Category | Risk |
|-----------|----------|------|
| amsi_scan_buffer_patch | Memory Patching | High |
| reflection_context_null | Reflection | High |
| force_amsi_error | Context Manipulation | Medium |
| powershell_downgrade | PS Downgrade | Low |
| clm_bypass | Context Manipulation | Medium |
| type_confusion | Reflection | Medium |
| wldp_com | COM Hijacking | Low |

**MITRE ATT&CK:** T1562.001 - Impair Defenses: Disable or Modify Tools

---

#### 15. EDR Evasion Toolkit

**Category:** Evasion
**Primary Use:** Generate syscall stubs and explore EDR bypass techniques.

**Basic Syntax:**
```bash
python3 edr_evasion.py [options]
```

**Common Command Examples:**
```bash
# List all techniques
python3 edr_evasion.py --list

# Explore direct syscalls technique
python3 edr_evasion.py --technique direct_syscalls --plan

# Generate syscall stubs
python3 edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx

# Generate API hashes
python3 edr_evasion.py --hash-apis VirtualAlloc,CreateThread,WriteProcessMemory
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--technique` | `-t` | - | Technique to explore |
| `--list` | `-l` | False | List techniques |
| `--category` | `-c` | - | Filter by category |
| `--syscall` | `-s` | - | Get syscall information |
| `--list-syscalls` | - | False | List available syscalls |
| `--generate-stubs` | - | - | Generate syscall stubs |
| `--hash-apis` | - | - | Generate API hashes |
| `--platform` | - | windows_x64 | x64 or x86 |
| `--plan` | `-p` | False | Show plan only |
| `--json` | `-j` | False | JSON output |

**Available Techniques:**

| Technique | Category | Description |
|-----------|----------|-------------|
| direct_syscalls | Direct Syscalls | Bypass user-mode hooks |
| full_unhooking | Unhooking | Replace hooked ntdll |
| module_stomping | Memory Evasion | Hide in legitimate DLL |
| sleep_encryption | Memory Evasion | Encrypt during sleep |
| etw_patching | ETW Bypass | Prevent ETW logging |
| api_hashing | API Hashing | Resolve via hashes |

**Key Syscalls (Windows 10):**

| Syscall | Number | Description |
|---------|--------|-------------|
| NtAllocateVirtualMemory | 0x18 | Allocate memory |
| NtWriteVirtualMemory | 0x3A | Write to memory |
| NtCreateThreadEx | 0xC1 | Create thread |
| NtProtectVirtualMemory | 0x50 | Change protection |
| NtOpenProcess | 0x26 | Open process handle |
| NtQueueApcThread | 0x45 | Queue APC |

---

## Defensive Tools (5)

---

#### 16. Network Monitor

**Category:** Detection
**Primary Use:** Monitor network connections and detect suspicious activity.

**Basic Syntax:**
```bash
python3 tool.py [options]
```

**Common Command Examples:**
```bash
# Single snapshot
python3 tool.py

# Show all connections
python3 tool.py --show-all

# Continuous monitoring
python3 tool.py --continuous --interval 30

# JSON logging
python3 tool.py --continuous --quiet --output json >> network.log
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--show-all` | - | False | Show all connections |
| `--continuous` | - | False | Continuous monitoring |
| `--interval` | - | 30 | Monitoring interval (sec) |
| `--quiet` | `-q` | False | Suppress banner |
| `--output` | - | text | Output format: text, json |
| `--plan` | `-p` | False | Preview plan |

**Detection Rules:**

| Rule | Severity | Trigger |
|------|----------|---------|
| SUSPICIOUS_PORT | HIGH | Connections to 4444, 31337, etc. |
| HIGH_CONNECTION_COUNT | MEDIUM | Process with 50+ connections |
| EXTERNAL_CONNECTIONS | LOW | Many external IPs |
| UNUSUAL_LISTENERS | MEDIUM | Non-standard listening ports |
| DNS_TUNNELING | HIGH | High DNS query rate |

**Suspicious Ports Monitored:**
```
4444  - Metasploit default
5555  - Common RAT
6666/6667 - IRC/backdoor
31337 - Elite/backdoor
12345 - NetBus
9001/9050/9150 - Tor
```

---

#### 17. Baseline Auditor

**Category:** Integrity Monitoring
**Primary Use:** Create and audit system baselines for file integrity and process monitoring.

**Basic Syntax:**
```bash
python3 tool.py --mode <create|audit> [options]
```

**Common Command Examples:**
```bash
# Create baseline
python3 tool.py --mode create --paths /etc --baseline baseline.json

# Audit against baseline
python3 tool.py --mode audit --baseline baseline.json

# Multiple paths
python3 tool.py --mode create --paths /etc,/bin,/usr/bin --baseline system.json
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--mode` | - | Required | create or audit |
| `--paths` | - | - | Paths to baseline (create) |
| `--baseline` | - | - | Baseline file path |
| `--output` | - | text | Output format: text, json |
| `--plan` | `-p` | False | Preview plan |

**Severity Levels:**

| Severity | Description |
|----------|-------------|
| CRITICAL | /etc/passwd, /etc/shadow, sudoers, SSH config |
| HIGH | Changes to /etc, /bin, /sbin, /usr/bin |
| MEDIUM | Other monitored files, new processes |
| LOW | Missing expected items |

---

#### 18. IOC Scanner

**Category:** Detection
**Primary Use:** Scan systems for Indicators of Compromise.

**Basic Syntax:**
```bash
python3 tool.py --scan-type <type> [options]
```

**Common Command Examples:**
```bash
# File scanning
python3 tool.py --scan-type file --target /var/log --ioc-file threats.json

# Network scanning
python3 tool.py --scan-type network --ioc-file known_bad_ips.json

# Full system scan
python3 tool.py --scan-type all --target /home --output json
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--scan-type` | - | Required | file, network, process, all |
| `--target` | - | - | Target directory (file scan) |
| `--ioc-file` | - | - | IOC file (repeatable) |
| `--ioc-type` | - | auto | IOC type for CSV files |
| `--output` | - | text | Output format: text, json |
| `--plan` | `-p` | False | Preview plan |
| `-q` | - | False | Quiet mode |

**Supported IOC Types:**

| Type | Description |
|------|-------------|
| ip | IPv4/IPv6 addresses |
| domain | Domain names |
| hash_md5 | MD5 hashes |
| hash_sha1 | SHA1 hashes |
| hash_sha256 | SHA256 hashes |
| url | Full URLs |
| filename | File names |
| email | Email addresses |

**IOC File Format (JSON):**
```json
{
  "iocs": [
    {
      "type": "ip",
      "value": "192.168.1.100",
      "description": "Known C2",
      "severity": "HIGH"
    }
  ]
}
```

---

#### 19. Log Analyzer

**Category:** Analysis
**Primary Use:** Parse security logs and detect attack patterns.

**Basic Syntax:**
```bash
python3 tool.py -f <logfile> [options]
```

**Common Command Examples:**
```bash
# Analyze auth logs
python3 tool.py -f /var/log/auth.log --format auth

# Web server logs
python3 tool.py -f /var/log/apache2/access.log --format apache

# Multiple files with JSON output
python3 tool.py -f /var/log/syslog -f /var/log/auth.log --output json
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `-f` | - | Required | Log file (repeatable) |
| `--format` | - | auto | Log format: syslog, auth, apache, nginx |
| `--output` | - | text | Output format: text, json |
| `-q` | - | False | Quiet mode |
| `--plan` | `-p` | False | Preview plan |

**Detection Rules:**

| Rule | Severity | Description |
|------|----------|-------------|
| BRUTE_FORCE_DETECTION | HIGH | 5+ failed logins in 5 min |
| PASSWORD_SPRAY_DETECTION | CRITICAL | 10+ users from same IP |
| SUSPICIOUS_USER_AGENT | MEDIUM | Known malicious tools |
| SQL_INJECTION_ATTEMPT | HIGH | SQLi patterns |
| PATH_TRAVERSAL_ATTEMPT | HIGH | Directory traversal |
| PRIVILEGE_ESCALATION | MEDIUM | Suspicious commands |

---

#### 20. Honeypot Detector

**Category:** Recon/Defense
**Primary Use:** Identify honeypot systems via behavioral analysis.

**Basic Syntax:**
```bash
python3 tool.py --target <ip> --port <port> [options]
```

**Common Command Examples:**
```bash
# Single target
python3 tool.py --target 192.168.1.100 --port 22

# Multiple ports
python3 tool.py --target 192.168.1.100 --ports 22,80,443,2222

# From target file
python3 tool.py --targets targets.txt --output json
```

**Key Flags Reference:**

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--target` | - | - | Target IP |
| `--port` | - | - | Single port |
| `--ports` | - | - | Multiple ports (comma-sep) |
| `--targets` | - | - | Target file (ip:port per line) |
| `--timeout` | - | 5.0 | Connection timeout |
| `--output` | - | text | Output format: text, json |
| `--plan` | `-p` | False | Preview plan |
| `-q` | - | False | Quiet mode |

**Detection Techniques:**

| Technique | Description |
|-----------|-------------|
| Banner Analysis | Known honeypot signatures |
| Timing Analysis | Suspicious response patterns |
| Behavior Analysis | Unusual service behaviors |
| Network Analysis | TTL/fingerprint anomalies |

**Known Honeypots Detected:**
- Cowrie (SSH/Telnet)
- Kippo (SSH)
- Dionaea (Multi-protocol)
- Glastopf (Web)
- Conpot (ICS/SCADA)
- HoneyD (Network simulation)

---

## Tool Chaining Quick Reference

### Reconnaissance Chain

```bash
# Step 1: Network Discovery
python3 network-scanner/tool.py 192.168.1.0/24 --methods tcp --output hosts.json

# Step 2: Port Scanning (parse hosts from JSON)
for host in $(jq -r '.results[] | select(.is_alive) | .ip' hosts.json); do
    python3 port-scanner/tool.py $host --ports top100 --banner --output ports_$host.json
done

# Step 3: Service Fingerprinting
python3 service-fingerprinter/tool.py 192.168.1.1 --ports 22,80,443 --aggressive

# Step 4: DNS Enumeration
python3 dns-enumerator/tool.py target.com --zone-transfer -r A,MX,NS,TXT

# Step 5: Web Enumeration
python3 web-directory-enumerator/tool.py http://target.com -x php,html,bak
```

### Exploitation Chain

```bash
# Step 1: Credential Testing
python3 credential-validator/tool.py 192.168.1.1 --protocol ftp -c creds.txt

# Step 2: Hash Cracking (if hashes obtained)
python3 hash-cracker/tool.py -f hashes.txt -w rockyou.txt -r capitalize,append_numbers

# Step 3: Payload Generation
python3 payload-generator/payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --lport 4444

# Step 4: Shellcode Encoding (if needed)
python3 shellcode-encoder/shellcode_encoder.py --input payload.bin --chain xor,rc4 --format python

# Step 5: Start Handler
python3 reverse-shell-handler/tool.py -l 4444 --multi
```

### Post-Exploitation Chain

```bash
# Step 1: AMSI Bypass (Windows)
python3 amsi-bypass/amsi_bypass.py --technique force_amsi_error --obfuscate 2 --base64

# Step 2: EDR Evasion Analysis
python3 edr-evasion-toolkit/edr_evasion.py --technique direct_syscalls --plan

# Step 3: Process Hollowing Analysis
python3 process-hollowing/process_hollowing.py --target svchost.exe --demo
```

### Detection Chain (Blue Team)

```bash
# Step 1: Network Monitoring
python3 defense/network-monitor/tool.py --continuous --interval 30 --output json >> network.log

# Step 2: IOC Scanning
python3 defense/ioc-scanner/tool.py --scan-type all --target /home --ioc-file threats.json

# Step 3: Log Analysis
python3 defense/log-analyzer/tool.py -f /var/log/auth.log -f /var/log/syslog --output json

# Step 4: Baseline Audit
python3 defense/baseline-auditor/tool.py --mode audit --baseline system_baseline.json

# Step 5: Honeypot Detection (validate deception)
python3 defense/honeypot-detector/tool.py --targets internal_honeypots.txt
```

---

## Port Reference Tables

### Common Service Ports

| Port | Service | Protocol | Notes |
|------|---------|----------|-------|
| 21 | FTP | TCP | File Transfer |
| 22 | SSH | TCP | Secure Shell |
| 23 | Telnet | TCP | Unencrypted remote |
| 25 | SMTP | TCP | Mail transfer |
| 53 | DNS | TCP/UDP | Domain resolution |
| 67-68 | DHCP | UDP | Dynamic IP |
| 80 | HTTP | TCP | Web |
| 110 | POP3 | TCP | Mail retrieval |
| 111 | RPC | TCP/UDP | Remote procedure call |
| 123 | NTP | UDP | Time sync |
| 135 | MSRPC | TCP | Windows RPC |
| 137-139 | NetBIOS | TCP/UDP | Windows networking |
| 143 | IMAP | TCP | Mail access |
| 161 | SNMP | UDP | Network management |
| 389 | LDAP | TCP | Directory services |
| 443 | HTTPS | TCP | Secure web |
| 445 | SMB | TCP | File sharing |
| 465 | SMTPS | TCP | Secure SMTP |
| 514 | Syslog | UDP | System logging |
| 587 | Submission | TCP | Mail submission |
| 636 | LDAPS | TCP | Secure LDAP |
| 993 | IMAPS | TCP | Secure IMAP |
| 995 | POP3S | TCP | Secure POP3 |
| 1433 | MSSQL | TCP | Microsoft SQL |
| 1521 | Oracle | TCP | Oracle DB |
| 2049 | NFS | TCP | Network file system |
| 3306 | MySQL | TCP | MySQL/MariaDB |
| 3389 | RDP | TCP | Remote Desktop |
| 5432 | PostgreSQL | TCP | PostgreSQL DB |
| 5900 | VNC | TCP | Virtual Network Computing |
| 5985 | WinRM | TCP | Windows Remote Mgmt |
| 6379 | Redis | TCP | Redis cache |
| 8080 | HTTP-Alt | TCP | Alternative web |
| 8443 | HTTPS-Alt | TCP | Alternative HTTPS |
| 27017 | MongoDB | TCP | MongoDB |

### Suspicious/Malicious Ports

| Port | Association | Notes |
|------|-------------|-------|
| 4444 | Metasploit | Default MSF handler |
| 5555 | RAT | Common backdoor |
| 6666 | IRC/Backdoor | Trojan default |
| 6667 | IRC | C2 channel |
| 31337 | Elite | "Elite" backdoor |
| 12345 | NetBus | NetBus trojan |
| 27374 | Sub7 | Sub7 trojan |
| 1234 | Generic | Common test port |
| 9001 | Tor | Tor traffic |
| 9050 | Tor SOCKS | Tor proxy |
| 9150 | Tor Browser | Tor browser proxy |
| 8291 | MikroTik | Winbox |
| 2222 | SSH Alt | Alternative SSH |

### Port Scan Presets

```bash
# Top 20 Ports
20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,8080

# Top 100 Ports
Full list available via: python3 port-scanner/tool.py --ports top100 --plan
```

---

## Default Credentials Table

### Network Devices

| Device/Vendor | Username | Password |
|---------------|----------|----------|
| Cisco | admin | admin |
| Cisco | cisco | cisco |
| Cisco | enable | - |
| Juniper | root | - |
| Netgear | admin | password |
| Linksys | admin | admin |
| D-Link | admin | admin |
| TP-Link | admin | admin |
| Ubiquiti | ubnt | ubnt |
| MikroTik | admin | - |
| Fortinet | admin | - |

### Web Applications

| Application | Username | Password |
|-------------|----------|----------|
| Tomcat | tomcat | tomcat |
| Tomcat | admin | admin |
| WordPress | admin | admin |
| Joomla | admin | admin |
| phpMyAdmin | root | - |
| Jenkins | admin | admin |
| Grafana | admin | admin |
| Zabbix | Admin | zabbix |

### Databases

| Database | Username | Password |
|----------|----------|----------|
| MySQL | root | - |
| MySQL | root | root |
| PostgreSQL | postgres | postgres |
| MongoDB | - | - |
| Redis | - | - |
| MSSQL | sa | sa |
| Oracle | sys | change_on_install |

### Operating Systems

| OS/Service | Username | Password |
|------------|----------|----------|
| Linux | root | toor |
| Windows | Administrator | - |
| ESXi | root | vmware |
| Proxmox | root | - |
| FreeNAS | root | freenas |

### Remote Access

| Service | Username | Password |
|---------|----------|----------|
| VNC | - | password |
| SSH | root | root |
| Telnet | admin | admin |
| RDP | Administrator | - |

---

## Output Parsing One-Liners

### jq Examples for JSON Parsing

```bash
# Extract live hosts from network scan
jq -r '.results[] | select(.is_alive) | .ip' scan_results.json

# Get open ports from port scan
jq -r '.results[] | select(.state == "open") | "\(.port)/\(.protocol) \(.service)"' ports.json

# Extract cracked hashes
jq -r '.results[] | select(.cracked) | "\(.hash) = \(.plaintext)"' cracked.json

# Get high severity alerts
jq '.alerts[] | select(.severity == "HIGH" or .severity == "CRITICAL")' report.json

# Count results by status
jq 'group_by(.state) | map({state: .[0].state, count: length})' results.json

# Extract unique IPs from results
jq -r '[.results[].ip] | unique | .[]' scan.json

# Filter by port number
jq '.results[] | select(.port == 22 or .port == 80)' ports.json

# Get service banners
jq -r '.results[] | select(.banner != null) | "\(.port): \(.banner)"' fingerprint.json

# Combine multiple JSON files
jq -s 'add' file1.json file2.json > combined.json

# Pretty print with selected fields
jq '.results[] | {ip, port, service, state}' scan.json
```

### grep Patterns for Filtering

```bash
# Find IP addresses in output
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' output.txt

# Find open ports
grep -E '^\s*[0-9]+/tcp\s+open' scan.txt

# Extract hostnames
grep -oE '[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+' output.txt

# Find email addresses
grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' output.txt

# Extract hashes (MD5)
grep -oE '[a-fA-F0-9]{32}' output.txt

# Extract hashes (SHA256)
grep -oE '[a-fA-F0-9]{64}' output.txt

# Find URLs
grep -oE 'https?://[^[:space:]]+' output.txt

# Filter lines with specific status
grep -E '\[(HIGH|CRITICAL)\]' alerts.txt

# Find failed login attempts
grep -i 'failed\|failure\|invalid' auth.log

# Extract timestamps
grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' log.txt
```

### Combined Parsing Examples

```bash
# Parse network scan and port scan live hosts
python3 tool.py 192.168.1.0/24 --json | \
    jq -r '.results[] | select(.is_alive) | .ip' | \
    while read ip; do
        python3 port-scanner/tool.py $ip --ports top20 --json >> all_ports.json
    done

# Extract and deduplicate all discovered services
cat *.json | jq -rs '[.[].results[].service] | unique | .[]'

# Generate target list from multiple scans
jq -rs '[.[].results[] | select(.is_alive or .state == "open") | .ip] | unique | .[]' *.json > targets.txt

# Count alerts by severity
cat report.json | jq '[.alerts[].severity] | group_by(.) | map({severity: .[0], count: length})'

# Export to CSV format
jq -r '.results[] | [.ip, .port, .service, .state] | @csv' scan.json > results.csv
```

---

## Environment Quick Setup

### Docker Commands

```bash
# Pull official images
docker pull python:3.11-slim
docker pull golang:1.21-alpine

# Build CPTC11 container
docker build -t cptc11 -f docker/Dockerfile .

# Run with network access
docker run -it --rm --network host cptc11

# Run specific tool
docker run -it --rm cptc11 python tools/network-scanner/tool.py 192.168.1.0/24

# Mount local directory for results
docker run -it --rm -v $(pwd)/output:/output cptc11

# Interactive shell
docker run -it --rm cptc11 /bin/bash

# With custom environment variables
docker run -it --rm -e LHOST=10.0.0.1 -e LPORT=4444 cptc11
```

### Docker Compose (Multi-Container)

```yaml
# docker-compose.yml
version: '3.8'
services:
  cptc11:
    build: .
    network_mode: host
    volumes:
      - ./output:/output
    environment:
      - PYTHONUNBUFFERED=1
```

```bash
# Start services
docker-compose up -d

# Execute commands
docker-compose exec cptc11 python tools/network-scanner/tool.py 10.0.0.0/24

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### CORE (Virtual Environment) Commands

```bash
# Create virtual environment
python3 -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements-test.txt

# Verify installation
python -c "import pytest; print('Ready')"

# Deactivate
deactivate
```

### Python Setup

```bash
# Verify Python version (3.8+ required)
python3 --version

# Create project virtual environment
cd /path/to/cptc11/python
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install -r requirements-test.txt

# Install TUI dependencies
pip install textual>=0.40.0 rich>=13.0.0

# Install development tools
pip install ruff pytest hypothesis

# Run linting
make lint

# Run tests
make test

# Run with coverage
make coverage
```

### Go Setup

```bash
# Verify Go version (1.19+ required)
go version

# Build all Go tools
cd /path/to/cptc11/golang/tools

# Build network scanner
cd network-scanner && go build -o scanner scanner.go

# Build port scanner
cd ../port-scanner && go build -o scanner scanner.go

# Build all at once
for dir in */; do
    cd "$dir" && go build -o "$(basename $dir)" *.go && cd ..
done

# Cross-compile for Windows
GOOS=windows GOARCH=amd64 go build -o scanner.exe scanner.go

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o scanner scanner.go
```

### Makefile Quick Reference

```bash
# From python/ directory
cd /path/to/cptc11/python

# Install dependencies
make install

# Run all tests
make test

# Run fast tests (exclude slow)
make test-fast

# Run fuzz tests
make test-fuzz

# Run linting
make lint

# Auto-fix lint issues
make lint-fix

# Format code
make format

# Run coverage
make coverage

# Run TUI
make run-tui
# or
python run_tui.py
```

### Environment Variables

```bash
# Set common variables
export LHOST="10.0.0.1"
export LPORT="4444"
export TARGET="192.168.1.0/24"

# Use in commands
python3 tool.py $TARGET
python3 payload_generator.py --lhost $LHOST --lport $LPORT

# Persistent configuration
echo 'export LHOST="10.0.0.1"' >> ~/.bashrc
source ~/.bashrc
```

### Quick Test Commands

```bash
# Test network scanner
python3 tools/network-scanner/tool.py 127.0.0.1 --plan

# Test port scanner
python3 tools/port-scanner/tool.py 127.0.0.1 --ports 22,80 --plan

# Test all tool imports
python3 tools/test_all_imports.py

# Run single test file
pytest tests/test_network_scanner.py -v

# Run specific test
pytest tests/test_port_scanner.py::test_tcp_connect -v
```

---

## Universal Flags (All Tools)

| Flag | Short | Description |
|------|-------|-------------|
| `--plan` | `-p` | Preview execution plan without running |
| `--verbose` | `-v` | Enable verbose output |
| `--output` | `-o` | Output file (JSON format) |
| `--json` | `-j` | JSON output format |
| `--doc` | - | Show tool documentation |
| `--help` | `-h` | Show help message |

---

## Quick Command Syntax Summary

### Offensive Tools

```bash
# Reconnaissance
network-scanner     <targets> [--methods tcp|arp|dns] [--ports X,Y,Z]
port-scanner        <target> [--ports X-Y|top20|all] [--scan-type connect|syn|udp]
service-fingerprinter <target> --ports X,Y,Z [--aggressive]
web-directory-enum  <url> [-w wordlist] [-x extensions]
dns-enumerator      <domain> [-z zone-transfer] [-r record-types]

# Network Utils
smb-enumerator      <target> [-u user] [-P pass] [-d domain]
http-request-tool   <url> [-X method] [-H header] [-d data]

# Credentials
credential-validator <target> --protocol <proto> [-c creds.txt]
hash-cracker        <hash> -w wordlist [-r rules] | -b -c charset

# Post-Exploitation
reverse-shell-handler -l <port> [--ssl] [--multi]

# Exploitation
payload-generator   --type <type> --lang <lang> --lhost <ip>
shellcode-encoder   --input <file> --encoding <encoder> [--format format]

# Evasion
process-hollowing   --target <process> [--demo] [--plan]
amsi-bypass         --technique <technique> [--obfuscate N] [--base64]
edr-evasion         --technique <technique> | --generate-stubs <syscalls>
```

### Defensive Tools

```bash
network-monitor     [--continuous] [--interval N]
baseline-auditor    --mode create|audit --paths|--baseline <path>
ioc-scanner         --scan-type file|network|process|all --target <path>
log-analyzer        -f <logfile> [--format syslog|auth|apache|nginx]
honeypot-detector   --target <ip> --port|--ports <ports>
```

---

## Version Information

- **CPTC11 Framework Version:** 1.0.0
- **Python Tools:** 15 total (10 Phase 1, 5 Phase 2)
- **Golang Ports:** 10 (Phase 1 complete)
- **Defensive Tools:** 5 total
- **Cheatsheet Version:** 1.0.0
- **Last Updated:** January 2026

---

## Legal Notice

This toolkit is provided for **authorized security testing and educational purposes only**.

Unauthorized access to computer systems is illegal. Always obtain proper written authorization before:
- Scanning networks you do not own
- Testing credentials against systems
- Generating or using payloads
- Conducting any penetration testing activities

The authors are not responsible for any misuse of these tools.

---

*CPTC11 Security Framework - Multi-Agent Developed Penetration Testing Toolkit*
