# Tool Detection Signatures Intelligence Report

**Classification:** CPTC Competition Preparation
**Date:** January 2026
**Analyst:** Docker Threat Intel Team

---

## Executive Summary

This report documents how common penetration testing tools are detected by defenders, including network signatures, file artifacts, and process behaviors. Understanding detection mechanisms enables teams to develop evasion strategies and select appropriate tools for different engagement phases.

---

## 1. Network Scanning Tool Detection

### 1.1 Nmap Detection

**Network Signatures**
```
# TCP SYN scan signature
- High volume of SYN packets without completing handshake
- Sequential or patterned port scanning
- TCP flags: SYN only (no ACK)

# Version detection signatures
- Banner grabbing probes
- Service-specific probe strings
- Unusual timing patterns

# IDS/Snort Rules Example
alert tcp any any -> $HOME_NET any (msg:"NMAP TCP Scan"; \
  flags:S; threshold:type threshold, track by_src, count 20, seconds 5; \
  sid:1000001;)
```

**Evasion Techniques**
- Fragment packets (-f)
- Randomize scan order (--randomize-hosts)
- Slow timing (-T1 or -T2)
- Decoy scanning (-D)
- Use allowed ports only

### 1.2 Masscan Detection

**Network Signatures**
```
- Extremely high packet rate
- Stateless SYN packets
- Distinctive TTL patterns
- No TCP state tracking

# Detection characteristics
- Bandwidth exhaustion alerts
- Firewall connection table overflow
- Sequential source port patterns
```

**Evasion Techniques**
- Rate limiting (--rate)
- Source port randomization
- Multiple source IPs
- Distributed scanning

### 1.3 Directory Brute Force Tools

**Gobuster/Dirb/Dirbuster**
```
# Detection patterns
- High volume HTTP requests
- Sequential file path probing
- Predictable User-Agent strings
- 404 response floods

# Common User-Agents detected
"gobuster"
"DirBuster"
"dirbuster"
"nikto"
```

**Evasion Techniques**
- Custom User-Agent strings
- Request delays
- Randomized wordlist order
- Authenticated sessions

---

## 2. Exploitation Framework Detection

### 2.1 Metasploit Framework

**Network Signatures**
```
# Meterpreter HTTP/HTTPS
- Checksum patterns in URIs
- Distinctive staging URLs
- TLS certificate characteristics
- Session heartbeat patterns

# Default payload signatures
- Stage 1 loader patterns
- Encoder remnants
- Known shellcode sequences

# Snort/Suricata rules target:
- Meterpreter reverse TCP connect
- HTTP stager communication
- Encrypted Meterpreter traffic patterns
```

**File Artifacts**
```
# Windows
C:\Users\*\AppData\Local\Temp\*.exe  (dropped payloads)
Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run

# Linux
/tmp/.* (hidden temp files)
/dev/shm/* (shared memory payloads)

# Memory indicators
- Reflective DLL patterns
- Process hollowing artifacts
- Inline function hooks
```

**Process Behaviors**
```
- Network connections from unusual processes
- Child process spawning patterns
- Memory injection indicators
- Privilege token manipulation
```

### 2.2 Cobalt Strike Detection

**Network Signatures**
```
# Beacon HTTP/HTTPS
- Default URI patterns (/ca, /dpixel, /__utm.gif)
- Malleable C2 profile detection
- Sleep/jitter timing patterns
- Encrypted metadata in cookies/headers

# DNS beaconing
- High volume DNS queries
- TXT record responses
- Encoded subdomain patterns
- Consistent query intervals
```

**File Artifacts**
```
# Beacon DLL/EXE
- YARA signatures for packed beacons
- Distinctive PE section names
- Known string patterns

# Artifacts to avoid
- service.exe (default name)
- beacon.dll
- artifact.exe
```

**Process Behaviors**
```
- Process injection (CreateRemoteThread)
- Token impersonation
- Named pipe communication
- Parent-child process anomalies
```

### 2.3 Sliver C2 Detection

**Network Signatures**
```
# mTLS communication
- Client certificate patterns
- Distinctive handshake sequences
- Implant registration traffic

# HTTP(S) C2
- URL path patterns
- Response size characteristics
- Timing intervals
```

**Evasion Notes**
- More customizable than Cobalt Strike
- Supports multiple C2 protocols
- Better OPSEC defaults

---

## 3. Credential Attack Tool Detection

### 3.1 Mimikatz Detection

**File Artifacts**
```
# Known file names
mimikatz.exe
mimilib.dll
mimidrv.sys

# Hashes (frequently updated)
# Check VirusTotal for current signatures
```

**Process Behaviors**
```
# Memory access patterns
- LSASS.exe memory reading
- Specific API calls:
  - MiniDumpWriteDump
  - OpenProcess on lsass
  - ReadProcessMemory

# Windows Event Logs
- Event ID 4656: Object handle requested
- Event ID 4663: Object access attempt
- Event ID 10: Sysmon process access
```

**EDR Detection**
```
- Credential dumping behavior signatures
- LSASS protection alerts
- Memory scanning for credential structures
- API hooking detection
```

### 3.2 Hashcat/John Detection

**File Artifacts**
```
# Hashcat
hashcat.exe / hashcat.bin
*.hcstat2 (statistics files)
*.pot (cracked password files)
kernels/*.cl (OpenCL kernels)

# John the Ripper
john.exe / john
john.pot
john.rec (session recovery)
```

**Process Behaviors**
```
- High CPU/GPU utilization
- Large memory allocation
- Extensive file I/O
- GPU driver interaction
```

### 3.3 Responder Detection

**Network Signatures**
```
# LLMNR/NBT-NS poisoning
- Spoofed responses to broadcast queries
- Multiple protocol responses
- Timing of responses (faster than legitimate)

# SMB capture
- Invalid SMB server responses
- NTLMv2 challenge patterns
```

**Detection Tools**
```
- Respounder (honeypot)
- Network behavior analysis
- Broadcast traffic monitoring
```

---

## 4. Privilege Escalation Tool Detection

### 4.1 LinPEAS/WinPEAS Detection

**File Artifacts**
```
# Linux
linpeas.sh
/tmp/linpeas*
Output files with distinctive formatting

# Windows
winPEAS.exe / winPEASany.exe
winPEAS.bat
Output files with color codes
```

**Process Behaviors**
```
# Linux
- Extensive file system enumeration
- Reading /etc/shadow attempt
- Capability enumeration
- SUID binary searching

# Windows
- Registry enumeration
- Service configuration queries
- Token privilege checks
- Scheduled task enumeration
```

**Detection Signatures**
```
# String patterns in scripts
"ADVISORY:"
"Interesting Files"
"Possible Passwords"
"SUID"
```

### 4.2 PowerSploit Detection

**File Artifacts**
```
# Script names
Invoke-Mimikatz.ps1
PowerView.ps1
Get-GPPPassword.ps1
Invoke-Shellcode.ps1
```

**Process Behaviors**
```
# PowerShell logging
- Script block logging (Event ID 4104)
- Module logging
- Transcription

# AMSI detection
- Known function signatures
- Obfuscation pattern detection
- Suspicious cmdlet combinations
```

**Evasion Techniques**
```
- AMSI bypass
- Script obfuscation
- Memory-only execution
- Custom function names
```

---

## 5. Container-Specific Tool Detection

### 5.1 Container Escape Tools

**Detection Patterns**
```
# Privileged container abuse
- Mount syscalls from containers
- Access to /dev/sda*
- cgroups manipulation

# Docker socket abuse
- API calls from container IPs
- Container creation from containers
- Unusual image pulls
```

### 5.2 Kubernetes Attack Tools

**Kube-hunter Detection**
```
- API scanning patterns
- Service account enumeration
- Node metadata access attempts
```

**Peirates Detection**
```
- kubectl-like commands from pods
- Secret enumeration patterns
- Service account token abuse
```

---

## 6. Network Traffic Artifacts

### 6.1 C2 Communication Patterns

**HTTP-Based C2**
```
# Indicators
- Beaconing intervals
- Fixed URI patterns
- Unusual HTTP methods
- Encoded payloads in parameters
- Cookie-based data exfiltration
```

**DNS-Based C2**
```
# Indicators
- High volume TXT queries
- Long subdomain names (encoded data)
- Queries to recently registered domains
- Consistent query timing
```

**Encrypted C2**
```
# SSL/TLS indicators
- Self-signed certificates
- Unusual certificate validity periods
- Mismatched CN/SAN fields
- Known C2 framework certificates
```

### 6.2 Data Exfiltration Patterns

```
# Large outbound transfers
- Unusual upload volume
- Compressed file transfers
- Encrypted blob transfers
- Off-hours data movement

# Protocol abuse
- DNS tunneling
- ICMP data encoding
- HTTP(S) chunked transfers
```

---

## 7. SIEM/EDR Correlation Rules

### 7.1 Splunk Detection Queries

```spl
# Nmap scan detection
index=firewall sourcetype=firewall_logs
| stats count by src_ip
| where count > 1000

# Credential dumping
index=windows EventCode=10 TargetImage="*lsass.exe"
| stats count by SourceImage

# PowerShell suspicious activity
index=windows EventCode=4104 ScriptBlockText="*Invoke-*"
| stats count by ScriptBlockText
```

### 7.2 Elastic Detection Rules

```json
{
  "rule": {
    "name": "Potential Credential Dumping",
    "query": "process.name:lsass.exe AND event.type:access"
  }
}
```

### 7.3 Sigma Rules

```yaml
title: Mimikatz Detection
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
  condition: selection
```

---

## 8. Evasion Recommendations

### 8.1 General Principles

1. **Know the defensive stack** - Identify EDR/AV before tool selection
2. **Living off the land** - Use built-in tools when possible
3. **Timing matters** - Operate during high-traffic periods
4. **Blend with normal** - Match legitimate traffic patterns
5. **Staged approach** - Light recon before heavy tools

### 8.2 Tool Modification

- Rename binaries and scripts
- Modify string signatures
- Change default ports and URIs
- Compile from source with modifications
- Use memory-only execution

### 8.3 Infrastructure OPSEC

- Rotate IP addresses
- Use legitimate cloud providers
- Domain fronting where applicable
- Aged domains for C2
- Valid SSL certificates

---

## 9. References

- MITRE ATT&CK Framework
- Sigma Rules Repository
- Elastic Detection Rules
- Florian Roth's YARA Rules
- Red Canary Threat Detection Reports
- SANS Hunt Evil Poster

---

**Document Version:** 1.0
**Next Review:** Quarterly
