# YARA Detection Rules

## Overview

This directory contains YARA rules and tools for detecting offensive security tools and malware patterns. These rules are designed for educational and CTF/training purposes.

**Author**: Detection Engineering Team
**Date**: 2026-01-10
**Purpose**: Educational/CTF Training Resource

## Directory Structure

```
yara/
├── rules/                        # YARA rule files
│   ├── payload_signatures.yar    # Detect generated payloads
│   ├── shellcode_patterns.yar    # Detect encoded shellcode
│   ├── tool_artifacts.yar        # Detect tool execution artifacts
│   ├── network_indicators.yar    # Network-based indicators
│   └── evasion_techniques.yar    # Detect evasion attempts
├── tests/                        # Test suite
│   └── test_yara_rules.py        # Unit tests for rules
├── samples/                      # Test samples
│   ├── benign/                   # Benign files for FP testing
│   └── README.md                 # Sample documentation
├── yara_scanner.py               # Python scanning wrapper
└── README.md                     # This file
```

## Installation

### Requirements

- Python 3.8+
- yara-python

### Install yara-python

```bash
# Using pip
pip install yara-python

# On macOS with Homebrew
brew install yara
pip install yara-python

# On Ubuntu/Debian
sudo apt-get install yara libyara-dev
pip install yara-python
```

## Quick Start

### Scan a File

```bash
# Basic file scan
python yara_scanner.py --file /path/to/suspicious.exe

# With JSON output
python yara_scanner.py --file sample.exe --format json

# Save results to file
python yara_scanner.py --file sample.exe --format json --output results.json
```

### Scan a Directory

```bash
# Recursive directory scan
python yara_scanner.py --directory /path/to/samples --recursive

# Non-recursive scan
python yara_scanner.py --directory /path/to/samples --no-recursive
```

### Scan a Process

```bash
# Scan process memory (requires elevated privileges)
sudo python yara_scanner.py --process 1234
```

### Planning Mode

```bash
# Show what would be scanned without executing
python yara_scanner.py --plan
```

## Rule Categories

### 1. Payload Signatures (`payload_signatures.yar`)

Detects common offensive payload patterns:

| Rule | Description | Confidence |
|------|-------------|------------|
| Meterpreter_Reverse_TCP_Staged | Metasploit Meterpreter staged payload | High |
| Meterpreter_Reverse_HTTPS | Meterpreter HTTPS transport | High |
| Cobalt_Strike_Beacon | Cobalt Strike beacon signatures | High |
| Generic_Reverse_Shell_Windows | Generic Windows reverse shell | Medium |
| Generic_Reverse_Shell_Linux | Generic Linux reverse shell | Medium |
| Python_Reverse_Shell | Python reverse shell scripts | High |
| PowerShell_Download_Execute | PowerShell download cradles | High |
| Webshell_Generic | Generic webshell patterns | Medium |
| Dropper_Generic | Generic dropper/loader patterns | Medium |
| Payload_XOR_Encoded | XOR-encoded payloads | Medium |

### 2. Shellcode Patterns (`shellcode_patterns.yar`)

Detects shellcode encoding and patterns:

| Rule | Description | Confidence |
|------|-------------|------------|
| Shellcode_Windows_x86_Egghunter | Windows x86 egghunter | High |
| Shellcode_Windows_x86_Reverse_Shell | Windows x86 reverse shell | High |
| Shellcode_Windows_x64_Reverse_Shell | Windows x64 reverse shell | High |
| Shellcode_Linux_x86_Reverse_Shell | Linux x86 reverse shell | High |
| Shellcode_Linux_x64_Reverse_Shell | Linux x64 reverse shell | High |
| Shellcode_Encoded_XOR | XOR-encoded shellcode | Medium |
| Shellcode_Encoded_AlphaNumeric | Alphanumeric encoded shellcode | High |
| Shellcode_Encoded_Base64 | Base64-encoded shellcode | Medium |
| Shellcode_Staged_Loader | Staged shellcode loader | Medium |
| Shellcode_NOP_Sled | NOP sled patterns | Medium |
| Shellcode_Metasploit_Shikata | Shikata_ga_nai encoder | High |
| Shellcode_Cobalt_Strike_Beacon | CS beacon shellcode | High |
| Shellcode_Process_Injection_Setup | Process injection setup | Medium |

### 3. Tool Artifacts (`tool_artifacts.yar`)

Detects artifacts from offensive security tools:

| Rule | Description | Confidence |
|------|-------------|------------|
| Tool_Mimikatz_Strings | Mimikatz credential dumper | High |
| Tool_Mimikatz_Binary | Mimikatz binary patterns | High |
| Tool_Impacket_Strings | Impacket toolset | High |
| Tool_BloodHound_Collector | BloodHound/SharpHound | High |
| Tool_Rubeus_Kerberos | Rubeus Kerberos tool | High |
| Tool_CobaltStrike_Artifacts | Cobalt Strike artifacts | High |
| Tool_PowerSploit_Scripts | PowerSploit toolkit | High |
| Tool_Nmap_Output | Nmap scan output | High |
| Tool_Metasploit_Artifacts | Metasploit Framework | High |
| Tool_Hashcat_Artifacts | Hashcat cracking tool | Medium |
| Tool_JohnTheRipper_Artifacts | John the Ripper | Medium |
| Tool_Responder_Artifacts | Responder LLMNR poisoner | High |
| Tool_Empire_Framework | Empire/Starkiller C2 | High |
| Tool_SQLMap_Artifacts | SQLMap injection tool | High |
| Tool_Burp_Suite_Artifacts | Burp Suite artifacts | High |

### 4. Network Indicators (`network_indicators.yar`)

Detects network-related malicious patterns:

| Rule | Description | Confidence |
|------|-------------|------------|
| Network_C2_Beacon_Pattern | Generic C2 beacon patterns | Medium |
| Network_HTTP_Suspicious_Headers | Suspicious HTTP headers | Medium |
| Network_DNS_Tunneling_Indicators | DNS tunneling tools | Medium |
| Network_Reverse_Shell_Connection | Reverse shell connections | High |
| Network_Exfiltration_Patterns | Data exfiltration patterns | Medium |
| Network_Proxy_Tunnel_Config | Proxy/tunnel configuration | Medium |
| Network_SMB_Lateral_Movement | SMB lateral movement | High |
| Network_RDP_Indicators | RDP tunneling/abuse | Medium |
| Network_Suspicious_Port_Patterns | Suspicious port usage | Low |
| Network_TOR_Usage | TOR network indicators | High |
| Network_ICMP_Tunneling | ICMP tunneling | Medium |
| Network_WebSocket_C2 | WebSocket-based C2 | Medium |

### 5. Evasion Techniques (`evasion_techniques.yar`)

Detects defense evasion techniques:

| Rule | Description | Confidence |
|------|-------------|------------|
| Evasion_AMSI_Bypass | AMSI bypass techniques | High |
| Evasion_ETW_Bypass | ETW bypass techniques | High |
| Evasion_UAC_Bypass | UAC bypass techniques | High |
| Evasion_Process_Hollowing | Process hollowing/RunPE | High |
| Evasion_DLL_Injection | DLL injection techniques | High |
| Evasion_Anti_Debug | Anti-debugging techniques | Medium |
| Evasion_Anti_VM | Anti-VM/sandbox techniques | Medium |
| Evasion_Obfuscation_Strings | String obfuscation | Medium |
| Evasion_Code_Injection_Techniques | Various code injection | High |
| Evasion_Living_Off_The_Land | LOLBAS/LOLBIN usage | Medium |
| Evasion_Timestomping | Timestamp manipulation | Medium |
| Evasion_Log_Tampering | Log tampering/clearing | High |
| Evasion_Defense_Disabling | Disabling security tools | High |

## Output Formats

### JSON Output

```json
{
  "scan_time": "2026-01-10T12:00:00",
  "total_files": 10,
  "files_with_matches": 2,
  "total_matches": 3,
  "matches": [
    {
      "rule": "Tool_Mimikatz_Strings",
      "namespace": "tool_artifacts",
      "tags": [],
      "meta": {
        "author": "Detection Engineering Team",
        "description": "Detects Mimikatz credential dumping tool",
        "confidence": "high",
        "severity": "critical"
      },
      "strings": [...],
      "file_path": "/path/to/file.exe",
      "file_hash": "sha256...",
      "file_size": 12345,
      "timestamp": "2026-01-10T12:00:00"
    }
  ],
  "errors": [],
  "rules_loaded": 5
}
```

### CSV Output

```csv
rule,namespace,file_path,file_hash,severity,confidence,timestamp
Tool_Mimikatz_Strings,tool_artifacts,/path/to/file.exe,sha256...,critical,high,2026-01-10T12:00:00
```

### Text Output (Default)

```
============================================================
YARA SCAN REPORT
============================================================
Scan Time: 2026-01-10T12:00:00
Rules Loaded: 5
Scan Mode: file
Total Files Scanned: 1
Files with Matches: 1
Total Matches: 1

------------------------------------------------------------
MATCHES
------------------------------------------------------------

[MATCH] Tool_Mimikatz_Strings
  Namespace: tool_artifacts
  File: /path/to/file.exe
  Hash: sha256...
  Size: 12345 bytes
  Metadata:
    author: Detection Engineering Team
    description: Detects Mimikatz credential dumping tool
    confidence: high
    severity: critical
  Matched Strings:
    0x00001000: $mimikatz = mimikatz

============================================================
```

## Running Tests

```bash
# Run all tests
cd /path/to/yara
python -m pytest tests/ -v

# Or use the test script directly
python tests/test_yara_rules.py
```

## Writing Custom Rules

### Rule Template

```yara
rule Custom_Detection_Name {
    meta:
        author = "Your Name"
        description = "Description of what this rule detects"
        date = "YYYY-MM-DD"
        version = "1.0"
        reference = "URL or internal reference"
        tlp = "amber"
        confidence = "high|medium|low"
        severity = "critical|high|medium|low"
        category = "payload|shellcode|tool|network|evasion"

    strings:
        // Unique strings
        $string1 = "unique_value" ascii wide nocase

        // Byte patterns
        $bytes1 = { DE AD BE EF ?? ?? 90 90 }

        // Regular expressions
        $regex1 = /pattern[0-9]{2,4}/ ascii

    condition:
        // File type check (optional)
        uint16(0) == 0x5A4D and

        // Size constraint (recommended)
        filesize < 10MB and

        // Detection logic
        (2 of ($string*) or $bytes1)
}
```

### Best Practices

1. **Always include metadata**: Author, description, date, confidence, severity
2. **Use file type constraints**: Check magic bytes for efficiency
3. **Set filesize limits**: Prevent scanning very large files
4. **Test for false positives**: Scan benign files before deployment
5. **Use descriptive variable names**: Makes rules self-documenting
6. **Combine weak indicators**: Multiple weak signals create strong detection
7. **Document regex patterns**: Complex patterns need comments

## Performance Considerations

- Place fast conditions first (filesize, magic bytes)
- Avoid overly broad regex patterns
- Use `fullword` modifier when appropriate
- Test rules against large file sets for performance
- Consider using YARA's `-p` flag for parallel scanning

## Legal Notice

These YARA rules are provided for educational and authorized security testing purposes only. Use of these rules for unauthorized access to computer systems is illegal. Always ensure you have proper authorization before scanning systems or files.

## References

- [YARA Documentation](https://yara.readthedocs.io/)
- [YARA Rules GitHub](https://github.com/Yara-Rules/rules)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)
