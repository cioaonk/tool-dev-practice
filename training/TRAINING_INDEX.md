# CPTC11 Training Index

A complete catalog of all training materials with descriptions, skill levels, and cross-references.

---

## Complete Index of All Training Materials

### Curriculum Documents

| Document | Location | Description |
|----------|----------|-------------|
| **README.md** | `training/README.md` | Quick start guide, learning paths, and program orientation |
| **TRAINING_INDEX.md** | `training/TRAINING_INDEX.md` | This file - complete index and cross-references |
| **GLOSSARY.md** | `training/GLOSSARY.md` | Comprehensive term definitions from A-Z with skill level indicators, common abbreviations, and port reference tables |

### Tool Guides (Walkthroughs)

| Document | Location | Skill Level | Description |
|----------|----------|-------------|-------------|
| **Network Scanner Walkthrough** | `walkthroughs/network-scanner-walkthrough.md` | [B/I] | Comprehensive 800+ line guide covering host discovery, port scanning, service fingerprinting, and DNS enumeration. Includes conceptual foundations, tool deep-dives, practical workflows, and troubleshooting. |
| **Payload Generator Walkthrough** | `walkthroughs/payload-generator-walkthrough.md` | [I] | Complete guide to payload creation covering reverse shells, web shells, shellcode encoding, and handler setup. Includes detection vectors and delivery strategies. |
| **EDR Evasion Walkthrough** | `walkthroughs/edr-evasion-walkthrough.md` | [A] | Advanced module on Endpoint Detection and Response evasion. Covers user-mode hooks, direct syscalls, AMSI bypass concepts, API hashing, and MITRE ATT&CK mapping. |

### Lab Exercises

| Lab | Location | Skill Level | Time Estimate | Description |
|-----|----------|-------------|---------------|-------------|
| **Lab 01: Network Reconnaissance** | `labs/lab-01-network-reconnaissance.md` | [B] | 60-90 min | Host discovery, port scanning, service fingerprinting, DNS enumeration, and attack surface documentation. 6 tasks plus 3 challenge tasks. |
| **Lab 02: Service Exploitation** | `labs/lab-02-service-exploitation.md` | [I] | 60-90 min | SMB enumeration, web service analysis, vulnerability mapping, and attack vector prioritization. Prerequisites: Lab 01. |
| **Lab 03: Credential Attacks** | `labs/lab-03-credential-attacks.md` | [I] | 60-90 min | Credential validation, hash cracking, dictionary attacks, rule-based attacks, and credential reuse testing. Prerequisites: Labs 01-02. |
| **Lab 04: Payload Delivery** | `labs/lab-04-payload-delivery.md` | [I/A] | 90-120 min | Reverse shell generation, handler setup, encoding, web shells, shellcode encoding, and multi-stage payloads. Prerequisites: Labs 01-03 plus Payload Walkthrough. |
| **Lab 05: Evasion Techniques** | `labs/lab-05-evasion-techniques.md` | [A] | 90-120 min | API hooks, syscall generation, API hashing, encoding analysis, MITRE ATT&CK mapping, and evasion strategy design. Prerequisites: Labs 01-04 plus EDR Walkthrough. |

### Cheatsheets

| Document | Location | Description |
|----------|----------|-------------|
| **Tool Commands Cheatsheet** | `cheatsheets/tool-commands-cheatsheet.md` | Universal reference for all toolkit commands. Covers network scanner, port scanner, service fingerprinter, DNS enumerator, SMB enumerator, credential validator, hash cracker, payload generator, reverse shell handler, shellcode encoder, and EDR evasion toolkit. |
| **Network Scanning Cheatsheet** | `cheatsheets/network-scanning-cheatsheet.md` | Quick reference for reconnaissance and enumeration including host discovery patterns, port scanning presets, fingerprinting commands, common port reference, and workflow templates. |
| **Payload Generation Cheatsheet** | `cheatsheets/payload-generation-cheatsheet.md` | Quick reference for payload creation including reverse shell commands, encoding options, obfuscation levels, handler setup, web shells, shellcode encoding, and delivery methods. |

---

## Materials by Skill Level

### Beginner Materials [B]

Materials appropriate for those with 0-1 years experience or new to offensive security.

| Material | Type | Focus Area |
|----------|------|------------|
| GLOSSARY.md | Reference | Term definitions and foundational concepts |
| Network Scanner Walkthrough | Walkthrough | Core reconnaissance techniques |
| Lab 01: Network Reconnaissance | Lab | Host discovery, port scanning, service enumeration |
| Network Scanning Cheatsheet | Cheatsheet | Quick command reference for recon |
| Tool Commands Cheatsheet | Cheatsheet | Universal command reference |

**Recommended Sequence:**
1. GLOSSARY.md
2. Network Scanner Walkthrough
3. Lab 01 (Tasks 1-4)
4. Network Scanning Cheatsheet

### Intermediate Materials [I]

Materials appropriate for those with 1-3 years experience or CTF background.

| Material | Type | Focus Area |
|----------|------|------------|
| Network Scanner Walkthrough | Walkthrough | Advanced scanning techniques |
| Payload Generator Walkthrough | Walkthrough | Payload creation and delivery |
| Lab 01: Network Reconnaissance | Lab | Challenge tasks and stealth scanning |
| Lab 02: Service Exploitation | Lab | SMB enumeration, web analysis |
| Lab 03: Credential Attacks | Lab | Hash cracking, credential validation |
| Lab 04: Payload Delivery | Lab | Shell generation, encoding |
| Payload Generation Cheatsheet | Cheatsheet | Payload command reference |

**Recommended Sequence:**
1. Complete Beginner sequence
2. Lab 01 Challenge Tasks
3. Lab 02 all tasks
4. Lab 03 all tasks
5. Payload Generator Walkthrough
6. Lab 04 (Tasks 1-5)

### Advanced Materials [A]

Materials appropriate for those with 3+ years experience requiring deep technical knowledge.

| Material | Type | Focus Area |
|----------|------|------------|
| EDR Evasion Walkthrough | Walkthrough | Hooks, syscalls, AMSI, detection bypass |
| Lab 04: Payload Delivery | Lab | Multi-stage payloads, platform selection |
| Lab 05: Evasion Techniques | Lab | Syscall stubs, API hashing, strategy design |

**Recommended Sequence:**
1. Complete Intermediate sequence
2. EDR Evasion Walkthrough
3. Lab 04 (Tasks 6-7 and Challenges)
4. Lab 05 all tasks

---

## Materials by Topic

### Reconnaissance

| Material | Type | Specific Topics |
|----------|------|-----------------|
| Network Scanner Walkthrough | Walkthrough | Host discovery, TCP scanning, ARP, DNS |
| Lab 01: Network Reconnaissance | Lab | Network mapping, service enumeration |
| Network Scanning Cheatsheet | Cheatsheet | Quick scan commands |
| GLOSSARY.md | Reference | Recon terminology |

**Tools Covered:** network-scanner, port-scanner, dns-enumerator

### Enumeration

| Material | Type | Specific Topics |
|----------|------|-----------------|
| Network Scanner Walkthrough (Part 4-5) | Walkthrough | Service fingerprinting, DNS enumeration |
| Lab 01 (Tasks 3-4) | Lab | Service and DNS enumeration |
| Lab 02: Service Exploitation | Lab | SMB shares, web enumeration |
| Tool Commands Cheatsheet | Cheatsheet | SMB, service, DNS commands |

**Tools Covered:** service-fingerprinter, dns-enumerator, smb-enumerator, web-directory-enumerator

### Exploitation

| Material | Type | Specific Topics |
|----------|------|-----------------|
| Lab 02: Service Exploitation | Lab | Service misconfigurations, attack vectors |
| Lab 03: Credential Attacks | Lab | Credential validation, hash cracking |
| Lab 04: Payload Delivery | Lab | Shell execution, payload delivery |
| Tool Commands Cheatsheet | Cheatsheet | Credential, hash commands |

**Tools Covered:** credential-validator, hash-cracker, http-request-tool

### Evasion

| Material | Type | Specific Topics |
|----------|------|-----------------|
| EDR Evasion Walkthrough | Walkthrough | Hooks, syscalls, AMSI, ETW |
| Lab 05: Evasion Techniques | Lab | Technique application, strategy |
| Payload Generator Walkthrough | Walkthrough | Encoding, obfuscation |

**Tools Covered:** edr-evasion-toolkit, shellcode-encoder, amsi-bypass

### Detection (Blue Team Focus)

| Material | Type | Specific Topics |
|----------|------|-----------------|
| EDR Evasion Walkthrough (Detection sections) | Walkthrough | How defenses detect attacks |
| Lab 05 Task 8 | Lab | Detection perspective exercises |
| All cheatsheets (OPSEC sections) | Cheatsheet | What gets logged, detection triggers |
| GLOSSARY.md | Reference | Security tool definitions |

### Development

| Material | Type | Specific Topics |
|----------|------|-----------------|
| Tool README files | Reference | Tool architecture, API usage |
| Tool Commands Cheatsheet | Cheatsheet | JSON output formats |
| python/tui/ source code | Source | TUI component architecture |
| python/tests/ | Source | Testing patterns |

### Infrastructure

| Material | Type | Specific Topics |
|----------|------|-----------------|
| README.md | Guide | Environment setup |
| Lab environment sections | Lab | Network configuration |
| Payload Generator Walkthrough | Walkthrough | Handler infrastructure |
| All labs (Environment Setup) | Lab | Lab network configurations |

---

## Cross-Reference Tables

### Tool to Training Document Mapping

| Tool | README | Walkthrough | Lab | Cheatsheet |
|------|--------|-------------|-----|------------|
| network-scanner | `python/tools/network-scanner/README.md` | Network Scanner Walkthrough | Lab 01 | Network Scanning Cheatsheet |
| port-scanner | `python/tools/port-scanner/README.md` | Network Scanner Walkthrough | Lab 01 | Network Scanning Cheatsheet |
| service-fingerprinter | `python/tools/service-fingerprinter/README.md` | Network Scanner Walkthrough | Lab 01, Lab 02 | Network Scanning Cheatsheet |
| dns-enumerator | `python/tools/dns-enumerator/README.md` | Network Scanner Walkthrough | Lab 01 | Network Scanning Cheatsheet |
| smb-enumerator | `python/tools/smb-enumerator/README.md` | - | Lab 02 | Tool Commands Cheatsheet |
| web-directory-enumerator | `python/tools/web-directory-enumerator/README.md` | - | Lab 02 | Tool Commands Cheatsheet |
| http-request-tool | `python/tools/http-request-tool/README.md` | - | Lab 02 | Tool Commands Cheatsheet |
| credential-validator | `python/tools/credential-validator/README.md` | - | Lab 03 | Tool Commands Cheatsheet |
| hash-cracker | `python/tools/hash-cracker/README.md` | - | Lab 03 | Tool Commands Cheatsheet |
| payload-generator | - | Payload Generator Walkthrough | Lab 04 | Payload Generation Cheatsheet |
| reverse-shell-handler | `python/tools/reverse-shell-handler/README.md` | Payload Generator Walkthrough | Lab 04 | Payload Generation Cheatsheet |
| shellcode-encoder | - | Payload Generator Walkthrough | Lab 04, Lab 05 | Payload Generation Cheatsheet |
| edr-evasion-toolkit | - | EDR Evasion Walkthrough | Lab 05 | Tool Commands Cheatsheet |

### Lab to Environment Mapping

| Lab | Network Range | Key Targets | Domain | Required Services |
|-----|---------------|-------------|--------|-------------------|
| Lab 01 | 10.10.10.0/24 | Gateway (10.10.10.1), DNS (10.10.10.2), DC (10.10.10.10), Web (10.10.10.20), File (10.10.10.30) | corp.local | SSH, HTTP, HTTPS, SMB, DNS |
| Lab 02 | 10.10.10.0/24 | File Server (10.10.10.30), Web Server (10.10.10.20), DC (10.10.10.10) | corp.local | SMB, HTTP, FTP |
| Lab 03 | 10.10.10.0/24 | FTP (10.10.10.30), Web (10.10.10.20), Mail (10.10.10.25) | corp.local | FTP, HTTP, SMTP |
| Lab 04 | 10.10.10.0/24 | Linux Web (10.10.10.20), Linux WS (10.10.10.50), Windows WS (10.10.10.60) | - | PHP, Python, PowerShell |
| Lab 05 | Simulated | Windows 10 Workstation, Windows Server 2019 | - | EDR simulation, AMSI |

### Prerequisites Chain

```
GLOSSARY.md
     |
     v
Network Scanner Walkthrough -----> Lab 01 -----> Lab 02 -----> Lab 03
                                                                  |
                                                                  v
Payload Generator Walkthrough --------------------------------> Lab 04
                                                                  |
                                                                  v
EDR Evasion Walkthrough --------------------------------------> Lab 05
```

### Difficulty Progression by Task Level

| Level | Description | Labs Containing |
|-------|-------------|-----------------|
| Level 1 (Foundation) | Guided exercises with detailed instructions | Lab 01 Tasks 1-2, Lab 02 Tasks 1-2, Lab 03 Tasks 1-4, Lab 04 Tasks 1-2, Lab 05 Tasks 1-2 |
| Level 2 (Application) | Semi-guided with strategic hints | Lab 01 Tasks 3-4, Lab 02 Tasks 3-4, Lab 03 Tasks 5-6, Lab 04 Tasks 3-4, Lab 05 Tasks 3-5 |
| Level 3 (Integration) | Minimal guidance, realistic scenarios | Lab 01 Tasks 5-6, Lab 02 Tasks 5-6, Lab 03 Tasks 7-8, Lab 04 Tasks 5-7, Lab 05 Tasks 6-8 |
| Level 4 (Mastery) | Complex challenges requiring creative problem-solving | All Labs - Challenge Tasks section |

---

## Quick Navigation

### By Task Type

- **I need to learn reconnaissance**: Start with Network Scanner Walkthrough
- **I need to practice enumeration**: Complete Lab 01 and Lab 02
- **I need to understand credentials**: Complete Lab 03
- **I need to create payloads**: Read Payload Generator Walkthrough, complete Lab 04
- **I need to evade defenses**: Read EDR Evasion Walkthrough, complete Lab 05
- **I need quick command reference**: Use appropriate Cheatsheet
- **I need term definitions**: Consult GLOSSARY.md

### By Time Available

| Time | Recommended Activity |
|------|---------------------|
| 15 minutes | Quick Start Guide in README.md |
| 30 minutes | Review relevant Cheatsheet |
| 60 minutes | Complete 2-3 lab tasks |
| 90 minutes | Complete one full lab |
| 2-3 hours | Complete one walkthrough with practice |
| Full day | Complete one phase of learning path |

### By Competition Preparation

| Competition Type | Focus Materials |
|------------------|-----------------|
| CTF (Time-limited) | Cheatsheets, Labs 01-04 |
| CPTC | All materials, emphasis on documentation |
| Red Team | Labs 04-05, EDR Evasion Walkthrough |
| Certification prep | Walkthroughs, all labs with solutions |

---

## Document Statistics

| Category | Count | Total Lines (approx) |
|----------|-------|---------------------|
| Walkthroughs | 3 | 2,700+ |
| Labs | 5 | 2,400+ |
| Cheatsheets | 3 | 1,300+ |
| Reference (Glossary) | 1 | 380+ |
| Index Documents | 2 | 600+ |
| **Total Training Documents** | **14** | **7,400+** |

---

*Index Version: 1.0.0 | Last Updated: January 2026*
