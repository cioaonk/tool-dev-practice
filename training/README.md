# CPTC Offensive Security Training Materials

A comprehensive training program for mastering the offensive security toolkit designed for CTF and CPTC competition preparation.

---

> **New to security?** Start with the [Glossary](GLOSSARY.md) to understand key terms used throughout these materials.

---

## Overview

This training package provides structured learning materials for the CPTC offensive security toolkit, progressing from fundamental concepts through advanced techniques. All materials are designed for authorized security testing and competition environments.

### Skill Level Guide

Throughout these materials, content is marked with skill level indicators:

| Level | Symbol | Description | Experience |
|-------|--------|-------------|------------|
| Beginner | **[B]** | Foundational concepts and guided exercises | 0-1 years |
| Intermediate | **[I]** | Applied techniques with strategic guidance | 1-3 years |
| Advanced | **[A]** | Complex scenarios requiring deep knowledge | 3+ years |

**Recommended Starting Points by Experience:**
- **Complete beginners**: Read the [Glossary](GLOSSARY.md) first, then start with Phase 1
- **CTF experience**: Start with the Network Scanner Walkthrough
- **Professional experience**: Review cheatsheets, focus on competition-specific labs

## Directory Structure

```
training/
├── README.md                      # This file
├── GLOSSARY.md                    # Term definitions and quick reference
├── walkthroughs/                  # Detailed tool guides
│   ├── network-scanner-walkthrough.md    [B/I]
│   ├── payload-generator-walkthrough.md  [I]
│   └── edr-evasion-walkthrough.md        [A]
├── labs/                          # Hands-on exercises
│   ├── lab-01-network-reconnaissance.md  [B]
│   ├── lab-02-service-exploitation.md    [I]
│   ├── lab-03-credential-attacks.md      [I]
│   ├── lab-04-payload-delivery.md        [I/A]
│   └── lab-05-evasion-techniques.md      [A]
├── cheatsheets/                   # Quick reference cards
│   ├── tool-commands-cheatsheet.md
│   ├── network-scanning-cheatsheet.md
│   └── payload-generation-cheatsheet.md
└── feedback/                      # Training feedback reports
```

## Prerequisites

### Technical Requirements

- Python 3.8+ installed and accessible via `python3`
- Network access to target lab environment (isolated/sandboxed)
- Root/Administrator access for certain scanning techniques (see note below)
- Basic familiarity with command-line interfaces (bash, PowerShell, or cmd)

> **Note on Root/Administrator Access**: Some scanning techniques (SYN scans, ARP discovery) require elevated privileges because they use raw network sockets. If you do not have root access, the tools will fall back to standard TCP connect scans, which work without special privileges but are more detectable.

### Knowledge Requirements

| Skill Level | Prerequisites | What This Means |
|-------------|---------------|-----------------|
| **Beginner [B]** | Basic networking | Understand what IP addresses (e.g., 192.168.1.1) and ports (e.g., 80, 443) are. See [Glossary](GLOSSARY.md) for definitions. |
| | Command line navigation | Can open a terminal, navigate directories (cd), run commands |
| | Client-server architecture | Know that clients request and servers respond |
| **Intermediate [I]** | TCP/IP fundamentals | Understand the three-way handshake (SYN, SYN-ACK, ACK) |
| | Common protocols | Know what HTTP, SSH, FTP, SMB do at a high level |
| | Basic scripting | Can write simple Python or Bash scripts |
| **Advanced [A]** | OS internals | Understand processes, memory management, DLLs |
| | Windows API/syscalls | Know how applications interact with the OS kernel |
| | Detection mechanisms | Familiar with how IDS, EDR, and AV detect threats |

> **Not sure about your level?** If you do not understand most terms in the Beginner row, start with the [Glossary](GLOSSARY.md) and external resources in the Support section.

## Skill Progression Path

> **Visual Learning Path**: Start at Phase 1 and work through sequentially. Each phase builds on the previous.
>
> ```
> Phase 1 [B]      Phase 2 [I]       Phase 3 [I]       Phase 4 [A]
> Reconnaissance -> Enumeration  ->  Payloads     ->  Evasion
>       |              |                |               |
>   Network        Services         Shells          EDR Bypass
>   Scanning       Credentials      Encoding        Syscalls
> ```

### Phase 1: Foundation (Weeks 1-2) [B]

**Objective**: Master reconnaissance and enumeration techniques

> **What is reconnaissance?** The information-gathering phase where you discover what systems exist and what services they run. Think of it as mapping the terrain before a journey.

1. **Start Here**: Read `walkthroughs/network-scanner-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-01-network-reconnaissance.md`
3. **Reference**: Keep `cheatsheets/network-scanning-cheatsheet.md` handy

**Tools Covered**:
- Network Scanner - discovers live hosts (which computers are on the network)
- Port Scanner - finds open ports (which services are available)
- DNS Enumerator - discovers subdomains (finds additional related systems)
- Service Fingerprinter - identifies versions (what software is running)

**Competencies**:
- [ ] Perform host discovery on a /24 network (a /24 contains 256 IP addresses)
- [ ] Identify open ports and running services
- [ ] Enumerate DNS records and subdomains
- [ ] Extract service version information

### Phase 2: Exploitation Preparation (Weeks 3-4) [I]

**Objective**: Identify and validate attack vectors

> **What is enumeration?** Going deeper than reconnaissance to extract detailed information - usernames, file shares, configurations - that reveals how to gain access.

1. **Lab Exercise**: Complete `labs/lab-02-service-exploitation.md`
2. **Lab Exercise**: Complete `labs/lab-03-credential-attacks.md`

**Tools Covered**:
- SMB Enumerator - finds Windows file shares and system information
- Credential Validator - tests username/password combinations against services
- Hash Cracker - recovers passwords from hash values (one-way encrypted passwords)

**Competencies**:
- [ ] Enumerate SMB shares and permissions
- [ ] Validate credentials against multiple protocols
- [ ] Perform dictionary attacks on hash files
- [ ] Identify credential reuse opportunities

### Phase 3: Payload Development (Weeks 5-6) [I]

**Objective**: Generate and deliver payloads effectively

> **What is a payload?** Code that runs on a target system to provide access. A reverse shell payload makes the target connect back to you, giving you a command line on that system.

1. **Read**: `walkthroughs/payload-generator-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-04-payload-delivery.md`
3. **Reference**: Use `cheatsheets/payload-generation-cheatsheet.md`

**Tools Covered**:
- Payload Generator - creates reverse shell code for different platforms
- Shellcode Encoder - transforms payload to avoid detection signatures
- Reverse Shell Handler - listens for and manages incoming shell connections

**Competencies**:
- [ ] Generate platform-appropriate reverse shells
- [ ] Encode payloads to avoid basic detection
- [ ] Set up and manage shell handlers
- [ ] Understand payload delivery mechanisms

### Phase 4: Evasion Techniques (Weeks 7-8) [A]

**Objective**: Bypass defensive controls

> **Prerequisite Warning**: This phase requires understanding of Windows internals, memory management, and API concepts. Complete all previous phases before attempting.

> **What is EDR?** Endpoint Detection and Response - advanced security software that monitors system behavior, not just known malware signatures. Evading EDR requires understanding how it detects threats.

1. **Read**: `walkthroughs/edr-evasion-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-05-evasion-techniques.md`

**Tools Covered**:
- EDR Evasion Toolkit - generates code to bypass security monitoring
- AMSI Bypass - allows PowerShell scripts to run without being scanned
- Process Hollowing - hides malicious code inside legitimate processes

**Competencies**:
- [ ] Understand EDR hook mechanisms (how security software intercepts API calls)
- [ ] Generate direct syscall stubs (calling the OS kernel directly)
- [ ] Apply appropriate evasion techniques based on target defenses
- [ ] Map techniques to MITRE ATT&CK framework (industry-standard threat classification)

## How to Use These Materials

### Walkthroughs

Walkthroughs provide comprehensive, step-by-step guidance for each tool category. They include:

- **Conceptual Foundation**: Theory behind the techniques
- **Tool Deep-Dive**: Detailed feature exploration
- **Practical Examples**: Real command sequences with expected output
- **Troubleshooting**: Common issues and solutions

**Recommended Approach**:
1. Read the entire walkthrough once for overview
2. Follow along with commands in your lab environment
3. Experiment with variations on the examples
4. Return to specific sections as reference material

### Lab Exercises

Labs provide hands-on challenges with progressive difficulty:

- **Level 1 (Foundation)**: Guided exercises with detailed instructions
- **Level 2 (Application)**: Semi-guided with strategic hints
- **Level 3 (Integration)**: Minimal guidance, realistic scenarios
- **Level 4 (Mastery)**: Complex challenges for competition preparation

**Lab Structure**:
1. **Objective**: What you will accomplish
2. **Environment**: Required setup and configuration
3. **Scenario**: Realistic operational context
4. **Tasks**: Specific deliverables
5. **Hints**: Progressive assistance (try without first)
6. **Solution**: Complete walkthrough (instructor use)
7. **Validation**: How to verify success

### Cheatsheets

Quick reference cards for rapid command lookup during:
- Competition time pressure
- Real engagement scenarios
- Quick refresher before assessments

**Note**: Understand the commands fully before relying on cheatsheets. They supplement, not replace, deep knowledge.

## Competition Preparation Tips

### Time Management

| Phase | Typical Allocation |
|-------|-------------------|
| Reconnaissance | 20-25% |
| Service Enumeration | 15-20% |
| Vulnerability Assessment | 20-25% |
| Exploitation | 25-30% |
| Documentation | 10-15% |

### Operational Discipline

1. **Always use planning mode first** (`--plan`) in competition environments
2. **Document everything** - timestamps, commands, outputs
3. **Validate findings** before reporting
4. **Maintain stealth** where required by competition rules
5. **Rotate techniques** to avoid detection patterns

### Common Mistakes to Avoid

- Scanning too aggressively and triggering alerts
- Missing easy wins while chasing complex exploits
- Forgetting to enumerate thoroughly before exploiting
- Not validating credentials across multiple services
- Neglecting documentation during time pressure

## Environment Setup

### Lab Network Requirements

```
Attacker Machine (Your System)
├── Python 3.6+
├── Network access to lab range
└── All toolkit tools installed

Target Lab Network (Isolated)
├── Various target hosts
├── Multiple services (HTTP, SSH, SMB, etc.)
└── Simulated enterprise environment
```

### Verification Commands

```bash
# Verify Python version
python3 --version

# Test network scanner (from project root)
python3 python/tools/network-scanner/tool.py 127.0.0.1 --plan

# Verify connectivity to lab
ping <lab-gateway-ip>
```

## Safety and Ethics

### Authorized Use Only

All tools and techniques in this training are for:
- Authorized penetration testing engagements
- CTF and CPTC competitions
- Educational lab environments
- Security research with proper authorization

### Never Use Against

- Systems you do not own or have written authorization to test
- Production environments without explicit approval
- Third-party systems without contracts in place
- Public networks or internet-facing targets without authorization

### Competition Ethics

- Follow all competition rules and scope limitations
- Report discovered vulnerabilities appropriately
- Do not interfere with other teams
- Maintain professionalism in all interactions

## Support and Resources

### Documentation

- Individual tool README files in `python/tools/<tool-name>/README.md`
- This training guide and associated materials
- Planning mode output for any tool (`--plan` flag)

### Practice Environments

- HTB Academy (education.hackthebox.com)
- TryHackMe (tryhackme.com)
- Local lab environments (Docker/VM-based)
- Past CPTC practice packets

### External References

- MITRE ATT&CK Framework (attack.mitre.org)
- OWASP Testing Guide (owasp.org)
- PTES Technical Guidelines (pentest-standard.org)

## Assessment Checklist

Before competition, ensure you can:

### Reconnaissance
- [ ] Discover live hosts on a network segment
- [ ] Identify open ports using multiple scan types
- [ ] Enumerate DNS records and subdomains
- [ ] Fingerprint services and extract versions

### Credential Attacks
- [ ] Validate credentials against FTP, HTTP, SMTP
- [ ] Perform dictionary attacks on password hashes
- [ ] Identify default/weak credentials

### Payload Operations
- [ ] Generate reverse shells for multiple platforms
- [ ] Encode payloads to avoid null bytes
- [ ] Set up handlers and manage sessions

### Evasion
- [ ] Understand EDR detection mechanisms
- [ ] Generate syscall stubs for API bypass
- [ ] Apply appropriate obfuscation techniques

## Version Information

| Component | Version |
|-----------|---------|
| Training Materials | 1.0.0 |
| Toolkit Version | 1.0.0 |
| Last Updated | January 2026 |

---

**Remember**: Success in competitions comes from thorough preparation, methodical execution, and continuous learning. Master the fundamentals, practice regularly, and stay curious.

Good luck with your training and competitions!
