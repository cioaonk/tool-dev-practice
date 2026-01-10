# CPTC Offensive Security Training Materials

A comprehensive training program for mastering the offensive security toolkit designed for CTF and CPTC competition preparation.

## Overview

This training package provides structured learning materials for the CPTC offensive security toolkit, progressing from fundamental concepts through advanced techniques. All materials are designed for authorized security testing and competition environments.

## Directory Structure

```
training/
├── README.md                      # This file
├── walkthroughs/                  # Detailed tool guides
│   ├── network-scanner-walkthrough.md
│   ├── payload-generator-walkthrough.md
│   └── edr-evasion-walkthrough.md
├── labs/                          # Hands-on exercises
│   ├── lab-01-network-reconnaissance.md
│   ├── lab-02-service-exploitation.md
│   ├── lab-03-credential-attacks.md
│   ├── lab-04-payload-delivery.md
│   └── lab-05-evasion-techniques.md
└── cheatsheets/                   # Quick reference cards
    ├── tool-commands-cheatsheet.md
    ├── network-scanning-cheatsheet.md
    └── payload-generation-cheatsheet.md
```

## Prerequisites

### Technical Requirements

- Python 3.6+ installed and accessible via `python3`
- Network access to target lab environment (isolated/sandboxed)
- Root/Administrator access for certain scanning techniques
- Basic familiarity with command-line interfaces

### Knowledge Requirements

| Skill Level | Prerequisites |
|-------------|---------------|
| **Beginner** | Basic networking (IP addresses, ports, protocols) |
| | Command line navigation |
| | Understanding of client-server architecture |
| **Intermediate** | TCP/IP stack fundamentals |
| | Common service protocols (HTTP, SSH, FTP, SMB) |
| | Basic scripting (Python/Bash) |
| **Advanced** | Operating system internals (process, memory) |
| | Windows API and syscall concepts |
| | Detection mechanisms (IDS/IPS, EDR, AV) |

## Skill Progression Path

### Phase 1: Foundation (Weeks 1-2)

**Objective**: Master reconnaissance and enumeration techniques

1. **Start Here**: Read `walkthroughs/network-scanner-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-01-network-reconnaissance.md`
3. **Reference**: Keep `cheatsheets/network-scanning-cheatsheet.md` handy

**Tools Covered**:
- Network Scanner (host discovery)
- Port Scanner (service detection)
- DNS Enumerator (subdomain discovery)
- Service Fingerprinter (version identification)

**Competencies**:
- [ ] Perform host discovery on a /24 network
- [ ] Identify open ports and running services
- [ ] Enumerate DNS records and subdomains
- [ ] Extract service version information

### Phase 2: Exploitation Preparation (Weeks 3-4)

**Objective**: Identify and validate attack vectors

1. **Lab Exercise**: Complete `labs/lab-02-service-exploitation.md`
2. **Lab Exercise**: Complete `labs/lab-03-credential-attacks.md`

**Tools Covered**:
- SMB Enumerator (share and system enumeration)
- Credential Validator (authentication testing)
- Hash Cracker (offline password recovery)

**Competencies**:
- [ ] Enumerate SMB shares and permissions
- [ ] Validate credentials against multiple protocols
- [ ] Perform dictionary attacks on hash files
- [ ] Identify credential reuse opportunities

### Phase 3: Payload Development (Weeks 5-6)

**Objective**: Generate and deliver payloads effectively

1. **Read**: `walkthroughs/payload-generator-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-04-payload-delivery.md`
3. **Reference**: Use `cheatsheets/payload-generation-cheatsheet.md`

**Tools Covered**:
- Payload Generator (shell creation)
- Shellcode Encoder (payload obfuscation)
- Reverse Shell Handler (connection management)

**Competencies**:
- [ ] Generate platform-appropriate reverse shells
- [ ] Encode payloads to avoid basic detection
- [ ] Set up and manage shell handlers
- [ ] Understand payload delivery mechanisms

### Phase 4: Evasion Techniques (Weeks 7-8)

**Objective**: Bypass defensive controls

1. **Read**: `walkthroughs/edr-evasion-walkthrough.md`
2. **Lab Exercise**: Complete `labs/lab-05-evasion-techniques.md`

**Tools Covered**:
- EDR Evasion Toolkit (bypass techniques)
- AMSI Bypass (script execution)
- Process Hollowing (injection techniques)

**Competencies**:
- [ ] Understand EDR hook mechanisms
- [ ] Generate direct syscall stubs
- [ ] Apply appropriate evasion techniques
- [ ] Map techniques to MITRE ATT&CK framework

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

# Test network scanner
python3 /path/to/tools/network-scanner/tool.py 127.0.0.1 --plan

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

- Individual tool README files in `/python/tools/<tool-name>/README.md`
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
