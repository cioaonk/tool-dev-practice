# Welcome to CPTC11 Training

A comprehensive offensive security training program designed for CTF competitions, CPTC preparation, and professional security assessments. This library provides structured learning materials that progress from fundamental concepts through advanced evasion techniques.

---

## Prerequisites

### Required Skills

Before starting this training program, you should have:

- **Basic Networking Knowledge**: Understand IP addresses, ports, and client-server architecture
- **Command Line Proficiency**: Navigate directories, run commands, and edit files from terminal
- **Programming Fundamentals**: Basic familiarity with Python scripting

### Software Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.8+ | Tool execution and scripting |
| Git | Latest | Version control and updates |
| Terminal | bash/zsh/PowerShell | Command execution |
| Text Editor | Any | Reviewing and editing files |

### Environment Setup

1. **Verify Python Installation**
```bash
python3 --version
# Expected: Python 3.8.x or higher
```

2. **Clone or Access the Repository**
```bash
cd /path/to/cptc11
```

3. **Install Dependencies**
```bash
pip3 install -r python/tools/environment/requirements.txt
```

4. **Verify Network Access**
   - Ensure you have connectivity to your lab environment
   - Confirm firewall rules allow required traffic
   - Never test against unauthorized systems

---

## Quick Start Guide

Get up and running in 15 minutes with this accelerated introduction.

### Step 1: Environment Verification (3 minutes)

```bash
# Verify Python
python3 --version

# Test a tool (planning mode is safe)
python3 python/tools/network-scanner/tool.py 127.0.0.1 --plan
```

If you see the planning output without errors, your environment is correctly configured.

### Step 2: First Tool Execution (5 minutes)

Run your first network scan against localhost:

```bash
# Preview what will happen
python3 python/tools/network-scanner/tool.py 127.0.0.1 --plan

# Execute the scan
python3 python/tools/network-scanner/tool.py 127.0.0.1 --verbose
```

Expected output shows any services running on your local machine.

### Step 3: Review Key Concepts (5 minutes)

Open and read the [Glossary](GLOSSARY.md) to familiarize yourself with essential terms:
- Reconnaissance
- Port
- Service
- Payload
- Handler

### Step 4: First Lab Preparation (2 minutes)

Navigate to your first lab exercise:

```bash
# Review Lab 01
cat training/labs/lab-01-network-reconnaissance.md
```

You are now ready to begin the structured training program.

---

## Learning Paths

Choose the path that matches your experience level and goals.

### Beginner Path (4-6 weeks)

For those new to offensive security or with limited practical experience.

1. **Week 1-2: Foundation**
   - Read [GLOSSARY.md](GLOSSARY.md) thoroughly
   - Complete [Network Scanner Walkthrough](walkthroughs/network-scanner-walkthrough.md)
   - Finish [Lab 01: Network Reconnaissance](labs/lab-01-network-reconnaissance.md)
   - Reference [Network Scanning Cheatsheet](cheatsheets/network-scanning-cheatsheet.md)

2. **Week 3-4: Enumeration**
   - Complete [Lab 02: Service Exploitation](labs/lab-02-service-exploitation.md)
   - Complete [Lab 03: Credential Attacks](labs/lab-03-credential-attacks.md)
   - Study [Tool Commands Cheatsheet](cheatsheets/tool-commands-cheatsheet.md)

3. **Week 5-6: Introduction to Payloads**
   - Read [Payload Generator Walkthrough](walkthroughs/payload-generator-walkthrough.md)
   - Complete [Lab 04: Payload Delivery](labs/lab-04-payload-delivery.md) (Level 1-2 tasks only)
   - Reference [Payload Generation Cheatsheet](cheatsheets/payload-generation-cheatsheet.md)

### Intermediate Path (3-4 weeks)

For those with CTF experience or 1-3 years security background.

1. **Week 1: Reconnaissance Mastery**
   - Review [Network Scanner Walkthrough](walkthroughs/network-scanner-walkthrough.md)
   - Complete [Lab 01](labs/lab-01-network-reconnaissance.md) including Challenge Tasks
   - Complete [Lab 02](labs/lab-02-service-exploitation.md) all tasks

2. **Week 2: Credential and Service Attacks**
   - Complete [Lab 03: Credential Attacks](labs/lab-03-credential-attacks.md) all tasks
   - Practice tool chaining for efficient enumeration

3. **Week 3-4: Payload Operations**
   - Study [Payload Generator Walkthrough](walkthroughs/payload-generator-walkthrough.md)
   - Complete [Lab 04: Payload Delivery](labs/lab-04-payload-delivery.md) all tasks
   - Begin [EDR Evasion Walkthrough](walkthroughs/edr-evasion-walkthrough.md)

### Advanced Path (2-3 weeks)

For experienced practitioners focusing on evasion and advanced techniques.

1. **Week 1: Review and Refinement**
   - Speed-run Labs 01-04 focusing on efficiency
   - Study all cheatsheets for rapid reference
   - Identify personal weak areas

2. **Week 2-3: Evasion Techniques**
   - Complete [EDR Evasion Walkthrough](walkthroughs/edr-evasion-walkthrough.md)
   - Finish [Lab 05: Evasion Techniques](labs/lab-05-evasion-techniques.md) all tasks
   - Practice combining multiple techniques

### Blue Team Path (2-3 weeks)

For defenders seeking to understand offensive techniques.

1. **Week 1: Understand the Attack Surface**
   - [Network Scanner Walkthrough](walkthroughs/network-scanner-walkthrough.md)
   - [Lab 01](labs/lab-01-network-reconnaissance.md) - Focus on detection sections
   - Document what attackers look for and how

2. **Week 2: Detection Opportunities**
   - [Payload Generator Walkthrough](walkthroughs/payload-generator-walkthrough.md) - Focus on detection vectors
   - Review OPSEC notes in cheatsheets
   - [EDR Evasion Walkthrough](walkthroughs/edr-evasion-walkthrough.md) - Focus on "Detection Methods" sections

3. **Week 3: Building Defenses**
   - [Lab 05](labs/lab-05-evasion-techniques.md) Task 8 (Detection Perspective)
   - Create detection rules based on learned techniques
   - Document blue team response procedures

### Developer Path (1-2 weeks)

For those contributing to tool development.

1. **Week 1: Tool Architecture**
   - Review tool README files in `python/tools/*/README.md`
   - Understand planning mode implementation
   - Study JSON output formats

2. **Week 2: Integration**
   - Review test files in `python/tests/`
   - Understand tool chaining patterns
   - Study TUI components in `python/tui/`

---

## Training Materials Overview

### Documentation Structure

```
training/
├── README.md                 # This file - Quick start and orientation
├── TRAINING_INDEX.md         # Complete index of all materials
├── GLOSSARY.md               # Term definitions and quick reference
├── walkthroughs/             # Comprehensive step-by-step guides
│   ├── network-scanner-walkthrough.md    [B/I]
│   ├── payload-generator-walkthrough.md  [I]
│   └── edr-evasion-walkthrough.md        [A]
├── labs/                     # Hands-on exercises
│   ├── lab-01-network-reconnaissance.md  [B]
│   ├── lab-02-service-exploitation.md    [I]
│   ├── lab-03-credential-attacks.md      [I]
│   ├── lab-04-payload-delivery.md        [I/A]
│   └── lab-05-evasion-techniques.md      [A]
├── cheatsheets/              # Quick reference cards
│   ├── tool-commands-cheatsheet.md
│   ├── network-scanning-cheatsheet.md
│   └── payload-generation-cheatsheet.md
└── feedback/                 # Training feedback reports
```

### Skill Level Indicators

| Symbol | Level | Experience | Description |
|--------|-------|------------|-------------|
| [B] | Beginner | 0-1 years | Guided exercises with detailed explanations |
| [I] | Intermediate | 1-3 years | Applied techniques with strategic guidance |
| [A] | Advanced | 3+ years | Complex scenarios requiring deep knowledge |

### Material Types

- **Walkthroughs**: Comprehensive guides with theory, examples, and troubleshooting
- **Labs**: Hands-on exercises with objectives, tasks, hints, and solutions
- **Cheatsheets**: Quick reference cards for commands and workflows
- **Glossary**: Term definitions and concept explanations

---

## Getting Help

### Self-Service Resources

1. **Glossary**: Check [GLOSSARY.md](GLOSSARY.md) for term definitions
2. **Planning Mode**: Use `--plan` flag on any tool to preview operations
3. **Help Flags**: Run any tool with `--help` for usage information
4. **Lab Hints**: Each lab includes progressive hints in collapsible sections

### Troubleshooting Common Issues

| Issue | Solution |
|-------|----------|
| "Module not found" | Run `pip3 install -r requirements.txt` |
| "Permission denied" | Some scans require root/admin privileges |
| "Connection refused" | Verify target is reachable and service is running |
| "Timeout" | Increase timeout with `--timeout` flag |

### Tool-Specific Help

```bash
# View tool help
python3 python/tools/<tool-name>/tool.py --help

# Preview operation safely
python3 python/tools/<tool-name>/tool.py <args> --plan

# Read tool README
cat python/tools/<tool-name>/README.md
```

### External Resources

- **MITRE ATT&CK Framework**: [attack.mitre.org](https://attack.mitre.org) - Technique reference
- **OWASP**: [owasp.org](https://owasp.org) - Web security guidance
- **HackTheBox Academy**: [academy.hackthebox.com](https://academy.hackthebox.com) - Practice environments
- **TryHackMe**: [tryhackme.com](https://tryhackme.com) - Guided learning paths

### Reporting Issues

If you encounter problems with training materials:

1. Document the specific issue and steps to reproduce
2. Note your environment (OS, Python version, tool version)
3. Check if the issue persists in planning mode
4. Submit feedback through appropriate channels

---

## Safety and Ethics

### Authorized Use Only

All tools and techniques in this training program are intended for:
- Authorized penetration testing engagements
- CTF and CPTC competitions
- Isolated lab environments
- Security research with proper authorization

### Never Use Against

- Systems without explicit written authorization
- Production environments without approval
- Third-party systems without contracts
- Public networks or internet targets without permission

### Competition Conduct

- Follow all competition rules and scope limitations
- Report discovered vulnerabilities appropriately
- Do not interfere with other teams
- Maintain professionalism at all times

---

## Next Steps

1. **Verify your environment** using the Quick Start Guide above
2. **Choose your learning path** based on experience and goals
3. **Begin with the Glossary** if any terms are unfamiliar
4. **Complete Lab 01** as your first hands-on exercise

Good luck with your training. Thorough preparation leads to competition success.

---

*Training Materials Version: 1.0.0 | Last Updated: January 2026*
