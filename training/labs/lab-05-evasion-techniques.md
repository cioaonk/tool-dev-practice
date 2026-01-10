# Lab 05: Evasion Techniques

**Skill Level**: Advanced [A]

A hands-on exercise in understanding and applying EDR evasion techniques.

> **Warning**: This is an advanced lab. Complete all previous labs and the EDR Evasion Walkthrough before attempting.

---

## Lab Information

| Attribute | Value |
|-----------|-------|
| Difficulty | Advanced |
| Time Estimate | 90-120 minutes |
| Prerequisites | Labs 01-04 completed, EDR Evasion Walkthrough |
| Tools Required | edr-evasion-toolkit, shellcode-encoder, amsi-bypass |

## Prerequisites Checklist

**Stop here if you cannot check all boxes:**

- [ ] Completed Labs 01 through 04
- [ ] Read the [EDR Evasion Walkthrough](../walkthroughs/edr-evasion-walkthrough.md) thoroughly
- [ ] Understand what EDR is and how user-mode hooks work
- [ ] Know what a syscall is and why direct syscalls can evade hooks
- [ ] Understand the concept of the Windows kernel vs. user mode

**Key Terms for This Lab**: EDR, Hook, Syscall, AMSI, ETW, Kernel, User-mode (see [Glossary](../GLOSSARY.md))

> **Important**: This lab focuses on conceptual understanding and artifact generation. Actual EDR evasion in production environments requires additional techniques not covered here. The techniques taught are for educational purposes and competition scenarios.

---

## Objective

Understand EDR detection mechanisms and practice applying evasion techniques. Learn to select appropriate techniques based on target defenses and map activities to the MITRE ATT&CK framework.

---

## Environment Setup

### Lab Environment

```
Targets:
- Windows 10 Workstation (simulated EDR)
- Windows Server 2019 (enterprise monitoring)

Simulated Defenses:
- User-mode API hooking
- AMSI (for PowerShell)
- Script block logging
- Process monitoring
```

### Note on Lab Exercises

This lab focuses on understanding evasion concepts rather than live exploitation. Exercises involve:
- Generating and analyzing evasion artifacts
- Understanding detection mechanisms
- Planning evasion strategies

---

## Scenario

You have gained initial access to a corporate Windows environment. The organization has deployed EDR solutions that monitor API calls and script execution. You need to understand the defenses and select appropriate evasion techniques for continued operations.

---

## Tasks

### Task 1: Understanding API Hooks (Level 1 - Foundation)

**Objective**: Understand how EDR API hooks work.

**Instructions**:

1. Review the EDR evasion documentation:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py --doc
```

2. Explore the direct syscalls technique:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique direct_syscalls \
    --plan
```

3. Answer the following questions:
   - How do EDR hooks intercept API calls?
   - Why do direct syscalls bypass these hooks?
   - What detection still applies even with direct syscalls?

**Deliverable**: Written answers to the questions above

---

### Task 2: Syscall Stub Generation (Level 1 - Foundation)

**Objective**: Generate syscall stubs for common operations.

**Instructions**:

1. List available syscalls:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py --list-syscalls
```

2. Get details for memory allocation syscall:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --syscall NtAllocateVirtualMemory
```

3. Generate syscall stubs for a typical injection chain:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx
```

4. Document the syscall numbers and their purposes.

**Deliverable**: Syscall stub code with documentation

---

### Task 3: API Hashing (Level 2 - Application)

**Objective**: Generate API hashes to avoid string detection.

**Instructions**:

1. Generate hashes for common APIs:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --hash-apis VirtualAlloc,VirtualProtect,CreateThread,WriteProcessMemory
```

2. Document the hash values:

**Template**:
```
API Resolution via Hashing
==========================

DJB2 Algorithm Hashes:
- VirtualAlloc: 0x________
- VirtualProtect: 0x________
- CreateThread: 0x________
- WriteProcessMemory: 0x________

Purpose: Instead of storing API names as strings (easily detected),
resolve functions by walking export table and comparing hash values.
```

**Deliverable**: API hash reference document

---

### Task 4: Shellcode Encoding Analysis (Level 2 - Application)

**Objective**: Analyze encoding effectiveness.

**Instructions**:

1. Create sample shellcode (use a simple example):
```bash
# Simple NOP sled + INT3 for testing
echo -n -e '\x90\x90\x90\x90\xCC' > test_shellcode.bin
```

2. Analyze the original:
```bash
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input test_shellcode.bin \
    --analyze
```

3. Apply different encodings and compare:
```bash
# XOR encoding
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input test_shellcode.bin \
    --encoding xor \
    --analyze

# Chain encoding
python3 /path/to/shellcode-encoder/shellcode_encoder.py \
    --input test_shellcode.bin \
    --chain xor,add,rot \
    --analyze
```

4. Document entropy changes and size differences.

**Deliverable**: Encoding comparison analysis

---

### Task 5: Technique Category Exploration (Level 2 - Application)

**Objective**: Understand different evasion technique categories.

**Instructions**:

1. List all available techniques:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py --list
```

2. For each category, explore one technique:
```bash
# Unhooking
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique full_unhooking --plan

# Memory evasion
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique module_stomping --plan

# ETW bypass
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique etw_patching --plan
```

3. Create a technique comparison matrix.

**Template**:
```
| Technique | What it Bypasses | What Still Detects | Risk Level |
|-----------|------------------|-------------------|------------|
| Direct Syscalls | User-mode hooks | Kernel telemetry | High |
| Full Unhooking | All user-mode hooks | Memory integrity | High |
| Module Stomping | Memory scanning | Behavioral | High |
| ETW Patching | ETW-based logging | External ETW | Medium |
```

**Deliverable**: Technique comparison matrix

---

### Task 6: MITRE ATT&CK Mapping (Level 3 - Integration)

**Objective**: Map evasion techniques to the ATT&CK framework.

**Instructions**:

1. For each technique studied, identify the ATT&CK mapping:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique direct_syscalls --json | python3 -c "import sys,json; print(json.load(sys.stdin)['mitre_attack'])"
```

2. Create an ATT&CK mapping document:

**Template**:
```
# MITRE ATT&CK Mapping for Evasion Techniques

## Technique: Direct Syscalls
- ATT&CK ID: T1106
- Name: Native API
- Tactic: Execution
- Description: Execution via direct system calls

## Technique: EDR Unhooking
- ATT&CK ID: T1562.001
- Name: Disable or Modify Tools
- Tactic: Defense Evasion
- Description: Removing security tool hooks

[Continue for each technique...]
```

**Deliverable**: Complete ATT&CK mapping document

---

### Task 7: Evasion Strategy Design (Level 3 - Integration)

**Objective**: Design an evasion strategy for a specific scenario.

**Scenario**:
You need to execute shellcode on a Windows 10 system with:
- CrowdStrike Falcon EDR
- Windows Defender
- PowerShell script block logging
- AMSI enabled

**Instructions**:

1. Analyze the threat model:
   - What detection capabilities does each control provide?
   - What are the gaps?

2. Design a multi-technique approach:
   - Shellcode encoding strategy
   - API call evasion method
   - Execution method

3. Document your strategy:

**Template**:
```
# Evasion Strategy Document

## Target Environment
- EDR: CrowdStrike Falcon
- AV: Windows Defender
- Monitoring: Script block logging, AMSI

## Threat Model
| Control | Detection Capability | Evasion Approach |
|---------|---------------------|------------------|
| Falcon | User-mode hooks | Direct syscalls |
| Defender | Signature + behavior | Encoding + staging |
| AMSI | Script content | AMSI bypass |

## Execution Plan
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Fallback Options
- If approach A fails: [Alternative]
- If detected: [Response]
```

**Deliverable**: Complete evasion strategy document

---

### Task 8: Detection Perspective (Level 3 - Integration)

**Objective**: Understand evasion from the defender's perspective.

**Instructions**:

1. For each evasion technique, document how defenders can detect it:
```bash
python3 /path/to/edr-evasion-toolkit/edr_evasion.py \
    --technique direct_syscalls --plan
# Look for "Detection Methods" in output
```

2. Create a detection opportunities document:

**Template**:
```
# Blue Team Detection Guide

## Detecting Direct Syscalls
- Indicator: syscall instruction outside ntdll.dll
- Method: Call stack analysis
- Data Source: ETW / Kernel telemetry
- Alert Criteria: [Specific criteria]

## Detecting Unhooking
- Indicator: ntdll.dll memory modifications
- Method: Memory integrity monitoring
- Data Source: EDR memory scans
- Alert Criteria: [Specific criteria]

[Continue for each technique...]
```

**Deliverable**: Detection guide from blue team perspective

---

## Challenge Tasks (Level 4 - Mastery)

### Challenge 1: Custom Evasion Chain

Design and document a custom evasion chain that:
1. Avoids static signatures (encoding)
2. Bypasses user-mode hooks (syscalls)
3. Evades behavioral analysis (timing/staging)
4. Works within memory constraints

### Challenge 2: EDR Fingerprinting

Research how to identify which EDR is deployed on a target without triggering alerts. Document:
- Passive identification methods
- Active identification methods (with risks)
- EDR-specific evasion considerations

### Challenge 3: Living-off-the-Land Evasion

Design an attack chain using only:
- Built-in Windows binaries
- Direct syscalls (no suspicious imports)
- No dropped files

Document the complete chain from execution to persistence.

---

## Hints

<details>
<summary>Hint 1: Understanding Syscall Numbers</summary>

Syscall numbers change between Windows versions. Always verify:
```bash
python3 edr_evasion.py --syscall NtAllocateVirtualMemory
```
The tool shows the number for a specific Windows version.
</details>

<details>
<summary>Hint 2: Chain Encoding Order</summary>

When using chain encoding, remember:
- Encoding order: A -> B -> C
- Decoding order: C -> B -> A (reverse!)
</details>

<details>
<summary>Hint 3: Kernel Still Sees Everything</summary>

Direct syscalls bypass user-mode hooks but NOT:
- Kernel callbacks
- ETW
- Kernel-mode minifilters

Plan accordingly.
</details>

<details>
<summary>Hint 4: Behavioral vs. Signature</summary>

Encoding defeats signatures but NOT behavioral analysis. If your execution pattern is suspicious (allocate -> write -> execute), it may still be caught.
</details>

---

## Solution Guide

<details>
<summary>Click to reveal solution (Instructor Use)</summary>

### Task 1 Solution

**How do EDR hooks intercept API calls?**
EDR solutions inject DLLs into every process and modify the first bytes of critical functions in ntdll.dll to redirect execution to EDR analysis code.

**Why do direct syscalls bypass these hooks?**
Direct syscalls execute the syscall instruction from your own code, never calling the hooked ntdll.dll functions. The hook is simply skipped.

**What detection still applies?**
- Kernel callbacks (process/thread creation)
- ETW telemetry
- Behavioral analysis
- Call stack analysis (no ntdll frame)

### Task 7 Solution

**Strategy for CrowdStrike + Defender + AMSI:**

1. **Shellcode Preparation**
   - Chain encode: XOR -> RC4
   - Avoid common signatures
   - Test against Defender before deployment

2. **Execution Method**
   - Use direct syscalls for memory operations
   - Generate stubs for NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx

3. **If PowerShell Needed**
   - Apply AMSI bypass before main payload
   - Avoid using Invoke-Expression with suspicious strings

4. **Execution Flow**
   - Allocate RW memory (not RWX initially)
   - Write decoded shellcode
   - Change protection to RX
   - Create thread to execute

</details>

---

## Assessment Criteria

| Criteria | Points | Description |
|----------|--------|-------------|
| API Hook Understanding | 15 | Correct explanations |
| Syscall Generation | 15 | Proper stubs created |
| API Hashing | 10 | Correct hash values |
| Encoding Analysis | 15 | Thorough comparison |
| Technique Comparison | 15 | Complete matrix |
| ATT&CK Mapping | 15 | Accurate mappings |
| Strategy Design | 15 | Realistic approach |

**Total: 100 points**

---

## Ethical Considerations

### Responsible Use

Evasion techniques are powerful and potentially dangerous. Remember:

1. **Authorization**: Only use against systems you have permission to test
2. **Scope**: Stay within engagement boundaries
3. **Documentation**: Record all techniques used for reporting
4. **Disclosure**: Report discovered vulnerabilities responsibly

### The Defender's Perspective

Understanding evasion makes you a better defender:
- Know what attacks look like
- Understand detection gaps
- Improve security controls
- Develop better monitoring

---

## Cleanup

```bash
# Remove test files
rm -f test_shellcode.bin

# Remove generated artifacts
rm -f *.asm *.py *.cs

# Clear any temporary files
```

---

## Next Steps

After completing this lab:

1. Review the **Tool Commands Cheatsheet** for quick reference
2. Practice combining techniques in isolated lab environments
3. Study real-world case studies of EDR evasion
4. Consider pursuing advanced certifications (OSEP, CRTO)
