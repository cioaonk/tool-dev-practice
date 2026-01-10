# EDR Evasion Walkthrough

**Skill Level**: Advanced [A]

A comprehensive guide to understanding and applying EDR evasion techniques for CTF and CPTC competitions.

> **Warning**: This is an advanced module. Complete all previous phases before attempting this content.

---

## Prerequisites Check

**Stop here if you cannot answer YES to all of these:**

- [ ] Completed the Payload Generator Walkthrough
- [ ] Understand what a process is in Windows (a running program)
- [ ] Know what memory allocation means (getting space in RAM)
- [ ] Understand the concept of APIs (functions programs call to do things)
- [ ] Know what a DLL is (code library used by Windows programs)

**If you answered NO to any question**, review:
- [Glossary](../GLOSSARY.md) entries for: DLL, Kernel, Syscall, Hook, EDR, AMSI
- External resources on Windows internals basics

---

## Module Overview

### Purpose
Understand Endpoint Detection and Response (EDR) mechanisms and learn techniques to evade detection during authorized security assessments. This advanced module covers the theory and application of modern evasion techniques.

> **What is EDR?** Endpoint Detection and Response is advanced security software that monitors everything your computer does - process creation, memory access, network connections, file operations. Unlike antivirus (which looks for known bad files), EDR looks for suspicious BEHAVIORS.

### Learning Objectives
By completing this walkthrough, you will be able to:
- Understand how EDR solutions detect malicious activity
- Explain user-mode hooking and why it enables detection
- Generate direct syscall stubs to bypass hooks
- Apply appropriate evasion techniques based on target defenses
- Map techniques to the MITRE ATT&CK framework

### Time Estimate
- Reading: 90 minutes
- Hands-on Practice: 3-4 hours

### Key Terms for This Module

| Term | Definition |
|------|------------|
| **EDR** | Endpoint Detection and Response - advanced security monitoring |
| **Hook** | Code that intercepts function calls to inspect them |
| **Syscall** | Direct request to the operating system kernel |
| **User-mode** | Normal application space (restricted permissions) |
| **Kernel-mode** | Operating system core (full permissions) |
| **ntdll.dll** | Windows DLL containing syscall interfaces |

### Disclaimer

**This module covers advanced techniques that could be misused.**

These techniques are taught for:
- Understanding defensive gaps
- Authorized red team engagements
- CTF/CPTC competitions
- Security research

Never use these techniques without explicit authorization.

---

## Part 1: Conceptual Foundation

### Understanding EDR

#### What is EDR?

Endpoint Detection and Response (EDR) solutions monitor endpoint activity to detect and respond to threats. Unlike traditional antivirus (signature-based), EDR focuses on behavioral analysis.

#### EDR Detection Capabilities

| Layer | What EDR Sees | Example Detection |
|-------|---------------|-------------------|
| **Kernel** | Process creation, file operations | Suspicious process spawning |
| **User-Mode Hooks** | API calls, parameters | Process injection attempts |
| **Network** | Connections, DNS queries | C2 communication patterns |
| **File System** | File creation, modification | Malware dropping to disk |
| **Memory** | Memory allocation, protection changes | RWX memory regions |

### How User-Mode Hooks Work

EDR solutions inject hooks into critical Windows API functions to inspect calls before they execute.

#### Normal API Call Flow

```
YOUR CODE                  NTDLL.DLL               KERNEL
    |                          |                      |
    | -- VirtualAlloc() -----> |                      |
    |                          | -- syscall --------> |
    |                          |                      | [Allocates memory]
    |                          | <-- return --------- |
    | <-- pointer ------------ |                      |
```

#### Hooked API Call Flow

```
YOUR CODE                  NTDLL.DLL (HOOKED)       EDR          KERNEL
    |                          |                      |             |
    | -- VirtualAlloc() -----> |                      |             |
    |                          | -- JMP to EDR -----> |             |
    |                          |                      | [Inspect]   |
    |                          |                      | [Log]       |
    |                          |                      | [Decide]    |
    |                          | <-- Continue ------- |             |
    |                          | -- syscall -------------------- > |
    |                          |                      |             |
```

#### Hook Implementation

Normal function prologue:
```asm
; Original NtAllocateVirtualMemory
mov r10, rcx          ; 4C 8B D1
mov eax, 0x18         ; B8 18 00 00 00  (syscall number)
syscall               ; 0F 05
ret                   ; C3
```

Hooked function:
```asm
; Hooked NtAllocateVirtualMemory
jmp <edr_handler>     ; E9 XX XX XX XX  (5-byte jump)
; Original bytes overwritten...
```

### Why Direct Syscalls Work

If we execute the syscall instruction directly from our own code, we bypass the hooked ntdll.dll entirely:

```
YOUR CODE (Direct Syscall)                          KERNEL
    |                                                  |
    | -- mov r10, rcx                                  |
    | -- mov eax, 0x18                                 |
    | -- syscall -----------------------------------> |
    |                                                  | [Allocates memory]
    | <-- return ------------------------------------- |

[EDR user-mode hooks never see this call!]
```

**Important Limitation**: Kernel-mode telemetry still applies. ETW (Event Tracing for Windows) and kernel callbacks can still detect activity.

> **Critical OPSEC Understanding**: Direct syscalls bypass the interception point (user-mode hooks) but the RESULT of your actions (process created, memory allocated, file written) is still visible to kernel-level monitoring. Syscalls are not invisibility - they are just one detection bypass.

### Detection Layers Deep-Dive

Understanding these layers is crucial for realistic expectations:

#### Layer 1: User-Mode Hooks
- **What**: Inline hooks in ntdll.dll, kernel32.dll
- **Bypassed by**: Direct syscalls, unhooking
- **Detection coverage**: ~40% of EDR visibility

#### Layer 2: Kernel Callbacks
- **What**: PsSetCreateProcessNotifyRoutine, etc.
- **Sees**: Process/thread creation, image loads
- **Bypassed by**: Nothing from user-mode (kernel lives above)
- **Detection coverage**: ~30% of EDR visibility

#### Layer 3: ETW (Event Tracing for Windows)
- **What**: System-wide event logging
- **Sees**: .NET, PowerShell, process events
- **Bypassed by**: ETW patching (in-process only)
- **Detection coverage**: ~20% of EDR visibility

#### Layer 4: Behavioral Analysis
- **What**: ML models analyzing patterns
- **Sees**: Sequences of suspicious activities
- **Bypassed by**: Blending in, living-off-the-land
- **Detection coverage**: ~10% but catches novel attacks

> **Detection Awareness Summary**: Even with perfect user-mode evasion, 50-60% of EDR detection capability remains active. Plan accordingly.

---

## Part 2: EDR Evasion Toolkit Deep-Dive

### Tool Location

```
/path/to/tools/edr-evasion-toolkit/edr_evasion.py
```

### Core Capabilities

- **Direct Syscall Generation**: Assembly stubs for bypassing hooks
- **Technique Documentation**: Detailed evasion technique information
- **API Hashing**: Generate hash values to avoid string detection
- **MITRE ATT&CK Mapping**: Framework references

### Listing Available Techniques

```bash
python3 edr_evasion.py --list
```

**Expected Output:**
```
Available EDR Evasion Techniques:
==================================

DIRECT SYSCALLS:
  direct_syscalls     Execute syscalls directly bypassing hooks [High Risk]

UNHOOKING:
  full_unhooking      Replace hooked ntdll with clean copy [High Risk]

MEMORY EVASION:
  module_stomping     Hide payload in legitimate DLL memory [High Risk]
  sleep_encryption    Encrypt payload during sleep periods [Medium Risk]

ETW BYPASS:
  etw_patching        Patch ETW to prevent logging [Medium Risk]

API HASHING:
  api_hashing         Resolve APIs via hash values [Low Risk]
```

### Exploring Techniques

```bash
# Get detailed information about a technique
python3 edr_evasion.py --technique direct_syscalls --plan
```

**Output:**
```
[PLAN MODE] Technique: direct_syscalls
==================================================

Description:
  Direct syscalls bypass user-mode hooks by executing the syscall
  instruction directly instead of calling hooked ntdll functions.

How it Works:
  1. Identify syscall number for target function
  2. Set up registers per calling convention
  3. Execute syscall instruction directly
  4. Process return value

Detection Methods:
  - Syscall instructions outside ntdll.dll
  - Call stack analysis (no ntdll frame)
  - Syscall number enumeration in non-system code

Effectiveness:
  - Bypasses: User-mode hooks
  - Does NOT bypass: Kernel callbacks, ETW, behavioral analysis

MITRE ATT&CK:
  - ID: T1106
  - Technique: Native API
  - Tactic: Execution

Risk Level: High
```

> **How Defenders Detect Direct Syscalls**:
> 1. **Call stack analysis**: Normal calls go through ntdll.dll. Direct syscalls have unusual call stacks.
> 2. **Code location**: Syscall instructions should only be in system DLLs, not your executable.
> 3. **Behavioral patterns**: The sequence allocate-write-execute is suspicious regardless of method.
>
> Modern EDRs like CrowdStrike and Microsoft Defender for Endpoint specifically detect direct syscall patterns.

### Working with Syscalls

#### Listing Available Syscalls

```bash
python3 edr_evasion.py --list-syscalls
```

**Output:**
```
Available Syscalls:
====================

| Syscall                    | Win10 22H2 | Description                    |
|----------------------------|------------|--------------------------------|
| NtAllocateVirtualMemory    | 0x18       | Allocate virtual memory        |
| NtWriteVirtualMemory       | 0x3A       | Write to process memory        |
| NtCreateThreadEx           | 0xC1       | Create thread in process       |
| NtProtectVirtualMemory     | 0x50       | Change memory protection       |
| NtOpenProcess              | 0x26       | Open process handle            |
| NtQueueApcThread           | 0x45       | Queue APC to thread            |
```

#### Getting Syscall Details

```bash
python3 edr_evasion.py --syscall NtAllocateVirtualMemory
```

**Output:**
```
Syscall: NtAllocateVirtualMemory
================================

Syscall Number (Windows 10 22H2): 0x18

Function Signature:
  NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,       // rcx
    PVOID *BaseAddress,         // rdx
    ULONG_PTR ZeroBits,         // r8
    PSIZE_T RegionSize,         // r9
    ULONG AllocationType,       // [rsp+0x28]
    ULONG Protect               // [rsp+0x30]
  );

Common Use Cases:
  - Allocating memory for shellcode
  - Creating RWX regions
  - Process hollowing preparations

Detection Notes:
  - RWX allocations are suspicious
  - Remote process allocations highly suspicious
  - Often followed by NtWriteVirtualMemory
```

> **OPSEC Warning**: The syscall numbers shown are for specific Windows versions. Windows 11 has different syscall numbers than Windows 10, and even Windows 10 builds vary. Using wrong syscall numbers will crash the program. Always verify the target OS version.

### Generating Syscall Stubs

```bash
# Generate assembly stub for x64
python3 edr_evasion.py --generate-stubs NtAllocateVirtualMemory
```

**Output:**
```asm
; Direct syscall stub for NtAllocateVirtualMemory
; Windows 10 22H2 - Syscall Number: 0x18
; Usage: Call with same parameters as NtAllocateVirtualMemory

NtAllocateVirtualMemory PROC
    mov r10, rcx              ; Move first param to r10 (syscall convention)
    mov eax, 18h              ; Syscall number
    syscall                   ; Execute syscall
    ret                       ; Return to caller
NtAllocateVirtualMemory ENDP
```

#### Multiple Syscalls

```bash
# Generate stubs for common injection chain
python3 edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx
```

#### x86 Stubs

```bash
# Generate for 32-bit
python3 edr_evasion.py --generate-stubs NtAllocateVirtualMemory --platform windows_x86
```

### API Hashing

Generate hash values to avoid string detection:

```bash
python3 edr_evasion.py --hash-apis VirtualAlloc,CreateThread,WriteProcessMemory
```

**Output:**
```
API Hash Values:
================

| API Name              | DJB2         | ROR13        |
|-----------------------|--------------|--------------|
| VirtualAlloc          | 0x91AFCA54   | 0x382C0F97   |
| CreateThread          | 0x7C0017A5   | 0x160D6838   |
| WriteProcessMemory    | 0xE7BDD8C5   | 0x4F9D8627   |

Usage:
  Instead of GetProcAddress("VirtualAlloc"), search export table
  for function where hash(name) == 0x91AFCA54
```

---

## Part 3: AMSI Bypass Deep-Dive

### Tool Location

```
/path/to/tools/amsi-bypass/amsi_bypass.py
```

### Understanding AMSI

AMSI (Antimalware Scan Interface) is a Windows interface that allows applications to send content to antimalware solutions for scanning.

#### Where AMSI Applies

| Application | What Gets Scanned |
|-------------|-------------------|
| PowerShell | All script blocks |
| .NET | Assembly loads, reflection |
| VBScript/JScript | WSH scripts |
| Office VBA | Macro code |

#### AMSI Architecture

```
POWERSHELL                    AMSI.DLL                 DEFENDER
    |                            |                        |
    | -- Script content -------> |                        |
    |                            | -- AmsiScanBuffer ---> |
    |                            |                        | [Scan]
    |                            | <-- Result ----------- |
    | <-- Allow/Block ---------- |                        |
```

### AMSI Bypass Concepts

The toolkit demonstrates bypass concepts (educational purposes):

```bash
python3 amsi_bypass.py --list
```

**Output:**
```
AMSI Bypass Concepts:
=====================

1. AMSI PATCH
   - Concept: Patch AmsiScanBuffer to return clean
   - Detection: Memory integrity checks
   - MITRE: T1562.001

2. AMSI CONTEXT CORRUPTION
   - Concept: Corrupt AMSI context structure
   - Detection: AMSI initialization monitoring
   - MITRE: T1562.001

3. AMSI PROVIDER HIJACK
   - Concept: Register malicious AMSI provider
   - Detection: Provider registration monitoring
   - MITRE: T1562.001
```

### Understanding the Concepts

```bash
python3 amsi_bypass.py --technique amsi_patch --plan
```

**Output:**
```
[PLAN MODE] Technique: amsi_patch
==================================================

Concept Overview:
  The AmsiScanBuffer function in amsi.dll scans content.
  If patched to immediately return AMSI_RESULT_CLEAN,
  no content gets flagged as malicious.

Typical Approach:
  1. Load amsi.dll (usually already loaded in PS)
  2. Get address of AmsiScanBuffer
  3. Change memory protection to RWX
  4. Write bytes that return immediately
  5. Restore memory protection

Detection Vectors:
  - amsi.dll memory modifications
  - Unexpected returns from AmsiScanBuffer
  - VirtualProtect calls on amsi.dll

Note: This is an educational description of the concept.
Modern EDRs detect many known bypass techniques.
```

---

## Part 4: Process Hollowing Concepts

### Tool Location

```
/path/to/tools/process-hollowing/process_hollowing.py
```

### Understanding Process Hollowing

Process hollowing is a technique where a legitimate process is created in a suspended state, its memory is unmapped, and malicious code is written in its place.

```
NORMAL PROCESS                    HOLLOWED PROCESS

+------------------+              +------------------+
| notepad.exe      |              | notepad.exe      | <- Looks like notepad
| Original Code    |     VS       | Malicious Code   | <- Actually shellcode
| Normal behavior  |              | Hidden behavior  |
+------------------+              +------------------+
```

### Process Hollowing Steps

```bash
python3 process_hollowing.py --technique classic --plan
```

**Output:**
```
[PLAN MODE] Process Hollowing - Classic
=========================================

Steps:
  1. CreateProcess with CREATE_SUSPENDED
     - Spawns target (e.g., notepad.exe) without executing

  2. NtUnmapViewOfSection
     - Removes original executable from memory

  3. VirtualAllocEx
     - Allocates memory in target for payload

  4. WriteProcessMemory
     - Writes payload to allocated memory

  5. SetThreadContext
     - Updates entry point to payload

  6. ResumeThread
     - Begins execution of payload

API Calls (Detection Points):
  - CreateProcess (SUSPENDED)
  - NtUnmapViewOfSection
  - VirtualAllocEx (RWX)
  - WriteProcessMemory
  - SetThreadContext
  - ResumeThread

MITRE ATT&CK:
  - ID: T1055.012
  - Technique: Process Injection: Process Hollowing
```

---

## Part 5: Shellcode Encoder for Evasion

### Encoding for AV Evasion

```bash
# List available encoders
python3 /path/to/shellcode-encoder/shellcode_encoder.py --list
```

### Effective Encoding Strategies

#### Strategy 1: Single Strong Encoder

```bash
# RC4 encryption with custom key
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --encoding rc4 \
    --key your_custom_key_here \
    --format csharp
```

#### Strategy 2: Chain Encoding

```bash
# Multiple encoding layers
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --chain xor,add,rot \
    --null-free \
    --format powershell
```

#### Strategy 3: Environment-Keyed Encoding

Decode only in target environment:

```bash
# Generate shellcode keyed to specific value
python3 shellcode_encoder.py \
    --input shellcode.bin \
    --encoding xor \
    --key $(echo -n "TARGET-HOSTNAME" | md5sum | cut -c1-16)
```

---

## Part 6: MITRE ATT&CK Mapping

### Technique Reference

| Tool/Technique | ATT&CK ID | Name | Tactic |
|----------------|-----------|------|--------|
| Direct Syscalls | T1106 | Native API | Execution |
| Unhooking | T1562.001 | Disable or Modify Tools | Defense Evasion |
| ETW Bypass | T1562.006 | Indicator Blocking | Defense Evasion |
| Module Stomping | T1055 | Process Injection | Defense Evasion |
| API Hashing | T1027 | Obfuscated Files | Defense Evasion |
| Process Hollowing | T1055.012 | Process Hollowing | Defense Evasion |
| AMSI Bypass | T1562.001 | Disable or Modify Tools | Defense Evasion |

### Using ATT&CK in Reporting

```bash
# Get ATT&CK mapping for technique
python3 edr_evasion.py --technique direct_syscalls --json | jq '.mitre_attack'
```

---

## Part 7: Practical Application

### Evasion Decision Framework

```
START
  |
  v
[What defenses are present?]
  |
  +-- Basic AV only
  |     |
  |     v
  |   [Use encoding/obfuscation]
  |   [Standard payloads often work]
  |
  +-- EDR with hooks
  |     |
  |     v
  |   [Consider direct syscalls]
  |   [Apply AMSI bypass if PS needed]
  |
  +-- Advanced EDR + behavioral
        |
        v
      [Combine multiple techniques]
      [Living-off-the-land]
      [Careful timing/staging]
```

### Technique Combination Example

**Scenario**: Windows target with EDR, need to execute shellcode

1. **Encode shellcode** (avoid static signatures)
```bash
python3 shellcode_encoder.py \
    --input meterpreter.bin \
    --chain xor,rc4 \
    --null-free \
    --format csharp
```

2. **Generate syscall stubs** (avoid user-mode hooks)
```bash
python3 edr_evasion.py \
    --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx
```

3. **Understand the process** (plan before execution)
```bash
python3 process_hollowing.py --technique classic --plan
```

### Competition Strategy

| Time Available | Approach |
|----------------|----------|
| Minimal | Basic encoding, common payloads |
| Moderate | Custom encoding, staged delivery |
| Extensive | Full evasion chain, custom loaders |

---

## Part 8: Troubleshooting

### Issue: Syscall fails with access denied

**Possible Causes:**
1. Wrong syscall number for OS version
2. Insufficient privileges
3. Parameter validation failing

**Solutions:**
```bash
# Verify syscall number for target OS
python3 edr_evasion.py --syscall NtAllocateVirtualMemory

# Check OS version on target
cmd> ver
```

### Issue: Payload still detected

**Possible Causes:**
1. Behavioral detection (not signature)
2. Kernel telemetry
3. Known loader pattern

**Solutions:**
- Change execution pattern
- Add delays between operations
- Use different process injection technique

### Issue: AMSI still catching scripts

**Possible Causes:**
1. Bypass technique detected
2. Bypass not applied before scan
3. Multiple AMSI providers

**Solutions:**
- Try different bypass approach
- Ensure bypass runs first
- Check for additional security software

---

## Part 9: Competition Tips

### Pre-Competition Preparation

- [ ] Pre-generate syscall stubs for common functions
- [ ] Pre-encode shellcode variants
- [ ] Document which techniques work against which EDRs
- [ ] Have fallback options ready

### Quick Reference: When to Use What

| Scenario | Technique |
|----------|-----------|
| PowerShell blocked | AMSI bypass concept |
| API calls monitored | Direct syscalls |
| Shellcode detected | Chain encoding |
| Process injection detected | Module stomping |
| All else fails | Living-off-the-land |

### Time-Pressure Decision Making

```
[Payload detected?]
      |
  +---+---+
  |       |
 YES     NO --> Execute
  |
  v
[Try encoding] --> [Detected?] --> NO --> Execute
                        |
                       YES
                        |
                        v
               [Try direct syscalls] --> [Works?] --> YES --> Execute
                                            |
                                           NO
                                            |
                                            v
                                   [Report and move on]
```

---

## Summary Checklist

After completing this walkthrough:

- [ ] Understand how EDR hooks work
- [ ] Can explain why direct syscalls bypass hooks
- [ ] Know limitations (kernel telemetry still applies)
- [ ] Can generate syscall stubs
- [ ] Understand AMSI and bypass concepts
- [ ] Can apply appropriate encoding
- [ ] Know MITRE ATT&CK mappings for techniques
- [ ] Can make time-pressure decisions on technique selection

---

## Next Steps

After completing this walkthrough:
1. Complete **Lab 05: Evasion Techniques** for hands-on practice
2. Review the **Tool Commands Cheatsheet** for quick reference
3. Practice combining techniques in isolated lab environments
