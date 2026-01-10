# EDR Evasion Toolkit

A comprehensive educational toolkit demonstrating EDR (Endpoint Detection and Response) evasion techniques for authorized security testing and research.

## DISCLAIMER

**This tool is for authorized security testing and educational purposes only.**

EDR evasion techniques are powerful and potentially dangerous. Using these techniques without explicit authorization is illegal. This toolkit is designed for:
- Authorized red team engagements
- Security research
- CTF competitions
- Educational purposes
- Understanding defensive gaps

## Features

- **Direct Syscalls**: Generate syscall stubs to bypass user-mode hooks
- **Unhooking Techniques**: Concepts for removing EDR hooks from ntdll.dll
- **Memory Evasion**: Module stomping, sleep encryption, no-RWX techniques
- **ETW Bypass**: Techniques for evading Event Tracing for Windows
- **API Hashing**: Generate hash values to avoid string detection
- **Callback Information**: Understanding kernel callbacks
- **Planning Mode**: Detailed analysis without execution
- **MITRE ATT&CK Mapping**: Technique references to ATT&CK framework

## Installation

No additional dependencies - uses Python standard library only.

```bash
chmod +x edr_evasion.py
```

## Usage

### List Available Techniques

```bash
python edr_evasion.py --list
python edr_evasion.py --list --category direct_syscalls
python edr_evasion.py --list --json
```

### Explore Techniques

```bash
# Get detailed information about a technique
python edr_evasion.py --technique direct_syscalls --plan
python edr_evasion.py --technique full_unhooking --plan
python edr_evasion.py --technique module_stomping --plan
```

### Syscall Information

```bash
# List available syscalls
python edr_evasion.py --list-syscalls

# Get specific syscall info
python edr_evasion.py --syscall NtAllocateVirtualMemory
python edr_evasion.py --syscall NtCreateThreadEx --json
```

### Generate Syscall Stubs

```bash
# Generate assembly stubs
python edr_evasion.py --generate-stubs NtAllocateVirtualMemory
python edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory,NtCreateThreadEx

# For x86
python edr_evasion.py --generate-stubs NtAllocateVirtualMemory --platform windows_x86
```

### API Hashing

```bash
# Generate hash values for API names
python edr_evasion.py --hash-apis VirtualAlloc,CreateThread,WriteProcessMemory
python edr_evasion.py --hash-apis kernel32.dll,ntdll.dll --json
```

### Documentation

```bash
python edr_evasion.py --doc
python edr_evasion.py --doc --json
```

## Available Techniques

| Technique | Category | Risk | Description |
|-----------|----------|------|-------------|
| `direct_syscalls` | Direct Syscalls | High | Execute syscalls directly bypassing hooks |
| `full_unhooking` | Unhooking | High | Replace hooked ntdll with clean copy |
| `module_stomping` | Memory Evasion | High | Hide payload in legitimate DLL memory |
| `sleep_encryption` | Memory Evasion | Medium | Encrypt payload during sleep periods |
| `etw_patching` | ETW Bypass | Medium | Patch ETW to prevent logging |
| `api_hashing` | API Hashing | Low | Resolve APIs via hash values |

## Technique Categories

- **direct_syscalls**: Direct system call execution
- **unhooking**: Removing EDR hooks from DLLs
- **memory_evasion**: Memory-based evasion techniques
- **api_hashing**: String obfuscation via hashing
- **callback_manipulation**: Kernel callback techniques
- **etw_bypass**: Event Tracing bypass methods

## Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--technique` | `-t` | Technique to explore |
| `--list` | `-l` | List available techniques |
| `--category` | `-c` | Filter by category |
| `--syscall` | `-s` | Get syscall information |
| `--list-syscalls` | | List available syscalls |
| `--generate-stubs` | | Generate syscall stubs |
| `--hash-apis` | | Generate API hashes |
| `--platform` | | Target platform (x64/x86) |
| `--plan` | `-p` | Show execution plan only |
| `--json` | `-j` | JSON output format |
| `--doc` | | Show documentation |

## Available Syscalls

| Syscall | Win10 | Description |
|---------|-------|-------------|
| NtAllocateVirtualMemory | 0x18 | Allocate virtual memory |
| NtWriteVirtualMemory | 0x3A | Write to process memory |
| NtCreateThreadEx | 0xC1 | Create thread in process |
| NtProtectVirtualMemory | 0x50 | Change memory protection |
| NtOpenProcess | 0x26 | Open process handle |
| NtQueueApcThread | 0x45 | Queue APC to thread |

## Integration

### As a Module

```python
from edr_evasion import EDREvasionToolkit, TechniqueCategory, Platform

toolkit = EDREvasionToolkit()

# List techniques
techniques = toolkit.list_techniques()

# Get technique details
tech = toolkit.get_technique("direct_syscalls")
print(tech.description)
print(tech.detection_methods)

# Generate syscall stub
stub = toolkit.generate_syscall_stub("NtAllocateVirtualMemory", Platform.WINDOWS_X64)
print(stub)

# Generate API hashes
hashes = toolkit.generate_api_hashes(["VirtualAlloc", "CreateThread"])
for api, h in hashes.items():
    print(f"{api}: DJB2=0x{h['djb2']:08X}")
```

### Documentation Hook

```python
from edr_evasion import get_documentation

docs = get_documentation()
print(docs['techniques'])
print(docs['mitre_techniques'])
```

## Understanding EDR Hooks

### How EDR Hooks Work

1. EDR loads DLL into every process
2. EDR modifies ntdll.dll function prologues
3. Original: `mov r10, rcx; mov eax, XX; syscall`
4. Hooked: `jmp <edr_handler>`
5. EDR handler inspects call, then optionally allows

### Why Direct Syscalls Work

- Direct syscalls skip the hooked ntdll functions
- Execute syscall instruction directly from our code
- EDR user-mode hooks never see the call
- BUT: Kernel-mode monitoring still applies

## Detection Considerations

### For Red Teams

- Modern EDRs use multiple detection layers
- Kernel callbacks detect process/thread creation
- ETW provides telemetry even with user-mode bypasses
- Behavioral analysis catches suspicious patterns
- Combine multiple techniques for best results

### For Blue Teams

- Monitor for syscall instructions outside ntdll
- Validate call stacks for API calls
- Use kernel-mode telemetry
- Monitor memory protection changes
- Watch for ntdll.dll modifications

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Name |
|-----------|-----------|------|
| Direct Syscalls | T1106 | Native API |
| Unhooking | T1562.001 | Disable or Modify Tools |
| ETW Bypass | T1562.006 | Indicator Blocking |
| Module Stomping | T1055 | Process Injection |
| API Hashing | T1027 | Obfuscated Files |

## Educational Resources

### Recommended Reading

- [Bypassing User-Mode Hooks](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/)
- [Hell's Gate](https://github.com/am0nsec/HellsGate)
- [Halo's Gate](https://blog.sektor7.net/#!res/2021/halosgate.md)
- [SysWhispers](https://github.com/jthuraisamy/SysWhispers)

### Detection Research

- [Detecting Manual Syscalls](https://winternl.com/detecting-manual-syscalls-from-user-mode/)
- [EDR Telemetry](https://github.com/tsale/EDR-Telemetry)

## Limitations

This toolkit provides **educational demonstrations** of evasion concepts:

1. Does not provide working exploit code
2. Syscall numbers may vary between Windows versions
3. Kernel-mode detection is not addressed
4. Modern EDRs use multiple detection methods
5. Techniques become less effective as they're publicized

## Legal Notice

This toolkit is provided for authorized security testing and educational purposes only. Users are responsible for:

1. Obtaining proper authorization before testing
2. Complying with all applicable laws
3. Using techniques only in authorized engagements
4. Understanding the risks involved

Unauthorized use of these techniques may violate computer crime laws.

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/)
- [ReactOS - Open Source Windows Reference](https://reactos.org/)

## License

For authorized security testing only. See main project license.
