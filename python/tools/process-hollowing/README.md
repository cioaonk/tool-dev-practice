# Process Hollowing Demonstrator

An educational tool for understanding the process hollowing technique used in offensive security and malware analysis.

## DISCLAIMER

**This tool is for authorized security testing and educational purposes only.**

This tool demonstrates the *concepts* of process hollowing without performing actual process manipulation. It is designed for:
- Learning about evasion techniques
- Understanding detection opportunities
- Preparing for CTF competitions
- Security research and education

## What is Process Hollowing?

Process hollowing (MITRE ATT&CK T1055.012) is a code injection technique where:
1. A legitimate process is created in a suspended state
2. The original executable image is unmapped from memory
3. Malicious code is written into the hollowed process
4. The thread context is modified to point to the malicious entry point
5. The process is resumed, executing the malicious code

The result is malicious code running inside what appears to be a legitimate process.

## Features

- **Educational Demonstration**: Step-by-step explanation of the technique
- **Planning Mode**: Shows what would happen without executing
- **API Documentation**: Details on Windows APIs involved
- **Detection Guidance**: How to identify process hollowing
- **Target Analysis**: Common target processes and their characteristics
- **JSON Output**: Machine-readable output for integration

## Installation

No additional dependencies required - uses Python standard library only.

```bash
chmod +x process_hollowing.py
```

## Usage

### Planning Mode (Recommended Start)

```bash
# Show execution plan for hollowing svchost.exe
python process_hollowing.py --target svchost.exe --plan

# Plan with PPID spoofing
python process_hollowing.py --target notepad.exe --ppid-spoof --plan
```

### Educational Demonstration

```bash
# Full demonstration with step explanations
python process_hollowing.py --target svchost.exe --demo
```

### List Common Targets

```bash
python process_hollowing.py --list-targets
python process_hollowing.py --list-targets --json
```

### Detection Guidance

```bash
python process_hollowing.py --detection-guide
```

### Explain Specific Step

```bash
# Explain step 3 (Unmap Original Image)
python process_hollowing.py --step 3
```

### Get Documentation

```bash
python process_hollowing.py --doc
python process_hollowing.py --doc --json
```

## Process Hollowing Steps

1. **Create Suspended Process** - Start target with CREATE_SUSPENDED flag
2. **Query Process Information** - Get PEB address to find image base
3. **Unmap Original Image** - Remove original executable from memory
4. **Allocate New Memory** - Reserve space for malicious payload
5. **Write Payload** - Copy PE headers and sections
6. **Fix Image Base in PEB** - Update PEB to reflect new image
7. **Set Thread Context** - Point instruction pointer to new entry
8. **Resume Execution** - Start the hollowed process

## Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--target` | `-t` | Target process name (e.g., svchost.exe) |
| `--payload` | | Payload source path (for planning) |
| `--platform` | | Target platform (windows_x86, windows_x64) |
| `--plan` | `-p` | Show execution plan only |
| `--demo` | `-d` | Run educational demonstration |
| `--list-targets` | | List common target processes |
| `--detection-guide` | | Show detection guidance |
| `--step` | | Explain specific step (1-8) |
| `--ppid-spoof` | | Include PPID spoofing in plan |
| `--block-dlls` | | Include DLL blocking in plan |
| `--json` | `-j` | JSON output format |
| `--doc` | | Show documentation |

## Common Target Processes

| Process | Typical Parent | Suspicion Level | Notes |
|---------|---------------|-----------------|-------|
| svchost.exe | services.exe | Low | Multiple instances normal |
| RuntimeBroker.exe | svchost.exe | Low | Modern Windows |
| notepad.exe | explorer.exe | Medium | GUI expected |
| calc.exe | explorer.exe | Medium | Modern calc is UWP |

## Detection Vectors

### API Monitoring
- CreateProcess with CREATE_SUSPENDED
- NtUnmapViewOfSection calls
- WriteProcessMemory to suspended processes
- SetThreadContext modifications

### Memory Analysis
- Image path vs memory content mismatch
- RWX memory regions
- PEB ImageBaseAddress discrepancies

### Behavioral Indicators
- Network connections from unexpected processes
- Suspicious parent-child relationships
- Command line anomalies

## Integration

### As a Module

```python
from process_hollowing import ProcessHollowingDemonstrator, HollowingConfig, Platform

demo = ProcessHollowingDemonstrator()

# Get common targets
targets = demo.get_common_targets()

# Create config
config = HollowingConfig(
    target_process="svchost.exe",
    payload_source="beacon.exe",
    platform=Platform.WINDOWS_X64
)

# Generate plan
plan = demo.plan(config)
print(plan)
```

### Documentation Hook

```python
from process_hollowing import get_documentation

docs = get_documentation()
print(docs['technique_reference'])
```

## MITRE ATT&CK Reference

- **ID**: T1055.012
- **Technique**: Process Injection: Process Hollowing
- **Tactic**: Defense Evasion, Privilege Escalation

## Detection Tools

- Process Monitor (procmon)
- Process Hacker
- Volatility Framework
- pe-sieve / Hollows Hunter
- Sysmon with appropriate configuration

## References

- [MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)
- [Process Hollowing - ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- [Understanding Process Hollowing - EndGame](https://www.elastic.co/blog/process-hollowing-and-portable-executable-relocations)

## License

For authorized security testing and education only. See main project license.
