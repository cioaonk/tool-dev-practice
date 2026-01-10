# AMSI Bypass Generator

A tool for generating AMSI (Antimalware Scan Interface) bypass techniques with various obfuscation levels for authorized security testing.

## DISCLAIMER

**This tool is for authorized security testing and educational purposes only.**

AMSI is a security feature designed to protect systems. Bypassing AMSI without explicit authorization is illegal and unethical. Only use this tool:
- During authorized penetration tests
- In CTF competitions
- In controlled lab environments
- For security research with proper permissions

## What is AMSI?

The Antimalware Scan Interface (AMSI) is a Windows security feature introduced in Windows 10 that:
- Provides a standardized interface for applications to request malware scans
- Scans PowerShell scripts, VBScript, JScript, and WMI operations
- Integrates with installed antimalware products
- Operates at runtime, scanning content before execution

## Features

- **Multiple Bypass Techniques**: Various approaches to AMSI bypass
- **Obfuscation Levels**: 0-3 levels of code obfuscation
- **Base64 Encoding**: PowerShell -enc compatible output
- **Planning Mode**: Analyze techniques before generation
- **Chain Generation**: Multi-technique bypass chains
- **Category Filtering**: Filter techniques by type
- **JSON Output**: Machine-readable output

## Installation

No additional dependencies - uses Python standard library only.

```bash
chmod +x amsi_bypass.py
```

## Usage

### List Available Techniques

```bash
python amsi_bypass.py --list
python amsi_bypass.py --list --category memory_patching
python amsi_bypass.py --list --json
```

### Planning Mode

```bash
# Plan specific technique
python amsi_bypass.py --technique force_amsi_error --plan

# Plan all techniques
python amsi_bypass.py --plan
```

### Generate Bypass

```bash
# Basic generation
python amsi_bypass.py --technique force_amsi_error

# With obfuscation
python amsi_bypass.py --technique amsi_scan_buffer_patch --obfuscate 2

# Base64 encoded for -enc delivery
python amsi_bypass.py --technique force_amsi_error --base64

# JSON output
python amsi_bypass.py --technique force_amsi_error --json
```

### Chain Generation

```bash
# Generate multi-technique chain
python amsi_bypass.py --chain

# Plan chain
python amsi_bypass.py --chain --plan
```

### Documentation

```bash
python amsi_bypass.py --doc
python amsi_bypass.py --doc --json
```

## Available Techniques

| Technique | Category | Risk Level | Description |
|-----------|----------|------------|-------------|
| `amsi_scan_buffer_patch` | Memory Patching | High | Patches AmsiScanBuffer return value |
| `reflection_context_null` | Reflection | High | Nullifies AMSI context via reflection |
| `force_amsi_error` | Context Manipulation | Medium | Forces AMSI initialization failure |
| `powershell_downgrade` | PS Downgrade | Low | Uses PowerShell v2 (no AMSI) |
| `clm_bypass` | Context Manipulation | Medium | Bypasses Constrained Language Mode |
| `type_confusion` | Reflection | Medium | Uses type confusion for bypass |
| `wldp_com` | COM Hijacking | Low | Uses COM objects for bypass |

## Obfuscation Levels

- **Level 0**: No obfuscation, raw code
- **Level 1**: String splitting for sensitive terms
- **Level 2**: Variable name randomization
- **Level 3**: Additional string encoding and concatenation

## Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--technique` | `-t` | Bypass technique to use |
| `--obfuscate` | `-o` | Obfuscation level 0-3 |
| `--base64` | `-b` | Base64 encode for -enc delivery |
| `--plan` | `-p` | Show execution plan only |
| `--list` | `-l` | List available techniques |
| `--chain` | | Generate multi-technique chain |
| `--category` | `-c` | Filter by category |
| `--json` | `-j` | JSON output format |
| `--doc` | | Show documentation |

## Bypass Categories

- **memory_patching**: Direct memory manipulation techniques
- **reflection**: .NET reflection-based bypasses
- **com_hijacking**: COM object abuse
- **powershell_downgrade**: Version downgrade attacks
- **context_manipulation**: PowerShell context changes
- **string_obfuscation**: String-based evasion

## Integration

### As a Module

```python
from amsi_bypass import AMSIBypassGenerator, BypassCategory

generator = AMSIBypassGenerator()

# List techniques
techniques = generator.get_available_techniques()

# Get techniques by category
memory_techniques = generator.get_techniques_by_category(BypassCategory.MEMORY_PATCHING)

# Generate bypass
result = generator.generate_bypass(
    technique_name="force_amsi_error",
    obfuscation=2,
    encode_base64=True
)
print(result['code'])

# Get obfuscated code only
code = generator.obfuscate_bypass("force_amsi_error", level=2)
```

### Documentation Hook

```python
from amsi_bypass import get_documentation

docs = get_documentation()
print(docs['amsi_overview'])
```

## Detection Methods (For Defenders)

### Script Block Logging
Enable PowerShell script block logging to capture AMSI bypass attempts:
```powershell
# Group Policy: Administrative Templates > Windows Components > Windows PowerShell
# Turn on PowerShell Script Block Logging
```

### Memory Scanning
Monitor for known byte patterns in amsi.dll memory regions.

### ETW Tracing
Enable Event Tracing for Windows (ETW) for AMSI events.

### Behavioral Analysis
- Monitor for reflection API usage
- Detect PowerShell v2 invocations
- Watch for amsiInitFailed field access

## Operational Notes

1. **Test First**: Always test in isolated environment
2. **Combine Techniques**: Use multiple evasion methods
3. **Monitor Logging**: Be aware of PowerShell logging
4. **Update Signatures**: Bypass techniques get signatured quickly
5. **Obfuscation**: Higher levels reduce detection, but also readability

## MITRE ATT&CK

- **ID**: T1562.001
- **Technique**: Impair Defenses: Disable or Modify Tools
- **Tactic**: Defense Evasion

## References

- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- [PowerShell AMSI and Logging Evasion](https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/)

## License

For authorized security testing only. See main project license.
