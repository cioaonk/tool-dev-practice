#!/usr/bin/env python3
"""
EDR Evasion Toolkit
Collection of EDR evasion techniques for authorized penetration testing

DISCLAIMER: This tool is for authorized security testing and educational purposes only.
Evading security products without authorization is illegal. Use responsibly.
"""

import argparse
import sys
import json
import struct
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod


class TechniqueCategory(Enum):
    """Categories of EDR evasion techniques"""
    DIRECT_SYSCALLS = "direct_syscalls"
    UNHOOKING = "unhooking"
    MEMORY_EVASION = "memory_evasion"
    API_HASHING = "api_hashing"
    CALLBACK_MANIPULATION = "callback_manipulation"
    ETW_BYPASS = "etw_bypass"
    PROCESS_INJECTION = "process_injection"


class Platform(Enum):
    """Target platform"""
    WINDOWS_X86 = "windows_x86"
    WINDOWS_X64 = "windows_x64"


class RiskLevel(Enum):
    """Risk level for technique"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SyscallInfo:
    """Information about a Windows syscall"""
    name: str
    syscall_number_win10: int
    syscall_number_win11: int
    description: str
    parameters: List[str]
    hooked_by: List[str]


@dataclass
class EvasionTechnique:
    """EDR evasion technique definition"""
    name: str
    category: TechniqueCategory
    description: str
    code_concept: str
    detection_methods: List[str]
    mitigations: List[str]
    mitre_technique: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.HIGH
    requires_admin: bool = False
    platform: Platform = Platform.WINDOWS_X64


class DirectSyscallGenerator:
    """
    Generator for direct syscall stubs.
    Demonstrates the concept of bypassing user-mode API hooks.
    """

    # Common syscalls used in offensive operations
    SYSCALLS = {
        "NtAllocateVirtualMemory": SyscallInfo(
            name="NtAllocateVirtualMemory",
            syscall_number_win10=0x18,
            syscall_number_win11=0x18,
            description="Allocate virtual memory in a process",
            parameters=["ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"],
            hooked_by=["CrowdStrike Falcon", "Carbon Black", "SentinelOne", "Microsoft Defender"]
        ),
        "NtWriteVirtualMemory": SyscallInfo(
            name="NtWriteVirtualMemory",
            syscall_number_win10=0x3A,
            syscall_number_win11=0x3A,
            description="Write to virtual memory of a process",
            parameters=["ProcessHandle", "BaseAddress", "Buffer", "NumberOfBytesToWrite", "NumberOfBytesWritten"],
            hooked_by=["CrowdStrike Falcon", "Carbon Black", "SentinelOne"]
        ),
        "NtCreateThreadEx": SyscallInfo(
            name="NtCreateThreadEx",
            syscall_number_win10=0xC1,
            syscall_number_win11=0xC2,
            description="Create a thread in a process",
            parameters=["ThreadHandle", "DesiredAccess", "ObjectAttributes", "ProcessHandle", "StartRoutine", "..."],
            hooked_by=["Most EDRs"]
        ),
        "NtProtectVirtualMemory": SyscallInfo(
            name="NtProtectVirtualMemory",
            syscall_number_win10=0x50,
            syscall_number_win11=0x50,
            description="Change memory protection",
            parameters=["ProcessHandle", "BaseAddress", "RegionSize", "NewProtect", "OldProtect"],
            hooked_by=["CrowdStrike Falcon", "Carbon Black"]
        ),
        "NtOpenProcess": SyscallInfo(
            name="NtOpenProcess",
            syscall_number_win10=0x26,
            syscall_number_win11=0x26,
            description="Open a handle to a process",
            parameters=["ProcessHandle", "DesiredAccess", "ObjectAttributes", "ClientId"],
            hooked_by=["Most EDRs"]
        ),
        "NtQueueApcThread": SyscallInfo(
            name="NtQueueApcThread",
            syscall_number_win10=0x45,
            syscall_number_win11=0x45,
            description="Queue an APC to a thread",
            parameters=["ThreadHandle", "ApcRoutine", "ApcArgument1", "ApcArgument2", "ApcArgument3"],
            hooked_by=["CrowdStrike Falcon", "SentinelOne"]
        ),
    }

    def get_syscall_stub_x64(self, syscall_name: str, syscall_number: int) -> str:
        """Generate x64 syscall stub assembly"""
        return f'''
; Direct Syscall Stub: {syscall_name}
; Syscall Number: 0x{syscall_number:02X}
; Platform: Windows x64

{syscall_name} PROC
    mov r10, rcx                ; Move first param to r10 (syscall convention)
    mov eax, 0{syscall_number:02X}h          ; Syscall number
    syscall                     ; Execute syscall
    ret                         ; Return
{syscall_name} ENDP
'''

    def get_syscall_stub_x86(self, syscall_name: str, syscall_number: int) -> str:
        """Generate x86 syscall stub assembly"""
        return f'''
; Direct Syscall Stub: {syscall_name}
; Syscall Number: 0x{syscall_number:02X}
; Platform: Windows x86

{syscall_name} PROC
    mov eax, 0{syscall_number:02X}h          ; Syscall number
    mov edx, esp                ; Pointer to args
    sysenter                    ; Execute syscall (or int 2Eh for older)
    ret                         ; Return
{syscall_name} ENDP
'''

    def get_syscall_info(self, name: str) -> Optional[SyscallInfo]:
        """Get information about a syscall"""
        return self.SYSCALLS.get(name)

    def list_syscalls(self) -> List[str]:
        """List available syscalls"""
        return list(self.SYSCALLS.keys())


class UnhookingTechniques:
    """
    Demonstrations of unhooking techniques.
    Shows concepts for removing EDR hooks from ntdll.dll
    """

    def get_full_dll_unhook_concept(self) -> str:
        """Concept for full DLL unhooking via disk read"""
        return '''
# Full DLL Unhooking Concept (Educational)
# Technique: Read clean ntdll.dll from disk and replace hooked .text section

Pseudocode:
1. Get handle to current process's ntdll.dll
2. Read clean copy of ntdll.dll from C:\\Windows\\System32\\ntdll.dll
3. Parse PE headers to find .text section
4. Change memory protection of loaded ntdll .text to RWX
5. Copy clean .text section over hooked version
6. Restore original memory protection

Detection Vectors:
- File read of ntdll.dll from disk
- Memory protection changes to ntdll
- .text section modification
- ETW events for memory operations
'''

    def get_syscall_stub_unhook_concept(self) -> str:
        """Concept for unhooking via syscall stub restoration"""
        return '''
# Syscall Stub Unhooking Concept (Educational)
# Technique: Restore just the first bytes of hooked functions

Pseudocode:
1. Identify hooked functions (look for JMP instructions at start)
2. Read clean syscall stub bytes from:
   - Disk copy of ntdll.dll
   - KnownDLLs (\\KnownDlls\\ntdll.dll)
   - Suspended process's ntdll
3. Overwrite just the syscall stub (first ~20 bytes)

Original syscall stub pattern (x64):
  4C 8B D1          mov r10, rcx
  B8 XX XX XX XX    mov eax, <syscall_number>
  0F 05             syscall
  C3                ret

Hook pattern (typical EDR):
  E9 XX XX XX XX    jmp <hook_address>
  ...
'''

    def get_perun_fart_concept(self) -> str:
        """Concept for Perun's Fart technique"""
        return '''
# Perun's Fart Technique Concept (Educational)
# Technique: Use legitimate Windows mechanisms to get clean ntdll

Approaches:
1. Read from KnownDLLs section:
   - NtOpenSection("\\KnownDlls\\ntdll.dll")
   - Map section and read clean bytes

2. Spawn suspended process:
   - Create process in suspended state
   - Read its ntdll.dll (before EDR hooks)
   - Terminate suspended process

3. Use debugging APIs:
   - Debug a suspended process
   - Read ntdll from debuggee

Benefits:
- Doesn't read from disk (avoids file system monitoring)
- Uses legitimate Windows APIs
- Harder to detect than direct disk reads
'''


class MemoryEvasionTechniques:
    """
    Memory-based evasion techniques demonstration
    """

    def get_module_stomping_concept(self) -> str:
        """Concept for module stomping technique"""
        return '''
# Module Stomping Concept (Educational)
# Technique: Hide payload in legitimate DLL's memory

Pseudocode:
1. Load a legitimate, unused DLL (e.g., amsi.dll, clrjit.dll)
2. Find its .text section (or writable section)
3. Change memory protection to RWX
4. Overwrite with payload
5. Execute from the "legitimate" module's memory

Benefits:
- Memory region appears to belong to signed Microsoft DLL
- Call stack shows legitimate module
- Memory scanning may skip signed modules

Detection Vectors:
- Private pages in signed module
- Hash mismatch between disk and memory
- Abnormal section permissions
'''

    def get_heap_encryption_concept(self) -> str:
        """Concept for heap encryption during sleep"""
        return '''
# Sleep Encryption Concept (Educational)
# Technique: Encrypt payload in memory during sleep

Pseudocode:
def encrypted_sleep(duration_ms):
    # Generate random key
    key = generate_random_key(32)

    # Find our payload in memory
    payload_region = find_payload_memory()

    # Encrypt payload
    encrypted = xor_encrypt(payload_region, key)

    # Overwrite payload with encrypted version
    write_memory(payload_region, encrypted)

    # Change protection to NO_ACCESS or RW (remove X)
    protect_memory(payload_region, PAGE_READWRITE)

    # Sleep
    sleep(duration_ms)

    # Restore protection
    protect_memory(payload_region, PAGE_EXECUTE_READ)

    # Decrypt payload
    decrypted = xor_decrypt(payload_region, key)
    write_memory(payload_region, decrypted)

    # Zero key from memory
    secure_zero(key)

Benefits:
- Payload not scannable during sleep
- Appears as encrypted/random data
- Memory protection changes indicate inactivity
'''

    def get_no_rwx_concept(self) -> str:
        """Concept for avoiding RWX memory"""
        return '''
# No RWX Memory Concept (Educational)
# Technique: Avoid suspicious RWX memory regions

Traditional (Suspicious):
1. Allocate RWX memory
2. Write shellcode
3. Execute

Better Approach:
1. Allocate RW memory
2. Write shellcode
3. Change to RX (VirtualProtect)
4. Execute

Even Better:
1. Allocate RW memory
2. Write shellcode
3. Create RX mapping of same pages (section view)
4. Execute from RX mapping

Benefits:
- No RWX regions (highly suspicious)
- Follows W^X principle
- Harder to detect via memory scanning
'''


class CallbackManipulation:
    """
    Techniques for manipulating security callbacks
    """

    def get_callback_removal_concept(self) -> str:
        """Concept for kernel callback removal (requires driver)"""
        return '''
# Kernel Callback Manipulation Concept (Educational)
# Note: Requires kernel-mode access (driver)

Common EDR Callbacks:
1. PsSetCreateProcessNotifyRoutine - Process creation
2. PsSetCreateThreadNotifyRoutine - Thread creation
3. PsSetLoadImageNotifyRoutine - Image/DLL loading
4. CmRegisterCallback - Registry operations
5. ObRegisterCallbacks - Object handle operations

Technique Overview:
1. Load kernel driver (requires signing or vulnerability)
2. Locate callback arrays in kernel memory
3. Find EDR callbacks by module name/pattern
4. Zero out or redirect callback entries

Detection Vectors:
- Driver loading events
- Kernel memory modifications
- Callback array integrity checks
- PatchGuard (in some cases)

Note: This is a highly privileged operation requiring
kernel access. Modern systems have many protections.
'''


class ETWBypassTechniques:
    """
    ETW (Event Tracing for Windows) bypass techniques
    """

    def get_etw_patching_concept(self) -> str:
        """Concept for ETW bypass via patching"""
        return '''
# ETW Bypass Concept (Educational)
# Technique: Patch ETW functions to prevent logging

Target Functions:
1. ntdll!EtwEventWrite - Main event writing function
2. ntdll!EtwEventWriteFull - Extended event writing

Patching Approach:
1. Resolve address of EtwEventWrite
2. Change memory protection to RWX
3. Write 'ret' instruction (0xC3) at function start
4. Restore memory protection

Pseudocode:
    etw_addr = GetProcAddress(ntdll, "EtwEventWrite")
    VirtualProtect(etw_addr, 1, PAGE_EXECUTE_READWRITE, &old)
    *(BYTE*)etw_addr = 0xC3  // ret
    VirtualProtect(etw_addr, 1, old, &old)

Detection Vectors:
- Memory modification to ntdll
- ETW session still exists but no events
- Integrity checking of ETW functions
- Kernel-mode ETW still functional

Note: Only bypasses user-mode ETW providers
'''

    def get_etw_provider_disable_concept(self) -> str:
        """Concept for disabling ETW providers"""
        return '''
# ETW Provider Disabling Concept (Educational)
# Technique: Disable specific ETW providers

PowerShell Example (Admin Required):
    # List providers
    logman query providers

    # Disable .NET provider
    logman stop "EventLog-Microsoft-Windows-DotNETRuntime" -ets

    # Disable PowerShell provider
    logman stop "EventLog-Microsoft-Windows-PowerShell" -ets

Programmatic Approach:
1. Enumerate active ETW sessions
2. Find sessions subscribed to security providers
3. Stop sessions or unsubscribe providers

Common Security Providers:
- Microsoft-Windows-PowerShell
- Microsoft-Windows-DotNETRuntime
- Microsoft-Antimalware-Scan-Interface
- Microsoft-Windows-Threat-Intelligence

Detection Vectors:
- Provider/session state changes
- Missing expected events
- Audit logs for ETW modifications
'''


class APIHashingTechniques:
    """
    API hashing techniques for avoiding string detection
    """

    @staticmethod
    def djb2_hash(name: str) -> int:
        """DJB2 hash algorithm"""
        h = 5381
        for c in name:
            h = ((h << 5) + h) + ord(c)
            h &= 0xFFFFFFFF
        return h

    @staticmethod
    def ror13_hash(name: str) -> int:
        """ROR13 hash algorithm"""
        h = 0
        for c in name:
            h = ((h >> 13) | (h << 19)) + ord(c)
            h &= 0xFFFFFFFF
        return h

    def get_api_hashing_concept(self) -> str:
        """Concept for API hashing"""
        return '''
# API Hashing Concept (Educational)
# Technique: Resolve APIs at runtime using hash values

Traditional (Detectable):
    kernel32 = LoadLibrary("kernel32.dll")
    VirtualAlloc = GetProcAddress(kernel32, "VirtualAlloc")

With API Hashing:
    kernel32 = find_module_by_hash(KERNEL32_HASH)
    VirtualAlloc = find_export_by_hash(kernel32, VIRTUALALLOC_HASH)

Hash Function (DJB2):
    def djb2(name):
        h = 5381
        for c in name:
            h = ((h << 5) + h) + ord(c)
        return h & 0xFFFFFFFF

Benefits:
- No cleartext API strings in binary
- Harder static analysis
- Defeats simple string scanning

Detection Vectors:
- Hash value signatures
- PEB walking patterns
- Export enumeration behavior
'''

    def generate_hash_table(self, api_names: List[str]) -> Dict[str, Dict[str, int]]:
        """Generate hash table for API names"""
        return {
            name: {
                "djb2": self.djb2_hash(name),
                "ror13": self.ror13_hash(name)
            }
            for name in api_names
        }


class EDREvasionToolkit:
    """Main EDR Evasion Toolkit class"""

    def __init__(self):
        self.syscall_gen = DirectSyscallGenerator()
        self.unhooking = UnhookingTechniques()
        self.memory_evasion = MemoryEvasionTechniques()
        self.callback_manip = CallbackManipulation()
        self.etw_bypass = ETWBypassTechniques()
        self.api_hashing = APIHashingTechniques()

        self.techniques = self._define_techniques()

    def _define_techniques(self) -> Dict[str, EvasionTechnique]:
        """Define available evasion techniques"""
        return {
            "direct_syscalls": EvasionTechnique(
                name="Direct Syscalls",
                category=TechniqueCategory.DIRECT_SYSCALLS,
                description="Execute syscalls directly to bypass user-mode API hooks",
                code_concept=self.syscall_gen.get_syscall_stub_x64("NtAllocateVirtualMemory", 0x18),
                detection_methods=[
                    "Syscall instruction outside ntdll",
                    "Call stack analysis showing no ntdll",
                    "EDR kernel callbacks still trigger"
                ],
                mitigations=[
                    "Kernel-mode monitoring",
                    "Call stack validation",
                    "Syscall origin verification"
                ],
                mitre_technique="T1106",
                risk_level=RiskLevel.HIGH
            ),

            "full_unhooking": EvasionTechnique(
                name="Full DLL Unhooking",
                category=TechniqueCategory.UNHOOKING,
                description="Replace hooked ntdll.dll .text section with clean copy",
                code_concept=self.unhooking.get_full_dll_unhook_concept(),
                detection_methods=[
                    "File read of ntdll.dll",
                    "Memory protection changes",
                    ".text section modification",
                    "PE section hash mismatch"
                ],
                mitigations=[
                    "Kernel-mode hooks",
                    "Periodic hook verification",
                    "File access monitoring"
                ],
                mitre_technique="T1562.001",
                risk_level=RiskLevel.HIGH
            ),

            "module_stomping": EvasionTechnique(
                name="Module Stomping",
                category=TechniqueCategory.MEMORY_EVASION,
                description="Hide payload in legitimate DLL's memory space",
                code_concept=self.memory_evasion.get_module_stomping_concept(),
                detection_methods=[
                    "Private pages in signed module",
                    "Memory hash vs disk hash",
                    "Abnormal module behavior"
                ],
                mitigations=[
                    "Memory integrity scanning",
                    "Module hash verification",
                    "Behavioral analysis"
                ],
                mitre_technique="T1055",
                risk_level=RiskLevel.HIGH
            ),

            "sleep_encryption": EvasionTechnique(
                name="Sleep Encryption",
                category=TechniqueCategory.MEMORY_EVASION,
                description="Encrypt payload in memory during sleep periods",
                code_concept=self.memory_evasion.get_heap_encryption_concept(),
                detection_methods=[
                    "Memory protection patterns",
                    "Entropy changes in memory",
                    "Decryption at wake"
                ],
                mitigations=[
                    "Continuous memory scanning",
                    "Protection change monitoring",
                    "Sleep pattern analysis"
                ],
                mitre_technique="T1027",
                risk_level=RiskLevel.MEDIUM
            ),

            "etw_patching": EvasionTechnique(
                name="ETW Patching",
                category=TechniqueCategory.ETW_BYPASS,
                description="Patch ETW functions to prevent event logging",
                code_concept=self.etw_bypass.get_etw_patching_concept(),
                detection_methods=[
                    "ETW function modification",
                    "Missing expected events",
                    "Kernel ETW still active"
                ],
                mitigations=[
                    "Kernel-mode ETW",
                    "ETW integrity monitoring",
                    "Function hooking detection"
                ],
                mitre_technique="T1562.006",
                risk_level=RiskLevel.MEDIUM
            ),

            "api_hashing": EvasionTechnique(
                name="API Hashing",
                category=TechniqueCategory.API_HASHING,
                description="Resolve APIs via hash to avoid string detection",
                code_concept=self.api_hashing.get_api_hashing_concept(),
                detection_methods=[
                    "Known hash patterns",
                    "PEB walking behavior",
                    "Export enumeration"
                ],
                mitigations=[
                    "Hash signature detection",
                    "Behavioral analysis",
                    "API resolution monitoring"
                ],
                mitre_technique="T1027",
                risk_level=RiskLevel.LOW
            ),
        }

    def get_technique(self, name: str) -> Optional[EvasionTechnique]:
        """Get a specific technique by name"""
        return self.techniques.get(name)

    def list_techniques(self) -> List[str]:
        """List available techniques"""
        return list(self.techniques.keys())

    def get_techniques_by_category(self, category: TechniqueCategory) -> List[EvasionTechnique]:
        """Get techniques filtered by category"""
        return [t for t in self.techniques.values() if t.category == category]

    def generate_syscall_stub(self, syscall_name: str, platform: Platform = Platform.WINDOWS_X64) -> str:
        """Generate a syscall stub for a given syscall"""
        info = self.syscall_gen.get_syscall_info(syscall_name)
        if not info:
            raise ValueError(f"Unknown syscall: {syscall_name}")

        if platform == Platform.WINDOWS_X64:
            return self.syscall_gen.get_syscall_stub_x64(syscall_name, info.syscall_number_win10)
        else:
            return self.syscall_gen.get_syscall_stub_x86(syscall_name, info.syscall_number_win10)

    def generate_api_hashes(self, api_names: List[str]) -> Dict:
        """Generate hash values for API names"""
        return self.api_hashing.generate_hash_table(api_names)

    def plan(self, technique_name: str) -> str:
        """Generate execution plan for a technique"""
        output = []
        output.append("")
        output.append("[PLAN MODE] Tool: edr-evasion-toolkit")
        output.append("=" * 65)
        output.append("")
        output.append("DISCLAIMER: For authorized security testing only.")
        output.append("Evading security controls without authorization is illegal.")
        output.append("")

        if technique_name == "all":
            output.append("-" * 65)
            output.append("Available EDR Evasion Techniques:")
            output.append("-" * 65)
            for name, tech in self.techniques.items():
                output.append(f"\n  {name}")
                output.append(f"    Category: {tech.category.value}")
                output.append(f"    Risk Level: {tech.risk_level.value}")
                output.append(f"    MITRE: {tech.mitre_technique or 'N/A'}")
                output.append(f"    Description: {tech.description}")
        else:
            if technique_name not in self.techniques:
                output.append(f"ERROR: Unknown technique '{technique_name}'")
                output.append(f"Available: {', '.join(self.techniques.keys())}")
                return "\n".join(output)

            tech = self.techniques[technique_name]
            output.append("-" * 65)
            output.append("Technique Details:")
            output.append("-" * 65)
            output.append(f"  Name: {tech.name}")
            output.append(f"  Category: {tech.category.value}")
            output.append(f"  Risk Level: {tech.risk_level.value}")
            output.append(f"  MITRE ATT&CK: {tech.mitre_technique or 'N/A'}")
            output.append(f"  Requires Admin: {'Yes' if tech.requires_admin else 'No'}")
            output.append(f"  Platform: {tech.platform.value}")
            output.append("")
            output.append("Description:")
            output.append(f"  {tech.description}")
            output.append("")
            output.append("-" * 65)
            output.append("Detection Methods (How defenders detect this):")
            output.append("-" * 65)
            for method in tech.detection_methods:
                output.append(f"  ! {method}")
            output.append("")
            output.append("-" * 65)
            output.append("Defensive Mitigations:")
            output.append("-" * 65)
            for mitigation in tech.mitigations:
                output.append(f"  * {mitigation}")
            output.append("")
            output.append("-" * 65)
            output.append("Technique Concept:")
            output.append("-" * 65)
            output.append(tech.code_concept)

        output.append("")
        output.append("-" * 65)
        output.append("Risk Assessment:")
        output.append("-" * 65)
        output.append("  These techniques are well-known to EDR vendors")
        output.append("  Modern EDRs use multiple detection layers")
        output.append("  Kernel-mode components may still detect activity")
        output.append("  Combine multiple techniques for better results")
        output.append("")
        output.append("This is PLAN MODE - educational content only.")
        output.append("=" * 65)
        output.append("")

        return "\n".join(output)


def get_documentation() -> Dict:
    """
    Documentation hook for integration with documentation agent.
    Returns structured documentation for this tool.
    """
    return {
        "name": "EDR Evasion Toolkit",
        "version": "1.0.0",
        "category": "Evasion",
        "description": "Collection of EDR evasion techniques for authorized penetration testing and security research.",
        "author": "Offensive Security Toolsmith",
        "disclaimer": "For authorized security testing only. Evading security controls without authorization is illegal.",
        "usage": {
            "list_techniques": "python edr_evasion.py --list",
            "plan_technique": "python edr_evasion.py --technique direct_syscalls --plan",
            "syscall_info": "python edr_evasion.py --syscall NtAllocateVirtualMemory",
            "generate_stubs": "python edr_evasion.py --generate-stubs NtAllocateVirtualMemory,NtWriteVirtualMemory",
            "api_hashes": "python edr_evasion.py --hash-apis VirtualAlloc,CreateThread"
        },
        "techniques": {
            "direct_syscalls": "Execute syscalls directly bypassing hooks",
            "full_unhooking": "Replace hooked ntdll with clean copy",
            "module_stomping": "Hide payload in legitimate DLL memory",
            "sleep_encryption": "Encrypt payload during sleep periods",
            "etw_patching": "Patch ETW to prevent logging",
            "api_hashing": "Resolve APIs via hash values"
        },
        "categories": [
            "direct_syscalls",
            "unhooking",
            "memory_evasion",
            "api_hashing",
            "callback_manipulation",
            "etw_bypass"
        ],
        "arguments": [
            {"name": "--technique", "description": "Technique to explore", "required": False},
            {"name": "--list", "description": "List available techniques", "required": False},
            {"name": "--category", "description": "Filter by category", "required": False},
            {"name": "--syscall", "description": "Get syscall information", "required": False},
            {"name": "--generate-stubs", "description": "Generate syscall stubs", "required": False},
            {"name": "--hash-apis", "description": "Generate API hashes", "required": False},
            {"name": "--plan", "description": "Show execution plan only", "required": False},
            {"name": "--json", "description": "Output in JSON format", "required": False}
        ],
        "mitre_techniques": [
            "T1106 - Native API",
            "T1562.001 - Disable or Modify Tools",
            "T1562.006 - Indicator Blocking",
            "T1055 - Process Injection",
            "T1027 - Obfuscated Files or Information"
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1106/",
            "https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/",
            "https://blog.sektor7.net/#!res/2021/halosgate.md"
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="EDR Evasion Toolkit - Educational evasion techniques",
        epilog="DISCLAIMER: For authorized security testing only."
    )

    parser.add_argument("--technique", "-t", help="Technique to explore")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available techniques")
    parser.add_argument("--category", "-c",
                        choices=[c.value for c in TechniqueCategory],
                        help="Filter by category")
    parser.add_argument("--syscall", "-s", help="Get syscall information")
    parser.add_argument("--list-syscalls", action="store_true",
                        help="List available syscalls")
    parser.add_argument("--generate-stubs", help="Generate syscall stubs (comma-separated)")
    parser.add_argument("--hash-apis", help="Generate API hashes (comma-separated)")
    parser.add_argument("--platform", choices=["windows_x64", "windows_x86"],
                        default="windows_x64", help="Target platform")
    parser.add_argument("--plan", "-p", action="store_true",
                        help="Show execution plan only")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--doc", action="store_true",
                        help="Show documentation")

    args = parser.parse_args()
    toolkit = EDREvasionToolkit()

    # Handle documentation
    if args.doc:
        docs = get_documentation()
        if args.json:
            print(json.dumps(docs, indent=2))
        else:
            print(f"\n{docs['name']} v{docs['version']}")
            print("=" * 65)
            print(f"\n{docs['description']}\n")
            print(f"Disclaimer: {docs['disclaimer']}")
            print("\nAvailable Techniques:")
            for name, desc in docs['techniques'].items():
                print(f"  - {name}: {desc}")
        return 0

    # Handle list syscalls
    if args.list_syscalls:
        syscalls = toolkit.syscall_gen.list_syscalls()
        if args.json:
            syscall_info = {}
            for name in syscalls:
                info = toolkit.syscall_gen.get_syscall_info(name)
                syscall_info[name] = {
                    "syscall_win10": hex(info.syscall_number_win10),
                    "syscall_win11": hex(info.syscall_number_win11),
                    "description": info.description,
                    "hooked_by": info.hooked_by
                }
            print(json.dumps(syscall_info, indent=2))
        else:
            print("\nAvailable Syscalls:")
            print("-" * 60)
            for name in syscalls:
                info = toolkit.syscall_gen.get_syscall_info(name)
                print(f"\n  {name}")
                print(f"    Win10: 0x{info.syscall_number_win10:02X}")
                print(f"    Description: {info.description}")
        return 0

    # Handle syscall info
    if args.syscall:
        info = toolkit.syscall_gen.get_syscall_info(args.syscall)
        if not info:
            print(f"Error: Unknown syscall '{args.syscall}'")
            return 1

        if args.json:
            print(json.dumps({
                "name": info.name,
                "syscall_win10": hex(info.syscall_number_win10),
                "syscall_win11": hex(info.syscall_number_win11),
                "description": info.description,
                "parameters": info.parameters,
                "hooked_by": info.hooked_by
            }, indent=2))
        else:
            print(f"\nSyscall: {info.name}")
            print("-" * 50)
            print(f"  Win10 Number: 0x{info.syscall_number_win10:02X}")
            print(f"  Win11 Number: 0x{info.syscall_number_win11:02X}")
            print(f"  Description: {info.description}")
            print(f"  Parameters: {', '.join(info.parameters)}")
            print(f"  Commonly Hooked By:")
            for edr in info.hooked_by:
                print(f"    - {edr}")
        return 0

    # Handle generate stubs
    if args.generate_stubs:
        syscall_names = [s.strip() for s in args.generate_stubs.split(',')]
        platform = Platform(args.platform)

        for name in syscall_names:
            try:
                stub = toolkit.generate_syscall_stub(name, platform)
                print(stub)
            except ValueError as e:
                print(f"; Error: {e}")
        return 0

    # Handle API hashing
    if args.hash_apis:
        api_names = [a.strip() for a in args.hash_apis.split(',')]
        hashes = toolkit.generate_api_hashes(api_names)

        if args.json:
            # Convert to hex strings for JSON
            json_hashes = {
                name: {
                    "djb2": hex(h["djb2"]),
                    "ror13": hex(h["ror13"])
                }
                for name, h in hashes.items()
            }
            print(json.dumps(json_hashes, indent=2))
        else:
            print("\nAPI Hashes:")
            print("-" * 50)
            for name, h in hashes.items():
                print(f"\n  {name}:")
                print(f"    DJB2:  0x{h['djb2']:08X}")
                print(f"    ROR13: 0x{h['ror13']:08X}")
        return 0

    # Handle list techniques
    if args.list:
        techniques = toolkit.techniques
        if args.category:
            cat = TechniqueCategory(args.category)
            techniques = {k: v for k, v in techniques.items() if v.category == cat}

        if args.json:
            output = {
                name: {
                    "name": t.name,
                    "category": t.category.value,
                    "risk_level": t.risk_level.value,
                    "mitre": t.mitre_technique,
                    "description": t.description
                }
                for name, t in techniques.items()
            }
            print(json.dumps(output, indent=2))
        else:
            print("\nEDR Evasion Techniques:")
            print("-" * 60)
            for name, tech in techniques.items():
                print(f"\n  {name}")
                print(f"    Name: {tech.name}")
                print(f"    Category: {tech.category.value}")
                print(f"    Risk: {tech.risk_level.value}")
                print(f"    MITRE: {tech.mitre_technique or 'N/A'}")
        return 0

    # Handle plan mode
    if args.plan:
        technique = args.technique or "all"
        print(toolkit.plan(technique))
        return 0

    # Handle technique detail
    if args.technique:
        tech = toolkit.get_technique(args.technique)
        if not tech:
            print(f"Error: Unknown technique '{args.technique}'")
            return 1

        if args.json:
            print(json.dumps({
                "name": tech.name,
                "category": tech.category.value,
                "description": tech.description,
                "risk_level": tech.risk_level.value,
                "mitre_technique": tech.mitre_technique,
                "detection_methods": tech.detection_methods,
                "mitigations": tech.mitigations,
                "code_concept": tech.code_concept
            }, indent=2))
        else:
            print(toolkit.plan(args.technique))
        return 0

    # Default: show help
    parser.print_help()
    print("\nUse --list to see available techniques or --plan for overview.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
