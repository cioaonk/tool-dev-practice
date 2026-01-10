#!/usr/bin/env python3
"""
Process Hollowing Demonstration Tool
Educational tool demonstrating process hollowing technique concepts

DISCLAIMER: This tool is for authorized security testing and educational purposes only.
Process hollowing is a technique used by malware. This implementation provides
educational demonstration of the concept without actual malicious functionality.
"""

import argparse
import sys
import json
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod


class ProcessState(Enum):
    """Process states during hollowing"""
    NOT_STARTED = auto()
    CREATED_SUSPENDED = auto()
    MEMORY_UNMAPPED = auto()
    PAYLOAD_WRITTEN = auto()
    CONTEXT_MODIFIED = auto()
    RESUMED = auto()
    FAILED = auto()


class Platform(Enum):
    """Target platform"""
    WINDOWS_X86 = "windows_x86"
    WINDOWS_X64 = "windows_x64"


@dataclass
class ProcessInfo:
    """Information about a process for hollowing"""
    name: str
    path: str
    architecture: str
    typical_parent: str
    suspicion_level: str  # low, medium, high
    notes: List[str] = field(default_factory=list)


@dataclass
class HollowingConfig:
    """Configuration for process hollowing operation"""
    target_process: str
    payload_source: str  # file path or "embedded"
    platform: Platform
    parent_pid: Optional[int] = None
    ppid_spoof: bool = False
    block_dlls: bool = False
    create_no_window: bool = True


@dataclass
class HollowingStep:
    """A single step in the hollowing process"""
    name: str
    description: str
    api_calls: List[str]
    detection_vectors: List[str]
    artifacts: List[str]


class WindowsAPISimulator:
    """
    Simulates Windows API calls for educational purposes.
    Does NOT actually call Windows APIs - purely demonstrative.
    """

    @staticmethod
    def get_api_prototype(api_name: str) -> Dict:
        """Get API prototype information"""
        api_info = {
            "CreateProcessA": {
                "dll": "kernel32.dll",
                "prototype": "BOOL CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)",
                "key_flags": ["CREATE_SUSPENDED (0x4)", "CREATE_NO_WINDOW (0x08000000)"],
                "returns": "Process and thread handles in PROCESS_INFORMATION"
            },
            "NtUnmapViewOfSection": {
                "dll": "ntdll.dll",
                "prototype": "NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)",
                "key_flags": [],
                "returns": "NTSTATUS code"
            },
            "VirtualAllocEx": {
                "dll": "kernel32.dll",
                "prototype": "LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)",
                "key_flags": ["MEM_COMMIT (0x1000)", "MEM_RESERVE (0x2000)", "PAGE_EXECUTE_READWRITE (0x40)"],
                "returns": "Base address of allocated memory"
            },
            "WriteProcessMemory": {
                "dll": "kernel32.dll",
                "prototype": "BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)",
                "key_flags": [],
                "returns": "Boolean success/failure"
            },
            "GetThreadContext": {
                "dll": "kernel32.dll",
                "prototype": "BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)",
                "key_flags": ["CONTEXT_FULL (0x10000B)"],
                "returns": "Thread context structure"
            },
            "SetThreadContext": {
                "dll": "kernel32.dll",
                "prototype": "BOOL SetThreadContext(HANDLE hThread, const CONTEXT *lpContext)",
                "key_flags": [],
                "returns": "Boolean success/failure"
            },
            "ResumeThread": {
                "dll": "kernel32.dll",
                "prototype": "DWORD ResumeThread(HANDLE hThread)",
                "key_flags": [],
                "returns": "Previous suspend count"
            },
            "NtQueryInformationProcess": {
                "dll": "ntdll.dll",
                "prototype": "NTSTATUS NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)",
                "key_flags": ["ProcessBasicInformation (0)"],
                "returns": "Process information structure"
            }
        }
        return api_info.get(api_name, {"dll": "unknown", "prototype": "unknown"})


class ProcessHollowingDemonstrator:
    """
    Educational demonstration of process hollowing technique.
    This class explains the technique without performing actual hollowing.
    """

    # Common target processes for hollowing (educational reference)
    COMMON_TARGETS = [
        ProcessInfo(
            name="svchost.exe",
            path="C:\\Windows\\System32\\svchost.exe",
            architecture="x64",
            typical_parent="services.exe",
            suspicion_level="low",
            notes=["Multiple instances normal", "Commonly targeted", "Should have -k parameter"]
        ),
        ProcessInfo(
            name="RuntimeBroker.exe",
            path="C:\\Windows\\System32\\RuntimeBroker.exe",
            architecture="x64",
            typical_parent="svchost.exe",
            suspicion_level="low",
            notes=["Multiple instances normal", "Modern Windows target"]
        ),
        ProcessInfo(
            name="notepad.exe",
            path="C:\\Windows\\System32\\notepad.exe",
            architecture="x64",
            typical_parent="explorer.exe",
            suspicion_level="medium",
            notes=["Commonly used in demos", "GUI application expected"]
        ),
        ProcessInfo(
            name="calc.exe",
            path="C:\\Windows\\System32\\calc.exe",
            architecture="x64",
            typical_parent="explorer.exe",
            suspicion_level="medium",
            notes=["Modern calc.exe is a UWP wrapper", "Legacy calc may be needed"]
        ),
    ]

    def __init__(self):
        self.steps: List[HollowingStep] = self._define_steps()
        self.current_state = ProcessState.NOT_STARTED
        self.api_simulator = WindowsAPISimulator()

    def _define_steps(self) -> List[HollowingStep]:
        """Define the steps of process hollowing"""
        return [
            HollowingStep(
                name="Create Suspended Process",
                description="Create target process in a suspended state using CREATE_SUSPENDED flag",
                api_calls=["CreateProcessA/W with CREATE_SUSPENDED (0x4)"],
                detection_vectors=[
                    "Process creation with suspended state",
                    "Parent-child process relationship",
                    "Command line arguments analysis"
                ],
                artifacts=[
                    "Suspended process in memory",
                    "Thread handle",
                    "Process handle"
                ]
            ),
            HollowingStep(
                name="Query Process Information",
                description="Get the PEB (Process Environment Block) address to locate image base",
                api_calls=["NtQueryInformationProcess", "ReadProcessMemory"],
                detection_vectors=[
                    "Cross-process memory reads",
                    "PEB access patterns"
                ],
                artifacts=[
                    "PEB address",
                    "Image base address"
                ]
            ),
            HollowingStep(
                name="Unmap Original Image",
                description="Unmap the original executable image from the process",
                api_calls=["NtUnmapViewOfSection"],
                detection_vectors=[
                    "Section unmapping in suspended process",
                    "NtUnmapViewOfSection call patterns"
                ],
                artifacts=[
                    "Unmapped memory region",
                    "Hollow process space"
                ]
            ),
            HollowingStep(
                name="Allocate New Memory",
                description="Allocate memory at the original image base (or new location)",
                api_calls=["VirtualAllocEx with PAGE_EXECUTE_READWRITE"],
                detection_vectors=[
                    "RWX memory allocation",
                    "Cross-process memory allocation",
                    "Allocation at image base address"
                ],
                artifacts=[
                    "Allocated memory region",
                    "RWX permissions"
                ]
            ),
            HollowingStep(
                name="Write Payload",
                description="Write the new PE image (headers + sections) to allocated memory",
                api_calls=["WriteProcessMemory (multiple calls)"],
                detection_vectors=[
                    "Cross-process writes",
                    "PE header patterns in memory",
                    "Section alignment writes"
                ],
                artifacts=[
                    "Written PE image",
                    "Modified process memory"
                ]
            ),
            HollowingStep(
                name="Fix Image Base in PEB",
                description="Update the ImageBaseAddress in PEB to point to new image",
                api_calls=["WriteProcessMemory to PEB"],
                detection_vectors=[
                    "PEB modification",
                    "Image base mismatch"
                ],
                artifacts=[
                    "Modified PEB"
                ]
            ),
            HollowingStep(
                name="Set Thread Context",
                description="Modify thread context to point EIP/RIP to new entry point",
                api_calls=["GetThreadContext", "SetThreadContext"],
                detection_vectors=[
                    "Thread context modification",
                    "Entry point redirection"
                ],
                artifacts=[
                    "Modified thread context",
                    "New entry point"
                ]
            ),
            HollowingStep(
                name="Resume Execution",
                description="Resume the suspended thread to execute the injected code",
                api_calls=["ResumeThread"],
                detection_vectors=[
                    "Resumed process behavior",
                    "Image/process name mismatch",
                    "Network connections from unexpected process"
                ],
                artifacts=[
                    "Running hollowed process"
                ]
            )
        ]

    def get_common_targets(self) -> List[ProcessInfo]:
        """Get list of common target processes"""
        return self.COMMON_TARGETS

    def explain_step(self, step_index: int) -> str:
        """Get detailed explanation of a specific step"""
        if step_index < 0 or step_index >= len(self.steps):
            return "Invalid step index"

        step = self.steps[step_index]
        output = []
        output.append(f"\n{'='*60}")
        output.append(f"Step {step_index + 1}: {step.name}")
        output.append(f"{'='*60}")
        output.append(f"\nDescription: {step.description}")
        output.append("\nAPI Calls:")
        for api in step.api_calls:
            output.append(f"  - {api}")
            # Get API details
            api_name = api.split()[0].split('/')[0]
            info = self.api_simulator.get_api_prototype(api_name)
            if info['dll'] != 'unknown':
                output.append(f"    DLL: {info['dll']}")
        output.append("\nDetection Vectors:")
        for vector in step.detection_vectors:
            output.append(f"  ! {vector}")
        output.append("\nArtifacts Created:")
        for artifact in step.artifacts:
            output.append(f"  * {artifact}")

        return "\n".join(output)

    def plan(self, config: HollowingConfig) -> str:
        """Generate execution plan without performing any actions"""
        output = []
        output.append("")
        output.append("[PLAN MODE] Tool: process-hollowing")
        output.append("=" * 60)
        output.append("")
        output.append("DISCLAIMER: Educational demonstration only.")
        output.append("This tool does NOT perform actual process hollowing.")
        output.append("")
        output.append("-" * 60)
        output.append("Configuration:")
        output.append("-" * 60)
        output.append(f"  Target Process: {config.target_process}")
        output.append(f"  Payload Source: {config.payload_source}")
        output.append(f"  Platform: {config.platform.value}")
        output.append(f"  PPID Spoofing: {'Enabled' if config.ppid_spoof else 'Disabled'}")
        output.append(f"  Block Non-MS DLLs: {'Enabled' if config.block_dlls else 'Disabled'}")
        output.append(f"  Create No Window: {'Yes' if config.create_no_window else 'No'}")
        output.append("")

        # Find target info
        target_info = None
        for t in self.COMMON_TARGETS:
            if t.name.lower() == config.target_process.lower():
                target_info = t
                break

        if target_info:
            output.append("-" * 60)
            output.append("Target Process Analysis:")
            output.append("-" * 60)
            output.append(f"  Path: {target_info.path}")
            output.append(f"  Architecture: {target_info.architecture}")
            output.append(f"  Typical Parent: {target_info.typical_parent}")
            output.append(f"  Suspicion Level: {target_info.suspicion_level}")
            output.append("  Notes:")
            for note in target_info.notes:
                output.append(f"    - {note}")
            output.append("")

        output.append("-" * 60)
        output.append("Execution Steps (Would Be Performed):")
        output.append("-" * 60)
        for i, step in enumerate(self.steps, 1):
            output.append(f"\n  Step {i}: {step.name}")
            output.append(f"    {step.description}")
            output.append(f"    APIs: {', '.join(step.api_calls)}")

        output.append("")
        output.append("-" * 60)
        output.append("Combined Detection Vectors:")
        output.append("-" * 60)
        all_vectors = set()
        for step in self.steps:
            all_vectors.update(step.detection_vectors)
        for vector in sorted(all_vectors):
            output.append(f"  ! {vector}")

        output.append("")
        output.append("-" * 60)
        output.append("Risk Assessment:")
        output.append("-" * 60)
        output.append("  Technique Risk: HIGH")
        output.append("  EDR Detection Likelihood: HIGH")
        output.append("  Forensic Artifacts: MEDIUM")
        output.append("")
        output.append("Mitigations Recommended:")
        output.append("  - Use direct syscalls to avoid API hooking")
        output.append("  - Consider unhooking ntdll.dll")
        output.append("  - Use PPID spoofing for parent process")
        output.append("  - Block non-Microsoft DLLs to prevent injection")
        output.append("")
        output.append("This is PLAN MODE - no actions were performed.")
        output.append("=" * 60)
        output.append("")

        return "\n".join(output)

    def demonstrate(self, config: HollowingConfig) -> str:
        """
        Educational demonstration showing what would happen.
        Does NOT perform actual process hollowing.
        """
        output = []
        output.append("")
        output.append("[DEMONSTRATION MODE] Process Hollowing")
        output.append("=" * 60)
        output.append("")
        output.append("NOTE: This is an educational demonstration.")
        output.append("No actual process manipulation is performed.")
        output.append("")

        for i, step in enumerate(self.steps):
            output.append(self.explain_step(i))

        output.append("")
        output.append("=" * 60)
        output.append("Demonstration Complete")
        output.append("=" * 60)
        output.append("")
        output.append("Key Takeaways:")
        output.append("  1. Process hollowing creates a legitimate-looking process")
        output.append("  2. The technique replaces process memory with malicious code")
        output.append("  3. Detection focuses on API patterns and memory anomalies")
        output.append("  4. Modern EDRs hook key APIs to detect this technique")
        output.append("")

        return "\n".join(output)

    def get_detection_guidance(self) -> str:
        """Get guidance for detecting process hollowing"""
        output = []
        output.append("")
        output.append("Process Hollowing Detection Guidance")
        output.append("=" * 60)
        output.append("")
        output.append("API Monitoring:")
        output.append("  - CreateProcess with CREATE_SUSPENDED flag")
        output.append("  - NtUnmapViewOfSection calls")
        output.append("  - WriteProcessMemory to suspended processes")
        output.append("  - SetThreadContext modifications")
        output.append("")
        output.append("Memory Analysis:")
        output.append("  - Image path vs memory content mismatch")
        output.append("  - RWX memory regions in trusted processes")
        output.append("  - PEB ImageBaseAddress discrepancies")
        output.append("  - Section header anomalies")
        output.append("")
        output.append("Behavioral Indicators:")
        output.append("  - Network connections from unexpected processes")
        output.append("  - Child processes with suspicious parents")
        output.append("  - Process command line anomalies")
        output.append("")
        output.append("Tools:")
        output.append("  - Process Monitor (procmon)")
        output.append("  - Process Hacker")
        output.append("  - Volatility Framework")
        output.append("  - pe-sieve / Hollows Hunter")
        output.append("")

        return "\n".join(output)


def get_documentation() -> Dict:
    """
    Documentation hook for integration with documentation agent.
    Returns structured documentation for this tool.
    """
    return {
        "name": "Process Hollowing Demonstrator",
        "version": "1.0.0",
        "category": "Evasion/Education",
        "description": "Educational tool demonstrating process hollowing technique concepts without performing actual malicious operations.",
        "author": "Offensive Security Toolsmith",
        "disclaimer": "For authorized security testing and education only. Does not perform actual process hollowing.",
        "usage": {
            "plan_mode": "python process_hollowing.py --target svchost.exe --plan",
            "demonstration": "python process_hollowing.py --target notepad.exe --demo",
            "list_targets": "python process_hollowing.py --list-targets",
            "detection_guide": "python process_hollowing.py --detection-guide"
        },
        "technique_reference": {
            "mitre_attack": "T1055.012",
            "mitre_name": "Process Injection: Process Hollowing",
            "description": "Adversaries may inject malicious code into suspended and hollowed processes to evade defenses."
        },
        "arguments": [
            {"name": "--target", "description": "Target process name (e.g., svchost.exe)", "required": False},
            {"name": "--payload", "description": "Payload source (for planning only)", "required": False},
            {"name": "--plan", "description": "Show execution plan without any action", "required": False},
            {"name": "--demo", "description": "Run educational demonstration", "required": False},
            {"name": "--list-targets", "description": "List common target processes", "required": False},
            {"name": "--detection-guide", "description": "Show detection guidance", "required": False},
            {"name": "--step", "description": "Explain specific step (1-8)", "required": False},
            {"name": "--ppid-spoof", "description": "Plan with PPID spoofing", "required": False},
            {"name": "--json", "description": "Output in JSON format", "required": False}
        ],
        "educational_value": [
            "Understand process hollowing technique",
            "Learn relevant Windows APIs",
            "Identify detection opportunities",
            "Prepare for CTF challenges"
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1055/012/",
            "https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations"
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Process Hollowing Educational Demonstrator",
        epilog="DISCLAIMER: For authorized security testing and education only."
    )

    parser.add_argument("--target", "-t", help="Target process name (e.g., svchost.exe)")
    parser.add_argument("--payload", help="Payload source path (for planning)")
    parser.add_argument("--platform", choices=["windows_x86", "windows_x64"],
                        default="windows_x64", help="Target platform")
    parser.add_argument("--plan", "-p", action="store_true",
                        help="Show execution plan (no action taken)")
    parser.add_argument("--demo", "-d", action="store_true",
                        help="Run educational demonstration")
    parser.add_argument("--list-targets", action="store_true",
                        help="List common target processes")
    parser.add_argument("--detection-guide", action="store_true",
                        help="Show detection guidance")
    parser.add_argument("--step", type=int, choices=range(1, 9),
                        help="Explain specific step (1-8)")
    parser.add_argument("--ppid-spoof", action="store_true",
                        help="Include PPID spoofing in plan")
    parser.add_argument("--block-dlls", action="store_true",
                        help="Include DLL blocking in plan")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--doc", action="store_true",
                        help="Show tool documentation")

    args = parser.parse_args()
    demonstrator = ProcessHollowingDemonstrator()

    # Handle documentation request
    if args.doc:
        docs = get_documentation()
        if args.json:
            print(json.dumps(docs, indent=2))
        else:
            print(f"\n{docs['name']} v{docs['version']}")
            print("=" * 60)
            print(f"\n{docs['description']}\n")
            print(f"MITRE ATT&CK: {docs['technique_reference']['mitre_attack']}")
            print(f"Technique: {docs['technique_reference']['mitre_name']}")
            print(f"\nDisclaimer: {docs['disclaimer']}")
        return 0

    # Handle list targets
    if args.list_targets:
        targets = demonstrator.get_common_targets()
        if args.json:
            print(json.dumps([{
                "name": t.name,
                "path": t.path,
                "architecture": t.architecture,
                "typical_parent": t.typical_parent,
                "suspicion_level": t.suspicion_level,
                "notes": t.notes
            } for t in targets], indent=2))
        else:
            print("\nCommon Process Hollowing Targets:")
            print("-" * 50)
            for t in targets:
                print(f"\n  {t.name}")
                print(f"    Path: {t.path}")
                print(f"    Arch: {t.architecture}")
                print(f"    Typical Parent: {t.typical_parent}")
                print(f"    Suspicion Level: {t.suspicion_level}")
                for note in t.notes:
                    print(f"    - {note}")
        return 0

    # Handle detection guide
    if args.detection_guide:
        print(demonstrator.get_detection_guidance())
        return 0

    # Handle specific step explanation
    if args.step:
        print(demonstrator.explain_step(args.step - 1))
        return 0

    # Default target if none specified
    target = args.target or "svchost.exe"
    payload = args.payload or "payload.exe"

    config = HollowingConfig(
        target_process=target,
        payload_source=payload,
        platform=Platform(args.platform),
        ppid_spoof=args.ppid_spoof,
        block_dlls=args.block_dlls
    )

    # Handle plan mode
    if args.plan:
        print(demonstrator.plan(config))
        return 0

    # Handle demonstration mode
    if args.demo:
        print(demonstrator.demonstrate(config))
        return 0

    # Default: show help
    parser.print_help()
    print("\nUse --plan for execution planning or --demo for educational demonstration.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
