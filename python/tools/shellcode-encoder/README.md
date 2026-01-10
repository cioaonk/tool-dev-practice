# Shellcode Encoder

A versatile shellcode encoder supporting multiple encoding techniques and output formats for evading signature-based detection.

## DISCLAIMER

**This tool is for authorized security testing and educational purposes only.**

Creating, distributing, or using malicious shellcode without authorization is illegal. This tool is designed for:
- Authorized penetration testing
- CTF competitions
- Security research
- Educational purposes

## Features

- **Multiple Encoders**: XOR, Rolling XOR, ADD, ROT, RC4, Base64
- **Chain Encoding**: Apply multiple encoders in sequence
- **Key Management**: Auto-generate or specify custom keys
- **Bad Character Avoidance**: Ensure output avoids specified bytes
- **Multiple Output Formats**: Raw, C array, Python, PowerShell, C#
- **Decoder Stub Generation**: Automatic decoder code generation
- **Shellcode Analysis**: Analyze characteristics before encoding
- **Planning Mode**: Preview operations before execution

## Installation

No additional dependencies for basic encoders. Uses Python standard library.

```bash
chmod +x shellcode_encoder.py
```

## Usage

### Basic Encoding

```bash
# XOR encode shellcode from file
python shellcode_encoder.py --input shellcode.bin --encoding xor

# Encode hex string
python shellcode_encoder.py --input "\\x31\\xc0\\x50\\x68" --encoding xor

# Specify key
python shellcode_encoder.py --input sc.bin --encoding xor --key deadbeef

# Multiple iterations
python shellcode_encoder.py --input sc.bin --encoding xor --iterations 3
```

### Output Formats

```bash
# C array format
python shellcode_encoder.py --input sc.bin --encoding xor --format c_array

# Python format
python shellcode_encoder.py --input sc.bin --encoding xor --format python

# PowerShell format
python shellcode_encoder.py --input sc.bin --encoding rc4 --format powershell

# C# format
python shellcode_encoder.py --input sc.bin --encoding add --format csharp
```

### Chain Encoding

```bash
# Apply multiple encoders
python shellcode_encoder.py --input sc.bin --chain xor,add,rot

# Plan chain encoding
python shellcode_encoder.py --input sc.bin --chain xor,rc4 --plan
```

### Shellcode Analysis

```bash
python shellcode_encoder.py --input sc.bin --analyze
python shellcode_encoder.py --input sc.bin --analyze --json
```

### Planning Mode

```bash
python shellcode_encoder.py --input sc.bin --encoding rc4 --plan
```

### Save Output

```bash
python shellcode_encoder.py --input sc.bin --encoding xor --output encoded.bin
```

## Available Encoders

| Encoder | Description | Key Size | Notes |
|---------|-------------|----------|-------|
| `xor` | Simple XOR encoding | 1+ bytes | Fast, easily detected |
| `xor_rolling` | Rolling XOR with changing key | 1 byte | Better than static XOR |
| `add` | ADD encoding (SUB to decode) | 1 byte | Simple but effective |
| `rot` | ROT/Caesar cipher | 1 byte | Rotation-based |
| `rc4` | RC4 stream cipher | Variable | Strong encryption |
| `base64` | Base64 encoding | N/A | Size increase |

## Output Formats

| Format | Description | Example |
|--------|-------------|---------|
| `raw` | Raw hex string | `31c050...` |
| `hex` | Escaped hex | `\x31\xc0\x50...` |
| `c_array` | C unsigned char array | `unsigned char sc[] = {0x31, 0xc0...};` |
| `python` | Python bytes literal | `sc = b"\x31\xc0..."` |
| `powershell` | PowerShell byte array | `[Byte[]] $sc = @(0x31, 0xc0...)` |
| `csharp` | C# byte array | `byte[] sc = new byte[] {0x31, 0xc0...};` |

## Command Line Arguments

| Argument | Short | Description |
|----------|-------|-------------|
| `--input` | `-i` | Input file or hex string |
| `--encoding` | `-e` | Encoding type |
| `--key` | `-k` | Encryption key (hex) |
| `--iterations` | `-n` | Encoding iterations |
| `--format` | `-f` | Output format |
| `--chain` | | Chain encoders (comma-separated) |
| `--null-free` | | Ensure no null bytes |
| `--bad-chars` | | Bad chars to avoid (hex) |
| `--output` | `-o` | Output file |
| `--analyze` | `-a` | Analyze shellcode |
| `--plan` | `-p` | Show plan only |
| `--list` | `-l` | List encoders |
| `--json` | `-j` | JSON output |
| `--doc` | | Show documentation |

## Integration

### As a Module

```python
from shellcode_encoder import ShellcodeEncoderTool, EncoderConfig, EncodingType, OutputFormat

tool = ShellcodeEncoderTool()

# Configure encoding
config = EncoderConfig(
    encoding_type=EncodingType.XOR,
    iterations=2,
    output_format=OutputFormat.PYTHON,
    null_free=True,
    bad_chars=b'\x00\x0a\x0d'
)

# Encode
shellcode = b"\x31\xc0\x50\x68"
result = tool.encode(shellcode, config)

print(f"Key: {result.key_used.hex()}")
print(f"Encoded: {result.encoded_shellcode.hex()}")
print(result.decoder_stub)
```

### Chain Encoding

```python
from shellcode_encoder import ShellcodeEncoderTool, EncodingType

tool = ShellcodeEncoderTool()

shellcode = b"\x31\xc0\x50\x68"
encodings = [EncodingType.XOR, EncodingType.ADD, EncodingType.ROT]

encoded, chain_info = tool.chain_encode(shellcode, encodings)

for step in chain_info:
    print(f"Step {step['step']}: {step['encoder']} -> {step['size']} bytes")
```

### Shellcode Analysis

```python
from shellcode_encoder import ShellcodeEncoderTool

tool = ShellcodeEncoderTool()
analysis = tool.analyze_shellcode(shellcode)

print(f"Size: {analysis['size']}")
print(f"Entropy: {analysis['entropy']}")
print(f"Null bytes: {analysis['null_bytes']}")
```

### Documentation Hook

```python
from shellcode_encoder import get_documentation

docs = get_documentation()
print(docs['encoders'])
```

## Decoder Stubs

Each encoder generates a decoder stub for the target platform:

### XOR Decoder (x86 Assembly)
```nasm
decoder:
    jmp short get_shellcode
decode_routine:
    pop esi
    xor ecx, ecx
    mov cl, <length>
decode_loop:
    xor byte [esi], <key>
    inc esi
    loop decode_loop
    jmp short shellcode
get_shellcode:
    call decode_routine
shellcode:
    ; Encoded shellcode here
```

## Bad Character Handling

Avoid common bad characters in exploit development:
- `\x00` - Null byte (string terminator)
- `\x0a` - Line feed
- `\x0d` - Carriage return
- `\x20` - Space (sometimes)

```bash
# Specify custom bad characters
python shellcode_encoder.py --input sc.bin --encoding xor --bad-chars 000a0d2025
```

## Evasion Considerations

1. **Single encoding is often insufficient** - Use chain encoding
2. **Decoder stubs are detectable** - Consider custom decoders
3. **Test against target AV/EDR** - Signatures vary
4. **Consider polymorphism** - Change encoder each time
5. **Combine with other techniques** - Process injection, etc.

## MITRE ATT&CK

- **ID**: T1027
- **Technique**: Obfuscated Files or Information
- **Sub-technique**: T1027.002 - Software Packing

## References

- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Metasploit msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Custom Shellcode Encoders](https://www.corelan.be/index.php/2010/02/25/exploit-writing-tutorial-part-9-introduction-to-win32-shellcoding/)

## License

For authorized security testing only. See main project license.
