"""
Shellcode Encoder Module
Encode shellcode using various techniques to evade detection
"""

from .shellcode_encoder import (
    ShellcodeEncoderTool,
    ShellcodeEncoder,
    XOREncoder,
    RollingXOREncoder,
    ADDEncoder,
    ROTEncoder,
    RC4Encoder,
    Base64Encoder,
    EncoderConfig,
    EncodingResult,
    EncodingType,
    OutputFormat,
    get_documentation
)

__all__ = [
    'ShellcodeEncoderTool',
    'ShellcodeEncoder',
    'XOREncoder',
    'RollingXOREncoder',
    'ADDEncoder',
    'ROTEncoder',
    'RC4Encoder',
    'Base64Encoder',
    'EncoderConfig',
    'EncodingResult',
    'EncodingType',
    'OutputFormat',
    'get_documentation'
]

__version__ = '1.0.0'
