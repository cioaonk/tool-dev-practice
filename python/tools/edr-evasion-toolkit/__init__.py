"""
EDR Evasion Toolkit Module
Collection of EDR evasion techniques for authorized penetration testing
"""

from .edr_evasion import (
    EDREvasionToolkit,
    DirectSyscallGenerator,
    UnhookingTechniques,
    MemoryEvasionTechniques,
    CallbackManipulation,
    ETWBypassTechniques,
    APIHashingTechniques,
    EvasionTechnique,
    TechniqueCategory,
    Platform,
    RiskLevel,
    SyscallInfo,
    get_documentation
)

__all__ = [
    'EDREvasionToolkit',
    'DirectSyscallGenerator',
    'UnhookingTechniques',
    'MemoryEvasionTechniques',
    'CallbackManipulation',
    'ETWBypassTechniques',
    'APIHashingTechniques',
    'EvasionTechnique',
    'TechniqueCategory',
    'Platform',
    'RiskLevel',
    'SyscallInfo',
    'get_documentation'
]

__version__ = '1.0.0'
