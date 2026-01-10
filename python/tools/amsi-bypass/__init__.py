"""
AMSI Bypass Generator Module
Generate AMSI bypass techniques for PowerShell
"""

from .amsi_bypass import (
    AMSIBypassGenerator,
    BypassTechnique,
    BypassCategory,
    RiskLevel,
    StringObfuscator,
    get_documentation
)

__all__ = [
    'AMSIBypassGenerator',
    'BypassTechnique',
    'BypassCategory',
    'RiskLevel',
    'StringObfuscator',
    'get_documentation'
]

__version__ = '1.0.0'
