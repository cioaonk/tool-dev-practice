"""
Process Hollowing Demonstrator Module
Educational tool for understanding process hollowing technique
"""

from .process_hollowing import (
    ProcessHollowingDemonstrator,
    HollowingConfig,
    HollowingStep,
    ProcessInfo,
    ProcessState,
    Platform,
    WindowsAPISimulator,
    get_documentation
)

__all__ = [
    'ProcessHollowingDemonstrator',
    'HollowingConfig',
    'HollowingStep',
    'ProcessInfo',
    'ProcessState',
    'Platform',
    'WindowsAPISimulator',
    'get_documentation'
]

__version__ = '1.0.0'
