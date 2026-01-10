"""
Payload Generator Module
Generate various payload formats for penetration testing
"""

from .payload_generator import (
    PayloadGenerator,
    PayloadConfig,
    PayloadOutput,
    PayloadTemplate,
    get_documentation
)

__all__ = [
    'PayloadGenerator',
    'PayloadConfig',
    'PayloadOutput',
    'PayloadTemplate',
    'get_documentation'
]

__version__ = '1.0.0'
