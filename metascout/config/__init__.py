"""
Configuration package for MetaScout
"""

from .constants import VERSION, SUPPORTED_EXTENSIONS, PRIVACY_CONCERNS, SECURITY_CONCERNS
from .dependencies import (
    check_dependencies, 
    OPTIONAL_DEPENDENCIES, 
    get_magic
)

__all__ = [
    'VERSION',
    'SUPPORTED_EXTENSIONS',
    'PRIVACY_CONCERNS',
    'SECURITY_CONCERNS',
    'check_dependencies',
    'OPTIONAL_DEPENDENCIES',
    'get_magic'
]