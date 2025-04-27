"""
Dependency management for MetaScout

This module handles checking for required and optional dependencies,
providing fallbacks where possible.
"""

import sys
import logging
import importlib
import mimetypes
from typing import Dict, Any, Optional, Tuple

# Dictionary to track available optional dependencies
OPTIONAL_DEPENDENCIES = {
    'magic': True,
    'yara-python': False,
    'pyssdeep': False,
    'docx': False,
    'openpyxl': False,
    'olefile': False,
    'pefile': False,
    'pyelftools': False,
    'macholib': False
}

def check_dependencies() -> None:
    """
    Check for all required dependencies and log warnings for missing
    optional dependencies.
    """
    # Required core dependencies
    required_packages = [
        "PIL", "PyPDF2", "tabulate", "mutagen", "exifread", 
        "colorama", "tqdm", "cryptography"
    ]
    
    for package in required_packages:
        try:
            importlib.import_module(package) if package != "PIL" else importlib.import_module("PIL")
        except ImportError:
            print(f"Error: Required dependency not found: {package}")
            print("Please install required dependencies with: pip install -r requirements.txt")
            sys.exit(1)
    
    # Optional dependencies
    check_optional_dependencies()

def check_optional_dependencies() -> None:
    """Check for optional dependencies and set availability flags."""
    # Check for python-magic with fallback to mimetypes
    try:
        import magic
        # Test if it actually works by calling a function
        test = magic.Magic()
        test.from_buffer(b"test")
        OPTIONAL_DEPENDENCIES['magic'] = True
    except (ImportError, AttributeError, TypeError):
        OPTIONAL_DEPENDENCIES['magic'] = False
        logging.warning("python-magic not available. Using mimetypes fallback.")
    
    # Check for YARA
    try:
        import yara
        OPTIONAL_DEPENDENCIES['yara-python'] = True
    except (ImportError, FileNotFoundError):
        OPTIONAL_DEPENDENCIES['yara-python'] = False
        logging.warning("yara-python not available. YARA rule scanning will be disabled.")
    
    # Check for ssdeep
    try:
        import ssdeep
        OPTIONAL_DEPENDENCIES['pyssdeep'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['pyssdeep'] = False
        logging.warning("pyssdeep not available. Fuzzy hash comparison will be disabled.")
    
    # Check for document analysis libraries
    try:
        import docx
        OPTIONAL_DEPENDENCIES['docx'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['docx'] = False
        logging.warning("python-docx not available. Word document analysis will be limited.")
    
    try:
        import openpyxl
        OPTIONAL_DEPENDENCIES['openpyxl'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['openpyxl'] = False
        logging.warning("openpyxl not available. Excel document analysis will be limited.")
    
    try:
        import olefile
        OPTIONAL_DEPENDENCIES['olefile'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['olefile'] = False
        logging.warning("olefile not available. Legacy Office document analysis will be limited.")
    
    # Check for executable analysis libraries
    try:
        import pefile
        OPTIONAL_DEPENDENCIES['pefile'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['pefile'] = False
        logging.warning("pefile not available. Windows executable analysis will be limited.")
    
    try:
        from elftools.elf.elffile import ELFFile
        OPTIONAL_DEPENDENCIES['pyelftools'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['pyelftools'] = False
        logging.warning("pyelftools not available. Linux executable analysis will be limited.")
    
    try:
        from macholib.MachO import MachO
        OPTIONAL_DEPENDENCIES['macholib'] = True
    except ImportError:
        OPTIONAL_DEPENDENCIES['macholib'] = False
        logging.warning("macholib not available. macOS executable analysis will be limited.")

# Magic fallback class
class FallbackMagic:
    """
    Fallback class providing a similar API to python-magic
    when the actual library is not available.
    """
    def __init__(self, mime=True):
        self.mime = mime
    
    def from_file(self, filename):
        """Guess mime type from file extension."""
        mime_type, encoding = mimetypes.guess_type(filename)
        if self.mime:
            return mime_type or "application/octet-stream"
        else:
            return f"data file ({mime_type or 'unknown'})"

# Create a global instance for fallback
magic = None

def get_magic():
    """
    Return either the real python-magic library or our fallback.
    Should be used instead of directly importing magic.
    """
    global magic
    if magic is None:
        if OPTIONAL_DEPENDENCIES['magic']:
            import magic as real_magic
            magic = real_magic
        else:
            magic = FallbackMagic()
    return magic

# Initialize by checking dependencies
check_dependencies()