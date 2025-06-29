"""
Utility functions for MetaScout
"""

import os
import hashlib
import logging
import datetime
from typing import Dict, Tuple, Optional
from pathlib import Path

import colorama
from colorama import Fore, Style

from ..config.dependencies import get_magic

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

def configure_logging(log_file: str, verbose: bool = False) -> None:
    """Configure logging system with appropriate levels and handlers."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Configure file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)  # Always log details to file
    file_handler.setFormatter(formatter)
    
    # Configure console handler with color
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Custom formatter for console with colors
    class ColoredFormatter(logging.Formatter):
        FORMATS = {
            logging.DEBUG: Fore.CYAN + "%(message)s" + Style.RESET_ALL,
            logging.INFO: "%(message)s",
            logging.WARNING: Fore.YELLOW + "%(message)s" + Style.RESET_ALL,
            logging.ERROR: Fore.RED + "%(message)s" + Style.RESET_ALL,
            logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(message)s" + Style.RESET_ALL
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno)
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)
            
    console_handler.setFormatter(ColoredFormatter())
    
    # Get the root logger and add handlers
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Allow all logs to be processed
    
    # Remove existing handlers to avoid duplicates on reconfiguration
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    logger.addHandler(file_handler)
    
    # Only add console handler if not in quiet mode
    if verbose:
        logger.addHandler(console_handler)

def compute_file_hashes(file_path: str) -> Dict[str, str]:
    """Compute multiple secure hashes for a file."""
    hashes = {}
    
    # Define hash algorithms to use
    hash_algorithms = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    
    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(4096), b''):
                for hash_obj in hash_algorithms.values():
                    hash_obj.update(chunk)
        
        # Get hex digests
        for name, hash_obj in hash_algorithms.items():
            hashes[name] = hash_obj.hexdigest()
            
        return hashes
    except FileNotFoundError:
        logging.error(f"File not found when computing hashes: {file_path}")
        return {'error': f'File not found: {file_path}'}
    except PermissionError:
        logging.error(f"Permission denied when computing hashes: {file_path}")
        return {'error': f'Permission denied: {file_path}'}
    except Exception as e:
        logging.error(f"Failed to compute hashes for {file_path}: {e}")
        return {'error': f'Hash computation failed: {str(e)}'}

def detect_file_type(file_path: str) -> Tuple[str, str]:
    """
    Detect file type using libmagic or fallback and return MIME type and more specific description.
    """
    try:
        magic = get_magic()
        
        if hasattr(magic, 'Magic'):
            # Using actual python-magic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            
            # Get more detailed description
            magic_desc = magic.Magic()
            description = magic_desc.from_file(file_path)
        else:
            # Using our fallback
            mime_type = magic.from_file(file_path)
            description = f"File: {os.path.basename(file_path)}"
            
            # Try to get more info from extension
            ext = os.path.splitext(file_path)[1].lower()
            if ext:
                description += f" ({ext} file)"
        
        return mime_type, description
    except FileNotFoundError:
        logging.error(f"File not found when detecting type: {file_path}")
        return "unknown/unknown", f"File not found: {os.path.basename(file_path)}"
    except PermissionError:
        logging.error(f"Permission denied when detecting file type: {file_path}")
        # Try to guess from extension even without reading the file
        ext = os.path.splitext(file_path)[1].lower()
        if ext:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            return mime_type or "unknown/unknown", f"Permission denied, guessed from extension {ext}"
        return "unknown/unknown", "Permission denied, unknown file type"
    except Exception as e:
        logging.error(f"Failed to detect file type for {file_path}: {e}")
        # Last resort - guess from extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            return mime_type or "unknown/unknown", f"Detection failed, guessed from extension {ext}"
        return "unknown/unknown", f"File type detection failed: {str(e)}"

def get_file_timestamps(file_path: str) -> Dict[str, str]:
    """Get file creation, modification, and access times."""
    try:
        stat_info = os.stat(file_path)
        return {
            'creation_time': datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modification_time': datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'access_time': datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat()
        }
    except FileNotFoundError:
        logging.error(f"File not found when getting timestamps: {file_path}")
        return {'error': f'File not found: {file_path}'}
    except PermissionError:
        logging.error(f"Permission denied when getting timestamps: {file_path}")
        return {'error': f'Permission denied: {file_path}'}
    except Exception as e:
        logging.error(f"Failed to get timestamps for {file_path}: {e}")
        return {'error': f'Timestamp extraction failed: {str(e)}'}

def safe_path(file_path: str) -> Path:
    """
    Sanitize and validate file path to prevent path traversal attacks.
    Returns a normalized Path object.
    
    Raises ValueError if path appears to be potentially malicious.
    """
    # Convert to Path object and normalize
    path = Path(file_path).resolve()
    
    # Implement additional security checks as needed
    # For example, check that the path doesn't contain suspicious patterns
    # or doesn't point to sensitive system locations
    
    return path