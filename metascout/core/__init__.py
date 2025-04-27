"""
Core package for MetaScout functionality
"""

from .models import FileMetadata, MetadataFinding
from .processor import process_file, process_files
from .utils import (
    configure_logging, 
    compute_file_hashes, 
    detect_file_type, 
    get_file_timestamps,
    safe_path
)

__all__ = [
    'FileMetadata',
    'MetadataFinding',
    'process_file',
    'process_files',
    'configure_logging',
    'compute_file_hashes',
    'detect_file_type',
    'get_file_timestamps',
    'safe_path'
]