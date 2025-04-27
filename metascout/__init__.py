"""
MetaScout - Advanced File Metadata Analysis Tool
"""

__version__ = "1.0.0"

from .core.models import FileMetadata, MetadataFinding
from .cli import main
from .core.processor import process_file, process_files

__all__ = ['main', 'process_file', 'process_files', 'FileMetadata', 'MetadataFinding']