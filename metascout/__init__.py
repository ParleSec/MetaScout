"""
MetaScout - Advanced File Metadata Analysis Tool
"""

__version__ = "1.0.0"

from .main import main, process_file, process_files, FileMetadata, MetadataFinding

__all__ = ['main', 'process_file', 'process_files', 'FileMetadata', 'MetadataFinding']