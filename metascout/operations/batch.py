"""
Batch processing operations for MetaScout
"""

import os
import logging
import fnmatch
from typing import List, Dict, Any, Optional

from ..core.processor import process_files


def process_directory(
    directory_path: str,
    recursive: bool = False,
    file_filter: Optional[str] = None,
    exclude_filter: Optional[str] = None,
    max_files: int = 0,
    options: Optional[Dict[str, Any]] = None
) -> List[Any]:
    """
    Process all files in a directory.
    
    Args:
        directory_path: Path to directory containing files to process
        recursive: Whether to process subdirectories recursively
        file_filter: Optional glob pattern to filter files (e.g., "*.jpg")
        exclude_filter: Optional glob pattern to exclude files (e.g., "*thumb*")
        max_files: Maximum number of files to process (0 = no limit)
        options: Dictionary of processing options
        
    Returns:
        List of FileMetadata objects
    """
    if options is None:
        options = {}
    
    # Normalize path
    directory_path = os.path.abspath(os.path.normpath(directory_path))
    
    if not os.path.isdir(directory_path):
        logging.error(f"Error: '{directory_path}' is not a valid directory.")
        return []
    
    # Collect all files
    files = []
    if recursive:
        # Recursive walk
        for root, _, filenames in os.walk(directory_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    else:
        # Non-recursive (just top directory)
        files = [os.path.join(directory_path, f) for f in os.listdir(directory_path) 
                if os.path.isfile(os.path.join(directory_path, f))]
    
    # Apply filters
    files = filter_files(files, file_filter, exclude_filter)
    
    # Apply max files limit
    if max_files > 0 and len(files) > max_files:
        logging.info(f"Limiting to {max_files} files out of {len(files)} found")
        files = files[:max_files]
    
    if not files:
        logging.warning("No files found to process.")
        return []
    
    # Process files
    return process_files(files, options)


def filter_files(
    file_paths: List[str],
    include_pattern: Optional[str] = None,
    exclude_pattern: Optional[str] = None
) -> List[str]:
    """
    Filter a list of file paths based on glob patterns.
    
    Args:
        file_paths: List of file paths to filter
        include_pattern: Optional glob pattern to include files
        exclude_pattern: Optional glob pattern to exclude files
        
    Returns:
        Filtered list of file paths
    """
    result = file_paths
    
    # Apply include pattern if specified
    if include_pattern:
        result = [f for f in result if fnmatch.fnmatch(os.path.basename(f), include_pattern)]
    
    # Apply exclude pattern if specified
    if exclude_pattern:
        result = [f for f in result if not fnmatch.fnmatch(os.path.basename(f), exclude_pattern)]
    
    return result


def group_files_by_type(file_paths: List[str]) -> Dict[str, List[str]]:
    """
    Group files by their extension.
    
    Args:
        file_paths: List of file paths to group
        
    Returns:
        Dictionary mapping extensions to lists of file paths
    """
    result = {}
    
    for file_path in file_paths:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in result:
            result[ext] = []
        result[ext].append(file_path)
    
    return result


def filter_files_by_size(
    file_paths: List[str],
    min_size: Optional[int] = None,
    max_size: Optional[int] = None
) -> List[str]:
    """
    Filter files by their size.
    
    Args:
        file_paths: List of file paths to filter
        min_size: Minimum file size in bytes (inclusive)
        max_size: Maximum file size in bytes (inclusive)
        
    Returns:
        Filtered list of file paths
    """
    result = []
    
    for file_path in file_paths:
        try:
            size = os.path.getsize(file_path)
            
            if min_size is not None and size < min_size:
                continue
                
            if max_size is not None and size > max_size:
                continue
                
            result.append(file_path)
        except OSError:
            # Skip files that can't be accessed
            logging.warning(f"Could not get size of {file_path}")
    
    return result