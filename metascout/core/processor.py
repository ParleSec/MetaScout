"""
Core file processing logic
"""

import os
import logging
import concurrent.futures
from typing import Dict, List, Any, Optional

import tqdm

from ..core.models import FileMetadata
from ..core.utils import detect_file_type, compute_file_hashes, get_file_timestamps
from ..config.constants import SUPPORTED_EXTENSIONS
from ..extractors import get_extractor_for_file
from ..analyzers import get_analyzers_for_file_type


def process_file(file_path: str, options: Optional[Dict[str, Any]] = None) -> FileMetadata:
    """
    Process a single file and extract its metadata and perform analysis.
    
    Args:
        file_path: Path to file to process
        options: Dictionary of processing options
        
    Returns:
        FileMetadata object containing extracted metadata and analysis results
    """
    if options is None:
        options = {}
    
    try:
        # Normalize and validate path
        file_path = os.path.abspath(os.path.normpath(file_path))
        if not os.path.isfile(file_path):
            return FileMetadata(
                file_path=file_path,
                file_type="unknown",
                file_size=0,
                mime_type="unknown",
                errors=[f"File not found or is not accessible: {file_path}"]
            )
        
        # Get basic file info
        mime_type, description = detect_file_type(file_path)
        file_size = os.path.getsize(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        
        # Determine file type
        if ext in SUPPORTED_EXTENSIONS['images']:
            file_type = "image"
        elif ext in SUPPORTED_EXTENSIONS['documents']:
            file_type = "document"
        elif ext in SUPPORTED_EXTENSIONS['audio']:
            file_type = "audio"
        elif ext in SUPPORTED_EXTENSIONS['video']:
            file_type = "video"
        elif ext in SUPPORTED_EXTENSIONS['executables']:
            file_type = "executable"
        else:
            file_type = "other"
        
        # Create basic FileMetadata object
        result = FileMetadata(
            file_path=file_path,
            file_type=file_type,
            file_size=file_size,
            mime_type=mime_type
        )
        
        # Get file hashes if requested
        if not options.get('skip_hashes', False):
            result.hashes = compute_file_hashes(file_path)
        
        # Get timestamps
        timestamps = get_file_timestamps(file_path)
        if 'creation_time' in timestamps:
            result.creation_time = timestamps['creation_time']
        if 'modification_time' in timestamps:
            result.modification_time = timestamps['modification_time']
        if 'access_time' in timestamps:
            result.access_time = timestamps['access_time']
        
        # Extract metadata
        if not options.get('skip_extraction', False):
            # Find appropriate extractor for this file type
            extractor = get_extractor_for_file(file_path, mime_type)
            if extractor:
                result.metadata = extractor.extract(file_path)
            else:
                # No specialized extractor available
                result.metadata = {"note": f"No specific extractor available for {file_type} files"}
        
        # Analyze metadata if requested
        if not options.get('skip_analysis', False) and result.metadata:
            # Get analyzers for this file type
            analyzers = get_analyzers_for_file_type(file_type)
            
            # Run each analyzer
            for analyzer in analyzers:
                try:
                    findings = analyzer.analyze(result.metadata)
                    if findings:
                        result.findings.extend(findings)
                except Exception as e:
                    logging.error(f"Error in analyzer {analyzer.__class__.__name__}: {e}")
                    result.errors.append(f"Analysis error: {str(e)}")
        
        return result
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return FileMetadata(
            file_path=file_path,
            file_type="unknown",
            file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            mime_type="unknown",
            errors=[f"Processing error: {str(e)}"]
        )


def process_files(file_paths: List[str], options: Optional[Dict[str, Any]] = None) -> List[FileMetadata]:
    """
    Process multiple files in parallel using a thread pool.
    
    Args:
        file_paths: List of file paths to process
        options: Dictionary of processing options
        
    Returns:
        List of FileMetadata objects
    """
    if options is None:
        options = {}
    
    results = []
    
    # Determine number of worker threads
    max_workers = options.get('max_workers', min(32, os.cpu_count() + 4))
    
    # Process files in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {executor.submit(process_file, file_path, options): file_path for file_path in file_paths}
        
        if options.get('show_progress', True) and len(file_paths) > 1:
            # Display progress bar for multiple files
            with tqdm.tqdm(total=len(file_paths), desc="Processing files", unit="file") as pbar:
                for future in concurrent.futures.as_completed(future_to_file):
                    result = future.result()
                    results.append(result)
                    pbar.update(1)
        else:
            # Without progress bar
            for future in concurrent.futures.as_completed(future_to_file):
                results.append(future.result())
    
    return results