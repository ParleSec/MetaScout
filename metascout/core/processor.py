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
from ..core.exceptions import (
    MetaScoutError, FileNotFoundError as MSFileNotFoundError, 
    PermissionError as MSPermissionError, CorruptedFileError, 
    ExtractionError, AnalysisError, handle_exception_gracefully
)
from ..config.constants import SUPPORTED_EXTENSIONS
from ..extractors import get_extractor_for_file
from ..analyzers import get_analyzers_for_file_type


@handle_exception_gracefully
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
        
        # Check if file exists and is accessible
        if not os.path.exists(file_path):
            error = MSFileNotFoundError(file_path)
            return FileMetadata(
                file_path=file_path,
                file_type="unknown",
                file_size=0,
                mime_type="unknown",
                errors=[error.to_dict()]
            )
        
        if not os.path.isfile(file_path):
            error = MetaScoutError(
                f"Path exists but is not a file: {file_path}",
                None,
                ["Ensure the path points to a file, not a directory", "Check the file path for typos"]
            )
            return FileMetadata(
                file_path=file_path,
                file_type="unknown",
                file_size=0,
                mime_type="unknown",
                errors=[error.to_dict()]
            )
        
        # Get basic file info with error handling
        try:
            mime_type, description = detect_file_type(file_path)
        except Exception as e:
            logging.warning(f"Could not detect file type for {file_path}: {e}")
            mime_type, description = "unknown/unknown", "Unknown file type"
        
        try:
            file_size = os.path.getsize(file_path)
        except OSError as e:
            if "permission" in str(e).lower() or "access" in str(e).lower():
                error = MSPermissionError(file_path, "read", e)
                return FileMetadata(
                    file_path=file_path,
                    file_type="unknown",
                    file_size=0,
                    mime_type="unknown",
                    errors=[error.to_dict()]
                )
            else:
                logging.warning(f"Could not get file size for {file_path}: {e}")
                file_size = 0
        
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
        
        # Extract metadata with improved error handling
        if not options.get('skip_extraction', False):
            try:
                # Find appropriate extractor for this file type
                extractor = get_extractor_for_file(file_path, mime_type)
                if extractor:
                    extracted_metadata = extractor.extract(file_path)
                    
                    # Check if extraction returned an error
                    if isinstance(extracted_metadata, dict) and 'error' in extracted_metadata:
                        error = ExtractionError(file_path, extractor.__class__.__name__, Exception(extracted_metadata['error']))
                        result.errors.append(error.to_dict())
                        result.metadata = {"extraction_failed": True}
                    else:
                        result.metadata = extracted_metadata
                else:
                    # No specialized extractor available
                    result.metadata = {"note": f"No specific extractor available for {file_type} files"}
            except Exception as e:
                error = ExtractionError(file_path, "unknown", e)
                result.errors.append(error.to_dict())
                result.metadata = {"extraction_failed": True}
        
        # Analyze metadata if requested with improved error handling
        if not options.get('skip_analysis', False) and result.metadata and not result.metadata.get('extraction_failed'):
            try:
                # Get analyzers for this file type
                analyzers = get_analyzers_for_file_type(file_type)
                
                # Run each analyzer
                for analyzer in analyzers:
                    try:
                        findings = analyzer.analyze(result.metadata)
                        if findings:
                            result.findings.extend(findings)
                    except Exception as e:
                        error = AnalysisError(file_path, analyzer.__class__.__name__, e)
                        result.errors.append(error.to_dict())
                        logging.warning(f"Analysis failed with {analyzer.__class__.__name__}: {e}")
            except Exception as e:
                error = AnalysisError(file_path, "analyzer_system", e)
                result.errors.append(error.to_dict())
        
        return result
    except MetaScoutError:
        # Re-raise our custom exceptions to be handled by the decorator
        raise
    except Exception as e:
        # Convert unexpected exceptions to user-friendly format
        error = MetaScoutError(
            f"Unexpected error while processing {os.path.basename(file_path)}",
            str(e),
            [
                "Try processing the file again",
                "Check if the file is corrupted or locked",
                "Use --verbose for more technical details",
                "Report this issue if it persists"
            ]
        )
        return FileMetadata(
            file_path=file_path,
            file_type="unknown",
            file_size=0,
            mime_type="unknown",
            errors=[error.to_dict()]
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