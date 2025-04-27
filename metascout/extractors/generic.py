"""
Generic file metadata extraction
"""

import os
import logging
import datetime
from typing import Dict, Any, Optional

from ..core.utils import detect_file_type, compute_file_hashes, get_file_timestamps
from .base import BaseExtractor


class GenericExtractor(BaseExtractor):
    """Extract basic metadata for any file type."""
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """
        Check if this extractor can handle the specified file.
        The generic extractor can handle any file, but is intended as a fallback.
        """
        return True
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract basic metadata for any file type."""
        try:
            metadata = {}
            
            # Use python-magic to identify file type
            mime_type, description = detect_file_type(file_path)
            metadata['mime_type'] = mime_type
            metadata['description'] = description
            
            # Get file size
            metadata['size'] = os.path.getsize(file_path)
            
            # Get file timestamps
            timestamps = get_file_timestamps(file_path)
            for key, value in timestamps.items():
                metadata[key] = value
            
            # Get file permissions
            try:
                stat_info = os.stat(file_path)
                metadata['permissions'] = oct(stat_info.st_mode)[-3:]
                
                # On Unix-like systems, get owner and group
                if hasattr(os, 'getgroupname') and hasattr(os, 'getusername'):
                    try:
                        metadata['owner'] = os.getusername(stat_info.st_uid)
                        metadata['group'] = os.getgroupname(stat_info.st_gid)
                    except:
                        # Fall back to numeric IDs if names can't be resolved
                        metadata['owner_id'] = stat_info.st_uid
                        metadata['group_id'] = stat_info.st_gid
            except:
                pass
            
            # Compute file hashes
            metadata['hashes'] = compute_file_hashes(file_path)
            
            # Try to detect file encoding for text files
            if mime_type and mime_type.startswith('text/'):
                metadata.update(self._detect_text_file_info(file_path))
            
            # Check for zip-based formats
            if self._might_be_zip_based(file_path, mime_type):
                metadata.update(self._examine_zip_content(file_path))
            
            return metadata
        except Exception as e:
            logging.error(f"Error extracting generic metadata from {file_path}: {e}")
            return {'error': str(e)}
    
    def _detect_text_file_info(self, file_path: str) -> Dict[str, Any]:
        """Detect encoding and basic info for text files."""
        text_info = {}
        
        try:
            # Try to detect encoding (using chardet if available)
            encoding = 'utf-8'  # Default assumption
            try:
                import chardet
                with open(file_path, 'rb') as f:
                    # Read up to 1MB to detect encoding
                    raw_data = f.read(1024 * 1024)
                    result = chardet.detect(raw_data)
                    if result['confidence'] > 0.7:
                        encoding = result['encoding']
            except ImportError:
                pass
            
            text_info['encoding'] = encoding
            
            # Count lines, words, and characters
            line_count = 0
            word_count = 0
            char_count = 0
            
            try:
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    for line in f:
                        line_count += 1
                        words = line.split()
                        word_count += len(words)
                        char_count += len(line)
                
                text_info['line_count'] = line_count
                text_info['word_count'] = word_count
                text_info['character_count'] = char_count
            except:
                pass
            
            # Try to detect if it's a specific type of text file
            filename = os.path.basename(file_path).lower()
            if filename.endswith('.json'):
                text_info['format'] = 'JSON'
            elif filename.endswith('.xml'):
                text_info['format'] = 'XML'
            elif filename.endswith('.html') or filename.endswith('.htm'):
                text_info['format'] = 'HTML'
            elif filename.endswith('.csv'):
                text_info['format'] = 'CSV'
            elif filename.endswith('.md'):
                text_info['format'] = 'Markdown'
            elif filename.endswith('.py'):
                text_info['format'] = 'Python'
            elif filename.endswith('.js'):
                text_info['format'] = 'JavaScript'
            elif filename.endswith('.css'):
                text_info['format'] = 'CSS'
            elif filename.endswith('.c') or filename.endswith('.cpp') or filename.endswith('.h'):
                text_info['format'] = 'C/C++'
            elif filename.endswith('.java'):
                text_info['format'] = 'Java'
            
        except Exception as e:
            logging.debug(f"Error detecting text file info: {e}")
        
        return {'text_info': text_info}
    
    def _might_be_zip_based(self, file_path: str, mime_type: Optional[str]) -> bool:
        """Check if the file might be a zip-based format (Office XML, JAR, APK, etc.)."""
        ext = os.path.splitext(file_path)[1].lower()
        zip_based_extensions = [
            '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp',  # Office formats
            '.jar', '.war', '.ear',  # Java archives
            '.apk', '.xpi', '.crx',  # Application packages
            '.epub', '.zip'  # Other formats
        ]
        
        if ext in zip_based_extensions:
            return True
        
        if mime_type and any(type_str in mime_type for type_str in 
                           ['zip', 'vnd.openxmlformats', 'vnd.oasis.opendocument']):
            return True
        
        # Try to check for ZIP signature
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header == b'PK\x03\x04':  # ZIP file signature
                    return True
        except:
            pass
        
        return False
    
    def _examine_zip_content(self, file_path: str) -> Dict[str, Any]:
        """Examine the contents of a zip-based file."""
        zip_info = {
            'archive_type': 'ZIP-based',
            'contents': {}
        }
        
        try:
            import zipfile
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path) as z:
                    # Get basic archive info
                    zip_info['file_count'] = len(z.filelist)
                    
                    # Check for specific file patterns to identify the format
                    file_list = set(f.filename for f in z.filelist)
                    
                    # Office Open XML (DOCX, XLSX, PPTX)
                    if '[Content_Types].xml' in file_list:
                        if 'word/document.xml' in file_list:
                            zip_info['archive_type'] = 'Microsoft Word Document (DOCX)'
                        elif 'xl/workbook.xml' in file_list:
                            zip_info['archive_type'] = 'Microsoft Excel Workbook (XLSX)'
                        elif 'ppt/presentation.xml' in file_list:
                            zip_info['archive_type'] = 'Microsoft PowerPoint Presentation (PPTX)'
                    
                    # OpenDocument Format (ODF)
                    if 'mimetype' in file_list:
                        try:
                            mimetype = z.read('mimetype').decode('utf-8')
                            if 'application/vnd.oasis.opendocument.text' in mimetype:
                                zip_info['archive_type'] = 'OpenDocument Text (ODT)'
                            elif 'application/vnd.oasis.opendocument.spreadsheet' in mimetype:
                                zip_info['archive_type'] = 'OpenDocument Spreadsheet (ODS)'
                            elif 'application/vnd.oasis.opendocument.presentation' in mimetype:
                                zip_info['archive_type'] = 'OpenDocument Presentation (ODP)'
                        except:
                            pass
                    
                    # Java archives (JAR, WAR)
                    if 'META-INF/MANIFEST.MF' in file_list:
                        zip_info['archive_type'] = 'Java Archive (JAR)'
                        if 'WEB-INF/' in file_list:
                            zip_info['archive_type'] = 'Web Application Archive (WAR)'
                    
                    # Android packages (APK)
                    if 'AndroidManifest.xml' in file_list:
                        zip_info['archive_type'] = 'Android Package (APK)'
                    
                    # Get file extension stats
                    extensions = {}
                    for file_info in z.filelist:
                        if not file_info.is_dir():
                            _, ext = os.path.splitext(file_info.filename)
                            ext = ext.lower()
                            if ext:
                                extensions[ext] = extensions.get(ext, 0) + 1
                    
                    if extensions:
                        zip_info['extensions'] = extensions
                    
                    # Get some metadata from the archive
                    zip_info['compressed_size'] = sum(f.compress_size for f in z.filelist)
                    zip_info['uncompressed_size'] = sum(f.file_size for f in z.filelist)
                    if zip_info['uncompressed_size'] > 0:
                        zip_info['compression_ratio'] = round(
                            zip_info['compressed_size'] / zip_info['uncompressed_size'] * 100, 2
                        )
            
        except Exception as e:
            logging.debug(f"Error examining ZIP content: {e}")
            zip_info['error'] = str(e)
        
        return {'archive_info': zip_info}