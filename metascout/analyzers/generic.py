"""
Generic metadata analysis for any file type
"""

import os
import datetime
from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class GenericAnalyzer(BaseAnalyzer):
    """
    Generic analyzer that can process metadata from any file type.
    This analyzer focuses on common metadata properties that are
    applicable to all file types.
    """
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """This analyzer can handle any file type."""
        return True
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """
        Analyze generic metadata applicable to any file type.
        
        Focuses on consistency issues, timestamps, and other common metadata.
        """
        findings = []
        
        # Check for timestamp anomalies
        findings.extend(self._analyze_timestamps(metadata))
        
        # Check MIME type consistency with extension
        findings.extend(self._analyze_mime_consistency(metadata))
        
        # Check for unusually small or large file sizes
        findings.extend(self._analyze_file_size(metadata))
        
        # Check file hashes for known issues
        findings.extend(self._analyze_hashes(metadata))
        
        # Check archive information
        findings.extend(self._analyze_archive_info(metadata))
        
        # Check text file information
        findings.extend(self._analyze_text_info(metadata))
        
        return findings
    
    def _analyze_timestamps(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze file timestamps for anomalies."""
        findings = []
        
        timestamps = {}
        for key in ('creation_time', 'modification_time', 'access_time'):
            if key in metadata and metadata[key]:
                timestamps[key] = metadata[key]
        
        if len(timestamps) >= 2:
            try:
                # Check for files created after they were modified (suspicious)
                if 'creation_time' in timestamps and 'modification_time' in timestamps:
                    creation = datetime.datetime.fromisoformat(timestamps['creation_time'])
                    modification = datetime.datetime.fromisoformat(timestamps['modification_time'])
                    
                    if creation > modification:
                        findings.append(MetadataFinding(
                            type="consistency",
                            description="File creation time is after modification time (suspicious)",
                            severity="medium",
                            data={"timestamps": timestamps}
                        ))
                
                # Check for future timestamps
                now = datetime.datetime.now()
                for name, timestamp_str in timestamps.items():
                    timestamp = datetime.datetime.fromisoformat(timestamp_str)
                    if timestamp > now:
                        findings.append(MetadataFinding(
                            type="consistency",
                            description=f"File {name.replace('_', ' ')} is in the future",
                            severity="medium",
                            data={"timestamp": timestamp_str}
                        ))
                
                # Check for very old timestamps
                min_year = 2000  # Arbitrary cutoff for "very old"
                for name, timestamp_str in timestamps.items():
                    timestamp = datetime.datetime.fromisoformat(timestamp_str)
                    if timestamp.year < min_year:
                        findings.append(MetadataFinding(
                            type="information",
                            description=f"File {name.replace('_', ' ')} is very old",
                            severity="low",
                            data={"timestamp": timestamp_str}
                        ))
            except (ValueError, TypeError) as e:
                # Handle timestamp parsing errors
                findings.append(MetadataFinding(
                    type="error",
                    description="Error analyzing timestamps",
                    severity="low",
                    data={"error": str(e), "timestamps": timestamps}
                ))
        
        return findings
    
    def _analyze_mime_consistency(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Check MIME type consistency with extension."""
        findings = []
        
        if 'mime_type' in metadata and 'file_path' in metadata:
            mime_type = metadata['mime_type']
            ext = os.path.splitext(metadata['file_path'])[1].lower()
            
            # Define some common MIME type and extension mappings
            mime_ext_map = {
                'image/jpeg': ['.jpg', '.jpeg'],
                'image/png': ['.png'],
                'application/pdf': ['.pdf'],
                'text/plain': ['.txt', '.text'],
                'application/msword': ['.doc'],
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
                'audio/mpeg': ['.mp3'],
                'video/mp4': ['.mp4']
            }
            
            if mime_type in mime_ext_map and ext not in mime_ext_map[mime_type]:
                expected_exts = ', '.join(mime_ext_map[mime_type])
                findings.append(MetadataFinding(
                    type="consistency",
                    description=f"File extension '{ext}' does not match MIME type '{mime_type}' (expected: {expected_exts})",
                    severity="medium",
                    data={"mime_type": mime_type, "extension": ext, "expected_extensions": mime_ext_map[mime_type]}
                ))
        
        return findings
    
    def _analyze_file_size(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Check for unusually small or large file sizes."""
        findings = []
        
        if 'size' in metadata:
            size = metadata['size']
            if size == 0:
                findings.append(MetadataFinding(
                    type="consistency",
                    description="File size is zero bytes (empty file)",
                    severity="medium",
                    data={"size": size}
                ))
            elif size < 100 and 'file_path' in metadata:
                ext = os.path.splitext(metadata['file_path'])[1].lower()
                if ext not in ['.txt', '.md', '.csv', '.json']:
                    findings.append(MetadataFinding(
                        type="consistency",
                        description=f"File is unusually small ({size} bytes)",
                        severity="low",
                        data={"size": size}
                    ))
            elif size > 1024 * 1024 * 1024:  # > 1 GB
                findings.append(MetadataFinding(
                    type="information",
                    description=f"File is very large ({size / (1024 * 1024 * 1024):.2f} GB)",
                    severity="low",
                    data={"size": size}
                ))
        
        return findings
    
    def _analyze_hashes(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Check file hashes for known issues."""
        findings = []
        
        if 'hashes' in metadata and 'md5' in metadata['hashes']:
            md5 = metadata['hashes']['md5']
            
            # List of known empty file hashes
            empty_file_md5 = "d41d8cd98f00b204e9800998ecf8427e"
            if md5 == empty_file_md5 and metadata.get('size', 0) > 0:
                findings.append(MetadataFinding(
                    type="consistency",
                    description="File hash matches empty file but size is not zero",
                    severity="high",
                    data={"hash": md5, "size": metadata.get('size', 0)}
                ))
            
            # Here you could add checks against known malware hashes
            # For example, checking against VirusTotal API or similar
            # This is just a placeholder
            known_malicious_hashes = []  # This would need to be populated
            if md5 in known_malicious_hashes:
                findings.append(MetadataFinding(
                    type="security",
                    description="File hash matches known malicious file",
                    severity="high",
                    data={"hash": md5}
                ))
        
        return findings
    
    def _analyze_archive_info(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze archive information if present."""
        findings = []
        
        if 'archive_info' in metadata:
            archive_info = metadata['archive_info']
            
            # Check compression ratio
            if 'compression_ratio' in archive_info:
                ratio = archive_info['compression_ratio']
                if ratio < 1.0:
                    findings.append(MetadataFinding(
                        type="information",
                        description=f"Archive has unusual compression ratio: {ratio}%",
                        severity="low",
                        data={"compression_ratio": ratio}
                    ))
            
            # Check for executable content in archives
            if 'extensions' in archive_info:
                executable_exts = ['.exe', '.dll', '.so', '.sh', '.bat', '.ps1', '.vbs']
                found_executables = []
                
                for ext, count in archive_info['extensions'].items():
                    if ext.lower() in executable_exts:
                        found_executables.append(f"{ext}: {count}")
                
                if found_executables:
                    findings.append(MetadataFinding(
                        type="security",
                        description="Archive contains executable files",
                        severity="medium",
                        data={"executables": found_executables}
                    ))
        
        return findings
    
    def _analyze_text_info(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze text file information if present."""
        findings = []
        
        if 'text_info' in metadata:
            text_info = metadata['text_info']
            
            # Check for encoding inconsistencies
            if 'encoding' in text_info and text_info['encoding'] not in ['utf-8', 'ascii']:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Text file uses non-standard encoding: {text_info['encoding']}",
                    severity="low",
                    data={"encoding": text_info['encoding']}
                ))
            
            # Check for unusually large text files
            if 'line_count' in text_info and text_info['line_count'] > 10000:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Text file is very large ({text_info['line_count']} lines)",
                    severity="low",
                    data={"line_count": text_info['line_count']}
                ))
        
        return findings