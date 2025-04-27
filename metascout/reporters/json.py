"""
JSON reporter for MetaScout
"""

import json
from typing import List, Dict, Any, Optional

from ..core.models import FileMetadata
from .base import BaseReporter


class JsonReporter(BaseReporter):
    """Reporter for JSON output format."""
    
    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize JSON reporter.
        
        Args:
            options: Options dictionary (supports 'indent' and 'compact' options)
        """
        super().__init__(options)
        
        # Get formatting options
        self.indent = self.options.get('indent', 2)
        self.compact = self.options.get('compact', False)
        self.include_metadata = self.options.get('include_metadata', True)
    
    def generate_report(self, results: List[FileMetadata]) -> str:
        """
        Generate a JSON report from analysis results.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            JSON formatted report
        """
        # Pre-process the results for serialization
        serialized_results = self._prepare_data(results)
        
        # Generate JSON
        if self.compact:
            return json.dumps(serialized_results, separators=(',', ':'), default=str)
        else:
            return json.dumps(serialized_results, indent=self.indent, default=str)
    
    def _prepare_data(self, results: List[FileMetadata]) -> Dict[str, Any]:
        """
        Prepare data structure for JSON serialization.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            Dictionary ready for JSON serialization
        """
        # For multiple files, create a report structure
        if len(results) > 1:
            report_data = {
                'report': {
                    'generated_at': self._get_timestamp(),
                    'file_count': len(results),
                    'summary': self._generate_summary(results),
                    'files': []
                }
            }
            
            # Add each file's data
            for result in results:
                file_data = self._process_file_metadata(result)
                report_data['report']['files'].append(file_data)
            
            return report_data
        
        # For a single file, just return its data
        elif len(results) == 1:
            return self._process_file_metadata(results[0])
        
        # Empty results
        else:
            return {'report': {'generated_at': self._get_timestamp(), 'file_count': 0, 'files': []}}
    
    def _process_file_metadata(self, result: FileMetadata) -> Dict[str, Any]:
        """
        Process a FileMetadata object for JSON serialization.
        
        Args:
            result: FileMetadata object
            
        Returns:
            Dictionary representation of FileMetadata
        """
        file_data = {
            'file_path': result.file_path,
            'file_name': self._get_filename(result.file_path),
            'file_type': result.file_type,
            'mime_type': result.mime_type,
            'file_size': result.file_size,
            'hashes': result.hashes or {},
            'timestamps': {
                'creation_time': result.creation_time,
                'modification_time': result.modification_time,
                'access_time': result.access_time
            },
            'findings': self._process_findings(result),
            'errors': result.errors
        }
        
        # Include detailed metadata if requested
        if self.include_metadata:
            file_data['metadata'] = result.metadata
        
        return file_data
    
    def _process_findings(self, result: FileMetadata) -> Dict[str, Any]:
        """
        Process findings for JSON serialization.
        
        Args:
            result: FileMetadata object
            
        Returns:
            Dictionary with findings organized by severity and type
        """
        findings_data = {
            'count': {
                'total': len(result.findings),
                'by_severity': {
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'other': 0
                },
                'by_type': {}
            },
            'details': []
        }
        
        # Process each finding
        for finding in result.findings:
            # Increment counts
            severity = finding.severity.lower()
            if severity in findings_data['count']['by_severity']:
                findings_data['count']['by_severity'][severity] += 1
            else:
                findings_data['count']['by_severity']['other'] += 1
            
            # Count by type
            finding_type = finding.type.lower()
            if finding_type not in findings_data['count']['by_type']:
                findings_data['count']['by_type'][finding_type] = 0
            findings_data['count']['by_type'][finding_type] += 1
            
            # Add finding details
            findings_data['details'].append({
                'type': finding.type,
                'description': finding.description,
                'severity': finding.severity,
                'data': finding.data
            })
        
        return findings_data
    
    def _generate_summary(self, results: List[FileMetadata]) -> Dict[str, Any]:
        """
        Generate summary data for multiple files.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            Summary dictionary
        """
        # Count findings by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'other': 0}
        type_counts = {}
        
        for result in results:
            for finding in result.findings:
                # Count by severity
                severity = finding.severity.lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts['other'] += 1
                
                # Count by type
                finding_type = finding.type.lower()
                if finding_type not in type_counts:
                    type_counts[finding_type] = 0
                type_counts[finding_type] += 1
        
        # Create file types summary
        file_types = {}
        for result in results:
            if result.file_type not in file_types:
                file_types[result.file_type] = 0
            file_types[result.file_type] += 1
        
        return {
            'findings': {
                'total': sum(severity_counts.values()),
                'by_severity': severity_counts,
                'by_type': type_counts
            },
            'file_types': file_types
        }
    
    def _get_filename(self, file_path: str) -> str:
        """Extract filename from path."""
        import os
        return os.path.basename(file_path)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        import datetime
        return datetime.datetime.now().isoformat()
    
    @classmethod
    def get_format_name(cls) -> str:
        """Get the name of the output format."""
        return "json"