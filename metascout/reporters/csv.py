"""
CSV reporter for MetaScout
"""

import csv
import io
from typing import List, Dict, Any, Optional

from ..core.models import FileMetadata
from .base import BaseReporter


class CsvReporter(BaseReporter):
    """Reporter for CSV output format."""
    
    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize CSV reporter.
        
        Args:
            options: Options dictionary (supports 'delimiter', 'mode' options)
        """
        super().__init__(options)
        
        # Get formatting options
        self.delimiter = self.options.get('delimiter', ',')
        self.mode = self.options.get('mode', 'findings')  # 'findings' or 'summary'
        
    def generate_report(self, results: List[FileMetadata]) -> str:
        """
        Generate a CSV report from analysis results.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            CSV formatted report
        """
        output = io.StringIO()
        writer = csv.writer(output, delimiter=self.delimiter)
        
        if self.mode == 'summary':
            self._write_summary_csv(writer, results)
        else:
            self._write_findings_csv(writer, results)
        
        return output.getvalue()
    
    def _write_findings_csv(self, writer: csv.writer, results: List[FileMetadata]) -> None:
        """
        Write CSV with focus on findings.
        
        Args:
            writer: CSV writer object
            results: List of FileMetadata objects
        """
        # Write header row
        writer.writerow([
            "File Path", "File Type", "Finding Type", "Severity", 
            "Description", "Data", "File Size", "File Hash (SHA256)"
        ])
        
        # Write rows for each finding
        for result in results:
            file_path = result.file_path
            file_type = result.file_type
            file_size = result.file_size
            file_hash = result.hashes.get('sha256', '') if result.hashes else ''
            
            if result.findings:
                for finding in result.findings:
                    # Convert finding data to string representation
                    data_str = "; ".join(f"{k}={v}" for k, v in finding.data.items()) if finding.data else ""
                    
                    writer.writerow([
                        file_path,
                        file_type,
                        finding.type,
                        finding.severity,
                        finding.description,
                        data_str,
                        file_size,
                        file_hash
                    ])
            else:
                # Write a row for files with no findings
                writer.writerow([
                    file_path,
                    file_type,
                    "none",
                    "none",
                    "No findings",
                    "",
                    file_size,
                    file_hash
                ])
    
    def _write_summary_csv(self, writer: csv.writer, results: List[FileMetadata]) -> None:
        """
        Write CSV with focus on file summary.
        
        Args:
            writer: CSV writer object
            results: List of FileMetadata objects
        """
        # Write header row
        writer.writerow([
            "File Path", "File Type", "File Size", "MIME Type", 
            "Creation Time", "Modification Time", "SHA256 Hash",
            "Findings (High)", "Findings (Medium)", "Findings (Low)",
            "Total Findings"
        ])
        
        # Write rows for each file
        for result in results:
            # Count findings by severity
            high_count = sum(1 for f in result.findings if f.severity.lower() == 'high')
            medium_count = sum(1 for f in result.findings if f.severity.lower() == 'medium')
            low_count = sum(1 for f in result.findings if f.severity.lower() == 'low')
            total_count = len(result.findings)
            
            writer.writerow([
                result.file_path,
                result.file_type,
                result.file_size,
                result.mime_type,
                result.creation_time or '',
                result.modification_time or '',
                result.hashes.get('sha256', '') if result.hashes else '',
                high_count,
                medium_count,
                low_count,
                total_count
            ])
    
    @classmethod
    def get_format_name(cls) -> str:
        """Get the name of the output format."""
        return "csv"