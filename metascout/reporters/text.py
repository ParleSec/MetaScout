"""
Text reporter for MetaScout
"""

import os
from typing import List, Dict, Any, Optional

from colorama import Fore, Style

from ..core.models import FileMetadata, MetadataFinding
from .base import BaseReporter, FormattedOutput


class TextReporter(BaseReporter):
    """Reporter for plain text output format."""
    
    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize text reporter.
        
        Args:
            options: Options dictionary (supports 'colorize' and 'detailed' options)
        """
        super().__init__(options)
        
        # Get formatting options
        self.colorize = self.options.get('colorize', True)
        self.detailed = self.options.get('detailed', True)
        
        # Initialize formatter
        self.formatter = FormattedOutput(colorize=self.colorize)
    
    def generate_report(self, results: List[FileMetadata]) -> str:
        """
        Generate a text report from analysis results.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            Formatted text report
        """
        output_parts = []
        
        # Generate summary section if multiple files
        if len(results) > 1:
            output_parts.append(self._generate_summary(results))
        
        # Generate detailed sections for each file
        for i, result in enumerate(results):
            if i > 0:
                output_parts.append("=" * 70)  # Separator between files
            
            output_parts.append(self._generate_file_section(result))
        
        return "\n".join(output_parts)
    
    def _generate_summary(self, results: List[FileMetadata]) -> str:
        """Generate summary section for multiple files."""
        output = []
        
        # Add report title
        output.append(self.formatter.header("Metadata Analysis Summary", level=1))
        output.append("")
        
        # Add file count
        output.append(f"Files analyzed: {len(results)}")
        
        # Count findings by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for finding in result.findings:
                if finding.severity.lower() in severity_counts:
                    severity_counts[finding.severity.lower()] += 1
        
        # Format finding counts with colors
        high_color = self.formatter.apply_color(f"{severity_counts['high']} High", 'red')
        medium_color = self.formatter.apply_color(f"{severity_counts['medium']} Medium", 'yellow')
        low_color = self.formatter.apply_color(f"{severity_counts['low']} Low", 'green')
        output.append(f"Total findings: {high_color}, {medium_color}, {low_color}")
        
        # Add file list with basic info
        output.append("")
        output.append(self.formatter.header("Files", level=2))
        
        for i, result in enumerate(results):
            high_count = sum(1 for f in result.findings if f.severity.lower() == 'high')
            medium_count = sum(1 for f in result.findings if f.severity.lower() == 'medium')
            low_count = sum(1 for f in result.findings if f.severity.lower() == 'low')
            
            # Format file name
            file_name = os.path.basename(result.file_path)
            if self.colorize:
                if high_count > 0:
                    file_name = f"{Fore.RED}{file_name}{Style.RESET_ALL}"
                elif medium_count > 0:
                    file_name = f"{Fore.YELLOW}{file_name}{Style.RESET_ALL}"
            
            # Add file info line
            output.append(f"  {i+1}. {file_name}")
            output.append(f"     Type: {result.file_type}, Size: {result.file_size:,} bytes")
            output.append(f"     Findings: {high_count} High, {medium_count} Medium, {low_count} Low")
        
        output.append("")
        return "\n".join(output)
    
    def _generate_file_section(self, result: FileMetadata) -> str:
        """Generate detailed section for a single file."""
        output = []
        
        # File info header
        file_name = os.path.basename(result.file_path)
        output.append(self.formatter.apply_color(f"File: {file_name}", 'cyan'))
        output.append(f"Path: {result.file_path}")
        output.append(f"Type: {result.file_type} ({result.mime_type})")
        output.append(f"Size: {result.file_size:,} bytes")
        
        # Add hashes
        if result.hashes:
            output.append("\nHashes:")
            for hash_type, hash_value in result.hashes.items():
                output.append(f"  {hash_type.upper()}: {hash_value}")
        
        # Add timestamps
        if result.creation_time or result.modification_time:
            output.append("\nTimestamps:")
            if result.creation_time:
                output.append(f"  Created: {result.creation_time}")
            if result.modification_time:
                output.append(f"  Modified: {result.modification_time}")
            if result.access_time:
                output.append(f"  Accessed: {result.access_time}")
        
        # Add detailed metadata if requested
        if self.detailed and result.metadata:
            output.append("\nMetadata:")
            output.append(self._format_metadata_dict(result.metadata, level=1))
        
        # Add findings
        output.append("\nAnalysis Findings:")
        if result.findings:
            output.append(self._format_findings(result.findings))
        else:
            output.append("  No notable findings.")
        
        # Add errors if any
        if result.errors:
            output.append("\nErrors:")
            for error in result.errors:
                output.append(f"  {self.formatter.apply_color(error, 'red')}")
        
        return "\n".join(output)
    
    def _format_metadata_dict(self, metadata: Dict[str, Any], level: int = 0) -> str:
        """
        Format a metadata dictionary for display.
        
        Args:
            metadata: Dictionary to format
            level: Indentation level
            
        Returns:
            Formatted string representation
        """
        output = []
        indent = "  " * level
        
        for key, value in sorted(metadata.items()):
            if isinstance(value, dict):
                output.append(f"{indent}{key}:")
                output.append(self._format_metadata_dict(value, level + 1))
            elif isinstance(value, list):
                if not value:
                    output.append(f"{indent}{key}: []")
                elif all(isinstance(item, (str, int, float, bool)) for item in value):
                    # For simple lists, format inline
                    value_str = ", ".join(str(item) for item in value)
                    output.append(f"{indent}{key}: [{value_str}]")
                else:
                    # For complex lists, format one per line
                    output.append(f"{indent}{key}:")
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            output.append(f"{indent}  [{i}]:")
                            output.append(self._format_metadata_dict(item, level + 2))
                        else:
                            output.append(f"{indent}  [{i}]: {item}")
            else:
                # For scalar values
                output.append(f"{indent}{key}: {value}")
        
        return "\n".join(output)
    
    def _format_findings(self, findings: List[MetadataFinding]) -> str:
        """
        Format a list of findings for display.
        
        Args:
            findings: List of MetadataFinding objects
            
        Returns:
            Formatted string representation
        """
        if not findings:
            return "  No notable findings."
        
        output = []
        severity_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'green',
            'info': 'cyan'
        }
        
        # Sort findings by severity (high to low)
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 999))
        
        for finding in sorted_findings:
            severity = finding.severity.lower()
            color = severity_colors.get(severity, 'reset')
            
            # Format finding header
            header = f"[{finding.type.upper()}] {finding.description}"
            output.append(self.formatter.apply_color(header, color))
            
            # Format additional data if present
            if finding.data:
                for key, value in finding.data.items():
                    if isinstance(value, dict):
                        output.append(f"  {key}:")
                        for k, v in value.items():
                            output.append(f"    {k}: {v}")
                    elif isinstance(value, list):
                        if len(value) > 5:
                            # For long lists, show sample with count
                            sample = ", ".join(str(item) for item in value[:5])
                            output.append(f"  {key}: {sample} (and {len(value)-5} more)")
                        else:
                            output.append(f"  {key}: {', '.join(str(item) for item in value)}")
                    else:
                        output.append(f"  {key}: {value}")
            
            output.append("")
        
        return "\n".join(output)
    
    @classmethod
    def get_format_name(cls) -> str:
        """Get the name of the output format."""
        return "text"