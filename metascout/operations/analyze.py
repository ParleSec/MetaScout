"""
Single file analysis operations
"""

import os
import json
import datetime
import logging
from typing import List, Optional

from colorama import Fore, Style

from ..core.models import FileMetadata, MetadataFinding


def write_report(results: List[FileMetadata], output_format: str, output_file: Optional[str] = None) -> None:
    """
    Write analysis results to file or stdout in specified format.
    
    Args:
        results: List of FileMetadata objects to report on
        output_format: Format of the report (text, json, csv, html)
        output_file: Optional file path to write report to (stdout if None)
    """
    if output_format == 'json':
        # JSON output
        output = json.dumps([r.to_dict() for r in results], indent=2, default=str)
    elif output_format == 'csv':
        # CSV output (simplified, focusing on findings)
        output = "file_path,file_type,finding_type,severity,description\n"
        for result in results:
            base_info = f'"{result.file_path}","{result.file_type}"'
            if result.findings:
                for finding in result.findings:
                    output += f'{base_info},"{finding.type}","{finding.severity}","{finding.description}"\n'
            else:
                output += f'{base_info},"none","none","No findings"\n'
    elif output_format == 'html':
        # HTML report
        output = generate_html_report(results)
    else:
        # Default text output
        output = generate_text_report(results)
    
    # Write to file or stdout
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"Report written to {output_file}")
    else:
        print(output)


def generate_text_report(results: List[FileMetadata]) -> str:
    """
    Generate a plain text report from analysis results.
    
    Args:
        results: List of FileMetadata objects
        
    Returns:
        Formatted text report
    """
    output_parts = []
    
    for i, result in enumerate(results):
        if i > 0:
            output_parts.append("=" * 70)  # Separator between files
        
        # File info header
        file_name = os.path.basename(result.file_path)
        output_parts.append(f"{Fore.CYAN}File: {file_name}{Style.RESET_ALL}")
        output_parts.append(f"Path: {result.file_path}")
        output_parts.append(f"Type: {result.file_type} ({result.mime_type})")
        output_parts.append(f"Size: {result.file_size:,} bytes")
        
        # Add hashes
        if result.hashes:
            output_parts.append("\nHashes:")
            for hash_type, hash_value in result.hashes.items():
                output_parts.append(f"  {hash_type.upper()}: {hash_value}")
        
        # Add timestamps
        if result.creation_time or result.modification_time:
            output_parts.append("\nTimestamps:")
            if result.creation_time:
                output_parts.append(f"  Created: {result.creation_time}")
            if result.modification_time:
                output_parts.append(f"  Modified: {result.modification_time}")
        
        # Findings
        output_parts.append("\nAnalysis Findings:")
        if result.findings:
            output_parts.append(format_findings(result.findings))
        else:
            output_parts.append("  No notable findings.")
    
    return "\n".join(output_parts)


def generate_html_report(results: List[FileMetadata]) -> str:
    """
    Generate an HTML report from analysis results.
    
    Args:
        results: List of FileMetadata objects
        
    Returns:
        HTML formatted report
    """
    html_parts = ['<!DOCTYPE html><html><head><title>Metadata Analysis Report</title>',
                  '<style>body{font-family:sans-serif;margin:20px;} .file{margin-bottom:20px;border:1px solid #ddd;padding:15px;border-radius:5px;}',
                  '.high{color:red;} .medium{color:orange;} .low{color:green;} .finding{margin:10px 0;} table{border-collapse:collapse;width:100%;}',
                  'th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd;} th{background-color:#f2f2f2;}</style></head><body>',
                  '<h1>Metadata Analysis Report</h1>']
    
    # Add generation timestamp
    html_parts.append(f'<p>Generated: {datetime.datetime.now().isoformat()}</p>')
    
    # Add summary section
    html_parts.append('<h2>Summary</h2>')
    html_parts.append('<table><tr><th>File</th><th>Type</th><th>Size</th><th>Findings</th></tr>')
    
    for result in results:
        high_count = sum(1 for f in result.findings if f.severity.lower() == 'high')
        medium_count = sum(1 for f in result.findings if f.severity.lower() == 'medium')
        low_count = sum(1 for f in result.findings if f.severity.lower() == 'low')
        
        findings_cell = f'<span class="high">{high_count} High</span>, ' \
                        f'<span class="medium">{medium_count} Medium</span>, ' \
                        f'<span class="low">{low_count} Low</span>'
        
        file_name = os.path.basename(result.file_path)
        html_parts.append(f'<tr><td>{file_name}</td><td>{result.file_type}</td>'
                          f'<td>{result.file_size:,} bytes</td><td>{findings_cell}</td></tr>')
    
    html_parts.append('</table>')
    
    # Add detailed results for each file
    html_parts.append('<h2>Detailed Results</h2>')
    
    for result in results:
        file_name = os.path.basename(result.file_path)
        html_parts.append(f'<div class="file"><h3>{file_name}</h3>')
        
        # File info
        html_parts.append('<h4>File Information</h4>')
        html_parts.append('<table>')
        html_parts.append(f'<tr><td>Full Path</td><td>{result.file_path}</td></tr>')
        html_parts.append(f'<tr><td>File Type</td><td>{result.file_type}</td></tr>')
        html_parts.append(f'<tr><td>MIME Type</td><td>{result.mime_type}</td></tr>')
        html_parts.append(f'<tr><td>Size</td><td>{result.file_size:,} bytes</td></tr>')
        
        # Add hashes
        if result.hashes:
            for hash_type, hash_value in result.hashes.items():
                html_parts.append(f'<tr><td>{hash_type.upper()} Hash</td><td>{hash_value}</td></tr>')
        
        # Add timestamps
        if result.creation_time:
            html_parts.append(f'<tr><td>Created</td><td>{result.creation_time}</td></tr>')
        if result.modification_time:
            html_parts.append(f'<tr><td>Modified</td><td>{result.modification_time}</td></tr>')
        
        html_parts.append('</table>')
        
        # Findings
        html_parts.append('<h4>Analysis Findings</h4>')
        
        if result.findings:
            for finding in result.findings:
                severity_class = finding.severity.lower()
                html_parts.append(f'<div class="finding {severity_class}">')
                html_parts.append(f'<strong>[{finding.type.upper()}] {finding.description}</strong>')
                
                # Add finding details if present
                if finding.data:
                    html_parts.append('<ul>')
                    for key, value in finding.data.items():
                        if isinstance(value, dict):
                            html_parts.append(f'<li>{key}:<ul>')
                            for k, v in value.items():
                                html_parts.append(f'<li>{k}: {v}</li>')
                            html_parts.append('</ul></li>')
                        elif isinstance(value, list):
                            html_parts.append(f'<li>{key}: {", ".join(str(item) for item in value)}</li>')
                        else:
                            html_parts.append(f'<li>{key}: {value}</li>')
                    html_parts.append('</ul>')
                
                html_parts.append('</div>')
        else:
            html_parts.append('<p>No notable findings.</p>')
        
        html_parts.append('</div>')
    
    html_parts.append('</body></html>')
    return ''.join(html_parts)


def format_findings(findings: List[MetadataFinding], format_type: str = 'text') -> str:
    """
    Format analysis findings for display in various formats.
    
    Args:
        findings: List of MetadataFinding objects
        format_type: Output format (text, json)
        
    Returns:
        Formatted string representation of findings
    """
    if not findings:
        return "No notable findings."
    
    if format_type == 'json':
        return json.dumps([f.__dict__ for f in findings], indent=2)
    
    # Text/console format with color
    output = []
    severity_colors = {
        'high': Fore.RED,
        'medium': Fore.YELLOW,
        'low': Fore.GREEN,
        'info': Fore.CYAN
    }
    
    for finding in findings:
        severity = finding.severity.lower()
        color = severity_colors.get(severity, '')
        
        # Format finding header
        header = f"[{finding.type.upper()}] {color}{finding.description}{Style.RESET_ALL}"
        output.append(header)
        
        # Format additional data if present
        if finding.data:
            for key, value in finding.data.items():
                if isinstance(value, dict):
                    output.append(f"  {key}:")
                    for k, v in value.items():
                        output.append(f"    {k}: {v}")
                elif isinstance(value, list):
                    output.append(f"  {key}: {', '.join(str(item) for item in value)}")
                else:
                    output.append(f"  {key}: {value}")
        
        output.append("")
    
    return "\n".join(output)