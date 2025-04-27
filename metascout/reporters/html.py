"""
HTML reporter for MetaScout
"""

import os
import datetime
import html
import json
from typing import List, Dict, Any, Optional

from ..core.models import FileMetadata, MetadataFinding
from .base import BaseReporter


class HtmlReporter(BaseReporter):
    """Reporter for HTML output format."""
    
    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize HTML reporter.
        
        Args:
            options: Options dictionary (supports 'title', 'include_metadata', 'theme' options)
        """
        super().__init__(options)
        
        # Get formatting options
        self.title = self.options.get('title', 'MetaScout Metadata Analysis Report')
        self.include_metadata = self.options.get('include_metadata', True)
        self.theme = self.options.get('theme', 'light')  # 'light' or 'dark'
    
    def generate_report(self, results: List[FileMetadata]) -> str:
        """
        Generate an HTML report from analysis results.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            HTML formatted report
        """
        # Generate HTML parts
        html_parts = []
        
        # Add HTML header, styles, and page beginning
        html_parts.extend(self._generate_html_header())
        
        # Add report header
        html_parts.append(f'<h1>{html.escape(self.title)}</h1>')
        html_parts.append(f'<p class="timestamp">Generated: {datetime.datetime.now().isoformat()}</p>')
        
        # Add summary section if multiple files
        if len(results) > 1:
            html_parts.append(self._generate_summary_section(results))
        
        # Add detailed results for each file
        html_parts.append('<h2>Detailed Results</h2>')
        
        for result in results:
            html_parts.append(self._generate_file_section(result))
        
        # Add page end
        html_parts.append('</body></html>')
        
        return ''.join(html_parts)
    
    def _generate_html_header(self) -> List[str]:
        """Generate HTML header with styles and script."""
        parts = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            f'<title>{html.escape(self.title)}</title>',
            '<meta charset="UTF-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
            '<style>',
        ]
        
        # Add CSS based on theme
        if self.theme == 'dark':
            parts.append(self._get_dark_theme_css())
        else:
            parts.append(self._get_light_theme_css())
        
        parts.extend([
            '</style>',
            '<script>',
            '''
            function toggleSection(id) {
                const section = document.getElementById(id);
                if (section) {
                    section.classList.toggle('collapsed');
                    
                    // Update toggle button text
                    const button = document.querySelector(`[data-target="${id}"]`);
                    if (button) {
                        if (section.classList.contains('collapsed')) {
                            button.textContent = 'Show';
                        } else {
                            button.textContent = 'Hide';
                        }
                    }
                }
            }
            
            function toggleAllFindings(fileId, show) {
                const findings = document.querySelectorAll(`#${fileId} .finding`);
                findings.forEach(finding => {
                    if (show) {
                        finding.classList.remove('collapsed');
                    } else {
                        finding.classList.add('collapsed');
                    }
                });
                
                // Update toggle buttons
                const buttons = document.querySelectorAll(`#${fileId} .toggle-btn`);
                buttons.forEach(button => {
                    const targetId = button.getAttribute('data-target');
                    if (targetId && targetId.includes('finding')) {
                        button.textContent = show ? 'Hide' : 'Show';
                    }
                });
            }
            ''',
            '</script>',
            '</head>',
            '<body>',
        ])
        
        return parts
    
    def _get_light_theme_css(self) -> str:
        """Get CSS for light theme."""
        return '''
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                margin: 20px;
                padding: 0;
                color: #333;
                background-color: #f8f9fa;
                line-height: 1.6;
            }
            
            h1, h2, h3, h4 {
                margin-top: 1.5em;
                margin-bottom: 0.5em;
                color: #2c3e50;
            }
            
            h1 { font-size: 2em; border-bottom: 2px solid #eaecef; padding-bottom: 0.3em; }
            h2 { font-size: 1.5em; border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; }
            h3 { font-size: 1.25em; }
            h4 { font-size: 1em; }
            
            .file {
                margin-bottom: 30px;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
                background-color: white;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            
            .summary {
                margin-bottom: 30px;
                padding: 15px;
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            
            .timestamp {
                color: #666;
                font-style: italic;
                margin-bottom: 20px;
            }
            
            table {
                border-collapse: collapse;
                width: 100%;
                margin: 1em 0;
            }
            
            th, td {
                text-align: left;
                padding: 8px;
                border-bottom: 1px solid #ddd;
            }
            
            th {
                background-color: #f2f2f2;
                font-weight: bold;
            }
            
            tr:hover {
                background-color: #f5f5f5;
            }
            
            .high { color: #e74c3c; }
            .medium { color: #f39c12; }
            .low { color: #27ae60; }
            
            .finding {
                margin: 10px 0;
                padding: 10px;
                border-left: 4px solid #ddd;
                background-color: #f9f9f9;
            }
            
            .finding.severity-high { border-left-color: #e74c3c; }
            .finding.severity-medium { border-left-color: #f39c12; }
            .finding.severity-low { border-left-color: #27ae60; }
            
            .file-info {
                margin-bottom: 15px;
            }
            
            .metadata-section, .findings-section {
                margin-top: 15px;
            }
            
            .collapsed .collapsible-content {
                display: none;
            }
            
            .toggle-btn {
                background-color: #f0f0f0;
                border: 1px solid #ddd;
                padding: 2px 8px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 0.8em;
                margin-left: 10px;
            }
            
            .toggle-btn:hover {
                background-color: #e0e0e0;
            }
            
            .toggle-all-btn {
                margin-bottom: 10px;
            }
            
            pre {
                background-color: #f6f8fa;
                border-radius: 3px;
                padding: 10px;
                overflow: auto;
                font-family: monospace;
                font-size: 0.9em;
                border: 1px solid #e1e4e8;
            }
        '''
    
    def _get_dark_theme_css(self) -> str:
        """Get CSS for dark theme."""
        return '''
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                margin: 20px;
                padding: 0;
                color: #e0e0e0;
                background-color: #1e1e1e;
                line-height: 1.6;
            }
            
            h1, h2, h3, h4 {
                margin-top: 1.5em;
                margin-bottom: 0.5em;
                color: #f0f0f0;
            }
            
            h1 { font-size: 2em; border-bottom: 2px solid #333; padding-bottom: 0.3em; }
            h2 { font-size: 1.5em; border-bottom: 1px solid #333; padding-bottom: 0.3em; }
            h3 { font-size: 1.25em; }
            h4 { font-size: 1em; }
            
            .file {
                margin-bottom: 30px;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 15px;
                background-color: #252525;
                box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            }
            
            .summary {
                margin-bottom: 30px;
                padding: 15px;
                background-color: #252525;
                border: 1px solid #333;
                border-radius: 5px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.3);
            }
            
            .timestamp {
                color: #888;
                font-style: italic;
                margin-bottom: 20px;
            }
            
            table {
                border-collapse: collapse;
                width: 100%;
                margin: 1em 0;
            }
            
            th, td {
                text-align: left;
                padding: 8px;
                border-bottom: 1px solid #444;
            }
            
            th {
                background-color: #333;
                font-weight: bold;
            }
            
            tr:hover {
                background-color: #2a2a2a;
            }
            
            .high { color: #ff6b6b; }
            .medium { color: #ffa94d; }
            .low { color: #51cf66; }
            
            .finding {
                margin: 10px 0;
                padding: 10px;
                border-left: 4px solid #444;
                background-color: #2a2a2a;
            }
            
            .finding.severity-high { border-left-color: #ff6b6b; }
            .finding.severity-medium { border-left-color: #ffa94d; }
            .finding.severity-low { border-left-color: #51cf66; }
            
            .file-info {
                margin-bottom: 15px;
            }
            
            .metadata-section, .findings-section {
                margin-top: 15px;
            }
            
            .collapsed .collapsible-content {
                display: none;
            }
            
            .toggle-btn {
                background-color: #333;
                border: 1px solid #555;
                padding: 2px 8px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 0.8em;
                margin-left: 10px;
                color: #e0e0e0;
            }
            
            .toggle-btn:hover {
                background-color: #444;
            }
            
            .toggle-all-btn {
                margin-bottom: 10px;
            }
            
            pre {
                background-color: #2d2d2d;
                border-radius: 3px;
                padding: 10px;
                overflow: auto;
                font-family: monospace;
                font-size: 0.9em;
                border: 1px solid #444;
                color: #e0e0e0;
            }
        '''
    
    def _generate_summary_section(self, results: List[FileMetadata]) -> str:
        """Generate summary section for multiple files."""
        parts = ['<div class="summary">']
        
        # Add summary heading
        parts.append('<h2>Summary</h2>')
        
        # Count findings by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            for finding in result.findings:
                sev = finding.severity.lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1
        
        # Add findings summary
        parts.append('<div class="findings-summary">')
        parts.append('<h3>Findings</h3>')
        parts.append('<table>')
        parts.append('<tr><th>Severity</th><th>Count</th></tr>')
        parts.append(f'<tr><td><span class="high">High</span></td><td>{severity_counts["high"]}</td></tr>')
        parts.append(f'<tr><td><span class="medium">Medium</span></td><td>{severity_counts["medium"]}</td></tr>')
        parts.append(f'<tr><td><span class="low">Low</span></td><td>{severity_counts["low"]}</td></tr>')
        parts.append(f'<tr><th>Total</th><th>{sum(severity_counts.values())}</th></tr>')
        parts.append('</table>')
        parts.append('</div>')
        
        # Add files table
        parts.append('<div class="files-summary">')
        parts.append('<h3>Files</h3>')
        parts.append('<table>')
        parts.append('<tr><th>File</th><th>Type</th><th>Size</th><th>Findings</th></tr>')
        
        for result in results:
            high_count = sum(1 for f in result.findings if f.severity.lower() == 'high')
            medium_count = sum(1 for f in result.findings if f.severity.lower() == 'medium')
            low_count = sum(1 for f in result.findings if f.severity.lower() == 'low')
            
            file_name = os.path.basename(result.file_path)
            safe_id = file_name.replace('.', '_').replace(' ', '_')
            
            findings_cell = (
                f'<span class="high">{high_count} High</span>, '
                f'<span class="medium">{medium_count} Medium</span>, '
                f'<span class="low">{low_count} Low</span>'
            )
            
            parts.append(
                f'<tr>'
                f'<td><a href="#{safe_id}">{html.escape(file_name)}</a></td>'
                f'<td>{html.escape(result.file_type)}</td>'
                f'<td>{result.file_size:,} bytes</td>'
                f'<td>{findings_cell}</td>'
                f'</tr>'
            )
        
        parts.append('</table>')
        parts.append('</div>')
        parts.append('</div>')
        
        return ''.join(parts)
    
    def _generate_file_section(self, result: FileMetadata) -> str:
        """Generate detailed section for a single file."""
        file_name = os.path.basename(result.file_path)
        safe_id = file_name.replace('.', '_').replace(' ', '_')
        
        parts = [f'<div class="file" id="{safe_id}">']
        
        # File header
        parts.append(f'<h3>{html.escape(file_name)}</h3>')
        
        # File info
        parts.append('<div class="file-info">')
        parts.append('<table>')
        parts.append(f'<tr><td>Full Path</td><td>{html.escape(result.file_path)}</td></tr>')
        parts.append(f'<tr><td>File Type</td><td>{html.escape(result.file_type)}</td></tr>')
        parts.append(f'<tr><td>MIME Type</td><td>{html.escape(result.mime_type)}</td></tr>')
        parts.append(f'<tr><td>Size</td><td>{result.file_size:,} bytes</td></tr>')
        
        # Add hashes
        if result.hashes:
            for hash_type, hash_value in result.hashes.items():
                parts.append(f'<tr><td>{hash_type.upper()} Hash</td><td>{hash_value}</td></tr>')
        
        # Add timestamps
        if result.creation_time:
            parts.append(f'<tr><td>Created</td><td>{result.creation_time}</td></tr>')
        if result.modification_time:
            parts.append(f'<tr><td>Modified</td><td>{result.modification_time}</td></tr>')
        if result.access_time:
            parts.append(f'<tr><td>Accessed</td><td>{result.access_time}</td></tr>')
        
        parts.append('</table>')
        parts.append('</div>')
        
        # Add findings section
        parts.append('<div class="findings-section">')
        parts.append('<h4>Analysis Findings')
        
        # Add toggle controls if there are findings
        if result.findings:
            parts.append(
                f'<button class="toggle-btn toggle-all-btn" onclick="toggleAllFindings(\'{safe_id}\', true)">Expand All</button>'
                f'<button class="toggle-btn toggle-all-btn" onclick="toggleAllFindings(\'{safe_id}\', false)">Collapse All</button>'
            )
        
        parts.append('</h4>')
        
        if result.findings:
            parts.extend(self._format_findings(result.findings, safe_id))
        else:
            parts.append('<p>No notable findings.</p>')
        
        parts.append('</div>')
        
        # Add metadata section if requested
        if self.include_metadata and result.metadata:
            metadata_id = f"{safe_id}_metadata"
            parts.append('<div class="metadata-section">')
            parts.append(
                f'<h4>Metadata'
                f'<button class="toggle-btn" onclick="toggleSection(\'{metadata_id}\')" data-target="{metadata_id}">Hide</button>'
                f'</h4>'
            )
            parts.append(f'<div id="{metadata_id}" class="collapsible-content">')
            parts.append(self._format_metadata(result.metadata))
            parts.append('</div>')
            parts.append('</div>')
        
        # Add errors section if any
        if result.errors:
            parts.append('<div class="errors-section">')
            parts.append('<h4>Errors</h4>')
            parts.append('<ul>')
            for error in result.errors:
                parts.append(f'<li class="high">{html.escape(error)}</li>')
            parts.append('</ul>')
            parts.append('</div>')
        
        parts.append('</div>')
        return ''.join(parts)
    
    def _format_findings(self, findings: List[MetadataFinding], file_id: str) -> List[str]:
        """Format findings for HTML display."""
        parts = []
        
        # Sort findings by severity (high to low)
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity.lower(), 999))
        
        for i, finding in enumerate(sorted_findings):
            severity = finding.severity.lower()
            finding_id = f"{file_id}_finding_{i}"
            
            parts.append(
                f'<div class="finding severity-{severity}" id="{finding_id}">'
                f'<strong>[{html.escape(finding.type.upper())}] {html.escape(finding.description)}</strong>'
                f'<button class="toggle-btn" onclick="toggleSection(\'{finding_id}_details\')" '
                f'data-target="{finding_id}_details">Hide</button>'
            )
            
            # Add finding details
            parts.append(f'<div id="{finding_id}_details" class="collapsible-content">')
            
            if finding.data:
                parts.append('<ul>')
                for key, value in finding.data.items():
                    if isinstance(value, dict):
                        parts.append(f'<li>{html.escape(key)}:<ul>')
                        for k, v in value.items():
                            parts.append(f'<li>{html.escape(k)}: {html.escape(str(v))}</li>')
                        parts.append('</ul></li>')
                    elif isinstance(value, list):
                        formatted_values = [html.escape(str(item)) for item in value]
                        parts.append(f'<li>{html.escape(key)}: {", ".join(formatted_values)}</li>')
                    else:
                        parts.append(f'<li>{html.escape(key)}: {html.escape(str(value))}</li>')
                parts.append('</ul>')
            
            parts.append('</div>')
            parts.append('</div>')
        
        return parts
    
    def _format_metadata(self, metadata: Dict[str, Any]) -> str:
        """Format metadata as a collapsible JSON view."""
        # Convert to JSON with pretty printing
        json_str = json.dumps(metadata, indent=2, default=str)
        
        # Escape for HTML
        escaped_json = html.escape(json_str)
        
        # Return as pre block
        return f'<pre>{escaped_json}</pre>'
    
    @classmethod
    def get_format_name(cls) -> str:
        """Get the name of the output format."""
        return "html"