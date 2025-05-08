"""
Operations package for MetaScout

This package contains the high-level operations that can be performed
on files, such as analysis, batch processing, comparison, and redaction.
"""

from .analyze import write_report, format_findings, generate_html_report, generate_text_report
from .batch import process_directory, filter_files
from .compare import compare_metadata, generate_comparison_html
from .redact import redact_metadata

__all__ = [
    'write_report',
    'format_findings',
    'generate_html_report',
    'generate_text_report',
    'process_directory',
    'filter_files',
    'compare_metadata',
    'generate_comparison_html',
    'redact_metadata'
]