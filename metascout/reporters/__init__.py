"""
Reporters package for MetaScout

This package contains report generators for different output formats.
"""

from .base import BaseReporter
from .text import TextReporter
from .html import HtmlReporter
from .json import JsonReporter
from .csv import CsvReporter

# Registry of available reporters
REPORTERS = {
    'text': TextReporter,
    'html': HtmlReporter,
    'json': JsonReporter,
    'csv': CsvReporter
}

def get_reporter(format_type: str):
    """
    Get a reporter instance for the specified format type.
    
    Args:
        format_type: Report format type (text, html, json, csv)
        
    Returns:
        Reporter instance or None if format is not supported
    """
    reporter_class = REPORTERS.get(format_type.lower())
    if reporter_class:
        return reporter_class()
    return None

def register_reporter(name: str, reporter_class):
    """
    Register a new reporter class.
    
    Args:
        name: Name of the format (e.g., 'xml')
        reporter_class: Reporter class to register
        
    Returns:
        None
    """
    REPORTERS[name.lower()] = reporter_class

__all__ = [
    'BaseReporter', 
    'TextReporter', 
    'HtmlReporter', 
    'JsonReporter', 
    'CsvReporter',
    'get_reporter', 
    'register_reporter', 
    'REPORTERS'
]