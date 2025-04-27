"""
Base reporter interface for MetaScout
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, IO, Union

from ..core.models import FileMetadata


class BaseReporter(ABC):
    """
    Abstract base class for all reporters.
    
    Reporters are responsible for formatting and outputting analysis results
    in various formats (text, HTML, JSON, CSV, etc.).
    """
    
    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize reporter with options.
        
        Args:
            options: Dictionary of reporter options
        """
        self.options = options or {}
    
    @abstractmethod
    def generate_report(self, results: List[FileMetadata]) -> str:
        """
        Generate a report from analysis results.
        
        Args:
            results: List of FileMetadata objects
            
        Returns:
            Formatted report as a string
        """
        pass
    
    def write_report(self, results: List[FileMetadata], output: Optional[Union[str, IO]] = None) -> None:
        """
        Write report to file or output stream.
        
        Args:
            results: List of FileMetadata objects
            output: Optional file path or file-like object to write to (stdout if None)
        """
        report = self.generate_report(results)
        
        if output is None:
            # Write to stdout
            print(report)
        elif isinstance(output, str):
            # Write to file path
            with open(output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report written to {output}")
        else:
            # Write to file-like object
            output.write(report)
    
    @classmethod
    @abstractmethod
    def get_format_name(cls) -> str:
        """
        Get the name of the output format.
        
        Returns:
            Format name (e.g., 'text', 'html', 'json', 'csv')
        """
        pass
    
    def get_file_extension(self) -> str:
        """
        Get the recommended file extension for this report format.
        
        Returns:
            File extension including leading dot (e.g., '.txt', '.html', '.json', '.csv')
        """
        format_name = self.get_format_name().lower()
        
        # Map format names to extensions
        extension_map = {
            'text': '.txt',
            'html': '.html',
            'json': '.json',
            'csv': '.csv',
            'xml': '.xml',
            'markdown': '.md'
        }
        
        return extension_map.get(format_name, f'.{format_name}')


class FormattedOutput:
    """
    Helper class for generating formatted output in different modes.
    
    This class provides methods for various output formatting tasks:
    - Indentation
    - Table formatting
    - Color coding
    - Section headers
    """
    
    def __init__(self, colorize: bool = True, indent_size: int = 2):
        """
        Initialize formatted output options.
        
        Args:
            colorize: Whether to use ANSI color codes
            indent_size: Number of spaces for each indentation level
        """
        self.colorize = colorize
        self.indent_size = indent_size
        
        # ANSI color codes
        self.colors = {
            'reset': '\033[0m',
            'red': '\033[31m',
            'green': '\033[32m',
            'yellow': '\033[33m',
            'blue': '\033[34m',
            'magenta': '\033[35m',
            'cyan': '\033[36m',
            'white': '\033[37m',
            'bright_red': '\033[91m',
            'bright_green': '\033[92m',
            'bright_yellow': '\033[93m',
            'bright_blue': '\033[94m',
            'bright_magenta': '\033[95m',
            'bright_cyan': '\033[96m',
            'bright_white': '\033[97m',
            'bold': '\033[1m',
            'underline': '\033[4m'
        }
    
    def indent(self, text: str, level: int = 1) -> str:
        """
        Indent text by a specified number of levels.
        
        Args:
            text: Text to indent
            level: Number of indentation levels
            
        Returns:
            Indented text
        """
        indent_str = ' ' * (self.indent_size * level)
        return indent_str + text.replace('\n', f'\n{indent_str}')
    
    def apply_color(self, text: str, color: str) -> str:
        """
        Apply ANSI color code to text.
        
        Args:
            text: Text to colorize
            color: Color name from self.colors
            
        Returns:
            Colorized text (if colorize is enabled)
        """
        if not self.colorize or color not in self.colors:
            return text
        
        return f"{self.colors[color]}{text}{self.colors['reset']}"
    
    def header(self, text: str, level: int = 1) -> str:
        """
        Format text as a header.
        
        Args:
            text: Header text
            level: Header level (1-3)
            
        Returns:
            Formatted header
        """
        if level == 1:
            separator = '=' * len(text)
            if self.colorize:
                return f"{self.colors['bold']}{text}{self.colors['reset']}\n{separator}"
            return f"{text}\n{separator}"
        elif level == 2:
            separator = '-' * len(text)
            if self.colorize:
                return f"{self.colors['bold']}{text}{self.colors['reset']}\n{separator}"
            return f"{text}\n{separator}"
        else:
            if self.colorize:
                return f"{self.colors['bold']}{text}{self.colors['reset']}"
            return text
    
    def severity_color(self, severity: str) -> str:
        """
        Get color for severity level.
        
        Args:
            severity: Severity string (high, medium, low)
            
        Returns:
            Color name
        """
        severity = severity.lower()
        if severity == 'high':
            return 'red'
        elif severity == 'medium':
            return 'yellow'
        elif severity == 'low':
            return 'green'
        else:
            return 'reset'