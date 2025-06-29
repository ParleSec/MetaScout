"""
Custom exceptions for MetaScout with user-friendly error messages
"""

from typing import Optional, List, Dict, Any


class MetaScoutError(Exception):
    """Base exception class for MetaScout with user-friendly messaging."""
    
    def __init__(self, message: str, details: Optional[str] = None, suggestions: Optional[List[str]] = None):
        """
        Initialize MetaScout exception.
        
        Args:
            message: Main error message (user-friendly)
            details: Technical details for debugging
            suggestions: List of suggested solutions
        """
        self.message = message
        self.details = details
        self.suggestions = suggestions or []
        super().__init__(self.get_full_message())
    
    def get_full_message(self) -> str:
        """Get the complete error message with suggestions."""
        msg = self.message
        if self.details:
            msg += f"\n\nTechnical details: {self.details}"
        if self.suggestions:
            msg += f"\n\nSuggestions:\n" + "\n".join(f"  • {s}" for s in self.suggestions)
        return msg
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "suggestions": self.suggestions
        }


class FileNotFoundError(MetaScoutError):
    """Raised when a file cannot be found or accessed."""
    
    def __init__(self, file_path: str, original_error: Optional[Exception] = None):
        message = f"Could not find or access file: {file_path}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Check that the file path is correct",
            "Verify that the file exists and is readable",
            "Ensure you have permission to access the file",
            "Try using an absolute path instead of a relative path"
        ]
        super().__init__(message, details, suggestions)
        self.file_path = file_path


class UnsupportedFileTypeError(MetaScoutError):
    """Raised when trying to process an unsupported file type."""
    
    def __init__(self, file_path: str, file_type: str, supported_types: Optional[List[str]] = None):
        message = f"Unsupported file type '{file_type}' for file: {file_path}"
        suggestions = ["Use a supported file format"]
        if supported_types:
            suggestions.append(f"Supported types: {', '.join(supported_types)}")
        suggestions.extend([
            "Check if the file extension is correct",
            "Try converting the file to a supported format"
        ])
        super().__init__(message, None, suggestions)
        self.file_path = file_path
        self.file_type = file_type


class CorruptedFileError(MetaScoutError):
    """Raised when a file appears to be corrupted or invalid."""
    
    def __init__(self, file_path: str, original_error: Optional[Exception] = None):
        message = f"File appears to be corrupted or invalid: {file_path}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Verify that the file is not corrupted",
            "Try opening the file with its native application",
            "Check if the file was completely downloaded or copied",
            "Ensure the file extension matches the actual file format"
        ]
        super().__init__(message, details, suggestions)
        self.file_path = file_path


class PermissionError(MetaScoutError):
    """Raised when there are insufficient permissions to access a file."""
    
    def __init__(self, file_path: str, operation: str = "access", original_error: Optional[Exception] = None):
        message = f"Permission denied: cannot {operation} file {file_path}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Check file permissions and ownership",
            "Run MetaScout with appropriate privileges",
            "Ensure the file is not locked by another application",
            "Try copying the file to a location you have write access to"
        ]
        super().__init__(message, details, suggestions)
        self.file_path = file_path
        self.operation = operation


class ExtractionError(MetaScoutError):
    """Raised when metadata extraction fails."""
    
    def __init__(self, file_path: str, extractor_name: str, original_error: Optional[Exception] = None):
        message = f"Failed to extract metadata from {file_path} using {extractor_name}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Try processing the file with a different tool first",
            "Check if the file format is supported",
            "Verify that the file is not corrupted",
            "Consider skipping metadata extraction with --skip-extraction"
        ]
        super().__init__(message, details, suggestions)
        self.file_path = file_path
        self.extractor_name = extractor_name


class AnalysisError(MetaScoutError):
    """Raised when metadata analysis fails."""
    
    def __init__(self, file_path: str, analyzer_name: str, original_error: Optional[Exception] = None):
        message = f"Analysis failed for {file_path} using {analyzer_name}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Try running without analysis using --skip-analysis",
            "Check if the metadata format is supported",
            "Report this issue if it persists with multiple files"
        ]
        super().__init__(message, details, suggestions)
        self.file_path = file_path
        self.analyzer_name = analyzer_name


class DependencyError(MetaScoutError):
    """Raised when a required dependency is missing."""
    
    def __init__(self, dependency_name: str, feature: str, install_command: Optional[str] = None):
        message = f"Missing dependency '{dependency_name}' required for {feature}"
        suggestions = [
            f"Install the required dependency: {install_command}" if install_command else f"Install {dependency_name}",
            "Check the installation documentation for requirements",
            "Consider using a different feature that doesn't require this dependency"
        ]
        super().__init__(message, None, suggestions)
        self.dependency_name = dependency_name
        self.feature = feature


class ConfigurationError(MetaScoutError):
    """Raised when there's a configuration issue."""
    
    def __init__(self, setting: str, value: Any, expected: str):
        message = f"Invalid configuration for '{setting}': got '{value}', expected {expected}"
        suggestions = [
            f"Check the value for '{setting}' in your configuration",
            "Refer to the documentation for valid configuration options",
            "Reset to default configuration if issues persist"
        ]
        super().__init__(message, None, suggestions)
        self.setting = setting
        self.value = value


class OutputError(MetaScoutError):
    """Raised when output generation fails."""
    
    def __init__(self, output_path: str, format_type: str, original_error: Optional[Exception] = None):
        message = f"Failed to generate {format_type} output to {output_path}"
        details = str(original_error) if original_error else None
        suggestions = [
            "Check that you have write permissions to the output directory",
            "Ensure there's enough disk space available",
            "Try a different output format or location",
            "Verify that the output path is valid"
        ]
        super().__init__(message, details, suggestions)
        self.output_path = output_path
        self.format_type = format_type


class ValidationError(MetaScoutError):
    """Raised when input validation fails."""
    
    def __init__(self, parameter: str, value: Any, constraint: str):
        message = f"Invalid value for '{parameter}': {value} does not meet constraint: {constraint}"
        suggestions = [
            f"Check the value provided for '{parameter}'",
            "Refer to the help documentation for valid values",
            "Use the --help option to see parameter requirements"
        ]
        super().__init__(message, None, suggestions)
        self.parameter = parameter
        self.value = value


def handle_exception_gracefully(func):
    """
    Decorator to handle exceptions gracefully and convert them to user-friendly messages.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except MetaScoutError:
            # Re-raise our custom exceptions as-is
            raise
        except FileNotFoundError as e:
            # Convert standard FileNotFoundError to our custom one
            file_path = args[0] if args else "unknown"
            raise FileNotFoundError(file_path, e)
        except PermissionError as e:
            # Convert standard PermissionError to our custom one
            file_path = args[0] if args else "unknown"
            raise PermissionError(file_path, "access", e)
        except Exception as e:
            # Convert any other exception to a generic MetaScoutError
            raise MetaScoutError(
                f"An unexpected error occurred in {func.__name__}",
                str(e),
                [
                    "Try running the operation again",
                    "Check the input parameters",
                    "Report this issue if it persists"
                ]
            )
    return wrapper


def format_error_for_cli(error: Exception, verbose: bool = False) -> str:
    """
    Format an error for command-line display.
    
    Args:
        error: The exception to format
        verbose: Whether to include technical details
        
    Returns:
        Formatted error message
    """
    if isinstance(error, MetaScoutError):
        msg = f"❌ {error.message}"
        
        if verbose and error.details:
            msg += f"\n\n🔍 Technical details:\n{error.details}"
        
        if error.suggestions:
            msg += f"\n\n💡 Suggestions:"
            for suggestion in error.suggestions:
                msg += f"\n  • {suggestion}"
        
        return msg
    else:
        # Handle non-MetaScout exceptions
        msg = f"❌ An unexpected error occurred: {str(error)}"
        if verbose:
            import traceback
            msg += f"\n\n🔍 Technical details:\n{traceback.format_exc()}"
        msg += f"\n\n💡 Suggestions:\n  • Try running the command again\n  • Check your input parameters\n  • Use --verbose for more details"
        return msg


def format_error_for_json(error: Exception) -> Dict[str, Any]:
    """
    Format an error for JSON output.
    
    Args:
        error: The exception to format
        
    Returns:
        Dictionary representation of the error
    """
    if isinstance(error, MetaScoutError):
        return error.to_dict()
    else:
        return {
            "error_type": "UnexpectedError",
            "message": str(error),
            "details": type(error).__name__,
            "suggestions": [
                "Try running the operation again",
                "Check the input parameters",
                "Report this issue if it persists"
            ]
        } 