"""
Metadata analyzers package

This package contains analyzers for different file types.
"""

from typing import List, Type

from .base import BaseAnalyzer
from .image import ImageAnalyzer
# Import other analyzers as they are implemented
# from .document import DocumentAnalyzer
# from .audio import AudioAnalyzer
# from .video import VideoAnalyzer
# from .executable import ExecutableAnalyzer
# from .generic import GenericAnalyzer
# from .pattern import PatternAnalyzer

# Register all available analyzers
ANALYZERS = [
    ImageAnalyzer,
    # Add other analyzers as they are implemented
    # DocumentAnalyzer,
    # AudioAnalyzer,
    # VideoAnalyzer,
    # ExecutableAnalyzer,
    # GenericAnalyzer,
    # PatternAnalyzer,
]

def get_analyzers_for_file_type(file_type: str) -> List[BaseAnalyzer]:
    """
    Get all appropriate analyzers for the specified file type.
    
    Args:
        file_type: Type of file
        
    Returns:
        List of BaseAnalyzer instances
    """
    analyzers = []
    
    for analyzer_class in ANALYZERS:
        if analyzer_class.can_handle(file_type):
            analyzers.append(analyzer_class())
    
    return analyzers

def register_analyzer(analyzer_class: Type[BaseAnalyzer]) -> None:
    """
    Register a new analyzer.
    
    Args:
        analyzer_class: Analyzer class to register
    """
    if analyzer_class not in ANALYZERS:
        ANALYZERS.append(analyzer_class)

__all__ = ['BaseAnalyzer', 'get_analyzers_for_file_type', 'register_analyzer']