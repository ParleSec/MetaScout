"""
Metadata extractors package

This package contains extractors for different file types.
"""

import os
from typing import Optional, Type, List

from .base import BaseExtractor
from .image import ImageExtractor
from .document import DocumentExtractor
from .audio import AudioExtractor
from .video import VideoExtractor
from .executable import ExecutableExtractor
from .generic import GenericExtractor

# Register all available extractors
EXTRACTORS = [
    ImageExtractor,
    DocumentExtractor,
    AudioExtractor,
    VideoExtractor,
    ExecutableExtractor,
    GenericExtractor,
]

def get_extractor_for_file(file_path: str, mime_type: Optional[str] = None) -> Optional[BaseExtractor]:
    """
    Get appropriate extractor for the specified file.
    
    Args:
        file_path: Path to file
        mime_type: Optional MIME type if already known
        
    Returns:
        Instance of BaseExtractor subclass or None if no extractor is available
    """
    for extractor_class in EXTRACTORS:
        if extractor_class.can_handle(file_path, mime_type):
            return extractor_class()
    
    return None

def register_extractor(extractor_class: Type[BaseExtractor]) -> None:
    """
    Register a new extractor.
    
    Args:
        extractor_class: Extractor class to register
    """
    if extractor_class not in EXTRACTORS:
        EXTRACTORS.append(extractor_class)

__all__ = ['BaseExtractor', 'get_extractor_for_file', 'register_extractor']