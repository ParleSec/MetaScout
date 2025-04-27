"""
Base extractor for metadata extraction
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class BaseExtractor(ABC):
    """
    Abstract base class for metadata extractors.
    All format-specific extractors should inherit from this class.
    """
    
    @abstractmethod
    def extract(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from the specified file.
        
        Args:
            file_path: Path to the file to extract metadata from
            
        Returns:
            Dictionary containing extracted metadata
        """
        pass
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """
        Check if this extractor can handle the specified file.
        
        Args:
            file_path: Path to the file to check
            mime_type: Optional MIME type if already known
            
        Returns:
            True if this extractor can handle the file, False otherwise
        """
        return False