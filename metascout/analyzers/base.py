"""
Base analyzer for metadata analysis
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any

from ..core.models import MetadataFinding


class BaseAnalyzer(ABC):
    """
    Abstract base class for metadata analyzers.
    All format-specific analyzers should inherit from this class.
    """
    
    @abstractmethod
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """
        Analyze metadata and return findings.
        
        Args:
            metadata: Dictionary containing metadata to analyze
            
        Returns:
            List of MetadataFinding objects
        """
        pass
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """
        Check if this analyzer can handle the specified file type.
        
        Args:
            file_type: Type of file to check
            
        Returns:
            True if this analyzer can handle the file type, False otherwise
        """
        return False