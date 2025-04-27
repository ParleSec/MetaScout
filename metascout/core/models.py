"""
Core data models for MetaScout
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any

@dataclass
class MetadataFinding:
    """Represents a finding or insight from metadata analysis."""
    type: str  # Type of finding (privacy, security, inconsistency, etc.)
    description: str  # Human-readable description
    severity: str  # high, medium, low
    data: Dict = field(default_factory=dict)  # Additional data related to the finding

@dataclass
class FileMetadata:
    """Container for file metadata and analysis results."""
    file_path: str
    file_type: str
    file_size: int
    mime_type: str
    hashes: Dict[str, str] = field(default_factory=dict)
    creation_time: Optional[str] = None
    modification_time: Optional[str] = None
    access_time: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    findings: List[MetadataFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return asdict(self)