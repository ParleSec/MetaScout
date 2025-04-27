"""
Document metadata analysis
"""

from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class DocumentAnalyzer(BaseAnalyzer):
    """Analyzer for document metadata."""
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """Check if this analyzer can handle the specified file type."""
        return file_type.lower() == 'document'
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze document metadata for privacy and security concerns."""
        findings = []
        
        # Check for author information
        author_fields = {}
        
        if 'document_info' in metadata:
            for key in ('Author', 'Creator', 'Producer', 'LastModifiedBy'):
                if key in metadata['document_info']:
                    author_fields[key] = metadata['document_info'][key]
        
        if 'document_properties' in metadata:
            for key in ('author', 'creator', 'last_modified_by'):
                if key in metadata['document_properties']:
                    author_fields[key] = metadata['document_properties'][key]
        
        if author_fields:
            findings.append(MetadataFinding(
                type="privacy",
                description="Author information found",
                severity="medium",
                data={"author_fields": author_fields}
            ))
        
        # Check for creation software
        creation_software = None
        for section in ('document_info', 'document_properties'):
            if section in metadata:
                for key in ('Creator', 'Producer', 'creator', 'producer', 'application'):
                    if key in metadata[section] and metadata[section][key]:
                        creation_software = metadata[section][key]
                        break
        
        if creation_software:
            findings.append(MetadataFinding(
                type="information",
                description=f"Document created with {creation_software}",
                severity="low",
                data={"software": creation_software}
            ))
        
        # Check for security features
        if 'security' in metadata:
            if metadata['security'].get('encrypted', False):
                findings.append(MetadataFinding(
                    type="security",
                    description="Document is encrypted/password-protected",
                    severity="medium",
                    data={"encryption": True}
                ))
            
            permissions = metadata['security'].get('permissions', {})
            restricted_permissions = {k: v for k, v in permissions.items() if not v}
            if restricted_permissions:
                findings.append(MetadataFinding(
                    type="security",
                    description="Document has restricted permissions",
                    severity="low",
                    data={"restricted_permissions": list(restricted_permissions.keys())}
                ))
        
        # Check for macros in Office documents
        if 'security' in metadata and 'macros_present' in metadata['security'] and metadata['security']['macros_present']:
            findings.append(MetadataFinding(
                type="security",
                description="Document contains macros",
                severity="high",
                data={"macros": True}
            ))
        
        # Check for date inconsistencies
        dates = {}
        for section in ('document_info', 'document_properties'):
            if section in metadata:
                for key in ('CreationDate', 'ModDate', 'created', 'modified'):
                    if key in metadata[section] and metadata[section][key]:
                        dates[key] = metadata[section][key]
        
        if len(dates) > 1:
            findings.append(MetadataFinding(
                type="information",
                description="Document timestamp information",
                severity="low",
                data={"dates": dates}
            ))
        
        # PDF-specific analysis
        if 'page_info' in metadata and 'pages' in metadata['page_info']:
            # Check for hidden content (optional content groups, etc.)
            for page in metadata['page_info']['pages']:
                if 'optional_content' in page and page['optional_content']:
                    findings.append(MetadataFinding(
                        type="security",
                        description="Document contains optional/hidden content",
                        severity="medium",
                        data={"page": page.get('index', 'unknown')}
                    ))
        
        # Check for document revisions/versions
        for section in ('document_info', 'document_properties'):
            if section in metadata:
                for key in ('version', 'revision', 'revisions'):
                    if key in metadata[section] and metadata[section][key]:
                        findings.append(MetadataFinding(
                            type="information",
                            description="Document contains revision information",
                            severity="low",
                            data={"revision_info": {key: metadata[section][key]}}
                        ))
        
        # Check for custom properties that might contain sensitive information
        if 'custom_properties' in metadata and metadata['custom_properties']:
            findings.append(MetadataFinding(
                type="privacy",
                description="Document contains custom properties",
                severity="low",
                data={"custom_properties": metadata['custom_properties']}
            ))
        
        # Check for embedded files
        if 'embedded_files' in metadata and metadata['embedded_files']:
            findings.append(MetadataFinding(
                type="security",
                description="Document contains embedded files",
                severity="high",
                data={"embedded_files_count": len(metadata['embedded_files'])}
            ))
        
        # Check for JavaScript (common in PDFs)
        if 'document_info' in metadata and 'has_javascript' in metadata['document_info'] and metadata['document_info']['has_javascript']:
            findings.append(MetadataFinding(
                type="security",
                description="Document contains JavaScript",
                severity="high",
                data={"javascript": True}
            ))
        
        return findings