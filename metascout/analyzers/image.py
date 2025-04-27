"""
Image metadata analysis for privacy and security concerns
"""

from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class ImageAnalyzer(BaseAnalyzer):
    """Analyzer for image metadata."""
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """Check if this analyzer can handle the specified file type."""
        return file_type.lower() == 'image'
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze image metadata for privacy and security concerns."""
        findings = []
        
        # Check for GPS information (privacy concern)
        if 'exif' in metadata:
            gps_keys = ('GPSInfo', 'GPS')
            for key in gps_keys:
                if key in metadata['exif']:
                    findings.append(MetadataFinding(
                        type="privacy",
                        description="GPS location data found in EXIF metadata",
                        severity="high",
                        data={"source": "EXIF", "field": key}
                    ))
        
        # Check for camera/device information (potential fingerprinting)
        device_info = {}
        for section in ('exif', 'basic'):
            if section in metadata:
                for key in ('Make', 'Model', 'Software', 'ProcessingSoftware'):
                    if key in metadata[section]:
                        device_info[key] = metadata[section][key]
        
        if device_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Device/software information found",
                severity="medium",
                data={"device_info": device_info}
            ))
        
        # Check for creation/modification dates
        dates = {}
        date_keys = ('DateTime', 'DateTimeOriginal', 'DateTimeDigitized', 'ModifyDate')
        for section in ('exif', 'iptc'):
            if section in metadata:
                for key in date_keys:
                    if key in metadata[section]:
                        dates[key] = metadata[section][key]
        
        if dates:
            findings.append(MetadataFinding(
                type="information",
                description="Image creation/modification timestamps found",
                severity="low",
                data={"dates": dates}
            ))
        
        # Check for IPTC contact info (privacy)
        contact_info = {}
        if 'iptc' in metadata:
            contact_fields = ('By-line', 'Credit', 'Source', 'Writer-Editor', 'Contact')
            for field in contact_fields:
                if field in metadata['iptc']:
                    contact_info[field] = metadata['iptc'][field]
        
        if contact_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Creator/contact information found in IPTC data",
                severity="medium",
                data={"contact_info": contact_info}
            ))
        
        # Check for editing software (authenticity)
        editing_software = None
        for section in ('exif', 'xmp'):
            if section in metadata:
                for key in ('Software', 'ProcessingSoftware', 'CreatorTool'):
                    if key in metadata[section]:
                        editing_software = metadata[section][key]
                        break
        
        if editing_software and any(sw.lower() in editing_software.lower() for sw in ('photoshop', 'gimp', 'lightroom', 'affinity')):
            findings.append(MetadataFinding(
                type="authenticity",
                description=f"Image edited with {editing_software}",
                severity="medium",
                data={"software": editing_software}
            ))
        
        # Check for XMP history (authenticity)
        if 'xmp' in metadata and 'raw' in metadata['xmp']:
            if 'xmpMM:History' in metadata['xmp']['raw']:
                findings.append(MetadataFinding(
                    type="authenticity",
                    description="XMP edit history found",
                    severity="medium",
                    data={"edit_history": "XMP history entries present"}
                ))
        
        # Look for embedded color profiles (potential fingerprinting)
        if 'basic' in metadata and 'color_profile' in metadata['basic'] and metadata['basic']['color_profile'] != 'None':
            findings.append(MetadataFinding(
                type="information",
                description="Embedded color profile found",
                severity="low",
                data={"color_profile": "Present"}
            ))
        
        return findings