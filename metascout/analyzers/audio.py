"""
Audio metadata analysis
"""

from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class AudioAnalyzer(BaseAnalyzer):
    """Analyzer for audio metadata."""
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """Check if this analyzer can handle the specified file type."""
        return file_type.lower() == 'audio'
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze audio metadata for privacy concerns."""
        findings = []
        
        # Check for personal information in tags
        personal_info = {}
        if 'tags' in metadata:
            personal_fields = ['artist', 'composer', 'albumartist', 'author', 'encoder', 'performer']
            for field in personal_fields:
                for key in metadata['tags']:
                    if field.lower() in key.lower() and metadata['tags'][key]:
                        personal_info[key] = metadata['tags'][key]
        
        if personal_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Personal information found in audio tags",
                severity="medium",
                data={"personal_info": personal_info}
            ))
        
        # Check for geolocation data
        geo_info = {}
        if 'tags' in metadata:
            geo_fields = ['geotag', 'location', 'latitude', 'longitude', 'geo']
            for key in metadata['tags']:
                if any(field in key.lower() for field in geo_fields):
                    geo_info[key] = metadata['tags'][key]
        
        if geo_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Geolocation information found in audio tags",
                severity="high",
                data={"geo_info": geo_info}
            ))
        
        # Check for recording device/software info
        device_info = {}
        if 'tags' in metadata:
            device_fields = ['encoder', 'encodedby', 'encoding', 'source', 'device', 'tool']
            for key in metadata['tags']:
                if any(field in key.lower() for field in device_fields):
                    device_info[key] = metadata['tags'][key]
        
        if device_info:
            findings.append(MetadataFinding(
                type="information",
                description="Recording device/software information found",
                severity="low",
                data={"device_info": device_info}
            ))
        
        # Check for unusual audio properties
        if 'audio_properties' in metadata:
            props = metadata['audio_properties']
            
            # Check for unusual channel configuration
            if 'channels' in props and props['channels'] > 2:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Unusual audio channel configuration: {props['channels']} channels",
                    severity="low",
                    data={"channels": props['channels']}
                ))
            
            # Check for high-quality audio (might be professional/original recording)
            if 'sample_rate' in props and props['sample_rate'] > 48000:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"High sample rate audio: {props['sample_rate']} Hz",
                    severity="low",
                    data={"sample_rate": props['sample_rate']}
                ))
            
            if 'bitrate' in props and props['bitrate'] > 320000:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"High bitrate audio: {props['bitrate'] // 1000} kbps",
                    severity="low",
                    data={"bitrate": props['bitrate']}
                ))
        
        # Check for embedded album art
        if 'pictures' in metadata and metadata['pictures']:
            findings.append(MetadataFinding(
                type="information",
                description=f"Audio file contains embedded pictures/album art",
                severity="low",
                data={"picture_count": len(metadata['pictures'])}
            ))
        
        # Check for copyright information
        copyright_info = {}
        if 'tags' in metadata:
            copyright_fields = ['copyright', 'rights', 'license']
            for key in metadata['tags']:
                if any(field in key.lower() for field in copyright_fields):
                    copyright_info[key] = metadata['tags'][key]
        
        if copyright_info:
            findings.append(MetadataFinding(
                type="information",
                description="Copyright information found",
                severity="low",
                data={"copyright_info": copyright_info}
            ))
        
        # Check for commercial identifiers
        commercial_info = {}
        if 'tags' in metadata:
            id_fields = ['isrc', 'barcode', 'catalog', 'upc', 'isbn']
            for key in metadata['tags']:
                if any(field in key.lower() for field in id_fields):
                    commercial_info[key] = metadata['tags'][key]
        
        if commercial_info:
            findings.append(MetadataFinding(
                type="information",
                description="Commercial identifiers found",
                severity="low",
                data={"commercial_info": commercial_info}
            ))
        
        # Check for lyrics
        if 'tags' in metadata:
            has_lyrics = False
            for key in metadata['tags']:
                if 'lyric' in key.lower() or 'text' in key.lower():
                    has_lyrics = True
                    break
            
            if has_lyrics:
                findings.append(MetadataFinding(
                    type="information",
                    description="Audio file contains embedded lyrics",
                    severity="low",
                    data={"lyrics_present": True}
                ))
        
        # Check for unusual or very long duration
        if 'audio_properties' in metadata and 'duration' in metadata['audio_properties']:
            duration = metadata['audio_properties']['duration']
            if duration > 7200:  # Longer than 2 hours
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Unusually long audio duration: {duration // 60:.1f} minutes",
                    severity="low",
                    data={"duration_seconds": duration}
                ))
        
        return findings