"""
Video metadata analysis
"""

from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class VideoAnalyzer(BaseAnalyzer):
    """Analyzer for video metadata."""
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """Check if this analyzer can handle the specified file type."""
        return file_type.lower() == 'video'
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze video metadata for privacy and security concerns."""
        findings = []
        
        # Check for unusual or high-quality encoding (potential sensitive content)
        if 'video_properties' in metadata:
            props = metadata['video_properties']
            
            # Check for high resolution
            if 'width' in props and 'height' in props:
                if props['width'] >= 3840 and props['height'] >= 2160:
                    findings.append(MetadataFinding(
                        type="information",
                        description="4K or higher resolution video",
                        severity="low",
                        data={"resolution": f"{props['width']}x{props['height']}"}
                    ))
                elif props['width'] >= 1920 and props['height'] >= 1080:
                    findings.append(MetadataFinding(
                        type="information",
                        description="Full HD resolution video",
                        severity="low",
                        data={"resolution": f"{props['width']}x{props['height']}"}
                    ))
            
            # Check for unusual aspect ratios
            if 'width' in props and 'height' in props and props['width'] > 0 and props['height'] > 0:
                aspect_ratio = props['width'] / props['height']
                if aspect_ratio < 0.5 or aspect_ratio > 3.0:
                    findings.append(MetadataFinding(
                        type="information",
                        description=f"Unusual aspect ratio: {aspect_ratio:.2f}",
                        severity="low",
                        data={"aspect_ratio": aspect_ratio}
                    ))
            
            # Check for high bitrate
            if 'bit_rate' in props and props['bit_rate'] > 15000000:  # > 15 Mbps
                findings.append(MetadataFinding(
                    type="information",
                    description="High bitrate video",
                    severity="low",
                    data={"bitrate": f"{props['bit_rate'] // 1000000} Mbps"}
                ))
            
            # Check for creation date/time
            for key in props:
                if any(date_key in key.lower() for date_key in ['date', 'time', 'created']):
                    findings.append(MetadataFinding(
                        type="information",
                        description="Video creation timestamp found",
                        severity="low",
                        data={"timestamp": {key: props[key]}}
                    ))
        
        # Check for geolocation data
        geo_info = {}
        if 'video_properties' in metadata:
            for key, value in metadata['video_properties'].items():
                if any(geo_key in key.lower() for geo_key in ['geo', 'gps', 'location', 'latitude', 'longitude']):
                    geo_info[key] = value
        
        if geo_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Geolocation information found in video metadata",
                severity="high",
                data={"geo_info": geo_info}
            ))
        
        # Check for device information
        device_info = {}
        if 'video_properties' in metadata:
            for key, value in metadata['video_properties'].items():
                if any(dev_key in key.lower() for dev_key in ['device', 'camera', 'make', 'model']):
                    device_info[key] = value
        
        if device_info:
            findings.append(MetadataFinding(
                type="privacy",
                description="Recording device information found",
                severity="medium",
                data={"device_info": device_info}
            ))
        
        # Check for encoding/authoring software
        software_info = {}
        if 'video_properties' in metadata:
            for key, value in metadata['video_properties'].items():
                if any(sw_key in key.lower() for sw_key in ['software', 'encoder', 'handler', 'application']):
                    software_info[key] = value
        
        if software_info:
            findings.append(MetadataFinding(
                type="information",
                description="Video editing/encoding software information found",
                severity="low",
                data={"software_info": software_info}
            ))
        
        # Check for multiple audio streams (potential hidden content)
        if 'audio_streams' in metadata and len(metadata['audio_streams']) > 1:
            findings.append(MetadataFinding(
                type="information",
                description=f"Multiple audio streams: {len(metadata['audio_streams'])}",
                severity="medium",
                data={"audio_streams_count": len(metadata['audio_streams'])}
            ))
            
            # Check for different languages in audio streams
            languages = set()
            for stream in metadata['audio_streams']:
                if 'tags' in stream and 'language' in stream['tags']:
                    languages.add(stream['tags']['language'])
                elif 'language' in stream:
                    languages.add(stream['language'])
            
            if len(languages) > 1:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Multiple languages in audio streams: {', '.join(languages)}",
                    severity="low",
                    data={"languages": list(languages)}
                ))
        
        # Check for subtitle streams (potential sensitive content)
        if 'subtitle_streams' in metadata and metadata['subtitle_streams']:
            subtitles = [
                f"{s.get('language', 'unknown')}: {s.get('codec', 'unknown')}" 
                for s in metadata['subtitle_streams']
            ]
            findings.append(MetadataFinding(
                type="information",
                description=f"Subtitle streams found: {len(metadata['subtitle_streams'])}",
                severity="low",
                data={"subtitles": subtitles}
            ))
        
        # Check for unusual codecs
        if 'video_properties' in metadata and 'codec' in metadata['video_properties']:
            codec = metadata['video_properties']['codec'].lower()
            common_codecs = ['h264', 'h.264', 'avc', 'h265', 'h.265', 'hevc', 'vp9', 'av1', 'mpeg4', 'mpeg2']
            
            if not any(common in codec for common in common_codecs):
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Unusual video codec: {metadata['video_properties']['codec']}",
                    severity="low",
                    data={"codec": metadata['video_properties']['codec']}
                ))
        
        # Check for unusual or very long duration
        if 'video_properties' in metadata and 'duration' in metadata['video_properties']:
            duration = float(metadata['video_properties']['duration'])
            if duration > 7200:  # Longer than 2 hours
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Long video duration: {duration / 60:.1f} minutes",
                    severity="low",
                    data={"duration_seconds": duration}
                ))
        
        # Check for chapters or markers
        if 'chapters' in metadata and metadata['chapters']:
            findings.append(MetadataFinding(
                type="information",
                description=f"Video contains {len(metadata['chapters'])} chapters/markers",
                severity="low",
                data={"chapters_count": len(metadata['chapters'])}
            ))
        
        # Check for metadata that might indicate stock footage or licensed content
        if 'video_properties' in metadata:
            for key, value in metadata['video_properties'].items():
                if any(term in key.lower() for term in ['copyright', 'license', 'rights']):
                    findings.append(MetadataFinding(
                        type="information",
                        description="Copyright/license information found",
                        severity="low",
                        data={key: value}
                    ))
        
        return findings