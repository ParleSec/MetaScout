"""
Video metadata extraction
"""

import os
import json
import logging
import subprocess
from typing import Dict, Any, Optional

from ..config.constants import SUPPORTED_EXTENSIONS
from .base import BaseExtractor


class VideoExtractor(BaseExtractor):
    """Extract metadata from video files."""
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """Check if this extractor can handle the specified file."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS['video']:
            return True
        
        if mime_type and mime_type.startswith('video/'):
            return True
            
        return False
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from video files."""
        metadata = {
            'video_properties': {},
            'audio_streams': [],
            'subtitle_streams': []
        }
        
        try:
            # Try to use FFProbe first (requires ffmpeg installation)
            if self._has_ffprobe():
                metadata = self._extract_with_ffprobe(file_path)
            # Fall back to mediainfo if available
            elif self._has_mediainfo():
                metadata = self._extract_with_mediainfo(file_path)
            # If neither is available, use basic file information
            else:
                metadata['video_properties'] = {
                    'note': 'Limited metadata available without ffprobe or mediainfo',
                    'file_size': os.path.getsize(file_path)
                }
                
                # Try to get basic container info based on extension
                ext = os.path.splitext(file_path)[1].lower()
                if ext == '.mp4':
                    metadata['video_properties']['container'] = 'MP4'
                elif ext == '.avi':
                    metadata['video_properties']['container'] = 'AVI'
                elif ext == '.mkv':
                    metadata['video_properties']['container'] = 'Matroska'
                elif ext == '.mov':
                    metadata['video_properties']['container'] = 'QuickTime'
                elif ext == '.wmv':
                    metadata['video_properties']['container'] = 'Windows Media'
            
            return metadata
        except Exception as e:
            logging.error(f"Error extracting video metadata from {file_path}: {e}")
            return {'error': str(e)}
    
    def _has_ffprobe(self) -> bool:
        """Check if ffprobe is available."""
        try:
            subprocess.run(['ffprobe', '-version'], stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _has_mediainfo(self) -> bool:
        """Check if mediainfo is available."""
        try:
            subprocess.run(['mediainfo', '--version'], stdout=subprocess.PIPE, 
                          stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _extract_with_ffprobe(self, file_path: str) -> Dict[str, Any]:
        """Extract video metadata using ffprobe."""
        metadata = {
            'video_properties': {},
            'audio_streams': [],
            'subtitle_streams': []
        }
        
        # Get video stream info
        cmd = [
            'ffprobe', 
            '-v', 'quiet', 
            '-print_format', 'json', 
            '-show_format', 
            '-show_streams', 
            file_path
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output = json.loads(result.stdout)
        
        # Format information
        if 'format' in output:
            metadata['video_properties'] = {
                'format': output['format'].get('format_name', 'unknown'),
                'duration': float(output['format'].get('duration', 0)),
                'size': int(output['format'].get('size', 0)),
                'bit_rate': int(output['format'].get('bit_rate', 0)) if 'bit_rate' in output['format'] else 0
            }
            
            # Additional format tags
            if 'tags' in output['format']:
                for tag, value in output['format']['tags'].items():
                    metadata['video_properties'][tag.lower()] = value
        
        # Stream information
        if 'streams' in output:
            for stream in output['streams']:
                stream_type = stream.get('codec_type', 'unknown')
                
                if stream_type == 'video':
                    metadata['video_properties'].update({
                        'codec': stream.get('codec_name', 'unknown'),
                        'width': stream.get('width', 0),
                        'height': stream.get('height', 0),
                        'fps': self._calculate_fps(stream.get('r_frame_rate', '0/1')),
                        'pix_fmt': stream.get('pix_fmt', 'unknown')
                    })
                    
                    # Add stream tags if present
                    if 'tags' in stream:
                        for tag, value in stream['tags'].items():
                            metadata['video_properties'][f'video_{tag.lower()}'] = value
                
                elif stream_type == 'audio':
                    audio_stream = {
                        'codec': stream.get('codec_name', 'unknown'),
                        'sample_rate': stream.get('sample_rate', 'unknown'),
                        'channels': stream.get('channels', 0),
                        'bit_rate': stream.get('bit_rate', 'unknown') if 'bit_rate' in stream else 'unknown'
                    }
                    
                    # Add stream tags if present
                    if 'tags' in stream:
                        audio_stream['tags'] = {}
                        for tag, value in stream['tags'].items():
                            audio_stream['tags'][tag.lower()] = value
                    
                    metadata['audio_streams'].append(audio_stream)
                
                elif stream_type == 'subtitle':
                    subtitle_stream = {
                        'codec': stream.get('codec_name', 'unknown'),
                        'language': stream.get('tags', {}).get('language', 'unknown')
                    }
                    metadata['subtitle_streams'].append(subtitle_stream)
        
        return metadata
    
    def _extract_with_mediainfo(self, file_path: str) -> Dict[str, Any]:
        """Extract video metadata using mediainfo."""
        metadata = {
            'video_properties': {},
            'audio_streams': [],
            'subtitle_streams': []
        }
        
        cmd = ['mediainfo', '--Output=JSON', file_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        output = json.loads(result.stdout)
        
        if 'media' in output and 'track' in output['media']:
            for track in output['media']['track']:
                track_type = track.get('@type', '').lower()
                
                if track_type == 'general':
                    # General container information
                    metadata['video_properties'].update({
                        'format': track.get('Format', 'unknown'),
                        'duration': float(track.get('Duration', 0)) if 'Duration' in track else 0,
                        'size': int(track.get('FileSize', 0)) if 'FileSize' in track else 0,
                        'bit_rate': int(track.get('OverallBitRate', 0)) if 'OverallBitRate' in track else 0
                    })
                    
                    # Extract other general properties of interest
                    for key in ['Title', 'Movie', 'Encoded_Date', 'Tagged_Date', 'Encoded_Application']:
                        if key in track:
                            metadata['video_properties'][key.lower()] = track[key]
                
                elif track_type == 'video':
                    # Video stream properties
                    metadata['video_properties'].update({
                        'codec': track.get('Format', 'unknown'),
                        'width': int(track.get('Width', 0)) if 'Width' in track else 0,
                        'height': int(track.get('Height', 0)) if 'Height' in track else 0,
                        'fps': float(track.get('FrameRate', 0)) if 'FrameRate' in track else 0,
                        'bit_depth': track.get('BitDepth', 'unknown'),
                        'scan_type': track.get('ScanType', 'unknown')
                    })
                
                elif track_type == 'audio':
                    # Audio stream properties
                    audio_stream = {
                        'codec': track.get('Format', 'unknown'),
                        'sample_rate': int(track.get('SamplingRate', 0)) if 'SamplingRate' in track else 0,
                        'channels': int(track.get('Channels', 0)) if 'Channels' in track else 0,
                        'bit_rate': int(track.get('BitRate', 0)) if 'BitRate' in track else 0
                    }
                    
                    # Extract other audio properties of interest
                    for key in ['Language', 'Title', 'Default', 'Forced']:
                        if key in track:
                            audio_stream[key.lower()] = track[key]
                    
                    metadata['audio_streams'].append(audio_stream)
                
                elif track_type == 'text':
                    # Subtitle stream properties
                    subtitle_stream = {
                        'codec': track.get('Format', 'unknown'),
                        'language': track.get('Language', 'unknown'),
                        'title': track.get('Title', 'unknown')
                    }
                    metadata['subtitle_streams'].append(subtitle_stream)
        
        return metadata
    
    def _calculate_fps(self, fps_string: str) -> float:
        """Calculate frames per second from a string like '24000/1001'."""
        try:
            if '/' in fps_string:
                numerator, denominator = map(int, fps_string.split('/'))
                if denominator != 0:
                    return numerator / denominator
            return float(fps_string)
        except (ValueError, ZeroDivisionError):
            return 0