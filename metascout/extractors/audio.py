"""
Audio metadata extraction
"""

import os
import logging
from typing import Dict, Any, Optional

from ..config.constants import SUPPORTED_EXTENSIONS
from .base import BaseExtractor


class AudioExtractor(BaseExtractor):
    """Extract metadata from audio files."""
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """Check if this extractor can handle the specified file."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS['audio']:
            return True
        
        if mime_type and mime_type.startswith('audio/'):
            return True
            
        return False
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from audio files."""
        metadata = {
            'audio_properties': {},
            'tags': {}
        }
        
        ext = os.path.splitext(file_path)[1].lower()
        
        try:
            # Use mutagen for general audio metadata extraction
            import mutagen
            audio = mutagen.File(file_path)
            
            if audio:
                # Extract audio properties
                if hasattr(audio.info, 'length'):
                    metadata['audio_properties']['duration'] = audio.info.length
                if hasattr(audio.info, 'bitrate'):
                    metadata['audio_properties']['bitrate'] = audio.info.bitrate
                if hasattr(audio.info, 'sample_rate'):
                    metadata['audio_properties']['sample_rate'] = audio.info.sample_rate
                if hasattr(audio.info, 'channels'):
                    metadata['audio_properties']['channels'] = audio.info.channels
                
                # Extract tags (metadata fields)
                for key, value in audio.items():
                    if isinstance(value, list) and len(value) == 1:
                        metadata['tags'][key] = str(value[0])
                    else:
                        metadata['tags'][key] = str(value)
            
            # Format-specific metadata extraction
            if ext == '.mp3':
                self._extract_mp3_metadata(file_path, metadata)
            elif ext == '.flac':
                self._extract_flac_metadata(file_path, metadata)
            elif ext == '.wav':
                self._extract_wav_metadata(file_path, metadata)
            elif ext == '.m4a' or ext == '.aac':
                self._extract_m4a_metadata(file_path, metadata)
            
            return metadata
        except Exception as e:
            logging.error(f"Error extracting audio metadata from {file_path}: {e}")
            return {'error': str(e)}
    
    def _extract_mp3_metadata(self, file_path: str, metadata: Dict[str, Any]) -> None:
        """Extract MP3-specific metadata."""
        try:
            from mutagen.id3 import ID3
            
            id3 = ID3(file_path)
            for frame in id3.values():
                frame_name = frame.__class__.__name__
                if frame_name not in metadata['tags']:
                    metadata['tags'][frame_name] = str(frame)
            
            # Extract specific ID3 frames of interest
            frames_of_interest = {
                'TIT2': 'title',
                'TPE1': 'artist',
                'TALB': 'album',
                'TDRC': 'year',
                'TCON': 'genre',
                'TRCK': 'track',
                'COMM': 'comment',
                'TCOM': 'composer',
                'TPUB': 'publisher',
                'TCOP': 'copyright',
                'TENC': 'encoded_by',
                'WXXX': 'url',
                'TPOS': 'disc',
                'TBPM': 'bpm',
                'TSRC': 'isrc',
                'TMED': 'media_type',
                'TCMP': 'compilation',
            }
            
            for frame_id, friendly_name in frames_of_interest.items():
                if frame_id in id3:
                    metadata['tags'][friendly_name] = str(id3[frame_id])
            
        except Exception as e:
            logging.warning(f"Failed to extract ID3 data: {e}")
    
    def _extract_flac_metadata(self, file_path: str, metadata: Dict[str, Any]) -> None:
        """Extract FLAC-specific metadata."""
        try:
            from mutagen.flac import FLAC
            
            flac = FLAC(file_path)
            # FLAC tags are already extracted by mutagen.File, but we might want to extract pictures
            if flac.pictures:
                metadata['pictures'] = []
                for picture in flac.pictures:
                    pic_info = {
                        'type': picture.type,
                        'mime': picture.mime,
                        'desc': picture.desc,
                        'width': picture.width,
                        'height': picture.height,
                        'depth': picture.depth,
                        'size': len(picture.data)
                    }
                    metadata['pictures'].append(pic_info)
        except Exception as e:
            logging.warning(f"Failed to extract FLAC data: {e}")
    
    def _extract_wav_metadata(self, file_path: str, metadata: Dict[str, Any]) -> None:
        """Extract WAV-specific metadata."""
        try:
            from mutagen.wave import WAVE
            
            wav = WAVE(file_path)
            # WAV tags are already extracted by mutagen.File, but we might want to check for specific chunks
            # Most WAV metadata is extracted through the basic mutagen.File call
        except Exception as e:
            logging.warning(f"Failed to extract WAV data: {e}")
    
    def _extract_m4a_metadata(self, file_path: str, metadata: Dict[str, Any]) -> None:
        """Extract M4A/AAC-specific metadata."""
        try:
            from mutagen.mp4 import MP4
            
            mp4 = MP4(file_path)
            # Map atom names to friendly names
            atom_map = {
                '©nam': 'title',
                '©ART': 'artist',
                '©alb': 'album',
                '©day': 'year',
                '©gen': 'genre',
                'trkn': 'track',
                '©wrt': 'composer',
                'cprt': 'copyright',
                '©too': 'encoded_by',
                'disk': 'disc',
                'tmpo': 'bpm',
                'cpil': 'compilation',
                'covr': 'cover',
            }
            
            for atom, friendly_name in atom_map.items():
                if atom in mp4:
                    if atom == 'covr':
                        metadata['pictures'] = [{
                            'type': 'cover',
                            'size': len(mp4[atom][0]),
                            'format': 'jpeg' if mp4[atom][0].startswith(b'\xff\xd8\xff') else 'png'
                        }]
                    else:
                        metadata['tags'][friendly_name] = str(mp4[atom])
        except Exception as e:
            logging.warning(f"Failed to extract M4A/AAC data: {e}")