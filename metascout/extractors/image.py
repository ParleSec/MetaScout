"""
Image metadata extraction
"""

import os
import logging
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET

from PIL import Image, ExifTags, IptcImagePlugin
import exifread

from ..config.constants import SUPPORTED_EXTENSIONS
from .base import BaseExtractor


class ImageExtractor(BaseExtractor):
    """Extract metadata from image files."""
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """Check if this extractor can handle the specified file."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS['images']:
            return True
        
        if mime_type and mime_type.startswith('image/'):
            return True
            
        return False
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive metadata from image files."""
        metadata = {
            'basic': {},
            'exif': {},
            'iptc': {},
            'xmp': {},
        }
        
        try:
            # Use PIL for basic image info
            with Image.open(file_path) as img:
                metadata['basic'] = {
                    'format': img.format,
                    'mode': img.mode,
                    'width': img.width,
                    'height': img.height,
                    'color_profile': img.info.get('icc_profile', 'None')
                }
                
                # Extract EXIF data
                exif_data = img._getexif()
                if exif_data:
                    # Convert numeric EXIF tags to readable names
                    metadata['exif'] = {
                        ExifTags.TAGS.get(tag, tag): str(value)
                        for tag, value in exif_data.items()
                        if tag in ExifTags.TAGS
                    }
                    
                    # Handle GPS info specially
                    if 'GPSInfo' in metadata['exif'] and isinstance(metadata['exif']['GPSInfo'], dict):
                        gps_info = {}
                        for key, val in metadata['exif']['GPSInfo'].items():
                            gps_key = ExifTags.GPSTAGS.get(key, key)
                            gps_info[gps_key] = val
                        metadata['exif']['GPSInfo'] = gps_info
                
                # Extract IPTC data
                iptc = IptcImagePlugin.getiptcinfo(img)
                if iptc:
                    metadata['iptc'] = {str(key): value.decode('utf-8', 'ignore') 
                                        if isinstance(value, bytes) else str(value) 
                                        for key, value in iptc.items()}
                
                # Extract XMP data if present
                if 'xmp' in img.info:
                    # Parse XML structure of XMP
                    try:
                        xmp_str = img.info['xmp'].decode('utf-8', 'ignore') if isinstance(img.info['xmp'], bytes) else img.info['xmp']
                        root = ET.fromstring(xmp_str)
                        metadata['xmp'] = {'raw': xmp_str}
                        
                        # Extract all namespaces
                        namespaces = {k: v for k, v in root.attrib.items() if k.startswith('xmlns:')}
                        
                        # Extract key properties from XMP data
                        for elem in root.iter():
                            tag = elem.tag.split('}')[-1]
                            if elem.text and elem.text.strip():
                                metadata['xmp'][tag] = elem.text.strip()
                    except Exception as e:
                        logging.warning(f"Failed to parse XMP data: {e}")
                        metadata['xmp'] = {'raw': str(img.info['xmp'])}
            
            # Use ExifRead for more thorough EXIF extraction
            with open(file_path, 'rb') as f:
                exif_tags = exifread.process_file(f, details=True)
                if exif_tags:
                    # Merge with existing EXIF data, preferring ExifRead values
                    for tag, value in exif_tags.items():
                        tag_name = tag.replace(' ', '_')
                        metadata['exif'][tag_name] = str(value)
            
            return metadata
        except FileNotFoundError:
            return {'error': f'Image file not found: {file_path}'}
        except PermissionError:
            return {'error': f'Permission denied accessing image file: {file_path}'}
        except Exception as e:
            # Check for common image-related errors
            error_msg = str(e).lower()
            if 'truncated' in error_msg or 'incomplete' in error_msg:
                return {'error': f'Image file appears to be corrupted or incomplete: {file_path}'}
            elif 'cannot identify image file' in error_msg:
                return {'error': f'File is not a valid image or format is not supported: {file_path}'}
            else:
                logging.error(f"Error extracting image metadata from {file_path}: {e}")
                return {'error': f'Failed to extract image metadata: {str(e)}'}