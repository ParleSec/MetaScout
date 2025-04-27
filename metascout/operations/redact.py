"""
Metadata redaction operations for MetaScout
"""

import os
import logging
import shutil
import tempfile
from typing import List, Dict, Any, Optional

from ..config.constants import SUPPORTED_EXTENSIONS
from ..config.dependencies import OPTIONAL_DEPENDENCIES


def redact_metadata(input_path: str, output_path: str, keep_fields: Optional[List[str]] = None) -> bool:
    """
    Create a copy of the file with metadata removed.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file
        keep_fields: List of metadata fields to preserve
        
    Returns:
        True if successful, False otherwise
    """
    if keep_fields is None:
        keep_fields = []
    
    ext = os.path.splitext(input_path)[1].lower()
    
    try:
        # Create a temporary directory for processing
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_output = os.path.join(temp_dir, os.path.basename(output_path))
            
            # Handle different file types
            if ext in SUPPORTED_EXTENSIONS['images']:
                # Process image files
                redact_image_metadata(input_path, temp_output, keep_fields)
            elif ext in SUPPORTED_EXTENSIONS['documents']:
                if ext == '.pdf':
                    redact_pdf_metadata(input_path, temp_output, keep_fields)
                else:
                    redact_office_metadata(input_path, temp_output, keep_fields)
            elif ext in SUPPORTED_EXTENSIONS['audio']:
                redact_audio_metadata(input_path, temp_output, keep_fields)
            else:
                # For unsupported types, just copy the file
                shutil.copy2(input_path, temp_output)
                logging.warning(f"Metadata redaction not supported for {ext} files. Created a plain copy.")
            
            # Move from temp location to final destination
            shutil.move(temp_output, output_path)
            
            return True
    except Exception as e:
        logging.error(f"Error during metadata redaction: {e}")
        return False


def redact_image_metadata(input_path: str, output_path: str, keep_fields: List[str]) -> None:
    """
    Remove metadata from image files.
    
    Args:
        input_path: Path to input image file
        output_path: Path to output image file
        keep_fields: List of metadata fields to preserve
    """
    try:
        from PIL import Image, TiffImagePlugin, ExifTags
        
        with Image.open(input_path) as img:
            # Create a new image with the same content but without metadata
            data = list(img.getdata())
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(data)
            
            # Keep only specified metadata if any
            preserved_data = {}
            if keep_fields:
                # Handle specific preservation logic based on image format
                if img.format == 'JPEG' and hasattr(img, '_exif'):
                    exif = img._getexif()
                    if exif:
                        for field in keep_fields:
                            for tag, value in exif.items():
                                tag_name = ExifTags.TAGS.get(tag, str(tag))
                                if tag_name == field or tag == field:
                                    preserved_data[tag] = value
            
            # Save with minimal metadata
            save_kwargs = {}
            if img.format == 'JPEG':
                if preserved_data and 'exif' in keep_fields:
                    try:
                        exif_bytes = TiffImagePlugin.ImageFileDirectory_v2()
                        for tag, value in preserved_data.items():
                            exif_bytes[tag] = value
                        save_kwargs['exif'] = exif_bytes.tobytes()
                    except Exception as e:
                        logging.warning(f"Could not preserve EXIF data: {e}")
                
                new_img.save(output_path, format=img.format, **save_kwargs)
            elif img.format == 'PNG':
                # PNG has no standard metadata blocks to preserve
                new_img.save(output_path, format=img.format)
            else:
                new_img.save(output_path, format=img.format)
    
    except Exception as e:
        logging.error(f"Error redacting image metadata: {e}")
        # Fallback: create a clean copy by converting
        try:
            with Image.open(input_path) as img:
                # Convert to a format that strips metadata
                if img.mode == 'RGBA':
                    new_img = Image.new('RGBA', img.size)
                    new_img.paste(img, (0, 0), img)
                else:
                    new_img = Image.new(img.mode, img.size)
                    new_img.paste(img, (0, 0))
                
                new_img.save(output_path)
        except Exception as fallback_error:
            logging.error(f"Fallback image redaction also failed: {fallback_error}")
            # Last resort: just copy the file
            shutil.copy2(input_path, output_path)
            raise RuntimeError("Could not redact image metadata")


def redact_pdf_metadata(input_path: str, output_path: str, keep_fields: List[str]) -> None:
    """
    Remove metadata from PDF files.
    
    Args:
        input_path: Path to input PDF file
        output_path: Path to output PDF file
        keep_fields: List of metadata fields to preserve
    """
    try:
        from PyPDF2 import PdfReader, PdfWriter
        
        with open(input_path, 'rb') as f_in:
            reader = PdfReader(f_in)
            
            # Create a new PDF writer
            writer = PdfWriter()
            
            # Copy all pages
            for page in reader.pages:
                writer.add_page(page)
            
            # Set minimal metadata or preserved fields
            if keep_fields:
                for field in keep_fields:
                    if reader.metadata and field in reader.metadata:
                        writer.add_metadata({f"/{field}": reader.metadata[f"/{field}"]})
            
            # Write the output file
            with open(output_path, 'wb') as f_out:
                writer.write(f_out)
    
    except Exception as e:
        logging.error(f"Error redacting PDF metadata: {e}")
        # Fallback: just copy the file
        shutil.copy2(input_path, output_path)
        raise RuntimeError("Could not redact PDF metadata")


def redact_office_metadata(input_path: str, output_path: str, keep_fields: List[str]) -> None:
    """
    Remove metadata from Office documents.
    
    Args:
        input_path: Path to input Office document
        output_path: Path to output Office document
        keep_fields: List of metadata fields to preserve
    """
    ext = os.path.splitext(input_path)[1].lower()
    
    try:
        if ext == '.docx' and OPTIONAL_DEPENDENCIES['docx']:
            import docx
            doc = docx.Document(input_path)
            
            # Reset core properties except those in keep_fields
            if not any(field in keep_fields for field in ['author', 'creator']):
                doc.core_properties.author = ''
            if 'title' not in keep_fields:
                doc.core_properties.title = ''
            if 'subject' not in keep_fields:
                doc.core_properties.subject = ''
            if 'comments' not in keep_fields:
                doc.core_properties.comments = ''
            if 'category' not in keep_fields:
                doc.core_properties.category = ''
            if 'keywords' not in keep_fields:
                doc.core_properties.keywords = ''
            
            # Save the document
            doc.save(output_path)
        
        elif ext == '.xlsx' and OPTIONAL_DEPENDENCIES['openpyxl']:
            import openpyxl
            wb = openpyxl.load_workbook(input_path)
            
            # Reset properties except those in keep_fields
            if not any(field in keep_fields for field in ['creator', 'author']):
                wb.properties.creator = ''
            if 'title' not in keep_fields:
                wb.properties.title = ''
            if 'subject' not in keep_fields:
                wb.properties.subject = ''
            if 'description' not in keep_fields:
                wb.properties.description = ''
            if 'category' not in keep_fields:
                wb.properties.category = ''
            if 'keywords' not in keep_fields:
                wb.properties.keywords = ''
            
            # Save the workbook
            wb.save(output_path)
        
        else:
            # For other office formats, we might need additional libraries
            # or external tools like LibreOffice command line
            shutil.copy2(input_path, output_path)
            logging.warning(f"Limited metadata redaction for {ext} files. Some metadata may remain.")
    
    except Exception as e:
        logging.error(f"Error redacting Office document metadata: {e}")
        # Fallback: just copy the file
        shutil.copy2(input_path, output_path)
        raise RuntimeError("Could not redact Office document metadata")


def redact_audio_metadata(input_path: str, output_path: str, keep_fields: List[str]) -> None:
    """
    Remove metadata from audio files.
    
    Args:
        input_path: Path to input audio file
        output_path: Path to output audio file
        keep_fields: List of metadata fields to preserve
    """
    ext = os.path.splitext(input_path)[1].lower()
    
    try:
        import mutagen
        
        if ext == '.mp3':
            try:
                from mutagen.id3 import ID3, ID3NoHeaderError
                
                # Create a temporary copy first
                shutil.copy2(input_path, output_path)
                
                try:
                    # Try to load ID3 tags
                    audio = ID3(output_path)
                    
                    # If keep_fields is empty, delete all tags
                    if not keep_fields:
                        audio.delete()
                    else:
                        # Otherwise, keep only specified tags
                        tags_to_keep = []
                        for frame in audio.values():
                            frame_name = frame.__class__.__name__
                            if frame_name in keep_fields or any(field.lower() in frame_name.lower() for field in keep_fields):
                                tags_to_keep.append(frame)
                        
                        # Delete all tags
                        audio.delete()
                        
                        # Re-add the ones to keep
                        for frame in tags_to_keep:
                            audio.add(frame)
                    
                    # Save the modified file
                    audio.save()
                
                except ID3NoHeaderError:
                    # No ID3 tags present, nothing to redact
                    pass
            except ImportError:
                logging.warning("Mutagen ID3 not available. Copying file without redaction.")
                shutil.copy2(input_path, output_path)
        
        elif ext in ['.flac', '.ogg']:
            # Handling for FLAC and OGG files
            audio = mutagen.File(input_path)
            
            if audio:
                # Create a copy with audio content
                shutil.copy2(input_path, output_path)
                
                # Load the copy
                new_audio = mutagen.File(output_path)
                
                # If keep_fields is empty, clear all tags
                if not keep_fields:
                    new_audio.clear()
                else:
                    # Keep only specified tags
                    tags_to_remove = []
                    for key in new_audio:
                        if not any(field.lower() in key.lower() for field in keep_fields):
                            tags_to_remove.append(key)
                    
                    for key in tags_to_remove:
                        del new_audio[key]
                
                # Save the modified file
                new_audio.save()
        
        else:
            # For other audio formats, just copy (limited support)
            shutil.copy2(input_path, output_path)
            logging.warning(f"Limited metadata redaction for {ext} files. Some metadata may remain.")
    
    except Exception as e:
        logging.error(f"Error redacting audio metadata: {e}")
        # Fallback: just copy the file
        shutil.copy2(input_path, output_path)
        raise RuntimeError("Could not redact audio metadata")


def redact_metadata_batch(
    input_files: List[str],
    output_dir: str,
    keep_fields: Optional[List[str]] = None,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Redact metadata from multiple files.
    
    Args:
        input_files: List of input file paths
        output_dir: Directory to save redacted files
        keep_fields: List of metadata fields to preserve
        options: Additional options
        
    Returns:
        Dictionary with results of batch redaction
    """
    if keep_fields is None:
        keep_fields = []
    
    if options is None:
        options = {}
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    results = {
        'successful': [],
        'failed': []
    }
    
    for input_file in input_files:
        try:
            # Determine output path
            filename = os.path.basename(input_file)
            output_path = os.path.join(output_dir, filename)
            
            # Add suffix if specified
            if 'suffix' in options:
                base, ext = os.path.splitext(output_path)
                output_path = f"{base}_{options['suffix']}{ext}"
            
            # Redact metadata
            success = redact_metadata(input_file, output_path, keep_fields)
            
            if success:
                results['successful'].append({
                    'input': input_file,
                    'output': output_path
                })
            else:
                results['failed'].append({
                    'input': input_file,
                    'error': 'Redaction failed'
                })
        except Exception as e:
            results['failed'].append({
                'input': input_file,
                'error': str(e)
            })
    
    # Add summary
    results['summary'] = {
        'total': len(input_files),
        'successful': len(results['successful']),
        'failed': len(results['failed'])
    }
    
    return results