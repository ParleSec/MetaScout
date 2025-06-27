"""
Unit tests for MetaScout extractors
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from PIL import Image
import io

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.extractors.base import BaseExtractor
from metascout.extractors.generic import GenericExtractor
from metascout.extractors.image import ImageExtractor
from metascout.extractors.document import DocumentExtractor
from metascout.extractors.audio import AudioExtractor
from metascout.extractors.video import VideoExtractor
from metascout.extractors.executable import ExecutableExtractor
from metascout.extractors import get_extractor_for_file


class TestBaseExtractor(unittest.TestCase):
    """Test the base extractor functionality."""
    
    def test_base_extractor_interface(self):
        """Test that BaseExtractor defines the required interface."""
        # Should not be able to instantiate directly
        with self.assertRaises(TypeError):
            BaseExtractor()
    
    def test_can_handle_method(self):
        """Test that can_handle is a class method."""
        # BaseExtractor should have can_handle as a class method
        self.assertTrue(hasattr(BaseExtractor, 'can_handle'))
        self.assertTrue(callable(BaseExtractor.can_handle))


class TestGenericExtractor(unittest.TestCase):
    """Test the generic extractor."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.extractor = GenericExtractor()
        
        # Create test files
        self.text_file = os.path.join(self.temp_dir.name, "test.txt")
        with open(self.text_file, "w") as f:
            f.write("This is a test file\nwith multiple lines\n")
        
        self.binary_file = os.path.join(self.temp_dir.name, "test.bin")
        with open(self.binary_file, "wb") as f:
            f.write(b"\x00\x01\x02\x03\x04\x05")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_can_handle_any_file(self):
        """Test that generic extractor can handle any file."""
        self.assertTrue(GenericExtractor.can_handle("text"))
        self.assertTrue(GenericExtractor.can_handle("image"))
        self.assertTrue(GenericExtractor.can_handle("document"))
        self.assertTrue(GenericExtractor.can_handle("other"))
    
    def test_extract_text_file(self):
        """Test extracting metadata from text file."""
        metadata = self.extractor.extract(self.text_file)
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('basic_info', metadata)
        self.assertIn('file_size', metadata['basic_info'])
        self.assertIn('mime_type', metadata['basic_info'])
        
        # Should have hashes
        self.assertIn('hashes', metadata)
        self.assertIn('md5', metadata['hashes'])
        self.assertIn('sha256', metadata['hashes'])
    
    def test_extract_binary_file(self):
        """Test extracting metadata from binary file."""
        metadata = self.extractor.extract(self.binary_file)
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('basic_info', metadata)
        self.assertIn('hashes', metadata)
        
        # Should detect as binary
        self.assertIn('mime_type', metadata['basic_info'])
    
    def test_extract_nonexistent_file(self):
        """Test extracting from non-existent file."""
        metadata = self.extractor.extract("/nonexistent/file.txt")
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('errors', metadata)
        self.assertGreater(len(metadata['errors']), 0)


class TestImageExtractor(unittest.TestCase):
    """Test the image extractor."""
    
    def setUp(self):
        """Set up test image files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.extractor = ImageExtractor()
        
        # Create a test image
        self.image_file = os.path.join(self.temp_dir.name, "test.jpg")
        img = Image.new('RGB', (100, 100), color='red')
        img.save(self.image_file, 'JPEG')
        
        # Create a PNG with metadata
        self.png_file = os.path.join(self.temp_dir.name, "test.png")
        png_img = Image.new('RGB', (200, 150), color='blue')
        png_img.save(self.png_file, 'PNG')
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_can_handle_images(self):
        """Test that image extractor handles image files."""
        self.assertTrue(ImageExtractor.can_handle("image"))
        self.assertFalse(ImageExtractor.can_handle("document"))
        self.assertFalse(ImageExtractor.can_handle("audio"))
    
    def test_extract_jpeg_metadata(self):
        """Test extracting JPEG metadata."""
        metadata = self.extractor.extract(self.image_file)
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('image_info', metadata)
        
        image_info = metadata['image_info']
        self.assertIn('width', image_info)
        self.assertIn('height', image_info)
        self.assertIn('format', image_info)
        
        self.assertEqual(image_info['width'], 100)
        self.assertEqual(image_info['height'], 100)
        self.assertEqual(image_info['format'], 'JPEG')
    
    def test_extract_png_metadata(self):
        """Test extracting PNG metadata."""
        metadata = self.extractor.extract(self.png_file)
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('image_info', metadata)
        
        image_info = metadata['image_info']
        self.assertEqual(image_info['width'], 200)
        self.assertEqual(image_info['height'], 150)
        self.assertEqual(image_info['format'], 'PNG')
    
    def test_extract_invalid_image(self):
        """Test extracting from invalid image file."""
        # Create a file that looks like an image but isn't
        fake_image = os.path.join(self.temp_dir.name, "fake.jpg")
        with open(fake_image, "w") as f:
            f.write("This is not an image")
        
        metadata = self.extractor.extract(fake_image)
        
        self.assertIsInstance(metadata, dict)
        # Should have errors or handle gracefully
        if 'errors' in metadata:
            self.assertGreater(len(metadata['errors']), 0)


class TestDocumentExtractor(unittest.TestCase):
    """Test the document extractor."""
    
    def setUp(self):
        """Set up test document files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.extractor = DocumentExtractor()
        
        # Create a simple text document
        self.text_doc = os.path.join(self.temp_dir.name, "document.txt")
        with open(self.text_doc, "w", encoding='utf-8') as f:
            f.write("Document Title\n")
            f.write("This is a sample document with some content.\n")
            f.write("It contains multiple paragraphs.\n")
            f.write("Contact: john@example.com\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_can_handle_documents(self):
        """Test that document extractor handles document files."""
        self.assertTrue(DocumentExtractor.can_handle("document"))
        self.assertFalse(DocumentExtractor.can_handle("image"))
        self.assertFalse(DocumentExtractor.can_handle("audio"))
    
    def test_extract_text_document(self):
        """Test extracting text document metadata."""
        metadata = self.extractor.extract(self.text_doc)
        
        self.assertIsInstance(metadata, dict)
        self.assertIn('document_info', metadata)
        
        doc_info = metadata['document_info']
        self.assertIn('text_content', doc_info)
        self.assertIn('line_count', doc_info)
        self.assertIn('word_count', doc_info)
        self.assertIn('character_count', doc_info)
        
        # Check content analysis
        self.assertGreater(doc_info['line_count'], 0)
        self.assertGreater(doc_info['word_count'], 0)
        self.assertGreater(doc_info['character_count'], 0)


class TestExtractorSystem(unittest.TestCase):
    """Test the extractor selection system."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create various test files
        self.text_file = os.path.join(self.temp_dir.name, "test.txt")
        with open(self.text_file, "w") as f:
            f.write("Text file content")
        
        # Create a small image
        self.image_file = os.path.join(self.temp_dir.name, "test.jpg")
        img = Image.new('RGB', (10, 10), color='red')
        img.save(self.image_file, 'JPEG')
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_get_extractor_for_file(self):
        """Test getting appropriate extractor for different files."""
        # Test text file
        text_extractor = get_extractor_for_file(self.text_file)
        self.assertIsNotNone(text_extractor)
        self.assertIsInstance(text_extractor, BaseExtractor)
        
        # Test image file
        image_extractor = get_extractor_for_file(self.image_file)
        self.assertIsNotNone(image_extractor)
        self.assertIsInstance(image_extractor, BaseExtractor)
    
    def test_extractor_fallback(self):
        """Test that generic extractor is used as fallback."""
        # Test with unknown file type
        unknown_file = os.path.join(self.temp_dir.name, "test.unknown")
        with open(unknown_file, "w") as f:
            f.write("Unknown file type")
        
        extractor = get_extractor_for_file(unknown_file)
        self.assertIsNotNone(extractor)
        self.assertIsInstance(extractor, BaseExtractor)
    
    def test_extractor_consistency(self):
        """Test that extractors return consistent metadata structure."""
        extractors = [
            get_extractor_for_file(self.text_file),
            get_extractor_for_file(self.image_file)
        ]
        
        for extractor in extractors:
            metadata = extractor.extract(self.text_file)
            self.assertIsInstance(metadata, dict)
            
            # All extractors should provide basic info
            if 'basic_info' in metadata:
                self.assertIn('file_size', metadata['basic_info'])


class TestAudioExtractor(unittest.TestCase):
    """Test the audio extractor."""
    
    def setUp(self):
        """Set up test environment."""
        self.extractor = AudioExtractor()
    
    def test_can_handle_audio(self):
        """Test that audio extractor handles audio files."""
        self.assertTrue(AudioExtractor.can_handle("audio"))
        self.assertFalse(AudioExtractor.can_handle("image"))
        self.assertFalse(AudioExtractor.can_handle("document"))
    
    def test_extractor_interface(self):
        """Test that audio extractor implements required interface."""
        self.assertTrue(hasattr(self.extractor, 'extract'))
        self.assertTrue(callable(self.extractor.extract))


class TestVideoExtractor(unittest.TestCase):
    """Test the video extractor."""
    
    def setUp(self):
        """Set up test environment."""
        self.extractor = VideoExtractor()
    
    def test_can_handle_video(self):
        """Test that video extractor handles video files."""
        self.assertTrue(VideoExtractor.can_handle("video"))
        self.assertFalse(VideoExtractor.can_handle("image"))
        self.assertFalse(VideoExtractor.can_handle("document"))
    
    def test_extractor_interface(self):
        """Test that video extractor implements required interface."""
        self.assertTrue(hasattr(self.extractor, 'extract'))
        self.assertTrue(callable(self.extractor.extract))


class TestExecutableExtractor(unittest.TestCase):
    """Test the executable extractor."""
    
    def setUp(self):
        """Set up test environment."""
        self.extractor = ExecutableExtractor()
    
    def test_can_handle_executable(self):
        """Test that executable extractor handles executable files."""
        self.assertTrue(ExecutableExtractor.can_handle("executable"))
        self.assertFalse(ExecutableExtractor.can_handle("image"))
        self.assertFalse(ExecutableExtractor.can_handle("document"))
    
    def test_extractor_interface(self):
        """Test that executable extractor implements required interface."""
        self.assertTrue(hasattr(self.extractor, 'extract'))
        self.assertTrue(callable(self.extractor.extract))


if __name__ == "__main__":
    unittest.main() 