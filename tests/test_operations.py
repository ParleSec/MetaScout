"""
Unit tests for MetaScout operations
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path
from PIL import Image

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.core.models import FileMetadata, MetadataFinding


class TestAnalyzeOperation(unittest.TestCase):
    """Test the analyze operation."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create test files
        self.text_file = self.test_dir / "test.txt"
        with open(self.text_file, "w") as f:
            f.write("Test content with email: test@example.com\n")
        
        self.image_file = self.test_dir / "test.jpg"
        img = Image.new('RGB', (100, 100), color='red')
        img.save(self.image_file, 'JPEG')
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_analyze_files_function(self):
        """Test analyze_files function if available."""
        try:
            from metascout.operations.analyze import analyze_files
            
            file_paths = [str(self.text_file), str(self.image_file)]
            results = analyze_files(file_paths)
            
            self.assertIsInstance(results, list)
            self.assertEqual(len(results), 2)
            
            for result in results:
                self.assertIsInstance(result, FileMetadata)
                
        except ImportError:
            self.skipTest("analyze_files operation not available")
    
    def test_analyze_single_file(self):
        """Test analyzing a single file."""
        try:
            from metascout.operations.analyze import analyze_file
            
            result = analyze_file(str(self.text_file))
            
            self.assertIsInstance(result, FileMetadata)
            self.assertGreater(result.file_size, 0)
            
        except ImportError:
            self.skipTest("analyze_file operation not available")


class TestBatchOperation(unittest.TestCase):
    """Test the batch operation."""
    
    def setUp(self):
        """Set up test directory."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create multiple test files
        for i in range(3):
            file_path = self.test_dir / f"file_{i}.txt"
            with open(file_path, "w") as f:
                f.write(f"Content of file {i}\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_process_directory(self):
        """Test processing an entire directory."""
        try:
            from metascout.operations.batch import process_directory
            
            results = process_directory(str(self.test_dir))
            
            self.assertIsInstance(results, list)
            self.assertGreater(len(results), 0)
            self.assertLessEqual(len(results), 3)
            
            for result in results:
                self.assertIsInstance(result, FileMetadata)
                
        except ImportError:
            self.skipTest("process_directory operation not available")


class TestCompareOperation(unittest.TestCase):
    """Test the compare operation."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create two similar files
        self.file1 = self.test_dir / "file1.txt"
        with open(self.file1, "w") as f:
            f.write("Similar content\n")
        
        self.file2 = self.test_dir / "file2.txt"
        with open(self.file2, "w") as f:
            f.write("Similar content\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_compare_files(self):
        """Test comparing two files."""
        try:
            from metascout.operations.compare import compare_files
            
            result = compare_files(str(self.file1), str(self.file2))
            
            # Should return some comparison result
            self.assertIsNotNone(result)
            
        except ImportError:
            self.skipTest("compare_files operation not available")


class TestRedactOperation(unittest.TestCase):
    """Test the redact operation."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create file with sensitive data
        self.sensitive_file = self.test_dir / "sensitive.txt"
        with open(self.sensitive_file, "w") as f:
            f.write("Contact: john@example.com\n")
            f.write("Phone: 555-123-4567\n")
        
        # Create image file
        self.image_file = self.test_dir / "photo.jpg"
        img = Image.new('RGB', (200, 200), color='blue')
        img.save(self.image_file, 'JPEG')
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_redact_text_file(self):
        """Test redacting sensitive data from text file."""
        try:
            from metascout.operations.redact import redact_file
            
            output_file = self.test_dir / "redacted.txt"
            result = redact_file(str(self.sensitive_file), str(output_file))
            
            # Should create redacted file
            self.assertTrue(output_file.exists())
            
            # Redacted file should not contain original sensitive data
            with open(output_file, "r") as f:
                content = f.read()
                self.assertNotIn("john@example.com", content)
                self.assertNotIn("555-123-4567", content)
                
        except ImportError:
            self.skipTest("redact_file operation not available")
    
    def test_redact_image_file(self):
        """Test redacting sensitive data from image file."""
        try:
            from metascout.operations.redact import redact_image
            
            output_file = self.test_dir / "redacted.jpg"
            result = redact_image(str(self.image_file), str(output_file))
            
            # Should create redacted image
            self.assertTrue(output_file.exists())
            
            # Should be a valid image
            img = Image.open(output_file)
            self.assertIsNotNone(img)
            
        except ImportError:
            self.skipTest("redact_image operation not available")


if __name__ == "__main__":
    unittest.main() 