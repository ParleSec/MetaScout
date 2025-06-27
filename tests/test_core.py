"""
Tests for MetaScout core functionality
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.core.models import FileMetadata, MetadataFinding
from metascout.core.utils import compute_file_hashes, detect_file_type, get_file_timestamps, safe_path
from metascout.core.processor import process_file


class TestCoreModels(unittest.TestCase):
    """Test core data models."""
    
    def test_metadata_finding(self):
        """Test MetadataFinding creation and attributes."""
        finding = MetadataFinding(
            type="privacy",
            description="Test finding",
            severity="high",
            data={"test_key": "test_value"}
        )
        
        self.assertEqual(finding.type, "privacy")
        self.assertEqual(finding.description, "Test finding")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.data["test_key"], "test_value")
    
    def test_file_metadata(self):
        """Test FileMetadata creation and methods."""
        metadata = FileMetadata(
            file_path="/test/path.txt",
            file_type="document",
            file_size=1024,
            mime_type="text/plain"
        )
        
        self.assertEqual(metadata.file_path, "/test/path.txt")
        self.assertEqual(metadata.file_type, "document")
        self.assertEqual(metadata.file_size, 1024)
        self.assertEqual(metadata.mime_type, "text/plain")
        self.assertEqual(len(metadata.findings), 0)
        self.assertEqual(len(metadata.errors), 0)
        
        # Test adding findings
        finding = MetadataFinding("test", "test finding", "low")
        metadata.findings.append(finding)
        self.assertEqual(len(metadata.findings), 1)
        
        # Test to_dict method
        metadata_dict = metadata.to_dict()
        self.assertIsInstance(metadata_dict, dict)
        self.assertEqual(metadata_dict["file_path"], "/test/path.txt")
        self.assertEqual(len(metadata_dict["findings"]), 1)


class TestCoreUtils(unittest.TestCase):
    """Test core utility functions."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")
        
        with open(self.test_file, "w") as f:
            f.write("This is a test file for MetaScout.\n")
            f.write("It contains sample content for testing.\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_compute_file_hashes(self):
        """Test file hash computation."""
        hashes = compute_file_hashes(self.test_file)
        
        # Should not have error
        self.assertNotIn('error', hashes)
        
        # Should have all expected hash types
        expected_hashes = ['md5', 'sha1', 'sha256', 'sha512']
        for hash_type in expected_hashes:
            self.assertIn(hash_type, hashes)
            self.assertIsInstance(hashes[hash_type], str)
            self.assertTrue(len(hashes[hash_type]) > 0)
        
        # Hash values should be consistent
        hashes2 = compute_file_hashes(self.test_file)
        for hash_type in expected_hashes:
            self.assertEqual(hashes[hash_type], hashes2[hash_type])
    
    def test_compute_file_hashes_nonexistent(self):
        """Test hash computation for non-existent file."""
        hashes = compute_file_hashes("/nonexistent/file.txt")
        self.assertIn('error', hashes)
    
    def test_detect_file_type(self):
        """Test file type detection."""
        mime_type, description = detect_file_type(self.test_file)
        
        self.assertIsInstance(mime_type, str)
        self.assertIsInstance(description, str)
        self.assertTrue(len(mime_type) > 0)
        self.assertTrue(len(description) > 0)
        
        # Should detect as text
        self.assertIn("text", mime_type.lower())
    
    def test_get_file_timestamps(self):
        """Test file timestamp extraction."""
        timestamps = get_file_timestamps(self.test_file)
        
        expected_keys = ['creation_time', 'modification_time', 'access_time']
        for key in expected_keys:
            self.assertIn(key, timestamps)
            self.assertIsInstance(timestamps[key], str)
            # Should be ISO format timestamp
            self.assertIn('T', timestamps[key])
    
    def test_safe_path(self):
        """Test path sanitization."""
        # Test normal path
        safe = safe_path("test.txt")
        self.assertIsInstance(safe, Path)
        
        # Test absolute path
        safe = safe_path("/absolute/path.txt")
        self.assertIsInstance(safe, Path)
        
        # Test with current directory
        safe = safe_path("./test.txt")
        self.assertIsInstance(safe, Path)


class TestCoreProcessor(unittest.TestCase):
    """Test core file processing functionality."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test.txt")
        
        with open(self.test_file, "w") as f:
            f.write("This is a test file for MetaScout.\n")
            f.write("Email: test@example.com\n")
            f.write("Phone: 555-123-4567\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_process_file_basic(self):
        """Test basic file processing."""
        result = process_file(self.test_file)
        
        self.assertIsInstance(result, FileMetadata)
        self.assertEqual(result.file_path, os.path.abspath(self.test_file))
        self.assertGreater(result.file_size, 0)
        self.assertIsInstance(result.mime_type, str)
        self.assertEqual(len(result.errors), 0)
    
    def test_process_file_with_options(self):
        """Test file processing with options."""
        options = {
            'skip_hashes': True,
            'skip_analysis': True
        }
        result = process_file(self.test_file, options)
        
        self.assertIsInstance(result, FileMetadata)
        self.assertEqual(len(result.hashes), 0)  # Should be empty due to skip_hashes
    
    def test_process_nonexistent_file(self):
        """Test processing non-existent file."""
        result = process_file("/nonexistent/file.txt")
        
        self.assertIsInstance(result, FileMetadata)
        self.assertGreater(len(result.errors), 0)
        self.assertIn("not found", result.errors[0].lower())


if __name__ == "__main__":
    unittest.main() 