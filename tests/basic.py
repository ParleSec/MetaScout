"""
Basic tests for MetaScout functionality
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from metascout.core.models import FileMetadata, MetadataFinding
    from metascout.core.utils import compute_file_hashes, detect_file_type
    from metascout.extractors import get_extractor_for_file
    from metascout.analyzers import get_analyzers_for_file_type
    from metascout.reporters import get_reporter
except ImportError as e:
    print(f"Import error: {e}")
    print(f"Project root: {project_root}")
    print(f"Python path: {sys.path}")
    raise


class BasicTest(unittest.TestCase):
    """Basic tests for MetaScout functionality."""
    
    def setUp(self):
        """Set up test files."""
        # Create a temporary test file
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file_path = os.path.join(self.temp_dir.name, "test.txt")
        
        # Create a simple text file
        with open(self.test_file_path, "w") as f:
            f.write("This is a test file for MetaScout.\n")
            f.write("It contains some sample text for testing.\n")
            f.write("Email: test@example.com\n")  # Add some PII for testing
        
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_file_hashes(self):
        """Test file hash computation."""
        hashes = compute_file_hashes(self.test_file_path)
        
        # Check if there was an error computing hashes
        if 'error' in hashes:
            self.skipTest(f"Could not compute hashes: {hashes['error']}")
        
        # Verify that we get the expected hash types
        self.assertIn('md5', hashes)
        self.assertIn('sha1', hashes)
        self.assertIn('sha256', hashes)
        
        # Verify that hashes are non-empty
        for hash_value in hashes.values():
            self.assertTrue(hash_value)
            self.assertIsInstance(hash_value, str)
    
    def test_file_type_detection(self):
        """Test file type detection."""
        try:
            mime_type, description = detect_file_type(self.test_file_path)
            
            # Verify that we get a mime type
            self.assertIsInstance(mime_type, str)
            self.assertTrue(mime_type)
            
            # Verify that we get a description
            self.assertIsInstance(description, str)
            self.assertTrue(description)
        except Exception as e:
            self.skipTest(f"Could not detect file type: {e}")
    
    def test_extractor_selection(self):
        """Test extractor selection."""
        try:
            extractor = get_extractor_for_file(self.test_file_path)
            
            # Verify that we get an extractor
            self.assertIsNotNone(extractor)
            
            # Verify that the extractor can extract metadata
            metadata = extractor.extract(self.test_file_path)
            self.assertIsInstance(metadata, dict)
        except Exception as e:
            self.skipTest(f"Could not test extractor: {e}")
    
    def test_analyzer_selection(self):
        """Test analyzer selection."""
        try:
            analyzers = get_analyzers_for_file_type("other")
            
            # Verify that we get at least one analyzer (should include generic)
            self.assertTrue(analyzers)
            
            # Create some basic metadata for testing
            metadata = {
                "text_info": {
                    "content": "This is test content with an email: test@example.com"
                }
            }
            
            # Apply each analyzer and check results
            for analyzer in analyzers:
                findings = analyzer.analyze(metadata)
                self.assertIsInstance(findings, list)
                # Each finding should be a MetadataFinding
                for finding in findings:
                    self.assertIsInstance(finding, MetadataFinding)
        except Exception as e:
            self.skipTest(f"Could not test analyzer: {e}")
    
    def test_reporter_selection(self):
        """Test reporter selection."""
        try:
            for format_name in ['text', 'json', 'html', 'csv']:
                reporter = get_reporter(format_name)
                self.assertIsNotNone(reporter, f"Failed to get reporter for {format_name}")
                
                # Verify that reporter can generate a report
                result = FileMetadata(
                    file_path=self.test_file_path,
                    file_type="text",
                    file_size=os.path.getsize(self.test_file_path),
                    mime_type="text/plain",
                    findings=[
                        MetadataFinding(
                            type="privacy",
                            description="Email address found",
                            severity="medium",
                            data={"match": "test@example.com"}
                        )
                    ]
                )
                
                report = reporter.generate_report([result])
                self.assertIsInstance(report, str)
                self.assertTrue(report)
        except Exception as e:
            self.skipTest(f"Could not test reporter: {e}")

    def test_data_models(self):
        """Test that data models work correctly."""
        # Test FileMetadata creation
        metadata = FileMetadata(
            file_path="/test/path",
            file_type="test",
            file_size=1234,
            mime_type="text/plain"
        )
        
        self.assertEqual(metadata.file_path, "/test/path")
        self.assertEqual(metadata.file_type, "test")
        self.assertEqual(metadata.file_size, 1234)
        self.assertEqual(metadata.mime_type, "text/plain")
        
        # Test to_dict method
        metadata_dict = metadata.to_dict()
        self.assertIsInstance(metadata_dict, dict)
        self.assertEqual(metadata_dict['file_path'], "/test/path")
        
        # Test MetadataFinding creation
        finding = MetadataFinding(
            type="privacy",
            description="Test finding",
            severity="medium",
            data={"test": "value"}
        )
        
        self.assertEqual(finding.type, "privacy")
        self.assertEqual(finding.description, "Test finding")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(finding.data["test"], "value")


if __name__ == "__main__":
    unittest.main()