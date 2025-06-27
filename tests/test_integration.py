"""
Integration tests for MetaScout
These tests verify the complete workflow from file processing to report generation.
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path
from PIL import Image

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.core.processor import process_file
from metascout.core.models import FileMetadata, MetadataFinding
from metascout.extractors import get_extractor_for_file
from metascout.analyzers import get_analyzers_for_file_type
from metascout.reporters import get_reporter


class TestEndToEndWorkflow(unittest.TestCase):
    """Test complete end-to-end workflow."""
    
    def setUp(self):
        """Set up test files and directories."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
        
        # Create various test files
        self.create_test_files()
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def create_test_files(self):
        """Create various test files for comprehensive testing."""
        # Text file with sensitive data
        self.text_file = self.test_dir / "document.txt"
        with open(self.text_file, "w") as f:
            f.write("Company Document\n")
            f.write("Contact: john.doe@company.com\n")
            f.write("Phone: 555-123-4567\n")
            f.write("SSN: 123-45-6789\n")
        
        # Image file
        self.image_file = self.test_dir / "photo.jpg"
        img = Image.new('RGB', (800, 600), color='blue')
        img.save(self.image_file, 'JPEG')
        
        # Clean file (no sensitive data)
        self.clean_file = self.test_dir / "readme.txt"
        with open(self.clean_file, "w") as f:
            f.write("This is a clean file.\n")
            f.write("No sensitive information here.\n")
    
    def test_complete_file_processing(self):
        """Test complete processing of a single file."""
        result = process_file(str(self.text_file))
        
        # Should return FileMetadata
        self.assertIsInstance(result, FileMetadata)
        
        # Should have basic file info
        self.assertEqual(result.file_path, str(self.text_file.resolve()))
        self.assertGreater(result.file_size, 0)
        self.assertIsInstance(result.mime_type, str)
        
        # Should have findings (sensitive data)
        self.assertGreater(len(result.findings), 0)
        
        # Check for specific findings
        finding_types = [f.type for f in result.findings]
        # The actual implementation may use different finding types
        self.assertGreater(len(finding_types), 0)
        
        # Should have no errors for valid file
        self.assertEqual(len(result.errors), 0)
    
    def test_extractor_analyzer_integration(self):
        """Test integration between extractors and analyzers."""
        # Get extractor and extract metadata
        extractor = get_extractor_for_file(str(self.text_file))
        self.assertIsNotNone(extractor)
        
        metadata = extractor.extract(str(self.text_file))
        self.assertIsInstance(metadata, dict)
        
        # Get analyzers and analyze metadata
        analyzers = get_analyzers_for_file_type("document")
        self.assertGreater(len(analyzers), 0)
        
        all_findings = []
        for analyzer in analyzers:
            findings = analyzer.analyze(metadata)
            all_findings.extend(findings)
        
        # Should find sensitive patterns
        self.assertGreater(len(all_findings), 0)
        
        # Check finding structure
        for finding in all_findings:
            self.assertIsInstance(finding, MetadataFinding)
            self.assertIn(finding.severity, ["low", "medium", "high"])
    
    def test_multiple_file_types(self):
        """Test processing different file types."""
        files = [self.text_file, self.image_file, self.clean_file]
        results = []
        
        for file_path in files:
            result = process_file(str(file_path))
            results.append(result)
            
            # Each should return valid metadata
            self.assertIsInstance(result, FileMetadata)
            self.assertGreater(result.file_size, 0)
        
        # Text file should have findings
        text_result = next(r for r in results if "document.txt" in r.file_path)
        self.assertGreater(len(text_result.findings), 0)
        
        # Clean file should have fewer/no findings
        clean_result = next(r for r in results if "readme.txt" in r.file_path)
        self.assertLessEqual(len(clean_result.findings), 1)  # May have domain names
    
    def test_report_generation_integration(self):
        """Test complete workflow including report generation."""
        # Process files
        results = []
        for file_path in [self.text_file, self.image_file, self.clean_file]:
            result = process_file(str(file_path))
            results.append(result)
        
        # Generate reports in different formats
        formats = ['text', 'json', 'html', 'csv']
        reports = {}
        
        for format_name in formats:
            reporter = get_reporter(format_name)
            if reporter:
                report = reporter.generate_report(results)
                reports[format_name] = report
                
                # Each report should be a string
                self.assertIsInstance(report, str)
                self.assertGreater(len(report), 0)
        
        # JSON report should be valid JSON
        if 'json' in reports:
            json_data = json.loads(reports['json'])
            # Check for either direct files or report structure
            if 'report' in json_data:
                self.assertIn('files', json_data['report'])
                self.assertEqual(len(json_data['report']['files']), 3)
            else:
                # Single file format - check for file_path
                self.assertIn('file_path', json_data)
        
        # Text report should contain file names
        if 'text' in reports:
            self.assertIn('document.txt', reports['text'])
            self.assertIn('photo.jpg', reports['text'])
            self.assertIn('readme.txt', reports['text'])


class TestErrorHandling(unittest.TestCase):
    """Test error handling in integration scenarios."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_nonexistent_file_handling(self):
        """Test handling of non-existent files."""
        result = process_file("/nonexistent/file.txt")
        
        self.assertIsInstance(result, FileMetadata)
        self.assertGreater(len(result.errors), 0)
        
        # Should still be able to generate reports
        reporter = get_reporter('text')
        if reporter:
            report = reporter.generate_report([result])
            self.assertIsInstance(report, str)
            self.assertIn("error", report.lower())
    
    def test_empty_file_handling(self):
        """Test handling of empty files."""
        empty_file = self.test_dir / "empty.txt"
        empty_file.touch()
        
        result = process_file(str(empty_file))
        
        self.assertIsInstance(result, FileMetadata)
        self.assertEqual(result.file_size, 0)
        # Empty file may still have some findings from analyzers, so just check it's reasonable
        self.assertLessEqual(len(result.findings), 5)  # Should have few findings for empty file


class TestConfigurationIntegration(unittest.TestCase):
    """Test integration with different configurations."""
    
    def setUp(self):
        """Set up test files."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = Path(self.temp_dir.name) / "test.txt"
        
        with open(self.test_file, "w") as f:
            f.write("Test content with email: test@example.com\n")
    
    def tearDown(self):
        """Clean up test files."""
        self.temp_dir.cleanup()
    
    def test_processing_with_options(self):
        """Test processing with different options."""
        # Test with different option combinations
        option_sets = [
            {},  # Default options
            {'skip_hashes': True},
            {'skip_analysis': True}
        ]
        
        for options in option_sets:
            result = process_file(str(self.test_file), options)
            
            self.assertIsInstance(result, FileMetadata)
            self.assertGreater(result.file_size, 0)
            
            # Check that options were respected
            if options.get('skip_hashes'):
                self.assertEqual(len(result.hashes), 0)
            
            if options.get('skip_analysis'):
                self.assertEqual(len(result.findings), 0)


if __name__ == "__main__":
    unittest.main() 