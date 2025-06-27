"""
Unit tests for MetaScout reporters
"""

import os
import sys
import unittest
import tempfile
import json
import csv
from pathlib import Path
from io import StringIO

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.core.models import FileMetadata, MetadataFinding
from metascout.reporters.base import BaseReporter
from metascout.reporters.text import TextReporter
from metascout.reporters.json import JSONReporter  
from metascout.reporters.html import HTMLReporter
from metascout.reporters.csv import CSVReporter
from metascout.reporters import get_reporter


class TestBaseReporter(unittest.TestCase):
    """Test the base reporter functionality."""
    
    def test_base_reporter_interface(self):
        """Test that BaseReporter defines the required interface."""
        # Should not be able to instantiate directly
        with self.assertRaises(TypeError):
            BaseReporter()
    
    def test_base_reporter_methods(self):
        """Test that BaseReporter has required methods."""
        self.assertTrue(hasattr(BaseReporter, 'generate_report'))
        self.assertTrue(hasattr(BaseReporter, 'format_findings'))


class TestTextReporter(unittest.TestCase):
    """Test the text reporter."""
    
    def setUp(self):
        """Set up test data."""
        self.reporter = TextReporter()
        
        # Create sample metadata
        self.sample_metadata = FileMetadata(
            file_path="/test/sample.txt",
            file_type="document",
            file_size=1024,
            mime_type="text/plain",
            findings=[
                MetadataFinding(
                    type="privacy",
                    description="Email address found",
                    severity="medium",
                    data={"matches": ["test@example.com"]}
                )
            ]
        )
    
    def test_generate_single_file_report(self):
        """Test generating report for single file."""
        report = self.reporter.generate_report([self.sample_metadata])
        
        self.assertIsInstance(report, str)
        self.assertIn("sample.txt", report)
        self.assertIn("Email address found", report)
        self.assertIn("medium", report)
    
    def test_generate_empty_report(self):
        """Test generating report with no files."""
        report = self.reporter.generate_report([])
        
        self.assertIsInstance(report, str)
        self.assertIn("No files", report)


class TestJSONReporter(unittest.TestCase):
    """Test the JSON reporter."""
    
    def setUp(self):
        """Set up test data."""
        self.reporter = JSONReporter()
        
        self.sample_metadata = FileMetadata(
            file_path="/test/sample.txt",
            file_type="document", 
            file_size=1024,
            mime_type="text/plain",
            findings=[
                MetadataFinding(
                    type="privacy",
                    description="Email found",
                    severity="medium",
                    data={"email": "test@example.com"}
                )
            ]
        )
    
    def test_generate_json_report(self):
        """Test generating JSON report."""
        report = self.reporter.generate_report([self.sample_metadata])
        
        self.assertIsInstance(report, str)
        
        # Should be valid JSON
        try:
            data = json.loads(report)
        except json.JSONDecodeError:
            self.fail("Generated report is not valid JSON")
        
        # Check structure
        self.assertIn("files", data)
        self.assertEqual(len(data["files"]), 1)


class TestHTMLReporter(unittest.TestCase):
    """Test the HTML reporter."""
    
    def setUp(self):
        """Set up test data."""
        self.reporter = HTMLReporter()
        
        self.sample_metadata = FileMetadata(
            file_path="/test/sample.txt",
            file_type="document",
            file_size=1024,
            mime_type="text/plain",
            findings=[
                MetadataFinding(
                    type="privacy",
                    description="Email address detected",
                    severity="high",
                    data={"matches": ["user@domain.com"]}
                )
            ]
        )
    
    def test_generate_html_report(self):
        """Test generating HTML report."""
        report = self.reporter.generate_report([self.sample_metadata])
        
        self.assertIsInstance(report, str)
        
        # Should contain HTML structure
        self.assertIn("<!DOCTYPE html>", report)
        self.assertIn("<html", report)
        self.assertIn("<head>", report)
        self.assertIn("<body>", report)
        self.assertIn("</html>", report)
        
        # Should contain content
        self.assertIn("sample.txt", report)
        self.assertIn("Email address detected", report)
        self.assertIn("high", report.lower())
    
    def test_html_escaping(self):
        """Test that HTML content is properly escaped."""
        dangerous_metadata = FileMetadata(
            file_path="/test/<script>alert('xss')</script>.txt",
            file_type="document",
            file_size=100,
            mime_type="text/plain",
            findings=[
                MetadataFinding(
                    type="test",
                    description="Test with <script> tags",
                    severity="low",
                    data={"content": "<script>alert('test')</script>"}
                )
            ]
        )
        
        report = self.reporter.generate_report([dangerous_metadata])
        
        # Should not contain unescaped script tags
        self.assertNotIn("<script>alert('xss')</script>", report)
        self.assertNotIn("<script>alert('test')</script>", report)
        
        # Should contain escaped versions
        self.assertIn("&lt;script&gt;", report)
    
    def test_css_styling(self):
        """Test that HTML report includes CSS styling."""
        report = self.reporter.generate_report([self.sample_metadata])
        
        # Should include CSS
        self.assertIn("<style>", report)
        self.assertIn("</style>", report)
        
        # Should have some basic styling
        self.assertIn("color:", report)
        self.assertIn("font-family:", report)


class TestCSVReporter(unittest.TestCase):
    """Test the CSV reporter."""
    
    def setUp(self):
        """Set up test data."""
        self.reporter = CSVReporter()
        
        self.sample_metadata = [
            FileMetadata(
                file_path="/test/file1.txt",
                file_type="document",
                file_size=1024,
                mime_type="text/plain",
                findings=[
                    MetadataFinding(
                        type="privacy",
                        description="Email found",
                        severity="medium",
                        data={"email": "test@example.com"}
                    )
                ]
            ),
            FileMetadata(
                file_path="/test/file2.jpg",
                file_type="image",
                file_size=2048,
                mime_type="image/jpeg",
                findings=[]
            )
        ]
    
    def test_generate_csv_report(self):
        """Test generating CSV report."""
        report = self.reporter.generate_report(self.sample_metadata)
        
        self.assertIsInstance(report, str)
        
        # Should contain CSV headers
        lines = report.strip().split('\n')
        headers = lines[0].split(',')
        
        expected_headers = ['file_path', 'file_type', 'file_size', 'mime_type', 'findings_count']
        for header in expected_headers:
            self.assertIn(header, headers)
        
        # Should have data rows
        self.assertGreater(len(lines), 1)
        self.assertIn('file1.txt', report)
        self.assertIn('file2.jpg', report)
    
    def test_csv_format_validation(self):
        """Test that generated CSV is properly formatted."""
        report = self.reporter.generate_report(self.sample_metadata)
        
        # Should be parseable as CSV
        csv_reader = csv.DictReader(StringIO(report))
        rows = list(csv_reader)
        
        self.assertEqual(len(rows), 2)
        
        # Check first row
        row1 = rows[0]
        self.assertIn('file1.txt', row1['file_path'])
        self.assertEqual(row1['file_type'], 'document')
        self.assertEqual(row1['findings_count'], '1')
        
        # Check second row
        row2 = rows[1]
        self.assertIn('file2.jpg', row2['file_path'])
        self.assertEqual(row2['file_type'], 'image')
        self.assertEqual(row2['findings_count'], '0')
    
    def test_csv_special_characters(self):
        """Test CSV handling of special characters."""
        special_metadata = FileMetadata(
            file_path='/test/file,with"comma.txt',
            file_type="document",
            file_size=100,
            mime_type="text/plain"
        )
        
        report = self.reporter.generate_report([special_metadata])
        
        # Should be parseable despite special characters
        csv_reader = csv.DictReader(StringIO(report))
        rows = list(csv_reader)
        
        self.assertEqual(len(rows), 1)
        self.assertIn('comma', rows[0]['file_path'])


class TestReporterSystem(unittest.TestCase):
    """Test the reporter selection system."""
    
    def setUp(self):
        """Set up test data."""
        self.sample_metadata = FileMetadata(
            file_path="/test/sample.txt",
            file_type="document",
            file_size=1024,
            mime_type="text/plain"
        )
    
    def test_get_reporter_by_format(self):
        """Test getting reporters by format name."""
        formats = ['text', 'json', 'html', 'csv']
        
        for format_name in formats:
            reporter = get_reporter(format_name)
            self.assertIsNotNone(reporter)
    
    def test_reporter_consistency(self):
        """Test that all reporters return string output."""
        formats = ['text', 'json', 'html', 'csv']
        
        for format_name in formats:
            reporter = get_reporter(format_name)
            if reporter:
                report = reporter.generate_report([self.sample_metadata])
                self.assertIsInstance(report, str)
                self.assertGreater(len(report), 0)


class TestReporterIntegration(unittest.TestCase):
    """Integration tests for reporters with complex data."""
    
    def setUp(self):
        """Set up complex test data."""
        self.complex_metadata = [
            FileMetadata(
                file_path="/sensitive/document.pdf",
                file_type="document",
                file_size=5242880,  # 5MB
                mime_type="application/pdf",
                hashes={
                    "md5": "5d41402abc4b2a76b9719d911017c592",
                    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
                },
                findings=[
                    MetadataFinding(
                        type="privacy",
                        description="Email addresses detected",
                        severity="high",
                        data={"matches": ["john@company.com", "admin@corp.org"]}
                    ),
                    MetadataFinding(
                        type="privacy", 
                        description="Phone numbers found",
                        severity="medium",
                        data={"matches": ["555-123-4567", "(555) 987-6543"]}
                    ),
                    MetadataFinding(
                        type="security",
                        description="Potential SSN detected",
                        severity="high",
                        data={"pattern": "XXX-XX-XXXX", "count": 2}
                    )
                ]
            ),
            FileMetadata(
                file_path="/images/photo.jpg",
                file_type="image",
                file_size=1048576,  # 1MB
                mime_type="image/jpeg",
                findings=[
                    MetadataFinding(
                        type="privacy",
                        description="GPS coordinates found in EXIF",
                        severity="high",
                        data={"latitude": 40.7128, "longitude": -74.0060}
                    )
                ]
            ),
            FileMetadata(
                file_path="/clean/readme.txt",
                file_type="document",
                file_size=1024,
                mime_type="text/plain",
                findings=[]
            )
        ]
    
    def test_comprehensive_text_report(self):
        """Test comprehensive text report generation."""
        reporter = TextReporter()
        report = reporter.generate_report(self.complex_metadata)
        
        self.assertIn("3 files analyzed", report)
        self.assertIn("document.pdf", report)
        self.assertIn("photo.jpg", report)
        self.assertIn("readme.txt", report)
        self.assertIn("Email addresses detected", report)
        self.assertIn("GPS coordinates", report)
        self.assertIn("HIGH", report)
        self.assertIn("MEDIUM", report)
    
    def test_comprehensive_json_report(self):
        """Test comprehensive JSON report generation."""
        reporter = JSONReporter()
        report = reporter.generate_report(self.complex_metadata)
        
        data = json.loads(report)
        
        self.assertEqual(len(data["files"]), 3)
        self.assertEqual(data["summary"]["total_files"], 3)
        self.assertEqual(data["summary"]["files_with_findings"], 2)
        self.assertGreater(data["summary"]["total_findings"], 0)
        
        # Check findings distribution
        high_severity = sum(1 for f in data["files"] 
                          for finding in f["findings"] 
                          if finding["severity"] == "high")
        self.assertGreater(high_severity, 0)
    
    def test_comprehensive_html_report(self):
        """Test comprehensive HTML report generation."""
        reporter = HTMLReporter()
        report = reporter.generate_report(self.complex_metadata)
        
        # Should be valid HTML
        self.assertIn("<!DOCTYPE html>", report)
        self.assertIn("</html>", report)
        
        # Should contain all files
        self.assertIn("document.pdf", report)
        self.assertIn("photo.jpg", report)
        self.assertIn("readme.txt", report)
        
        # Should have severity styling
        self.assertIn("high", report.lower())
        self.assertIn("medium", report.lower())
    
    def test_comprehensive_csv_report(self):
        """Test comprehensive CSV report generation."""
        reporter = CSVReporter()
        report = reporter.generate_report(self.complex_metadata)
        
        csv_reader = csv.DictReader(StringIO(report))
        rows = list(csv_reader)
        
        self.assertEqual(len(rows), 3)
        
        # Check findings counts
        pdf_row = next(r for r in rows if 'document.pdf' in r['file_path'])
        self.assertEqual(pdf_row['findings_count'], '3')
        
        jpg_row = next(r for r in rows if 'photo.jpg' in r['file_path'])
        self.assertEqual(jpg_row['findings_count'], '1')
        
        txt_row = next(r for r in rows if 'readme.txt' in r['file_path'])
        self.assertEqual(txt_row['findings_count'], '0')


if __name__ == "__main__":
    unittest.main() 