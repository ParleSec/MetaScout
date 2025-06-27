"""
Tests for MetaScout analyzer functionality
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add the project root to Python path for development testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from metascout.core.models import MetadataFinding
from metascout.analyzers.pattern import PatternAnalyzer
from metascout.analyzers.base import BaseAnalyzer
from metascout.analyzers import get_analyzers_for_file_type


class TestPatternAnalyzer(unittest.TestCase):
    """Test pattern analyzer functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.analyzer = PatternAnalyzer()
    
    def test_email_detection(self):
        """Test email pattern detection."""
        metadata = {
            "text_info": {
                "content": "Contact us at support@example.com or admin@test.org"
            },
            "document_info": {
                "author": "john.doe@company.com"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find email patterns
        email_findings = [f for f in findings if f.type == "privacy" and "email" in f.description.lower()]
        self.assertGreater(len(email_findings), 0)
        
        # Check that actual emails were found
        if email_findings:
            self.assertIn("matches", email_findings[0].data)
            matches = email_findings[0].data["matches"]
            self.assertIn("support@example.com", matches)
    
    def test_phone_number_detection(self):
        """Test phone number pattern detection."""
        metadata = {
            "contact_info": {
                "phone": "555-123-4567",
                "mobile": "(555) 987-6543"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find phone patterns
        phone_findings = [f for f in findings if f.type == "privacy" and "phone" in f.description.lower()]
        self.assertGreater(len(phone_findings), 0)
    
    def test_ssn_detection(self):
        """Test Social Security Number pattern detection."""
        metadata = {
            "personal_info": {
                "ssn": "123-45-6789"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find SSN patterns
        ssn_findings = [f for f in findings if "ssn" in f.description.lower()]
        self.assertGreater(len(ssn_findings), 0)
        
        if ssn_findings:
            self.assertEqual(ssn_findings[0].severity, "high")
    
    def test_url_detection(self):
        """Test URL pattern detection."""
        metadata = {
            "web_info": {
                "website": "https://www.example.com/page",
                "reference": "Visit http://test.org for more info"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find URL patterns
        url_findings = [f for f in findings if "url" in f.description.lower()]
        self.assertGreater(len(url_findings), 0)
    
    def test_no_patterns(self):
        """Test analyzer with metadata containing no sensitive patterns."""
        metadata = {
            "basic_info": {
                "title": "Document Title",
                "description": "A simple document without sensitive data"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should have few or no findings
        self.assertLessEqual(len(findings), 1)  # May have domain names
    
    def test_flatten_dict(self):
        """Test the dictionary flattening functionality."""
        nested_dict = {
            "level1": {
                "level2": {
                    "value": "test"
                },
                "simple": "data"
            },
            "list_data": ["item1", "item2"],
            "direct": "value"
        }
        
        flattened = self.analyzer._flatten_dict(nested_dict)
        
        self.assertIn("level1.level2.value", flattened)
        self.assertEqual(flattened["level1.level2.value"], "test")
        self.assertIn("level1.simple", flattened)
        self.assertEqual(flattened["level1.simple"], "data")
        self.assertIn("direct", flattened)
        self.assertEqual(flattened["direct"], "value")


class TestAnalyzerSystem(unittest.TestCase):
    """Test the analyzer system integration."""
    
    def test_get_analyzers_for_file_type(self):
        """Test getting analyzers for different file types."""
        # Test for image files
        image_analyzers = get_analyzers_for_file_type("image")
        self.assertGreater(len(image_analyzers), 0)
        
        # Test for document files
        doc_analyzers = get_analyzers_for_file_type("document")
        self.assertGreater(len(doc_analyzers), 0)
        
        # Test for other files (should include pattern analyzer)
        other_analyzers = get_analyzers_for_file_type("other")
        self.assertGreater(len(other_analyzers), 0)
        
        # All should be instances of BaseAnalyzer
        for analyzer in other_analyzers:
            self.assertIsInstance(analyzer, BaseAnalyzer)
    
    def test_analyzer_can_handle(self):
        """Test analyzer can_handle method."""
        # Pattern analyzer should handle any file type
        self.assertTrue(PatternAnalyzer.can_handle("image"))
        self.assertTrue(PatternAnalyzer.can_handle("document"))
        self.assertTrue(PatternAnalyzer.can_handle("other"))
    
    def test_analyzer_interface(self):
        """Test that analyzers implement the required interface."""
        analyzers = get_analyzers_for_file_type("other")
        
        for analyzer in analyzers:
            # Should have analyze method
            self.assertTrue(hasattr(analyzer, 'analyze'))
            self.assertTrue(callable(analyzer.analyze))
            
            # Should have can_handle class method
            self.assertTrue(hasattr(analyzer.__class__, 'can_handle'))
            self.assertTrue(callable(analyzer.__class__.can_handle))
    
    def test_analyzer_findings_format(self):
        """Test that analyzer findings are properly formatted."""
        analyzer = PatternAnalyzer()
        
        metadata = {
            "test": {
                "email": "test@example.com"
            }
        }
        
        findings = analyzer.analyze(metadata)
        
        for finding in findings:
            self.assertIsInstance(finding, MetadataFinding)
            self.assertIsInstance(finding.type, str)
            self.assertIsInstance(finding.description, str)
            self.assertIsInstance(finding.severity, str)
            self.assertIn(finding.severity, ["low", "medium", "high"])
            self.assertIsInstance(finding.data, dict)


class TestAdvancedPatterns(unittest.TestCase):
    """Test advanced pattern detection scenarios."""
    
    def setUp(self):
        """Set up test data."""
        self.analyzer = PatternAnalyzer()
    
    def test_credit_card_detection(self):
        """Test credit card number detection."""
        metadata = {
            "payment_info": {
                "card": "4111-1111-1111-1111",
                "note": "Card number 5555555555554444 on file"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find credit card patterns
        cc_findings = [f for f in findings if "credit" in f.description.lower()]
        self.assertGreater(len(cc_findings), 0)
    
    def test_ip_address_detection(self):
        """Test IP address detection."""
        metadata = {
            "network_info": {
                "server": "192.168.1.1",
                "external": "8.8.8.8",
                "logs": "Connection from 10.0.0.5"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find IP address patterns
        ip_findings = [f for f in findings if "ip" in f.description.lower()]
        self.assertGreater(len(ip_findings), 0)
    
    def test_mixed_patterns(self):
        """Test detection of multiple pattern types in same metadata."""
        metadata = {
            "mixed_data": {
                "content": "Contact John at john@example.com or call 555-123-4567. "
                           "Server IP: 192.168.1.100, Card: 4111-1111-1111-1111"
            }
        }
        
        findings = self.analyzer.analyze(metadata)
        
        # Should find multiple types of patterns
        pattern_types = set()
        for finding in findings:
            if "email" in finding.description.lower():
                pattern_types.add("email")
            elif "phone" in finding.description.lower():
                pattern_types.add("phone")
            elif "ip" in finding.description.lower():
                pattern_types.add("ip")
            elif "credit" in finding.description.lower():
                pattern_types.add("credit")
        
        self.assertGreater(len(pattern_types), 1)


if __name__ == "__main__":
    unittest.main() 