#!/usr/bin/env python3
"""
MetaScout Component Verification Script

This script checks and displays all registered extractors and analyzers in MetaScout.
It verifies that all components have been properly integrated.

Usage:
    python metascout_verify.py
"""

import sys
import inspect
from pathlib import Path
from importlib import import_module

# ANSI colors for pretty output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print a formatted header."""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD} {text} {Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")

def print_subheader(text):
    """Print a formatted subheader."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{text}{Colors.ENDC}\n")

def print_success(text):
    """Print a success message."""
    print(f"  {Colors.GREEN}✓ {text}{Colors.ENDC}")

def print_warning(text):
    """Print a warning message."""
    print(f"  {Colors.YELLOW}⚠ {text}{Colors.ENDC}")

def print_error(text):
    """Print an error message."""
    print(f"  {Colors.RED}✗ {text}{Colors.ENDC}")

def verify_metascout_installation():
    """Verify that MetaScout is installed correctly."""
    print_header("Verifying MetaScout Installation")
    
    try:
        # Try to import metascout
        import metascout
        print_success(f"MetaScout installed at: {Path(metascout.__file__).parent}")
        
        # Check version
        print_success(f"Version: {metascout.__version__}")
        
        return True
    except ImportError:
        print_error("MetaScout is not installed or not in PYTHONPATH")
        return False

def verify_extractors():
    """Verify all registered extractors."""
    print_header("Verifying Extractors")
    
    try:
        # Import the extractors
        from metascout.extractors import EXTRACTORS, get_extractor_for_file
        
        # Print all extractors
        print_subheader(f"Found {len(EXTRACTORS)} registered extractors:")
        
        # For each extractor, print details
        for idx, extractor_class in enumerate(EXTRACTORS, 1):
            print(f"{idx}. {extractor_class.__name__}")
            
            # Check if the extractor has the required methods
            if hasattr(extractor_class, 'can_handle') and hasattr(extractor_class, 'extract'):
                print_success("Has required methods: can_handle(), extract()")
            else:
                print_error("Missing required methods")
            
            # Print the module
            print(f"   Module: {extractor_class.__module__}")
            
            # Print the file
            module = import_module(extractor_class.__module__)
            if hasattr(module, '__file__'):
                print(f"   File: {module.__file__}")
            
            print()  # Empty line between extractors
        
        return True
    except (ImportError, AttributeError) as e:
        print_error(f"Error verifying extractors: {str(e)}")
        return False

def verify_analyzers():
    """Verify all registered analyzers."""
    print_header("Verifying Analyzers")
    
    try:
        # Import the analyzers
        from metascout.analyzers import ANALYZERS, get_analyzers_for_file_type
        
        # Print all analyzers
        print_subheader(f"Found {len(ANALYZERS)} registered analyzers:")
        
        # For each analyzer, print details
        for idx, analyzer_class in enumerate(ANALYZERS, 1):
            print(f"{idx}. {analyzer_class.__name__}")
            
            # Check if the analyzer has the required methods
            if hasattr(analyzer_class, 'can_handle') and hasattr(analyzer_class, 'analyze'):
                print_success("Has required methods: can_handle(), analyze()")
            else:
                print_error("Missing required methods")
            
            # Print the module
            print(f"   Module: {analyzer_class.__module__}")
            
            # Print the file
            module = import_module(analyzer_class.__module__)
            if hasattr(module, '__file__'):
                print(f"   File: {module.__file__}")
            
            print()  # Empty line between analyzers
        
        return True
    except (ImportError, AttributeError) as e:
        print_error(f"Error verifying analyzers: {str(e)}")
        return False

def verify_operations():
    """Verify all operations are exposed."""
    print_header("Verifying Operations")
    
    operations = [
        ('analyze', ['write_report', 'format_findings', 'generate_html_report', 'generate_text_report']),
        ('batch', ['process_directory', 'filter_files']),
        ('compare', ['compare_metadata', 'generate_comparison_html']),
        ('redact', ['redact_metadata'])
    ]
    
    all_verified = True
    
    for module_name, function_names in operations:
        try:
            # Import the module
            module = import_module(f"metascout.operations.{module_name}")
            
            print_subheader(f"Operations in {module_name}.py:")
            
            # Check each function
            for function_name in function_names:
                if hasattr(module, function_name):
                    # Get the function
                    function = getattr(module, function_name)
                    
                    # Check if it's a function
                    if callable(function):
                        # Get signature and docstring
                        sig = inspect.signature(function)
                        doc = inspect.getdoc(function)
                        
                        print_success(f"{function_name}{sig}")
                        
                        # Print short docstring summary if available
                        if doc:
                            doc_summary = doc.split('\n')[0]
                            print(f"   {doc_summary}")
                    else:
                        print_error(f"{function_name} is not callable")
                        all_verified = False
                else:
                    print_error(f"{function_name} not found in {module_name}.py")
                    all_verified = False
            
            print()  # Empty line between modules
            
        except ImportError as e:
            print_error(f"Could not import metascout.operations.{module_name}: {str(e)}")
            all_verified = False
    
    # Check if all operations are exposed in __init__.py
    try:
        # Import the module
        from metascout.operations import __all__ as exposed_operations
        
        print_subheader("Operations exposed in __init__.py:")
        
        # Create a flat list of all expected operations
        expected_operations = [func for _, funcs in operations for func in funcs]
        
        # Check each operation
        for operation in expected_operations:
            if operation in exposed_operations:
                print_success(f"{operation} is exposed")
            else:
                print_error(f"{operation} is not exposed in __init__.py")
                all_verified = False
        
        # Check for any unexpected operations
        for operation in exposed_operations:
            if operation not in expected_operations:
                print_warning(f"{operation} is exposed but not expected")
        
    except ImportError as e:
        print_error(f"Could not import metascout.operations: {str(e)}")
        all_verified = False
    
    return all_verified

def verify_file_processing():
    """Verify that basic file processing works."""
    print_header("Verifying File Processing")
    
    try:
        # Import the necessary functions
        from metascout import process_file
        
        # Create a simple test file
        import tempfile
        
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"This is a test file for MetaScout verification.")
            test_file = f.name
        
        print_subheader(f"Testing process_file with {Path(test_file).name}")
        
        # Try to process the file
        result = process_file(test_file)
        
        # Check the result
        if result and hasattr(result, 'file_path') and result.file_path == test_file:
            print_success("process_file returned a valid FileMetadata object")
            print(f"   File type: {result.file_type}")
            print(f"   MIME type: {result.mime_type}")
            print(f"   File size: {result.file_size} bytes")
            print(f"   Findings: {len(result.findings)}")
        else:
            print_error("process_file did not return a valid FileMetadata object")
        
        # Clean up
        Path(test_file).unlink()
        
        return True
    except Exception as e:
        print_error(f"Error verifying file processing: {str(e)}")
        return False

def main():
    """Run the MetaScout component verification."""
    print_header("MetaScout Component Verification")
    
    # Verify each component
    installation_ok = verify_metascout_installation()
    
    if not installation_ok:
        print_error("MetaScout installation verification failed. Cannot continue.")
        return 1
    
    extractors_ok = verify_extractors()
    analyzers_ok = verify_analyzers()
    operations_ok = verify_operations()
    processing_ok = verify_file_processing()
    
    # Print summary
    print_header("Verification Summary")
    
    if installation_ok:
        print_success("MetaScout installation: OK")
    else:
        print_error("MetaScout installation: FAILED")
    
    if extractors_ok:
        print_success("Extractors: OK")
    else:
        print_error("Extractors: FAILED")
    
    if analyzers_ok:
        print_success("Analyzers: OK")
    else:
        print_error("Analyzers: FAILED")
    
    if operations_ok:
        print_success("Operations: OK")
    else:
        print_error("Operations: FAILED")
    
    if processing_ok:
        print_success("File processing: OK")
    else:
        print_error("File processing: FAILED")
    
    # Overall result
    if all([installation_ok, extractors_ok, analyzers_ok, operations_ok, processing_ok]):
        print_header("MetaScout Verification Completed Successfully")
        return 0
    else:
        print_header("MetaScout Verification Failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())