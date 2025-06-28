#!/usr/bin/env python3
"""
Test runner for MetaScout

This script runs all tests and provides a comprehensive test report.
"""

import os
import sys
import unittest
import time
from pathlib import Path
from io import StringIO

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test configuration
TEST_VERBOSITY = 2
TEST_PATTERN = "test_*.py"


class ColoredTextTestResult(unittest.TextTestResult):
    """A test result class that can print colored text."""
    
    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.verbosity = verbosity  # Store verbosity for our methods
        # Check if we can use colors (Windows/Unix)
        try:
            import colorama
            colorama.init()
            self.use_colors = True
        except ImportError:
            self.use_colors = False
    
    def _colored(self, text, color_code):
        """Return colored text if colors are supported."""
        if self.use_colors:
            return f"\033[{color_code}m{text}\033[0m"
        return text
    
    def addSuccess(self, test):
        super().addSuccess(test)
        if self.verbosity > 1:
            self.stream.write(self._colored("✓ ", "32"))  # Green
            self.stream.write(f"{test._testMethodName}\n")
    
    def addError(self, test, err):
        super().addError(test, err)
        if self.verbosity > 1:
            self.stream.write(self._colored("✗ ERROR ", "31"))  # Red
            self.stream.write(f"{test._testMethodName}\n")
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.verbosity > 1:
            self.stream.write(self._colored("✗ FAIL ", "31"))  # Red
            self.stream.write(f"{test._testMethodName}\n")
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.verbosity > 1:
            self.stream.write(self._colored("⚠ SKIP ", "33"))  # Yellow
            self.stream.write(f"{test._testMethodName}: {reason}\n")


def discover_tests():
    """Discover and return all test suites."""
    loader = unittest.TestLoader()
    test_dir = Path(__file__).parent
    
    # Discover all test files
    suite = loader.discover(
        start_dir=str(test_dir),
        pattern=TEST_PATTERN,
        top_level_dir=str(project_root)
    )
    
    return suite


def run_tests(verbosity=TEST_VERBOSITY):
    """Run all tests and return results."""
    # Discover tests
    suite = discover_tests()
    
    # Create test runner with colored output
    stream = sys.stdout
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=verbosity,
        resultclass=ColoredTextTestResult
    )
    
    print("=" * 70)
    print("MetaScout Test Suite")
    print("=" * 70)
    print()
    
    # Run tests
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Print summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    successful = total_tests - failures - errors - skipped
    
    print(f"Total Tests:     {total_tests}")
    print(f"Successful:      {successful}")
    print(f"Failures:        {failures}")
    print(f"Errors:          {errors}")
    print(f"Skipped:         {skipped}")
    print(f"Duration:        {end_time - start_time:.2f} seconds")
    
    # Calculate success rate
    if total_tests > 0:
        success_rate = (successful / total_tests) * 100
        print(f"Success Rate:    {success_rate:.1f}%")
    
    # Print details for failures and errors
    if result.failures:
        print("\n" + "-" * 50)
        print("FAILURES:")
        print("-" * 50)
        for test, traceback in result.failures:
            print(f"\n{test}:")
            print(traceback)
    
    if result.errors:
        print("\n" + "-" * 50)
        print("ERRORS:")
        print("-" * 50)
        for test, traceback in result.errors:
            print(f"\n{test}:")
            print(traceback)
    
    # Return overall success
    return failures == 0 and errors == 0


def check_dependencies():
    """Check if required dependencies are available."""
    print("Checking dependencies...")
    
    required_modules = [
        "metascout.core.models",
        "metascout.core.utils", 
        "metascout.core.processor",
        "metascout.analyzers",
        "metascout.extractors",
        "metascout.reporters"
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except ImportError as e:
            print(f"✗ {module}: {e}")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\nMissing modules: {missing_modules}")
        print("Please check your MetaScout installation.")
        return False
    
    print("All required modules available.\n")
    return True


def main():
    """Main test runner entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MetaScout Test Runner")
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true", 
        help="Quiet output"
    )
    parser.add_argument(
        "--check-deps",
        action="store_true",
        help="Check dependencies and exit"
    )
    
    args = parser.parse_args()
    
    # Set verbosity
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    else:
        verbosity = 1
    
    # Check dependencies if requested
    if args.check_deps:
        if check_dependencies():
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Check dependencies before running tests
    if not check_dependencies():
        print("Cannot run tests due to missing dependencies.")
        sys.exit(1)
    
    # Run tests
    success = run_tests(verbosity)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main() 