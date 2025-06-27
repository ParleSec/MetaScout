# MetaScout Test Suite

This directory contains the comprehensive test suite for MetaScout.

## Running Tests

### Quick Start

Run all tests with the custom test runner:

```bash
python tests/run_tests.py
```

### Test Runner Options

- **Verbose output**: `python tests/run_tests.py --verbose`
- **Quiet output**: `python tests/run_tests.py --quiet`
- **Check dependencies**: `python tests/run_tests.py --check-deps`

### Alternative Methods

Run tests using unittest directly:

```bash
# Run all tests
python -m unittest discover tests -v

# Run specific test file
python -m unittest tests.test_core -v

# Run specific test class
python -m unittest tests.test_core.TestCoreUtils -v

# Run specific test method
python -m unittest tests.test_core.TestCoreUtils.test_compute_file_hashes -v
```

## Test Files

- **`basic.py`** - Basic functionality tests (legacy, for compatibility)
- **`test_core.py`** - Core functionality tests (models, utils, processor)
- **`test_analyzers.py`** - Analyzer and pattern matching tests
- **`run_tests.py`** - Custom test runner with colored output

## Test Structure

### Core Tests (`test_core.py`)
- **TestCoreModels**: Data model creation and serialization
- **TestCoreUtils**: Utility functions (hashes, file types, timestamps)
- **TestCoreProcessor**: File processing workflow

### Analyzer Tests (`test_analyzers.py`)
- **TestPatternAnalyzer**: Pattern detection (emails, phones, SSNs, etc.)
- **TestAnalyzerSystem**: Analyzer selection and integration
- **TestAdvancedPatterns**: Complex pattern scenarios

## Dependencies

The test suite requires all MetaScout dependencies to be installed. Optional dependencies may cause some tests to be skipped, but this is expected behavior.

### Required for Testing
- All packages in `requirements.txt`
- MetaScout modules properly importable

### Optional Dependencies
- `python-magic` - For file type detection (fallback available)
- `pyssdeep` - For fuzzy hashing (tests skip if unavailable)

## Test Coverage

The test suite covers:

✅ **Core Models** - FileMetadata, MetadataFinding  
✅ **Utility Functions** - Hashing, file type detection, timestamps  
✅ **File Processing** - Basic processing workflow  
✅ **Pattern Analysis** - Privacy-sensitive data detection  
✅ **Analyzer System** - Analyzer selection and integration  
✅ **Error Handling** - Graceful handling of missing files/dependencies  

## Adding New Tests

1. Create test files following the naming pattern `test_*.py`
2. Import test base classes and add project root to path:
   ```python
   import sys
   from pathlib import Path
   project_root = Path(__file__).parent.parent
   sys.path.insert(0, str(project_root))
   ```
3. Use `unittest.TestCase` as base class
4. Follow existing patterns for setup/teardown
5. Tests will be automatically discovered by the test runner

## Continuous Integration

The test suite is designed to:
- Run in CI/CD environments
- Handle missing optional dependencies gracefully  
- Provide detailed error reporting
- Exit with appropriate codes (0 = success, 1 = failure)

## Troubleshooting

### Import Errors
- Ensure you're running from the project root
- Check that all required dependencies are installed
- Verify MetaScout modules are properly structured

### Missing Dependencies
- Run `python tests/run_tests.py --check-deps` to diagnose
- Install missing packages with `pip install -r requirements.txt`

### Test Failures
- Run with `--verbose` flag for detailed output
- Check individual test files with unittest directly
- Review error messages in the test summary 