# MetaScout

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/) [![Metadata](https://img.shields.io/badge/Analysis-EXIF%20%7C%20PDF%20%7C%20ID3-green?style=for-the-badge&logo=files)](https://en.wikipedia.org/wiki/Metadata) [![Security](https://img.shields.io/badge/Security-Privacy%20%7C%20PII%20Detection-red?style=for-the-badge&logo=shield)](https://en.wikipedia.org/wiki/Personally_identifiable_information) [![CLI](https://img.shields.io/badge/Interface-CLI-purple?style=for-the-badge&logo=powershell)](https://docs.python.org/3/library/argparse.html) [![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE) 


## Project Overview

**MetaScout** is a comprehensive metadata security analyzer designed for detecting, analyzing, and securing sensitive information hidden in file metadata across multiple file formats. The tool extracts deep metadata from images, documents, PDFs, audio, video, and executable files, identifying privacy risks and security concerns while providing reporting and redaction capabilities.

## Installation

MetaScout requires Python 3.8 or later and can be installed using several methods:

### Option 1: Install from PyPI (Recommended)

```bash
# Install the base package
pip install metascout

# Install with all optional dependencies
pip install "metascout[full]"

# Install specific feature sets
pip install "metascout[document,executable]"
```

### Option 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/ParleSec/metascout.git
cd metascout

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### Platform-Specific Considerations

#### Windows

On Windows, the package installs the `metascout.exe` script to your Python Scripts directory. If this directory is not in your PATH, you can:

```bash
# Add to PATH (PowerShell)
$env:PATH += ";$env:USERPROFILE\AppData\Roaming\Python\Python3x\Scripts"

# Or run with full path
$env:USERPROFILE\AppData\Roaming\Python\Python3x\Scripts\metascout.exe
```

#### Linux/macOS

On Unix-like systems, ensure you have the required build dependencies for certain optional packages:

```bash
# Ubuntu/Debian
sudo apt-get install python3-dev libmagic-dev libfuzzy-dev

# macOS (using Homebrew)
brew install libmagic ssdeep
```

### Available Feature Sets

MetaScout uses optional dependencies for specialized features:

- `document`: Dependencies for enhanced document analysis
- `executable`: Dependencies for executable file analysis
- `security`: Enhanced security analysis features (YARA, ssdeep)
- `full`: All optional dependencies

### Verifying Installation

After installation, verify that MetaScout is working correctly:

```bash
# Check version
metascout --version

# Run self-tests
metascout test

# Test analyze command with a sample file
metascout analyze path/to/any/file.jpg
```

### Troubleshooting

If you encounter installation issues, try these steps:

1. Ensure Python 3.8+ is installed and in your PATH:
   ```bash
   python --version
   ```

2. If you get "command not found" errors:
   ```bash
   # Find where the metascout script was installed
   pip show metascout
   
   # Use python module directly
   python -m metascout
   ```

3. For dependency issues with optional packages:
   ```bash
   # Skip problematic dependency
   pip install metascout --no-deps
   pip install -r requirements.txt --skip-failed
   ```

## Purpose & Motivation

### Why MetaScout Exists

Files contain more information than you can see. Behind the visible content lies metadata - information about who created the file, when, where, with what software, and sometimes even location data or personally identifiable information (PII). MetaScout exposes this hidden information to:

- Identify privacy leaks in files before sharing them
- Detect potential security risks in received documents
- Create clean copies of files with sensitive metadata removed
- Verify file authenticity and identify potential manipulation
- Support compliance requirements for handling personal data

MetaScout is particularly valuable for security professionals, privacy-conscious individuals, and organizations that need to ensure documents they create or share don't contain unintentional leaks of sensitive information.

## Architecture

### System Structure

- `core/`: Core data models and processing logic
  - `models.py`: Data models for file metadata and findings
  - `processor.py`: Core file processing logic
  - `utils.py`: Utility functions for hashing, file operations, etc.
- `extractors/`: File-specific metadata extractors
  - `base.py`: Base extractor interface
  - `image.py`, `document.py`, `audio.py`, etc.: Format-specific extractors
- `analyzers/`: Analysis modules for different security concerns
  - `base.py`: Base analyzer interface
  - `pattern.py`: Pattern matching for PII detection
  - `image.py`, `document.py`, etc.: Format-specific analyzers
- `operations/`: High-level operations (analyze, batch, compare, redact)
- `reporters/`: Report generators for different output formats
- `config/`: Configuration and constants
- `cli.py`: Command-line interface

The modular design ensures each component has a single responsibility, making the codebase maintainable and extensible. New file formats, analysis techniques, or output formats can be added with minimal changes to the core system.

### Metadata Analysis Components

- **Extractors**: Format-specific modules that extract raw metadata
- **Analyzers**: Modules that evaluate metadata for privacy/security issues
- **Processors**: Core logic for orchestrating the analysis pipeline
- **Reporters**: Formatters for different output requirements

## Key Features

### 🔍 Deep Metadata Extraction

- EXIF data from images including GPS coordinates and device info
- Document properties from PDFs, Office documents (author, software, etc.)
- ID3 tags and embedded data in audio and video files
- Headers, libraries, and signatures from executable files

### 🚨 Privacy & Security Analysis

- PII detection through pattern matching (emails, phone numbers, SSNs)
- Location data detection in images and documents
- Suspicious patterns in executable files
- Document revision history and hidden content detection

### 📊 Comprehensive Reporting

- Multiple output formats (text, JSON, CSV, HTML)
- Severity-based finding classification (high, medium, low)
- Detailed file information including hashes and timestamps
- Visual reports with expandable sections in HTML format

### 🔄 Batch Processing & Comparison

- Recursive directory scanning with filtering
- Multi-threaded processing for large file collections
- Side-by-side metadata comparison between files
- Fuzzy hash comparison for similarity detection

### ✂️ Metadata Redaction

- Selective or complete metadata removal
- Creation of clean copies for sharing
- Preservation of essential metadata when needed
- Support for various file formats including images and PDFs

### 🔒 Advanced Analysis

- YARA integration for custom pattern detection
- Fuzzy hashing for file similarity analysis
- Detailed executable analysis for security risks
- Support for password-protected documents

## Example Code

```python
from metascout import process_file, process_files

# Analyze a single file
result = process_file("image.jpg")
print(f"Found {len(result.findings)} issues in {result.file_path}")

# Process findings
for finding in result.findings:
    if finding.severity == "high":
        print(f"[{finding.severity.upper()}] {finding.description}")
        for key, value in finding.data.items():
            print(f"  {key}: {value}")

# Batch process multiple files
results = process_files(["file1.pdf", "file2.docx", "file3.jpg"])
```

## Core Dependencies

- `pillow` - Image file handling and EXIF extraction
- `PyPDF2` - PDF metadata extraction and manipulation
- `mutagen` - Audio file metadata extraction
- `python-magic` - File type detection
- `exifread` - Enhanced EXIF data extraction
- `colorama` - Terminal color formatting
- `tabulate` - Table formatting for reports
- `tqdm` - Progress bars for batch processing

**Optional Dependencies:**
- `yara-python` - Pattern matching using YARA rules
- `ssdeep` - Fuzzy hash comparison
- `python-docx` / `openpyxl` - Office document analysis
- `pefile` / `pyelftools` / `macholib` - Executable analysis

## Usage & CLI

MetaScout CLI provides multiple commands for different metadata operations:

### Single File Analysis

```bash
# Basic file analysis with text output
metascout analyze image.jpg

# Generate an HTML report for a PDF
metascout analyze document.pdf --format html --output report.html

# Skip hash computation for faster analysis
metascout analyze large_file.mp4 --skip-hashes
```

Example output:
```
File: image.jpg
Path: /path/to/image.jpg
Type: image (image/jpeg)
Size: 2,345,678 bytes

Analysis Findings:
  [PRIVACY] GPS location data found in EXIF metadata
    source: EXIF
    field: GPSInfo
    
  [PRIVACY] Device information found
    device_info: {'Make': 'Apple', 'Model': 'iPhone 12'}
  
  [INFORMATION] Image creation timestamp found
    dates: {'DateTimeOriginal': '2025:04:15 14:32:45'}
```

### Batch Processing

```bash
# Process all files in a directory recursively
metascout batch /path/to/files --recursive

# Process only JPG files, excluding thumbnails
metascout batch /data/photos --filter "*.jpg" --exclude "*thumb*" --recursive

# Generate an HTML report for all documents
metascout batch /path/to/documents --format html --output report.html
```

### File Comparison

```bash
# Compare metadata between two files
metascout compare original.pdf modified.pdf

# Compare with HTML output
metascout compare file1.docx file2.docx --format html --output comparison.html

# Use fuzzy hashing for similarity detection
metascout compare original.jpg similar.jpg --fuzzy-hash
```

Example comparison output:

```

File Metadata Comparison Report
==============================

File 1: original.pdf
  Path: /path/to/original.pdf
  Type: document
  Size: 1,234,567 bytes
  MD5: a1b2c3d4e5f6...

File 2: modified.pdf
  Path: /path/to/modified.pdf
  Type: document
  Size: 1,245,678 bytes
  MD5: f6e5d4c3b2a1...

TIMESTAMPS
----------
  creation_time:
    File 1: 2025-04-10T12:34:56
    File 2: 2025-04-15T09:12:34

METADATA FIELDS
--------------
  document_info.Author:
    File 1: Original Author
    File 2: Modified Author
```

### Metadata Redaction

```bash
# Create a clean copy with all metadata removed
metascout redact confidential.jpg public.jpg

# Keep specific metadata fields while removing others
metascout redact document.pdf redacted.pdf --keep title author
```

### Additional Commands

```bash
# Get detailed information about global options
metascout --help

# Get detailed information about a specific command
metascout analyze --help

# Enable verbose output for any command
metascout analyze image.jpg --verbose
```

## Advanced Use Cases

### Privacy Audit Workflow

For organizations looking to audit documents for privacy compliance:

```bash
# 1. Scan a directory of documents for PII
metascout batch /path/to/documents --recursive --output audit.html --format html

# 2. Create clean versions of documents with issues
mkdir clean-documents
for file in $(grep -l "HIGH" audit.txt | cut -d ':' -f1); do
  metascout redact "$file" "clean-documents/$(basename "$file")" --keep title
done
```

### Security Investigation

For examining suspicious files:

```bash
# 1. Extract and analyze metadata from suspicious files
metascout analyze suspicious.exe --yara-rules security-rules.yar

# 2. Compare with known samples
metascout compare suspicious.exe reference.exe --fuzzy-hash
```

### Media File Management

For photographers or media professionals:

```bash
# 1. Check images for GPS data before posting online
for img in *.jpg; do
  metascout analyze "$img" --filter "GPS"
done

# 2. Create versions safe for sharing
mkdir web-safe
for img in *.jpg; do
  metascout redact "$img" "web-safe/$(basename "$img")" --keep copyright
done
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for more details.
