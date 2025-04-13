# MetaScout

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg) ![Python](https://img.shields.io/badge/python-3.8+-blue.svg) ![License](https://img.shields.io/badge/license-MIT-green.svg)

**Metadata Security Analyzer (metascout)** is an industry-leading command-line tool for extracting, analyzing, and securing file metadata across multiple file formats.

## Features

- **Comprehensive Metadata Extraction** - Deep metadata extraction from images, documents, PDFs, audio, video, and executable files
- **Security Analysis** - Identify privacy risks, security concerns, and suspicious patterns in file metadata
- **Multi-Format Support** - Process images, documents, audio, video, and executable files
- **Batch Processing** - Analyze entire directories of files with multi-threading support
- **File Comparison** - Compare metadata between files to identify changes or similarities
- **Metadata Redaction** - Create copies of files with sensitive metadata removed
- **Reporting Options** - Generate reports in text, JSON, CSV, or HTML formats
- **YARA Integration** - Use custom YARA rules for enhanced detection capabilities
- **Fuzzy Hashing** - Compare files using ssdeep fuzzy hashing to identify similarities

## Installation

```bash
# From PyPI
pip install metascout

# From source
git clone https://github.com/ParleSec/metascout.git
cd metascout
pip install .
```

## Dependencies

MetaScout requires the following core dependencies:
- pillow (for image file handling)
- PyPDF2 (for PDF file handling)
- python-magic (for file type detection)
- mutagen (for audio file metadata)
- colorama (for colorized output)
- tabulate (for table formatting)
- tqdm (for progress bars)

Additional optional dependencies provide enhanced functionality:
- ssdeep (for fuzzy hash comparison)
- yara-python (for pattern matching)
- python-docx, openpyxl (for Office document analysis)
- exifread (for enhanced EXIF extraction)
- pefile, pyelftools, macholib (for executable analysis)

## Usage

### Analyze a Single File

```bash
metascout analyze image.jpg
metascout analyze document.pdf --format json --output report.json
```

### Batch Process Multiple Files

```bash
metascout batch /path/to/directory --recursive
metascout batch /path/to/files --filter "*.jpg" --output photos_report.html --format html
```

### Compare Files

```bash
metascout compare original.pdf modified.pdf
metascout compare file1.docx file2.docx file3.docx --fuzzy-hash --format html --output comparison.html
```

### Redact Metadata

```bash
metascout redact sensitive.jpg clean.jpg
metascout redact confidential.pdf public.pdf --keep title author
```

## Command Reference

### Global Options
- `--verbose` - Enable verbose output
- `--quiet` - Suppress non-essential output 
- `--log-file FILE` - Specify log file (default: metascout.log)
- `--version` - Show version information

### `analyze` Command
Analyze a single file in detail.

```
metascout analyze FILE [OPTIONS]
```

Options:
- `--format FORMAT` - Output format: text, json, csv, html (default: text)
- `--output FILE` - Output file (default: stdout)
- `--skip-hashes` - Skip computing file hashes (faster)
- `--yara-rules PATH` - Path to YARA rules file or directory
- `--skip-analysis` - Extract metadata only without analysis

### `batch` Command
Process multiple files or directories.

```
metascout batch PATH [OPTIONS]
```

Options:
- `--recursive` - Process directories recursively
- `--format FORMAT` - Output format: text, json, csv, html (default: text)
- `--output FILE` - Output file (default: stdout)
- `--filter PATTERN` - Only process files matching this glob pattern
- `--exclude PATTERN` - Exclude files matching this glob pattern
- `--max-files N` - Maximum number of files to process
- `--threads N` - Number of worker threads (default: auto)
- `--yara-rules PATH` - Path to YARA rules file or directory

### `compare` Command
Compare metadata between two or more files.

```
metascout compare FILE1 FILE2 [FILE3...] [OPTIONS]
```

Options:
- `--format FORMAT` - Output format: text, json, html (default: text)
- `--output FILE` - Output file (default: stdout)
- `--fuzzy-hash` - Compare files using fuzzy hashing

### `redact` Command
Create a redacted copy with metadata removed.

```
metascout redact INPUT_FILE OUTPUT_FILE [OPTIONS]
```

Options:
- `--keep FIELDS` - Metadata fields to preserve (space-separated)

## Supported File Types

- **Images**: JPG, JPEG, PNG, TIFF, GIF, BMP, WebP
- **Documents**: PDF, DOCX, DOC, XLSX, XLS, PPTX, PPT, ODT
- **Audio**: MP3, WAV, FLAC, M4A, OGG, AAC
- **Video**: MP4, AVI, MKV, MOV, WMV
- **Executables**: EXE, DLL, SO, DYLIB
- **Scripts**: JS, PY, SH, PS1, BAT

## Examples

### Basic Analysis

```bash
# Analyze an image and show findings
metascout analyze photo.jpg

# Generate a detailed HTML report for a PDF document
metascout analyze document.pdf --format html --output document_report.html
```

### Batch Processing

```bash
# Process all files in a directory with recursive search
metascout batch /path/to/files --recursive

# Process only JPG files, excluding thumbnails
metascout batch /data/photos --filter "*.jpg" --exclude "*thumb*" --recursive
```

### Finding Privacy Issues

```bash
# Check an image for GPS/location data
metascout analyze vacation_photo.jpg

# Scan a directory of documents for personally identifiable information (PII)
metascout batch /path/to/documents --yara-rules privacy_rules.yar
```

### Security Auditing

```bash
# Check an executable for suspicious patterns
metascout analyze application.exe --yara-rules security_rules.yar

# Verify document integrity
metascout compare original.docx suspected_modified.docx --fuzzy-hash
```

### Creating Safe Copies for Sharing

```bash
# Create a clean version of an image with all metadata removed
metascout redact confidential.jpg public.jpg

# Create a PDF with only essential metadata preserved
metascout redact classified.pdf shareable.pdf --keep title author
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues, questions, or feature requests, please open an issue on the GitHub repository.