#!/usr/bin/env python3
"""
Example script demonstrating basic usage of the MetaScout package
"""

import os
import sys
import argparse

from metascout import process_file, process_files
from metascout.reporters import get_reporter
from metascout.operations.redact import redact_metadata


def analyze_single_file(file_path, output_format='text', output_file=None):
    """
    Analyze a single file and output results.
    
    Args:
        file_path: Path to file to analyze
        output_format: Output format (text, json, html, csv)
        output_file: Path to output file (None for stdout)
    """
    print(f"Analyzing file: {file_path}")
    
    # Process the file
    result = process_file(file_path)
    
    # Get appropriate reporter
    reporter = get_reporter(output_format)
    if not reporter:
        print(f"Error: Unsupported output format: {output_format}")
        return
    
    # Generate and write report
    reporter.write_report([result], output_file)


def analyze_directory(dir_path, recursive=False, output_format='text', output_file=None):
    """
    Analyze all files in a directory.
    
    Args:
        dir_path: Path to directory
        recursive: Whether to search recursively
        output_format: Output format (text, json, html, csv)
        output_file: Path to output file (None for stdout)
    """
    print(f"Analyzing directory: {dir_path} (recursive: {recursive})")
    
    # Collect files
    files = []
    if recursive:
        for root, _, filenames in os.walk(dir_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    else:
        files = [os.path.join(dir_path, f) for f in os.listdir(dir_path) 
                if os.path.isfile(os.path.join(dir_path, f))]
    
    print(f"Found {len(files)} files")
    
    # Process files
    results = process_files(files, {'show_progress': True})
    
    # Get appropriate reporter
    reporter = get_reporter(output_format)
    if not reporter:
        print(f"Error: Unsupported output format: {output_format}")
        return
    
    # Generate and write report
    reporter.write_report(results, output_file)


def redact_file(input_path, output_path, fields_to_keep=None):
    """
    Create a redacted copy of a file.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file
        fields_to_keep: List of metadata fields to preserve
    """
    print(f"Redacting file: {input_path} -> {output_path}")
    
    # Redact the file
    success = redact_metadata(input_path, output_path, fields_to_keep)
    
    if success:
        print(f"Successfully created redacted copy at: {output_path}")
        
        # Analyze the redacted file
        print("\nAnalysis of redacted file:")
        analyze_single_file(output_path)
    else:
        print("Error: Failed to redact file")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="MetaScout Example Script")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # 'analyze' command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single file")
    analyze_parser.add_argument("file", help="Path to file to analyze")
    analyze_parser.add_argument("--format", choices=["text", "json", "html", "csv"], default="text",
                              help="Output format (default: text)")
    analyze_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    
    # 'batch' command
    batch_parser = subparsers.add_parser("batch", help="Analyze multiple files in a directory")
    batch_parser.add_argument("directory", help="Path to directory to analyze")
    batch_parser.add_argument("--recursive", "-r", action="store_true", help="Search recursively")
    batch_parser.add_argument("--format", choices=["text", "json", "html", "csv"], default="text",
                             help="Output format (default: text)")
    batch_parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    
    # 'redact' command
    redact_parser = subparsers.add_parser("redact", help="Create redacted copy of a file")
    redact_parser.add_argument("input", help="Input file")
    redact_parser.add_argument("output", help="Output file")
    redact_parser.add_argument("--keep", nargs="+", help="Metadata fields to preserve")
    
    # Parse arguments
    args = parser.parse_args()
    
    if args.command == "analyze":
        analyze_single_file(args.file, args.format, args.output)
    elif args.command == "batch":
        analyze_directory(args.directory, args.recursive, args.format, args.output)
    elif args.command == "redact":
        redact_file(args.input, args.output, args.keep)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()