"""
Command-line interface for MetaScout
"""

import os
import sys
import argparse
import logging
import textwrap
from typing import Dict, List, Any, Optional

from .core.utils import configure_logging
from .core.models import FileMetadata
from .core.processor import process_file, process_files
from .core.exceptions import (
    MetaScoutError, FileNotFoundError, ValidationError, 
    format_error_for_cli, format_error_for_json
)
from .config.constants import VERSION, SUPPORTED_EXTENSIONS
from .operations.analyze import write_report
from .operations.compare import compare_metadata, generate_comparison_html
from .operations.redact import redact_metadata


def main() -> int:
    """Run the MetaScout CLI Tool."""
    # Create parser with subcommands
    parser = argparse.ArgumentParser(
        description=f"MetaScout v{VERSION} - Advanced File Metadata Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f'''
        Examples:
          metascout analyze image.jpg
          metascout analyze --format json --output report.json document.pdf
          metascout batch --recursive /path/to/directory --output report.html --format html
          metascout compare original.pdf modified.pdf
          
        Supported file types:
          Images: {', '.join(SUPPORTED_EXTENSIONS['images'])}
          Documents: {', '.join(SUPPORTED_EXTENSIONS['documents'])}
          Audio: {', '.join(SUPPORTED_EXTENSIONS['audio'])}
          Video: {', '.join(SUPPORTED_EXTENSIONS['video'])}
          Executables: {', '.join(SUPPORTED_EXTENSIONS['executables'])}
        ''')
    )
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress non-essential output')
    parser.add_argument('--log-file', default='metascout.log', help='Log file path')
    parser.add_argument('--version', action='version', version=f'MetaScout v{VERSION}')
    
    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # 'analyze' command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single file')
    analyze_parser.add_argument('file', help='Path to the file to analyze')
    analyze_parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], default='text',
                               help='Output format (default: text)')
    analyze_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    analyze_parser.add_argument('--skip-hashes', action='store_true', help='Skip computing file hashes')
    analyze_parser.add_argument('--yara-rules', help='Path to YARA rules file or directory')
    analyze_parser.add_argument('--skip-analysis', action='store_true', help='Skip analysis, extract metadata only')
    
    # 'batch' command
    batch_parser = subparsers.add_parser('batch', help='Process multiple files or directories')
    batch_parser.add_argument('path', help='Path to file or directory to process')
    batch_parser.add_argument('--recursive', '-r', action='store_true', help='Process directories recursively')
    batch_parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], default='text',
                             help='Output format (default: text)')
    batch_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    batch_parser.add_argument('--skip-hashes', action='store_true', help='Skip computing file hashes')
    batch_parser.add_argument('--threads', type=int, default=0, 
                             help='Number of worker threads (default: auto)')
    batch_parser.add_argument('--filter', help='Only process files matching this glob pattern')
    batch_parser.add_argument('--exclude', help='Exclude files matching this glob pattern')
    batch_parser.add_argument('--max-files', type=int, default=0, 
                             help='Maximum number of files to process (0 = unlimited)')
    batch_parser.add_argument('--yara-rules', help='Path to YARA rules file or directory')
    
    # 'compare' command
    compare_parser = subparsers.add_parser('compare', help='Compare metadata between files')
    compare_parser.add_argument('files', nargs='+', help='Files to compare')
    compare_parser.add_argument('--format', choices=['text', 'json', 'html'], default='text',
                               help='Output format (default: text)')
    compare_parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    compare_parser.add_argument('--fuzzy-hash', action='store_true', 
                               help='Compare files using fuzzy hashing')
    
    # 'redact' command
    redact_parser = subparsers.add_parser('redact', help='Create a redacted copy with metadata removed')
    redact_parser.add_argument('input_file', help='Input file to redact')
    redact_parser.add_argument('output_file', help='Output file path')
    redact_parser.add_argument('--keep', nargs='+', help='Metadata fields to preserve')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.quiet:
        log_level = logging.WARNING
    
    configure_logging(args.log_file, args.verbose and not args.quiet)
    
    from colorama import Fore, Style
    
    # Show banner unless quiet mode
    if not args.quiet:
        print(f"{Fore.CYAN}MetaScout v{VERSION}{Style.RESET_ALL} - Advanced File Metadata Analysis Tool")
        print(f"{'=' * 60}")
    
    # Process command
    if args.command == 'analyze':
        return handle_analyze_command(args)
    elif args.command == 'batch':
        return handle_batch_command(args)
    elif args.command == 'compare':
        return handle_compare_command(args)
    elif args.command == 'redact':
        return handle_redact_command(args)
    else:
        # No command specified, show help
        parser.print_help()
    
    return 0


def handle_analyze_command(args: argparse.Namespace) -> int:
    """Handle 'analyze' command."""
    try:
        # Validate input file
        file_path = os.path.abspath(os.path.normpath(args.file))
        if not os.path.exists(file_path):
            raise FileNotFoundError(file_path)
        if not os.path.isfile(file_path):
            raise ValidationError("file", file_path, "must be a file, not a directory")
        
        # Set up options
        options = {
            'skip_hashes': args.skip_hashes,
            'skip_analysis': args.skip_analysis,
            'yara_rules_path': args.yara_rules
        }
        
        # Process the file
        result = process_file(file_path, options)
        
        # Check for errors in the result and display them user-friendly
        if result.errors:
            for error_dict in result.errors:
                if isinstance(error_dict, dict):
                    print(f"⚠️  {error_dict.get('message', 'Unknown error occurred')}")
                    if args.verbose and error_dict.get('details'):
                        print(f"   Technical details: {error_dict['details']}")
                    if error_dict.get('suggestions'):
                        print("   Suggestions:")
                        for suggestion in error_dict['suggestions']:
                            print(f"   • {suggestion}")
                else:
                    print(f"⚠️  {error_dict}")
        
        # Output results
        write_report([result], args.format, args.output)
        return 0
        
    except MetaScoutError as e:
        print(format_error_for_cli(e, args.verbose))
        return 1
    except Exception as e:
        error_msg = format_error_for_cli(e, args.verbose)
        print(error_msg)
        return 1


def handle_batch_command(args: argparse.Namespace) -> int:
    """Handle 'batch' command."""
    try:
        path = os.path.abspath(os.path.normpath(args.path))
        
        # Validate input path
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        
        if os.path.isfile(path):
            # Single file mode
            files = [path]
        elif os.path.isdir(path):
            # Directory mode
            try:
                if args.recursive:
                    # Recursive walk
                    files = []
                    for root, _, filenames in os.walk(path):
                        for filename in filenames:
                            files.append(os.path.join(root, filename))
                else:
                    # Non-recursive (just top directory)
                    files = [os.path.join(path, f) for f in os.listdir(path) 
                            if os.path.isfile(os.path.join(path, f))]
            except PermissionError as e:
                raise MetaScoutError(
                    f"Permission denied accessing directory: {path}",
                    str(e),
                    [
                        "Check directory permissions",
                        "Run with appropriate privileges",
                        "Try a different directory"
                    ]
                )
            
            # Apply file filters if specified
            if args.filter:
                import fnmatch
                original_count = len(files)
                files = [f for f in files if fnmatch.fnmatch(os.path.basename(f), args.filter)]
                if not args.quiet:
                    print(f"📁 Filter applied: {len(files)} files match pattern '{args.filter}' (from {original_count} total)")
            
            if args.exclude:
                import fnmatch
                original_count = len(files)
                files = [f for f in files if not fnmatch.fnmatch(os.path.basename(f), args.exclude)]
                if not args.quiet:
                    print(f"📁 Exclusion applied: {len(files)} files remaining after excluding '{args.exclude}' (from {original_count})")
            
            # Apply max files limit if specified
            if args.max_files > 0 and len(files) > args.max_files:
                if not args.quiet:
                    print(f"📁 Limiting to {args.max_files} files out of {len(files)} found")
                files = files[:args.max_files]
        else:
            raise ValidationError("path", path, "must be a file or directory")
        
        if not files:
            raise MetaScoutError(
                "No files found to process",
                None,
                [
                    "Check that the directory contains files",
                    "Verify file filters are not too restrictive",
                    "Try using --recursive for subdirectories",
                    "Check file permissions"
                                 ]
             )
        
        # Set up options
        options = {
            'skip_hashes': args.skip_hashes,
            'max_workers': args.threads if args.threads > 0 else None,
            'show_progress': not args.quiet,
            'yara_rules_path': args.yara_rules
        }
        
        # Process files
        if not args.quiet:
            print(f"📊 Processing {len(files)} files...")
        
        results = process_files(files, options)
        
        # Display summary of errors if any
        total_errors = sum(len(result.errors) for result in results if result.errors)
        if total_errors > 0 and not args.quiet:
            print(f"⚠️  {total_errors} errors occurred during processing. Check the output for details.")
        
        # Output results
        write_report(results, args.format, args.output)
        return 0
        
    except MetaScoutError as e:
        print(format_error_for_cli(e, args.verbose))
        return 1
    except Exception as e:
        error_msg = format_error_for_cli(e, args.verbose)
        print(error_msg)
        return 1


def handle_compare_command(args: argparse.Namespace) -> int:
    """Handle 'compare' command."""
    # Compare metadata between files
    if len(args.files) < 2:
        logging.error("Error: At least two files are required for comparison.")
        return 1
    
    # Normalize paths
    file_paths = [os.path.abspath(os.path.normpath(f)) for f in args.files]
    
    # Validate files
    for file_path in file_paths:
        if not os.path.isfile(file_path):
            logging.error(f"Error: '{file_path}' is not a valid file.")
            return 1
    
    # Process files
    options = {'skip_analysis': True}  # Initial metadata extraction only
    results = []
    
    for file_path in file_paths:
        results.append(process_file(file_path, options))
    
    # Perform comparison
    comparison_results = compare_metadata(results, use_fuzzy_hash=args.fuzzy_hash)
    
    # Output comparison
    if args.format == 'json':
        import json
        output = json.dumps(comparison_results, indent=2, default=str)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"Comparison report written to {args.output}")
        else:
            print(output)
    elif args.format == 'html':
        # Generate HTML comparison report
        html_output = generate_comparison_html(comparison_results, file_paths)
        
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(html_output)
            print(f"Comparison report written to {args.output}")
        else:
            print(html_output)
    else:
        # Text output - would be implemented in operations/compare.py
        import json  # Temporary until text output is implemented
        print(json.dumps(comparison_results, indent=2, default=str))
    
    return 0


def handle_redact_command(args: argparse.Namespace) -> int:
    """Handle 'redact' command."""
    # Create redacted copy of a file
    input_path = os.path.abspath(os.path.normpath(args.input_file))
    output_path = os.path.abspath(os.path.normpath(args.output_file))
    
    if not os.path.isfile(input_path):
        logging.error(f"Error: Input file '{input_path}' does not exist.")
        return 1
    
    # Get fields to keep
    keep_fields = args.keep if args.keep else []
    
    # Perform redaction
    success = redact_metadata(input_path, output_path, keep_fields)
    
    if success:
        print(f"Created redacted copy at '{output_path}'")
        
        # Analyze the redacted file to confirm
        if not args.quiet:
            print("\nAnalysis of redacted file:")
            result = process_file(output_path)
            write_report([result], 'text')
    else:
        logging.error("Redaction failed. See log for details.")
        return 1
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)