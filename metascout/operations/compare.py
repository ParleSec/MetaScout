"""
File comparison operations for MetaScout
"""

import os
import json
import datetime
import logging
from typing import List, Dict, Any, Set, Optional

from ..core.models import FileMetadata
from ..config.dependencies import OPTIONAL_DEPENDENCIES


def compare_metadata(results: List[FileMetadata], use_fuzzy_hash: bool = False) -> Dict[str, Any]:
    """
    Compare metadata between multiple files.
    
    Args:
        results: List of FileMetadata objects to compare
        use_fuzzy_hash: Whether to perform fuzzy hash comparison
        
    Returns:
        Dictionary containing comparison results
    """
    comparison = {
        'files': [r.file_path for r in results],
        'basic_info': {},
        'timestamps': {},
        'hashes': {},
        'metadata_fields': {},
        'differences': [],
        'similarities': []
    }
    
    # Compare basic info
    comparison['basic_info']['file_type'] = [r.file_type for r in results]
    comparison['basic_info']['mime_type'] = [r.mime_type for r in results]
    comparison['basic_info']['file_size'] = [r.file_size for r in results]
    
    # Compare timestamps
    comparison['timestamps']['creation_time'] = [r.creation_time for r in results]
    comparison['timestamps']['modification_time'] = [r.modification_time for r in results]
    comparison['timestamps']['access_time'] = [r.access_time for r in results]
    
    # Compare file hashes
    hash_types = set()
    for r in results:
        if r.hashes:
            hash_types.update(r.hashes.keys())
    
    for hash_type in hash_types:
        comparison['hashes'][hash_type] = [r.hashes.get(hash_type) if r.hashes else None for r in results]
    
    # Identify key metadata fields across all files
    all_metadata_fields = set()
    metadata_values = {}
    
    for r in results:
        # Flatten metadata structure
        flat_metadata = {}
        
        def flatten_dict(d, parent_key=''):
            if not isinstance(d, dict):
                return
                
            for k, v in d.items():
                new_key = f"{parent_key}.{k}" if parent_key else k
                if isinstance(v, dict):
                    flatten_dict(v, new_key)
                else:
                    flat_metadata[new_key] = v
        
        flatten_dict(r.metadata)
        all_metadata_fields.update(flat_metadata.keys())
        
        # Store values for comparison
        for field, value in flat_metadata.items():
            if field not in metadata_values:
                metadata_values[field] = [None] * len(results)
            metadata_values[field][results.index(r)] = value
    
    # Add metadata field comparisons
    for field, values in metadata_values.items():
        # Only include fields that exist in multiple files and have different values
        if sum(1 for v in values if v is not None) > 1:
            comparison['metadata_fields'][field] = values
    
    # Identify significant differences
    for field, values in comparison['metadata_fields'].items():
        unique_values = set(str(v) for v in values if v is not None)
        if len(unique_values) > 1:
            comparison['differences'].append({
                'field': field,
                'values': values
            })
    
    # Perform fuzzy hash comparison if requested
    if use_fuzzy_hash and OPTIONAL_DEPENDENCIES['pyssdeep']:
        try:
            import pyssdeep as ssdeep
            
            # Compute fuzzy hashes
            fuzzy_hashes = []
            for r in results:
                try:
                    hash_value = ssdeep.hash_from_file(r.file_path)
                    fuzzy_hashes.append(hash_value)
                except Exception as e:
                    logging.error(f"Error computing fuzzy hash for {r.file_path}: {e}")
                    fuzzy_hashes.append(None)
            
            # Compare each pair
            comparison['fuzzy_hash'] = {
                'hashes': fuzzy_hashes,
                'comparisons': []
            }
            
            for i in range(len(fuzzy_hashes)):
                for j in range(i+1, len(fuzzy_hashes)):
                    if fuzzy_hashes[i] and fuzzy_hashes[j]:
                        similarity = ssdeep.compare(fuzzy_hashes[i], fuzzy_hashes[j])
                        comparison['fuzzy_hash']['comparisons'].append({
                            'file1': os.path.basename(results[i].file_path),
                            'file2': os.path.basename(results[j].file_path),
                            'similarity': similarity
                        })
        except ImportError:
            comparison['fuzzy_hash'] = {
                'error': "ssdeep package not installed"
            }
        except Exception as e:
            comparison['fuzzy_hash'] = {
                'error': f"Error performing fuzzy hash comparison: {str(e)}"
            }
    
    return comparison


def generate_comparison_html(comparison_results: Dict[str, Any], file_paths: List[str]) -> str:
    """
    Generate HTML report for file comparison.
    
    Args:
        comparison_results: Results from compare_metadata
        file_paths: List of file paths that were compared
        
    Returns:
        HTML formatted report
    """
    file_names = [os.path.basename(path) for path in file_paths]
    
    html_parts = ['<!DOCTYPE html><html><head><title>Metadata Comparison Report</title>',
                 '<style>body{font-family:sans-serif;margin:20px;} .section{margin-bottom:20px;border:1px solid #ddd;padding:15px;border-radius:5px;}',
                 '.different{background-color:#ffe0e0;} table{border-collapse:collapse;width:100%;}',
                 'th,td{text-align:left;padding:8px;border-bottom:1px solid #ddd;} th{background-color:#f2f2f2;}</style></head><body>',
                 '<h1>Metadata Comparison Report</h1>']
    
    # Add generation timestamp
    html_parts.append(f'<p>Generated: {datetime.datetime.now().isoformat()}</p>')
    
    # Add file overview
    html_parts.append('<div class="section"><h2>Files</h2><table><tr><th>File</th><th>Path</th></tr>')
    for i, path in enumerate(file_paths):
        html_parts.append(f'<tr><td>File {i+1}</td><td>{path}</td></tr>')
    html_parts.append('</table></div>')
    
    # Add basic info section
    html_parts.append('<div class="section"><h2>Basic Information</h2><table><tr><th>Property</th>')
    for name in file_names:
        html_parts.append(f'<th>{name}</th>')
    html_parts.append('</tr>')
    
    if 'basic_info' in comparison_results:
        for prop, values in comparison_results['basic_info'].items():
            # Determine if values are different
            unique_values = set(str(v) for v in values if v is not None)
            row_class = ' class="different"' if len(unique_values) > 1 else ''
            
            html_parts.append(f'<tr{row_class}><td>{prop}</td>')
            for value in values:
                html_parts.append(f'<td>{value if value is not None else "N/A"}</td>')
            html_parts.append('</tr>')
    
    html_parts.append('</table></div>')
    
    # Add timestamps section
    if 'timestamps' in comparison_results:
        html_parts.append('<div class="section"><h2>Timestamps</h2><table><tr><th>Timestamp</th>')
        for name in file_names:
            html_parts.append(f'<th>{name}</th>')
        html_parts.append('</tr>')
        
        for timestamp, values in comparison_results['timestamps'].items():
            # Determine if values are different
            unique_values = set(str(v) for v in values if v is not None)
            row_class = ' class="different"' if len(unique_values) > 1 else ''
            
            html_parts.append(f'<tr{row_class}><td>{timestamp}</td>')
            for value in values:
                html_parts.append(f'<td>{value if value is not None else "N/A"}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</table></div>')
    
    # Add hashes section
    if 'hashes' in comparison_results:
        html_parts.append('<div class="section"><h2>File Hashes</h2><table><tr><th>Hash Type</th>')
        for name in file_names:
            html_parts.append(f'<th>{name}</th>')
        html_parts.append('</tr>')
        
        for hash_type, values in comparison_results['hashes'].items():
            # Determine if values are different
            unique_values = set(str(v) for v in values if v is not None)
            row_class = ' class="different"' if len(unique_values) > 1 else ''
            
            html_parts.append(f'<tr{row_class}><td>{hash_type}</td>')
            for value in values:
                html_parts.append(f'<td>{value if value is not None else "N/A"}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</table></div>')
    
    # Add fuzzy hash comparison if available
    if 'fuzzy_hash' in comparison_results:
        html_parts.append('<div class="section"><h2>Fuzzy Hash Comparison</h2>')
        
        if 'error' in comparison_results['fuzzy_hash']:
            html_parts.append(f'<p>Error: {comparison_results["fuzzy_hash"]["error"]}</p>')
        else:
            # Show raw hashes
            html_parts.append('<h3>Fuzzy Hashes</h3><table><tr><th>File</th><th>Fuzzy Hash</th></tr>')
            for i, hash_value in enumerate(comparison_results['fuzzy_hash']['hashes']):
                html_parts.append(f'<tr><td>{file_names[i]}</td><td>{hash_value if hash_value else "N/A"}</td></tr>')
            html_parts.append('</table>')
            
            # Show comparisons
            if 'comparisons' in comparison_results['fuzzy_hash']:
                html_parts.append('<h3>Similarity Analysis</h3><table><tr><th>File 1</th><th>File 2</th><th>Similarity</th></tr>')
                for comp in comparison_results['fuzzy_hash']['comparisons']:
                    similarity = comp['similarity']
                    color = '#ff9999' if similarity < 50 else '#ffcc99' if similarity < 80 else '#99ff99'
                    html_parts.append(f'<tr style="background-color:{color}"><td>{comp["file1"]}</td><td>{comp["file2"]}</td>'
                                    f'<td>{similarity}%</td></tr>')
                html_parts.append('</table>')
        
        html_parts.append('</div>')
    
    # Add metadata differences section
    if 'differences' in comparison_results and comparison_results['differences']:
        html_parts.append('<div class="section"><h2>Key Metadata Differences</h2><table><tr><th>Field</th>')
        for name in file_names:
            html_parts.append(f'<th>{name}</th>')
        html_parts.append('</tr>')
        
        for diff in comparison_results['differences']:
            field = diff['field']
            values = diff['values']
            
            html_parts.append(f'<tr class="different"><td>{field}</td>')
            for value in values:
                html_parts.append(f'<td>{value if value is not None else "N/A"}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</table></div>')
    
    html_parts.append('</body></html>')
    return ''.join(html_parts)


def generate_comparison_text(comparison_results: Dict[str, Any], file_paths: List[str]) -> str:
    """
    Generate text report for file comparison.
    
    Args:
        comparison_results: Results from compare_metadata
        file_paths: List of file paths that were compared
        
    Returns:
        Text formatted report
    """
    output = []
    
    output.append("File Metadata Comparison Report")
    output.append("=" * 60)
    
    # Print file info
    for i, file_path in enumerate(file_paths):
        output.append(f"File {i+1}: {os.path.basename(file_path)}")
        output.append(f"  Path: {file_path}")
        
        if 'basic_info' in comparison_results:
            if 'file_type' in comparison_results['basic_info']:
                output.append(f"  Type: {comparison_results['basic_info']['file_type'][i]}")
            if 'file_size' in comparison_results['basic_info']:
                output.append(f"  Size: {comparison_results['basic_info']['file_size'][i]:,} bytes")
            
        if 'hashes' in comparison_results and 'md5' in comparison_results['hashes']:
            md5 = comparison_results['hashes']['md5'][i]
            output.append(f"  MD5: {md5 if md5 else 'N/A'}")
        
        output.append("")
    
    # Print comparison sections
    for section, details in comparison_results.items():
        if section not in ('files', 'fuzzy_hash'):
            output.append(f"{section.upper()}")
            output.append("-" * 60)
            
            if isinstance(details, dict):
                for key, values in details.items():
                    output.append(f"  {key}:")
                    
                    # Check if all values are the same
                    unique_values = set(str(v) for v in values if v is not None)
                    if len(unique_values) == 1:
                        output.append(f"    All files: {next(iter(unique_values))}")
                    else:
                        for i, value in enumerate(values):
                            value_str = str(value) if value is not None else 'N/A'
                            output.append(f"    File {i+1}: {value_str}")
            else:
                output.append(f"  {details}")
            
            output.append("")
    
    # Print fuzzy hash comparison if available
    if 'fuzzy_hash' in comparison_results:
        output.append("FUZZY HASH COMPARISON")
        output.append("-" * 60)
        
        if 'error' in comparison_results['fuzzy_hash']:
            output.append(f"  Error: {comparison_results['fuzzy_hash']['error']}")
        elif 'comparisons' in comparison_results['fuzzy_hash']:
            for comp in comparison_results['fuzzy_hash']['comparisons']:
                output.append(f"  {comp['file1']} vs {comp['file2']}: {comp['similarity']}% similarity")
        
        output.append("")
    
    return "\n".join(output)


def find_similar_files(
    file_paths: List[str],
    similarity_threshold: int = 70,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Find similar files within a group using fuzzy hashing.
    
    Args:
        file_paths: List of file paths to compare
        similarity_threshold: Minimum similarity percentage to consider files similar
        options: Additional options for processing
        
    Returns:
        Dictionary mapping file paths to lists of similar files
    """
    if not OPTIONAL_DEPENDENCIES['pyssdeep']:
        return {'error': "ssdeep package not installed"}
    
    try:
        import pyssdeep as ssdeep
        
        # Compute hashes for all files
        hashes = {}
        for path in file_paths:
            try:
                hash_value = ssdeep.hash_from_file(path)
                hashes[path] = hash_value
            except Exception as e:
                logging.warning(f"Could not compute hash for {path}: {e}")
        
        # Find similarities
        similarities = {}
        
        for path1, hash1 in hashes.items():
            similarities[path1] = []
            
            for path2, hash2 in hashes.items():
                if path1 != path2:
                    try:
                        similarity = ssdeep.compare(hash1, hash2)
                        if similarity >= similarity_threshold:
                            similarities[path1].append({
                                'path': path2,
                                'similarity': similarity
                            })
                    except Exception as e:
                        logging.warning(f"Error comparing {path1} and {path2}: {e}")
            
            # Sort by similarity (highest first)
            similarities[path1].sort(key=lambda x: x['similarity'], reverse=True)
        
        # Remove entries with no similar files
        result = {k: v for k, v in similarities.items() if v}
        
        return result
    except ImportError:
        return {'error': "ssdeep package not installed"}
    except Exception as e:
        return {'error': str(e)}