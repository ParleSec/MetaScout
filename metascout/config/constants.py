"""
Constants and default values used throughout MetaScout
"""

import re

# MetaScout version
VERSION = "1.0.0"

# Supported file extensions by type
SUPPORTED_EXTENSIONS = {
    'images': ['.jpg', '.jpeg', '.png', '.tiff', '.gif', '.bmp', '.webp'],
    'documents': ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.odt', '.ods', '.odp'],
    'audio': ['.mp3', '.wav', '.flac', '.m4a', '.ogg', '.aac'],
    'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv'],
    'archives': ['.zip', '.rar', '.tar', '.gz', '.7z'],
    'executables': ['.exe', '.dll', '.so', '.dylib'],
    'scripts': ['.js', '.py', '.sh', '.ps1', '.bat']
}

# Patterns for detecting privacy concerns
PRIVACY_CONCERNS = {
    'gps_data': re.compile(r'GPS|geotag|location', re.IGNORECASE),
    'email': re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)'),
    'phone': re.compile(r'\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
}

# List of terms that may indicate security concerns
SECURITY_CONCERNS = {
    'software_names': ['adobe', 'photoshop', 'microsoft', 'office', 'acrobat'],
    'suspicious_entries': ['hidden', 'password', 'encrypted', 'script', 'macro']
}