from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="metascout",
    version="1.0.0",
    author="Mason Parle",
    author_email="mason@masonparle.com",
    description="Advanced file metadata analysis and security tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ParleSec/metascout",
    project_urls={
        "Bug Tracker": "https://github.com/ParleSec/metascout/issues",
        "Documentation": "https://github.com/ParleSec/metascout#readme",
        "Source Code": "https://github.com/ParleSec/metascout",
    },
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Systems Administration",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Development Status :: 5 - Production/Stable",
        "Natural Language :: English",
    ],
    keywords="metadata, security, privacy, analysis, exif, pii",
    python_requires=">=3.8",
    install_requires=[
        "pillow>=9.0.0",
        "PyPDF2>=2.0.0",
        "python-magic>=0.4.24; platform_system!='Windows'",
        "python-magic-bin>=0.4.14; platform_system=='Windows'",
        "mutagen>=1.45.0",
        "colorama>=0.4.4",
        "tabulate>=0.8.9",
        "tqdm>=4.62.0",
        "exifread>=2.3.2",
        "cryptography>=35.0.0",
    ],
    extras_require={
        'full': [
            "python-docx>=0.8.11",  # Changed from docx to python-docx
            "openpyxl>=3.0.7",
            "olefile>=0.46",
            "pefile>=2021.5.24; platform_system=='Windows'",
            "pyelftools>=0.27; platform_system!='Windows'",
            "macholib>=1.15.2; platform_system=='Darwin'",
            "yara-python>=4.1.0",
            "ssdeep>=3.4",
        ],
        'document': [
            "python-docx>=0.8.11",  # Changed from docx to python-docx
            "openpyxl>=3.0.7",
            "olefile>=0.46",
        ],
        'executable': [
            "pefile>=2021.5.24; platform_system=='Windows'",
            "pyelftools>=0.27; platform_system!='Windows'",
            "macholib>=1.15.2; platform_system=='Darwin'",
        ],
        'security': [
            "yara-python>=4.1.0",
            "ssdeep>=3.4",
        ],
    },
    entry_points={
        "console_scripts": [
            "metascout=metascout.cli:main",
        ],
    },
)