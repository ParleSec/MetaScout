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
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Development Status :: 5 - Production/Stable",
    ],
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
            "docx>=0.8.11",
            "openpyxl>=3.0.7",
            "olefile>=0.46",
            "pefile>=2021.5.24; platform_system=='Windows'",
            "pyelftools>=0.27; platform_system!='Windows'",
            "macholib>=1.15.2; platform_system=='Darwin'",
            "yara-python>=4.1.0",
            "ssdeep>=3.4",
        ],
        'document': [
            "docx>=0.8.11",
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