from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="metascout",
    version="1.0.0",
    author="Security Expert",
    author_email="mason@masonparle.com",
    description="Advanced file metadata analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ParleSec/metascout",
    py_modules=["main"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pillow>=9.0.0",
        "PyPDF2>=2.0.0",
        "python-magic>=0.4.24",
        "mutagen>=1.45.0",
        "colorama>=0.4.4",
        "tabulate>=0.8.9",
        "tqdm>=4.62.0",
    ],
    entry_points={
        "console_scripts": [
            "metascout=metascout.main:main",
        ],
    },
)