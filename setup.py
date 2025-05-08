#!/usr/bin/env python3
"""
Setup script for Cookie Confusion Toolkit
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cookie-confusion-toolkit",
    version="0.1.0",
    author="Geeknik",
    author_email="your.email@example.com",
    description="A toolkit for researching cookie parsing inconsistencies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/geeknik/cookie-confusion-toolkit",
    project_urls={
        "Bug Tracker": "https://github.com/geeknik/cookie-confusion-toolkit/issues",
        "Documentation": "https://github.com/geeknik/cookie-confusion-toolkit/docs",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Testing :: Traffic Generation",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
        "selenium>=4.5.0",
        "beautifulsoup4>=4.11.0",
        "click>=8.1.0",
        "colorama>=0.4.5",
        "tqdm>=4.64.0",
        "pyyaml>=6.0",
        "cryptography>=38.0.0"
    ],
    entry_points={
        "console_scripts": [
            "cct=cookie_confusion_toolkit.cli:main",
            "cookiebomb=cookie_confusion_toolkit.cli:main",
            "clientfork=cookie_confusion_toolkit.cli:main",
            "serverdrift=cookie_confusion_toolkit.cli:main",
            "bypassgen=cookie_confusion_toolkit.cli:main",
        ],
    },
)
