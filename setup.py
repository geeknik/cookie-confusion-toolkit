"""
Setup script for the Cookie Confusion Toolkit.
"""

import os

from setuptools import find_packages, setup


def read(fname):
    """Read file content."""
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def get_version():
    """Get version from __init__.py."""
    version_file = os.path.join("src", "cookie_confusion_toolkit", "__init__.py")
    with open(version_file) as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"')
    return "0.0.1"


setup(
    name="cookie-confusion-toolkit",
    version=get_version(),
    author="geeknik",
    author_email="geeknik@protonmail.com",
    description="A comprehensive toolkit for testing cookie handling vulnerabilities",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    url="https://github.com/geeknik/cookie-confusion-toolkit",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"cookie_confusion_toolkit": ["templates/*", "config/*"]},
    include_package_data=True,
    install_requires=[
        "requests>=2.31.0",
        "selenium>=4.15.0",
        "urllib3>=2.0.0",
        "colorama>=0.4.6",
        "tqdm>=4.66.0",
        "python-dateutil>=2.8.2",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.0",
        "click>=8.1.0",
        "rich>=13.7.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.9.0",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
            "bandit>=1.7.0",
            "isort>=5.12.0",
            "pre-commit>=3.5.0",
        ],
        "docs": [
            "sphinx>=7.2.0",
            "sphinx-rtd-theme>=1.3.0",
            "myst-parser>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cct=cookie_confusion_toolkit.cli:main",
            "cookie-confusion=cookie_confusion_toolkit.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Framework :: Pytest",
    ],
    python_requires=">=3.9",
    keywords="security testing cookies http web vulnerabilities",
    project_urls={
        "Bug Reports": "https://github.com/geeknik/cookie-confusion-toolkit/issues",
        "Source": "https://github.com/geeknik/cookie-confusion-toolkit",
        "Documentation": "https://cookie-confusion-toolkit.readthedocs.io/",
    },
)
