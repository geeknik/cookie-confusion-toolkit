# Installation Guide

This guide will help you install the Cookie Confusion Toolkit (CCT) and set up your environment for security testing.

## Prerequisites

- Python 3.9 or higher
- pip (Python package installer)
- Appropriate permissions to install packages and run browser automation

## System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Memory**: At least 4GB RAM recommended
- **Storage**: At least 100MB free space
- **Browser**: At least one of Chrome, Firefox, or Edge should be installed for browser-based tests

## Installing from Source

1. Clone the repository:

```bash
git clone https://github.com/geeknik/cookie-confusion-toolkit.git
cd cookie-confusion-toolkit
```

2. Install the package in development mode:

```bash
pip install -e .
```

This will install the package and its dependencies while allowing you to modify the code.

## Dependencies

The toolkit requires several dependencies that will be automatically installed:

- **requests**: For making HTTP requests
- **selenium**: For browser automation
- **beautifulsoup4**: For HTML parsing
- **colorama**: For colored terminal output
- **tqdm**: For progress bars
- **pyyaml**: For configuration files
- **cryptography**: For cryptographic operations

## WebDriver Setup

For browser automation tests (ClientFork module), you'll need the appropriate WebDriver for your browser:

### Chrome

Download the ChromeDriver that matches your Chrome version from:
https://sites.google.com/chromium.org/driver/

Make sure it's in your PATH:

```bash
# Linux/macOS
chmod +x chromedriver
sudo mv chromedriver /usr/local/bin/

# Windows
# Add the directory containing chromedriver.exe to your PATH
```

### Firefox

Download GeckoDriver from:
https://github.com/mozilla/geckodriver/releases

Make sure it's in your PATH:

```bash
# Linux/macOS
chmod +x geckodriver
sudo mv geckodriver /usr/local/bin/

# Windows
# Add the directory containing geckodriver.exe to your PATH
```

### Edge

Download Edge WebDriver from:
https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/

Make sure it's in your PATH.

## Verifying the Installation

After installation, verify that everything is working correctly:

```bash
python -m cct --version
```

You should see the version number of the installed toolkit.

## Troubleshooting

### Common Issues

1. **Missing WebDriver**:
   
   Error: `SessionNotCreatedException: Message: session not created: Chrome version must be between X and Y`
   
   Solution: Download the correct WebDriver version that matches your browser.

2. **Permission Issues**:
   
   Error: `PermissionError: [Errno 13] Permission denied`
   
   Solution: Run the command with sudo (Linux/macOS) or as administrator (Windows).

3. **Import Errors**:
   
   Error: `ModuleNotFoundError: No module named 'X'`
   
   Solution: Ensure you've installed the package correctly with `pip install -e .` or `pip install cookie-confusion-toolkit`.

### Getting Help

If you encounter issues not covered here, please:

1. Check the GitHub issues to see if your problem has been reported
2. Create a new issue with detailed information about your environment and the error

## Next Steps

Once you have successfully installed the Cookie Confusion Toolkit, proceed to the [Usage Guide](./usage.md) to learn how to use the toolkit for testing.
