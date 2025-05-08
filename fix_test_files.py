#!/usr/bin/env python3
"""
Script to automatically fix test files with proper imports and formatting.
"""
import re
import os

# Define the correct imports structure for test files
correct_imports = """# Standard library imports
import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch, mock_open

# Third-party imports
import pytest

# Local imports - update paths to match module structure
from src.cookie_confusion_toolkit.utils.common import (
    is_valid_target,
    generate_random_string,
    safe_request,
    parse_cookie_string,
    get_set_cookie_headers,
    calculate_checksum,
    save_results,
    load_results,
    ethical_check,
    validate_authorization,
    rate_limit
)
from src.cookie_confusion_toolkit.utils.cookie_utils import (
    Cookie,
    parse_cookies_from_response,
    create_malformed_cookie,
    create_cookie_collision,
    simulate_browser_cookie_jar,
    detect_cookie_parser
)
from src.cookie_confusion_toolkit.cookiebomb import CookieBomb
"""

def remove_trailing_whitespace(file_path):
    """Remove trailing whitespace from a file."""
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Remove trailing whitespace from each line
    cleaned_lines = [line.rstrip() + '\n' for line in lines]
    
    # Remove the final newline if it creates an empty line at the end
    if cleaned_lines and cleaned_lines[-1] == '\n':
        cleaned_lines = cleaned_lines[:-1]
    
    with open(file_path, 'w') as f:
        f.writelines(cleaned_lines)
    
    print(f"✓ Removed trailing whitespace from {file_path}")

def fix_long_lines(file_path):
    """Fix lines that are too long in a file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Apply Black formatting to handle line length
    import subprocess
    try:
        result = subprocess.run(['black', '--line-length', '100', file_path], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Fixed line lengths in {file_path}")
        else:
            print(f"✗ Failed to fix line lengths in {file_path}: {result.stderr}")
    except Exception as e:
        print(f"✗ Error fixing line lengths in {file_path}: {e}")

def fix_import_order(file_path):
    """Fix import order in a file."""
    import subprocess
    try:
        result = subprocess.run(['isort', '--profile', 'black', file_path], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Fixed import order in {file_path}")
        else:
            print(f"✗ Failed to fix import order in {file_path}: {result.stderr}")
    except Exception as e:
        print(f"✗ Error fixing import order in {file_path}: {e}")

def fix_module_path_imports(file_path):
    """Fix module path imports to match current structure."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace common incorrect import patterns
    replacements = [
        (r'from src\.utils\.common import', 'from src.cookie_confusion_toolkit.utils.common import'),
        (r'from src\.utils\.cookie_utils import', 'from src.cookie_confusion_toolkit.utils.cookie_utils import'),
        (r'from src\.cookiebomb import', 'from src.cookie_confusion_toolkit.cookiebomb import'),
        (r'from src\.clientfork import', 'from src.cookie_confusion_toolkit.clientfork import'),
        (r'from src\.serverdrift import', 'from src.cookie_confusion_toolkit.serverdrift import'),
        (r'from src\.bypassgen import', 'from src.cookie_confusion_toolkit.bypassgen import'),
        (r'from src\.cli import', 'from src.cookie_confusion_toolkit.cli import'),
        (r"@patch\('src\.", "@patch('src.cookie_confusion_toolkit."),  # Fix patch decorators
    ]
    
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"✓ Fixed module path imports in {file_path}")

def add_encoding_to_open_calls(file_path):
    """Add explicit encoding to open() calls."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Replace open calls without encoding
    pattern = r'open\((.*?)\)(?!\s*\.)'  # Match open() not followed by a method call
    
    def replacement(match):
        args = match.group(1)
        if 'encoding=' not in args:
            # Add encoding parameter
            if args.endswith('"r"') or args.endswith("'r'"):
                return f'open({args}, encoding="utf-8")'
            elif not args.strip().endswith(','):
                return f'open({args}, encoding="utf-8")'
            else:
                return f'open({args} encoding="utf-8")'
        return match.group(0)
    
    new_content = re.sub(pattern, replacement, content)
    
    if new_content != content:
        with open(file_path, 'w') as f:
            f.write(new_content)
        print(f"✓ Added encoding to open calls in {file_path}")

def main():
    """Main function to fix all test files."""
    test_files = [
        'tests/unit/test_common.py',
        'tests/unit/test_cookie_utils.py',
        'tests/unit/test_cookiebomb.py',
        'tests/integration/test_full_assessment.py',
    ]
    
    print("Fixing test files...")
    
    for file_path in test_files:
        if os.path.exists(file_path):
            print(f"\nProcessing {file_path}...")
            
            # 1. Remove trailing whitespace
            remove_trailing_whitespace(file_path)
            
            # 2. Fix module path imports
            fix_module_path_imports(file_path)
            
            # 3. Add encoding to open calls
            add_encoding_to_open_calls(file_path)
            
            # 4. Fix import order
            fix_import_order(file_path)
            
            # 5. Fix long lines
            fix_long_lines(file_path)
        else:
            print(f"⚠ File not found: {file_path}")
    
    print("\nDone fixing test files!")

if __name__ == "__main__":
    main()
