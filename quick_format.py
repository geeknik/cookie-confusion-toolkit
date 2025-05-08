#!/usr/bin/env python3
"""
Quick script to format all Python files with black
"""
import subprocess
import os

# Find all Python files to format
for root, dirs, files in os.walk("."):
    # Skip certain directories
    skip_dirs = {'.git', '__pycache__', '.mypy_cache', '.pytest_cache', 'venv', '.venv', 'build', 'dist'}
    dirs[:] = [d for d in dirs if d not in skip_dirs]
    
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            try:
                result = subprocess.run(['black', filepath], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✓ Formatted {filepath}")
                else:
                    print(f"✗ Error formatting {filepath}: {result.stderr}")
            except Exception as e:
                print(f"✗ Exception formatting {filepath}: {e}")

print("Formatting complete!")
