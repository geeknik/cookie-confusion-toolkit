#!/usr/bin/env python3
"""
Script to format files with black
"""
import subprocess
import sys

files = [
    "setup.py",
    "src/cookie_confusion_toolkit/__init__.py",
    "examples/scripts/full_assessment.py",
    "examples/scripts/custom_tests.py",
    "examples/scripts/compare_browsers.py",
    "src/cookie_confusion_toolkit/cli.py",
    "src/cookie_confusion_toolkit/cookiebomb.py",
    "src/cookie_confusion_toolkit/utils/common.py",
    "src/cookie_confusion_toolkit/clientfork.py",
    "src/cookie_confusion_toolkit/bypassgen.py",
    "tests/conftest.py",
    "tests/unit/test_common.py",
    "src/cookie_confusion_toolkit/utils/cookie_utils.py",
    "tests/integration/test_full_assessment.py",
    "src/cookie_confusion_toolkit/serverdrift.py",
    "tests/unit/test_cookie_utils.py",
    "tests/unit/test_cookiebomb.py",
]

for file in files:
    try:
        subprocess.run(["black", file], check=True)
        print(f"✓ Formatted {file}")
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to format {file}: {e}")
    except FileNotFoundError:
        print(f"⚠ File not found: {file}")

print("Done!")
