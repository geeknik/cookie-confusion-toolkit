#!/bin/bash

# Script to fix linting issues automatically

echo "Installing required packages..."
pip install black isort flake8 mypy bandit

echo "Running Black formatter..."
black .

echo "Running isort..."
isort .

echo "Running flake8 (report only)..."
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

echo "Running mypy (report only)..."
mypy src/ --ignore-missing-imports || true

echo "Running bandit security checks..."
bandit -r src/ || true

echo "Linting fixes complete!"
