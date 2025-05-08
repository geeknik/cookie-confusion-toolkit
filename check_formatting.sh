#!/bin/bash

# Script to check if formatting is correct

echo "Checking formatting with black..."
black --check . || echo "Black formatting failed!"

echo -e "\nChecking import order with isort..."
isort --check-only --profile black . || echo "Import order failed!"

echo -e "\nRunning flake8 checks..."
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=100 --statistics

echo -e "\nDone!"
