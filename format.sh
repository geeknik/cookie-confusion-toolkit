#!/bin/bash

# Simple script to format code locally

echo "Installing/upgrading formatting tools..."
pip install -U black isort

echo "Running Black formatter..."
black .

echo "Running isort..."
isort .

echo "Formatting complete! Run 'git status' to see changes."
