# Fixing Formatting Issues

The CI is failing due to code formatting issues. To fix these, you have several options:

## Option 1: Run formatter locally

```bash
# Make the script executable
chmod +x format.sh

# Run the formatter
./format.sh

# Commit the changes
git add .
git commit -m "Fix code formatting with Black and isort"
git push
```

## Option 2: Use pre-commit hooks

```bash
# Install pre-commit
pip install pre-commit

# Install the hooks
pre-commit install

# Now Black and isort will run automatically before each commit
```

## Option 3: Manual formatting

```bash
# Install Black and isort
pip install black isort

# Format all Python files
black .
isort .

# Commit changes
git add .
git commit -m "Fix code formatting"
git push
```

## Option 4: Let GitHub Actions auto-format

Push to the main/develop branch and the auto-format workflow will run and commit the formatted code automatically.

## Checking your code before committing

```bash
# Check if code would be reformatted (doesn't change files)
black --check .

# See what would be changed
black --diff .
```

The CI expects all Python code to be formatted according to Black's standards with a line length of 100 characters.
