#!/bin/bash

set -e

echo "Setting up Garuda Threat Analyzer..."

# Check if Python 3.9+ is available
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.9"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.9 or higher is required. Found: $python_version"
    exit 1
fi

echo "Python version check passed: $python_version"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing Python packages..."
pip install -r requirements.txt

# Install Playwright browsers
echo "Installing Playwright browsers..."
playwright install chromium

# Create necessary directories
echo "Creating directories..."
mkdir -p logs screenshots temp

# Set up PaddleOCR models (download will happen on first use)
echo "PaddleOCR models will be downloaded on first use..."

# Make scripts executable
chmod +x run.sh

echo "Setup complete!"
echo ""
echo "To start the analyzer:"
echo "  ./run.sh"
echo ""
echo "To activate the virtual environment manually:"
echo "  source venv/bin/activate"