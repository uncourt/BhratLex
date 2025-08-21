#!/bin/bash

echo "Setting up Garuda Python Analyzer..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Create directories
mkdir -p screenshots
mkdir -p logs
mkdir -p data

echo "Setup complete! Activate with: source venv/bin/activate"