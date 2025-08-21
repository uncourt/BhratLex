#!/bin/bash

echo "Starting Garuda Python Analyzer..."

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export REDIS_URL="redis://localhost:6379"
export CLICKHOUSE_URL="http://localhost:8123"
export VLM_URL="http://localhost:8000/v1/chat/completions"

# Run the analyzer
python worker.py