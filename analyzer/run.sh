#!/bin/bash

set -e

echo "Starting Garuda Threat Analyzer..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run ./setup.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Check if required services are running
echo "Checking service dependencies..."

# Check Redis
if ! redis-cli ping > /dev/null 2>&1; then
    echo "Warning: Redis is not running. Make sure Redis is available at localhost:6379"
fi

# Check ClickHouse
if ! curl -s http://localhost:8123/ping > /dev/null 2>&1; then
    echo "Warning: ClickHouse is not running. Make sure ClickHouse is available at localhost:8123"
fi

# Check VLM server
if ! curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "Warning: VLM server is not running. Make sure vLLM server is available at localhost:8001"
    echo "To start the VLM server, run:"
    echo "  python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen2-VL-7B-Instruct-AWQ --trust-remote-code --dtype auto --api-key dummy --port 8001"
fi

echo "Starting analyzer worker..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Start the worker
python worker.py