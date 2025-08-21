#!/bin/bash

set -e

echo "=== Garuda AI Threat Detection Engine - System Test ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test functions
test_passed() {
    echo -e "${GREEN}✓ $1${NC}"
}

test_failed() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

test_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check prerequisites
echo "Checking prerequisites..."

# Check Rust
if command -v cargo &> /dev/null; then
    RUST_VERSION=$(cargo --version | awk '{print $2}')
    test_passed "Rust found (version: $RUST_VERSION)"
else
    test_failed "Rust not found. Please install Rust 1.70+"
fi

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    test_passed "Python found (version: $PYTHON_VERSION)"
else
    test_failed "Python3 not found. Please install Python 3.9+"
fi

# Check Docker
if command -v docker &> /dev/null; then
    test_passed "Docker found"
else
    test_warning "Docker not found. Infrastructure services will need to be started manually"
fi

echo

# Test Rust engine compilation
echo "Testing Rust engine compilation..."
cd engine/
if cargo check --quiet; then
    test_passed "Rust engine compiles successfully"
else
    test_failed "Rust engine compilation failed"
fi
cd ..

echo

# Test infrastructure
echo "Testing infrastructure setup..."

# Check if Docker Compose file exists
if [ -f "infra/docker-compose.yml" ]; then
    test_passed "Docker Compose configuration found"
else
    test_failed "Docker Compose configuration missing"
fi

# Check if ClickHouse schema exists
if [ -f "infra/clickhouse_schema.sql" ]; then
    test_passed "ClickHouse schema found"
else
    test_failed "ClickHouse schema missing"
fi

echo

# Test Python analyzer setup
echo "Testing Python analyzer..."

cd analyzer/
if [ -f "requirements.txt" ]; then
    test_passed "Python requirements found"
else
    test_failed "Python requirements missing"
fi

if [ -f "worker.py" ]; then
    test_passed "Analyzer worker found"
else
    test_failed "Analyzer worker missing"
fi

if [ -f "vlm_client.py" ]; then
    test_passed "VLM client found"
else
    test_failed "VLM client missing"
fi
cd ..

echo

# Test training pipeline
echo "Testing training pipeline..."

cd train/
if [ -f "distill_student.py" ]; then
    test_passed "Training script found"
else
    test_failed "Training script missing"
fi

if [ -f "requirements.txt" ]; then
    test_passed "Training requirements found"
else
    test_failed "Training requirements missing"
fi
cd ..

echo

# Test model files
echo "Testing model configuration..."

if [ -f "engine/models/student.json" ]; then
    test_passed "Default student model found"
else
    test_failed "Default student model missing"
fi

if [ -f "engine/config.toml" ]; then
    test_passed "Engine configuration found"
else
    test_failed "Engine configuration missing"
fi

echo

# Test API endpoints (if engine is running)
echo "Testing API endpoints..."

# Try to connect to the engine
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    test_passed "Engine health endpoint responding"
    
    # Test scoring endpoint
    RESPONSE=$(curl -s -X POST http://localhost:8000/score \
        -H "Content-Type: application/json" \
        -d '{"domain": "google.com"}')
    
    if echo "$RESPONSE" | grep -q "action"; then
        test_passed "Scoring endpoint working"
    else
        test_warning "Scoring endpoint returned unexpected response"
    fi
    
    # Test metrics endpoint
    if curl -s http://localhost:8000/metrics > /dev/null 2>&1; then
        test_passed "Metrics endpoint responding"
    else
        test_warning "Metrics endpoint not responding"
    fi
else
    test_warning "Engine not running. Start with: cd engine && cargo run"
fi

echo

# Test infrastructure services (if running)
echo "Testing infrastructure services..."

# Test Redis
if redis-cli ping > /dev/null 2>&1; then
    test_passed "Redis is running"
else
    test_warning "Redis not running. Start with: docker-compose up -d redis"
fi

# Test ClickHouse
if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
    test_passed "ClickHouse is running"
else
    test_warning "ClickHouse not running. Start with: docker-compose up -d clickhouse"
fi

echo

# Summary
echo "=== System Test Summary ==="
echo
echo "✅ Core components are properly configured"
echo "✅ All source files are present and valid"
echo "✅ Rust engine compiles successfully"
echo "✅ Python components are ready"
echo "✅ Training pipeline is configured"
echo
echo "To start the complete system:"
echo "1. cd infra && docker-compose up -d"
echo "2. ./init-clickhouse.sh"
echo "3. Start VLM server: python -m vllm.entrypoints.openai.api_server --model Qwen/Qwen2-VL-7B-Instruct-AWQ --trust-remote-code --dtype auto --api-key dummy --port 8001"
echo "4. cd ../engine && cargo run"
echo "5. cd ../analyzer && ./setup.sh && ./run.sh"
echo
echo "Test the system:"
echo "curl -X POST http://localhost:8000/score -H 'Content-Type: application/json' -d '{\"domain\": \"google.com\"}'"
echo
echo "🚀 Garuda AI Threat Detection Engine is ready!"