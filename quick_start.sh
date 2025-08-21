#!/bin/bash

echo "🚀 Garuda AI Threat Detection Engine - Quick Start"
echo "=================================================="

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 1: Starting Infrastructure${NC}"
echo "----------------------------------------"

# Start Redis and ClickHouse
cd infra
docker-compose up -d

echo -e "${GREEN}✅ Infrastructure started${NC}"

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 15

# Initialize ClickHouse
echo "Initializing ClickHouse database..."
./init-clickhouse.sh

echo -e "${GREEN}✅ Infrastructure ready${NC}"

echo -e "\n${BLUE}Step 2: Building Rust Engine${NC}"
echo "--------------------------------"

cd ../engine

# Check if Rust is installed
if ! command -v cargo > /dev/null; then
    echo -e "${YELLOW}⚠️  Rust not found. Installing Rust...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Build the engine
echo "Building Garuda engine..."
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Rust engine built successfully${NC}"
else
    echo -e "${RED}❌ Failed to build Rust engine${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 3: Setting up Python Analyzer${NC}"
echo "----------------------------------------"

cd ../analyzer

# Check if Python is installed
if ! command -v python3 > /dev/null; then
    echo -e "${RED}❌ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Setup Python environment
echo "Setting up Python environment..."
./setup.sh

echo -e "${GREEN}✅ Python analyzer setup complete${NC}"

echo -e "\n${BLUE}Step 4: Starting Services${NC}"
echo "----------------------------"

# Start Rust engine in background
echo "Starting Rust engine..."
cd ../engine
./target/release/garuda-engine &
ENGINE_PID=$!

# Wait for engine to start
sleep 5

# Check if engine is running
if curl -s http://localhost:3000/health > /dev/null; then
    echo -e "${GREEN}✅ Rust engine started successfully${NC}"
else
    echo -e "${RED}❌ Failed to start Rust engine${NC}"
    exit 1
fi

# Start Python analyzer in background
echo "Starting Python analyzer..."
cd ../analyzer
./run.sh &
ANALYZER_PID=$!

# Wait for analyzer to start
sleep 10

echo -e "${GREEN}✅ All services started${NC}"

echo -e "\n${BLUE}Step 5: Testing the System${NC}"
echo "----------------------------"

# Wait a bit for everything to initialize
sleep 5

# Run tests
echo "Running system tests..."
cd ..
./test_garuda.sh

echo -e "\n${BLUE}Step 6: System Status${NC}"
echo "------------------------"

echo "Service Status:"
echo "  - Redis: $(docker ps --format 'table {{.Names}} {{.Status}}' | grep garuda-redis)"
echo "  - ClickHouse: $(docker ps --format 'table {{.Names}} {{.Status}}' | grep garuda-clickhouse)"
echo "  - Rust Engine: $(ps -p $ENGINE_PID > /dev/null && echo "Running (PID: $ENGINE_PID)" || echo "Not running")"
echo "  - Python Analyzer: $(ps -p $ANALYZER_PID > /dev/null && echo "Running (PID: $ANALYZER_PID)" || echo "Not running")"

echo -e "\n${GREEN}🎉 Garuda is now running!${NC}"
echo ""
echo "Quick Test:"
echo "  curl -X POST http://localhost:3000/score \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"domain\": \"google.com\"}'"
echo ""
echo "Metrics:"
echo "  curl http://localhost:3000/metrics"
echo ""
echo "Health Check:"
echo "  curl http://localhost:3000/health"
echo ""
echo "To stop all services:"
echo "  pkill -f garuda-engine"
echo "  pkill -f worker.py"
echo "  cd infra && docker-compose down"
echo ""
echo "For detailed testing, run: ./test_garuda.sh"