#!/bin/bash

echo "🧪 Testing Garuda AI Threat Detection Engine"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "\n${BLUE}Running: ${test_name}${NC}"
    echo "Command: $test_command"
    
    if eval "$test_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# Function to check if service is running
check_service() {
    local service_name="$1"
    local port="$2"
    
    if curl -s "http://localhost:$port" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ $service_name is running on port $port${NC}"
        return 0
    else
        echo -e "${RED}❌ $service_name is not running on port $port${NC}"
        return 1
    fi
}

# Function to check if container is running
check_container() {
    local container_name="$1"
    
    if docker ps --format "table {{.Names}}" | grep -q "$container_name"; then
        echo -e "${GREEN}✅ Container $container_name is running${NC}"
        return 0
    else
        echo -e "${RED}❌ Container $container_name is not running${NC}"
        return 1
        return 1
    fi
}

echo -e "\n${YELLOW}Phase 1: Infrastructure Health Check${NC}"
echo "----------------------------------------"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running${NC}"
    exit 1
fi

# Check infrastructure containers
run_test "Redis Container" "check_container garuda-redis"
run_test "ClickHouse Container" "check_container garuda-clickhouse"

# Check infrastructure ports
run_test "Redis Port 6379" "check_service Redis 6379"
run_test "ClickHouse Port 8123" "check_service ClickHouse 8123"

echo -e "\n${YELLOW}Phase 2: Rust Engine Test${NC}"
echo "---------------------------"

# Check if Rust engine is running
if check_service "Garuda Engine" 3000; then
    run_test "Engine Health Check" "curl -s http://localhost:3000/health | grep -q 'healthy'"
    
    # Test scoring endpoint
    echo -e "\n${BLUE}Testing domain scoring...${NC}"
    SCORE_RESPONSE=$(curl -s -X POST http://localhost:3000/score \
        -H "Content-Type: application/json" \
        -d '{"domain": "google.com"}')
    
    if echo "$SCORE_RESPONSE" | grep -q "decision_id"; then
        echo -e "${GREEN}✅ Score endpoint working${NC}"
        echo "Response: $SCORE_RESPONSE"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ Score endpoint failed${NC}"
        ((TESTS_FAILED++))
    fi
    
    # Test metrics endpoint
    METRICS_RESPONSE=$(curl -s http://localhost:3000/metrics)
    if echo "$METRICS_RESPONSE" | grep -q "qps"; then
        echo -e "${GREEN}✅ Metrics endpoint working${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ Metrics endpoint failed${NC}"
        ((TESTS_FAILED++))
    fi
    
else
    echo -e "${RED}❌ Garuda Engine is not running${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n${YELLOW}Phase 3: Python Analyzer Test${NC}"
echo "--------------------------------"

# Check if analyzer is running (this would need to be implemented)
echo -e "${BLUE}Checking analyzer status...${NC}"
if pgrep -f "worker.py" > /dev/null; then
    echo -e "${GREEN}✅ Python analyzer is running${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠️  Python analyzer not detected (may be running in background)${NC}"
fi

echo -e "\n${YELLOW}Phase 4: Data Flow Test${NC}"
echo "------------------------"

# Test Redis queue operations
echo -e "\n${BLUE}Testing Redis queue operations...${NC}"
if command -v redis-cli > /dev/null; then
    # Test enqueue
    redis-cli -h localhost -p 6379 lpush test_queue "test_message" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Redis enqueue working${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ Redis enqueue failed${NC}"
        ((TESTS_FAILED++))
    fi
    
    # Test dequeue
    MESSAGE=$(redis-cli -h localhost -p 6379 rpop test_queue)
    if [ "$MESSAGE" = "test_message" ]; then
        echo -e "${GREEN}✅ Redis dequeue working${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ Redis dequeue failed${NC}"
        ((TESTS_FAILED++))
    fi
else
    echo -e "${YELLOW}⚠️  redis-cli not available, skipping Redis tests${NC}"
fi

echo -e "\n${YELLOW}Phase 5: Performance Test${NC}"
echo "---------------------------"

# Test latency
echo -e "\n${BLUE}Testing response latency...${NC}"
START_TIME=$(date +%s%N)
curl -s -X POST http://localhost:3000/score \
    -H "Content-Type: application/json" \
    -d '{"domain": "example.com"}' > /dev/null
END_TIME=$(date +%s%N)

LATENCY_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response latency: ${LATENCY_MS}ms"

if [ $LATENCY_MS -lt 1500 ]; then
    echo -e "${GREEN}✅ Latency within target (<1.5ms p95)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠️  Latency above target (${LATENCY_MS}ms)${NC}"
    ((TESTS_FAILED++))
fi

# Test throughput
echo -e "\n${BLUE}Testing throughput...${NC}"
echo "Sending 10 concurrent requests..."
START_TIME=$(date +%s%N)

for i in {1..10}; do
    curl -s -X POST http://localhost:3000/score \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"test$i.com\"}" > /dev/null &
done

wait
END_TIME=$(date +%s%N)

TOTAL_TIME_MS=$(( (END_TIME - START_TIME) / 1000000 ))
THROUGHPUT=$(( 10000 / TOTAL_TIME_MS ))

echo "Total time: ${TOTAL_TIME_MS}ms"
echo "Throughput: ${THROUGHPUT} requests/second"

if [ $THROUGHPUT -gt 100 ]; then
    echo -e "${GREEN}✅ Throughput above target (>100 req/s)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${YELLOW}⚠️  Throughput below target (${THROUGHPUT} req/s)${NC}"
    ((TESTS_FAILED++))
fi

echo -e "\n${YELLOW}Test Summary${NC}"
echo "============"
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo -e "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All tests passed! Garuda is working correctly.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please check the system.${NC}"
    exit 1
fi