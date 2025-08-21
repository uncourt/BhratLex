# Garuda - High-Performance AI Threat Detection Engine

A real-time threat detection system with inline hot path (≤1.5ms p95 latency) and async AI analysis for uncertain cases.

## Architecture

- **Rust Engine**: High-performance hot path with hard-intel gates, feature extraction, and ML models
- **Python Analyzer**: Async threat analysis using Playwright, OCR, and Vision Language Models
- **Reinforcement Learning**: LinUCB contextual bandit with weekly teacher→student distillation
- **Infrastructure**: Redis for caching, ClickHouse for analytics, Docker Compose for deployment

## Features

- **Threat Detection**: IDN homoglyphs, typosquatting, DGA entropy, CNAME cloaking, DNS rebinding
- **Hard Intel**: Google Safe Browsing, abuse.ch, Shadowserver, Spamhaus DROP
- **Actions**: ALLOW, WARN, BLOCK with confidence scores
- **Explainability**: Detailed reasons, screenshots, OCR text, and logs

## Quick Start

### 1. Start Infrastructure

```bash
cd infra
docker-compose up -d
./init-clickhouse.sh
```

### 2. Start VLM Server

```bash
# Install vLLM and start Qwen2-VL-7B server
pip install vllm
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2-VL-7B-Instruct-AWQ \
    --port 8000 \
    --host 0.0.0.0
```

### 3. Build and Run Rust Engine

```bash
cd engine
cargo build --release
./target/release/garuda-engine
```

### 4. Start Python Analyzer

```bash
cd analyzer
pip install -r requirements.txt
./run.sh
```

### 5. Test the System

```bash
# Score a domain
curl -X POST http://localhost:3000/score \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'

# Check metrics
curl http://localhost:3000/metrics
```

## API Endpoints

### POST /score
Score a domain for threats.

**Request:**
```json
{
  "domain": "example.com",
  "url": "https://example.com/path" // optional
}
```

**Response:**
```json
{
  "action": "ALLOW",
  "prob": 0.95,
  "reasons": ["Domain appears legitimate"],
  "decision_id": "uuid-here"
}
```

### POST /feedback
Update rewards for reinforcement learning.

**Request:**
```json
{
  "decision_id": "uuid-here",
  "reward": 1.0,
  "context": "User confirmed legitimate"
}
```

### GET /metrics
Get system performance metrics.

**Response:**
```json
{
  "qps": 1250.5,
  "p95_latency_ms": 1.2,
  "cache_hits": 0.87,
  "total_requests": 50000
}
```

## Training

Train the student model on historical data:

```bash
cd train
python distill_student.py --input data.csv --output ../engine/src/student.json
```

## Performance

- **Hot Path Latency**: ≤1.5ms p95
- **Throughput**: 1000+ QPS
- **Cache Hit Rate**: >85%
- **Accuracy**: >95% with hard-intel gates

## Development

### Project Structure

```
garuda/
├── infra/           # Docker Compose, ClickHouse schema
├── engine/          # Rust threat detection engine
├── analyzer/        # Python async analyzer
├── train/           # Model training scripts
└── README.md
```

### Building from Source

```bash
# Rust engine
cd engine
cargo build --release

# Python analyzer
cd analyzer
pip install -r requirements.txt
```

## Monitoring

- **Metrics**: Prometheus-compatible endpoints
- **Logs**: Structured JSON logging
- **Alerts**: Redis queue monitoring
- **Dashboard**: ClickHouse analytics

## Security

- Input validation and sanitization
- Rate limiting and DDoS protection
- Secure Redis and ClickHouse connections
- Audit logging for all decisions

## License

MIT License - see LICENSE file for details.