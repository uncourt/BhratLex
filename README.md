# Garuda AI Threat Detection Engine

A high-performance AI-powered threat detection engine with sub-1.5ms p95 latency for real-time domain and URL scoring.

## Architecture Overview

Garuda consists of four main components:

1. **Rust Engine** (`engine/`) - High-performance hot path with hard intel gates, feature extraction, student model inference, and LinUCB contextual bandit
2. **Python Analyzer** (`analyzer/`) - Async deep analysis using Playwright, OCR, and VLM for uncertain cases
3. **VLM Server** - Local Qwen2-VL-7B-Instruct-AWQ model via vLLM for visual threat analysis
4. **Infrastructure** (`infra/`) - Redis for queuing, ClickHouse for analytics and logging

## System Flow

```
Client → POST /score → Rust Engine → Hard Intel Gates → Feature Extraction → Student Model → LinUCB → Decision
                                 ↓
                            Redis Queue → Python Analyzer → Playwright → Screenshot → OCR → VLM → Verdict → ClickHouse
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Rust (1.70+)
- Python 3.9+
- NVIDIA GPU (for VLM server)

### 1. Start Infrastructure

```bash
cd infra/
docker-compose up -d
./init-clickhouse.sh
```

### 2. Start VLM Server

```bash
# Install vLLM
pip install vllm

# Start Qwen2-VL-7B server
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2-VL-7B-Instruct-AWQ \
  --trust-remote-code \
  --dtype auto \
  --api-key dummy \
  --port 8001
```

### 3. Build and Run Rust Engine

```bash
cd engine/
cargo build --release
./target/release/garuda-engine
```

Engine runs on `http://localhost:8000`

### 4. Setup and Run Python Analyzer

```bash
cd analyzer/
./setup.sh
./run.sh
```

### 5. Test the System

```bash
# Test benign domain
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'

# Test suspicious domain
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"domain": "g00gle.com", "url": "https://g00gle.com/login"}'

# Check metrics
curl http://localhost:8000/metrics
```

### 6. Verify in ClickHouse

```bash
docker exec -it clickhouse-server clickhouse-client
```

```sql
USE garuda;
SELECT * FROM decisions ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM analyzer ORDER BY timestamp DESC LIMIT 10;
```

## Training New Models

### Distill Student Model

```bash
cd train/
python distill_student.py --input data.csv --output ../engine/models/student.json
```

## API Reference

### POST /score

Score a domain/URL for threats.

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
  "action": "ALLOW|WARN|BLOCK",
  "probability": 0.85,
  "reasons": ["IDN homoglyph detected", "High entropy domain"],
  "decision_id": "uuid-here",
  "latency_ms": 1.2
}
```

### POST /feedback

Provide feedback for reinforcement learning.

**Request:**
```json
{
  "decision_id": "uuid-here",
  "reward": 1.0,
  "actual_threat": true
}
```

### GET /metrics

System performance metrics.

**Response:**
```json
{
  "qps": 1250.5,
  "p95_latency_ms": 1.1,
  "cache_hit_rate": 0.95,
  "decisions_today": 125000,
  "blocked_threats": 1250
}
```

## Configuration

### Engine Configuration (`engine/config.toml`)

```toml
[server]
host = "0.0.0.0"
port = 8000

[thresholds]
block_threshold = 0.8
warn_threshold = 0.5

[redis]
url = "redis://localhost:6379"

[clickhouse]
url = "http://localhost:8123"
database = "garuda"
```

### Analyzer Configuration (`analyzer/config.json`)

```json
{
  "vlm_endpoint": "http://localhost:8001/v1/chat/completions",
  "browser_timeout": 30,
  "max_workers": 4
}
```

## Performance Characteristics

- **Hot Path Latency**: p95 ≤ 1.5ms
- **Throughput**: 10,000+ QPS
- **Memory Usage**: ~200MB (engine), ~1GB (analyzer)
- **False Positive Rate**: <0.1% with hard intel gates

## Threat Detection Capabilities

- **IDN Homoglyphs**: Unicode lookalike detection
- **Typosquatting**: Edit distance analysis against popular domains
- **DGA Detection**: Entropy and n-gram analysis
- **Newly Registered Domains**: Age-based flagging
- **Dynamic DNS**: Provider detection
- **Parked Domains**: Content analysis
- **CNAME Cloaking**: DNS chain analysis
- **Cryptojacking**: CoinBlockerLists integration
- **Hard Intel**: Google Safe Browsing, abuse.ch, Shadowserver, Spamhaus

## Monitoring and Observability

- Real-time metrics via `/metrics` endpoint
- Decision logging in ClickHouse
- Performance dashboards (Grafana compatible)
- Alert thresholds for latency and accuracy

## Security Considerations

- Rate limiting on API endpoints
- Input validation and sanitization
- Secure VLM model serving
- Encrypted inter-service communication (production)

## Development

### Running Tests

```bash
# Rust tests
cd engine/
cargo test

# Python tests
cd analyzer/
python -m pytest tests/
```

### Adding New Threat Detectors

1. Implement detector in `engine/src/detectors/`
2. Add feature extraction logic
3. Update training pipeline
4. Retrain and deploy student model

## License

MIT License - see LICENSE file for details.
