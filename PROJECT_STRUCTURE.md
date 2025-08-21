# Garuda Project Structure

## Overview
Garuda is a high-performance AI Threat Detection Engine with inline hot path (≤1.5ms p95 latency) and async AI analysis for uncertain cases.

## Directory Structure

```
garuda/
├── README.md                 # Main project documentation
├── .env.example             # Environment variables template
├── quick_start.sh           # One-command setup and run script
├── test_garuda.sh           # Comprehensive system testing script
├── PROJECT_STRUCTURE.md     # This file
│
├── infra/                   # Infrastructure components
│   ├── docker-compose.yml   # Redis + ClickHouse services
│   ├── clickhouse_schema.sql # Database schema and tables
│   └── init-clickhouse.sh   # Database initialization script
│
├── engine/                  # Rust threat detection engine
│   ├── Cargo.toml          # Rust dependencies
│   ├── Dockerfile          # Container configuration
│   ├── .dockerignore       # Docker build exclusions
│   ├── src/
│   │   ├── main.rs         # Application entry point
│   │   ├── config.rs       # Configuration management
│   │   ├── types.rs        # Type definitions and structs
│   │   ├── features.rs     # Domain feature extraction
│   │   ├── hard_intel.rs   # Hard intelligence checking
│   │   ├── student_model.rs # Logistic regression model
│   │   ├── linucb.rs       # LinUCB contextual bandit
│   │   ├── models.rs       # Threat detection logic
│   │   ├── redis_client.rs # Redis client wrapper
│   │   └── routes.rs       # HTTP API endpoints
│   └── src/student.json    # Pre-trained student model
│
├── analyzer/                # Python async analyzer
│   ├── requirements.txt     # Python dependencies
│   ├── setup.sh            # Environment setup script
│   ├── run.sh              # Analyzer startup script
│   ├── worker.py            # Main analyzer worker
│   ├── vlm_client.py       # Vision Language Model client
│   └── utils.py            # Utility functions
│
└── train/                   # Model training
    ├── distill_student.py   # Student model training script
    └── sample_data.csv      # Sample training data
```

## Component Architecture

### 1. Infrastructure (infra/)
- **Redis**: Caching, queue management, metrics storage
- **ClickHouse**: Analytics database for decisions, analysis results, and rewards
- **Docker Compose**: Orchestration of infrastructure services

### 2. Rust Engine (engine/)
- **Hot Path**: Inline threat detection with ≤1.5ms p95 latency
- **Feature Extraction**: Domain analysis (IDN homoglyphs, typosquatting, DGA, etc.)
- **Hard Intel**: Google Safe Browsing, abuse.ch, Shadowserver, Spamhaus DROP
- **ML Models**: Student logistic regression + LinUCB contextual bandit
- **API Server**: Axum-based HTTP server with async support

### 3. Python Analyzer (analyzer/)
- **Async Processing**: Background analysis of uncertain cases
- **Playwright**: Headless browser automation for screenshots
- **PaddleOCR**: Text extraction from screenshots
- **VLM Integration**: Local vLLM server with Qwen2-VL-7B model
- **Queue Management**: Redis-based task queuing

### 4. Training (train/)
- **Model Distillation**: Teacher→student knowledge transfer
- **Feature Engineering**: Domain-specific feature extraction
- **Logistic Regression**: Lightweight student model training
- **Performance Metrics**: Accuracy, ROC AUC, classification reports

## Key Features

### Threat Detection
- **IDN Homoglyphs**: Internationalized domain name attacks
- **Typosquatting**: Character substitution and transposition
- **DGA Detection**: Domain Generation Algorithm entropy analysis
- **CNAME Cloaking**: DNS-based attack detection
- **Cryptojacking**: Mining script detection
- **Dynamic DNS**: Suspicious DNS provider detection

### Performance
- **Hot Path**: ≤1.5ms p95 latency for inline decisions
- **Throughput**: 1000+ QPS capability
- **Caching**: Redis-based response caching
- **Async Processing**: Non-blocking analysis for uncertain cases

### Machine Learning
- **Student Model**: Lightweight logistic regression
- **LinUCB**: Contextual bandit for action selection
- **Reinforcement Learning**: Reward-based model updates
- **Feature Importance**: Explainable threat detection

### Explainability
- **Detailed Reasons**: Specific threat explanations
- **Screenshots**: Visual evidence capture
- **OCR Text**: Extracted webpage content
- **Feature Scores**: Individual threat indicators
- **Confidence Levels**: Decision probability scores

## API Endpoints

### POST /score
Score a domain for threats with inline response.

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
  "probability": 0.95,
  "reasons": ["Domain appears legitimate"],
  "decision_id": "uuid-here",
  "features": {"length": 12.0, "entropy": 3.2},
  "hard_intel_hits": []
}
```

### POST /feedback
Update rewards for reinforcement learning.

### GET /metrics
Get system performance metrics.

### GET /health
Health check endpoint.

## Data Flow

1. **Client Request** → POST /score with domain
2. **Hot Path Processing**:
   - Feature extraction
   - Hard intel checking
   - Student model prediction
   - LinUCB action selection
   - Cache storage
3. **Async Analysis** (if uncertain):
   - Enqueue analysis task
   - Playwright screenshot capture
   - PaddleOCR text extraction
   - VLM threat analysis
   - ClickHouse storage
4. **Response**: Immediate decision + async analysis results

## Performance Targets

- **Latency**: ≤1.5ms p95 for hot path
- **Throughput**: 1000+ QPS
- **Cache Hit Rate**: >85%
- **Accuracy**: >95% with hard-intel gates
- **Availability**: 99.9% uptime

## Security Features

- Input validation and sanitization
- Rate limiting and DDoS protection
- Secure Redis and ClickHouse connections
- Audit logging for all decisions
- Hard intel verification gates

## Monitoring

- **Metrics**: QPS, latency, cache hits, action counts
- **Logs**: Structured JSON logging with tracing
- **Health Checks**: Service health monitoring
- **Alerts**: Redis queue monitoring and alerts

## Development

### Prerequisites
- Docker and Docker Compose
- Rust 1.75+
- Python 3.8+
- 8GB+ RAM for VLM server

### Quick Start
```bash
# Clone and setup
git clone <repository>
cd garuda

# One-command setup
./quick_start.sh

# Manual setup
cd infra && docker-compose up -d
cd ../engine && cargo build --release
cd ../analyzer && ./setup.sh
```

### Testing
```bash
# Run comprehensive tests
./test_garuda.sh

# Test individual components
curl -X POST http://localhost:3000/score \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

## Deployment

### Production Considerations
- Load balancing and auto-scaling
- Redis clustering for high availability
- ClickHouse replication for data durability
- VLM server optimization (GPU acceleration)
- Monitoring and alerting setup
- Backup and disaster recovery

### Container Deployment
```bash
# Build and run Rust engine
cd engine
docker build -t garuda-engine .
docker run -p 3000:3000 garuda-engine

# Run Python analyzer
cd analyzer
docker run -it --rm -v $(pwd):/app python:3.9 bash
pip install -r requirements.txt
python worker.py
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Ensure all tests pass
5. Submit pull request

## License

MIT License - see LICENSE file for details.