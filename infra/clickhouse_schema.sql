CREATE DATABASE IF NOT EXISTS garuda;

USE garuda;

-- Table for storing all decisions made by the engine
CREATE TABLE IF NOT EXISTS decisions (
    timestamp DateTime64(3) DEFAULT now64(),
    decision_id String,
    domain String,
    url String DEFAULT '',
    action Enum8('ALLOW' = 1, 'WARN' = 2, 'BLOCK' = 3),
    probability Float32,
    reasons Array(String),
    features Map(String, Float32),
    latency_ms Float32,
    hard_intel_match String DEFAULT '',
    student_score Float32,
    linucb_score Float32,
    client_ip String DEFAULT '',
    user_agent String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, decision_id)
TTL timestamp + INTERVAL 90 DAY;

-- Table for analyzer results from Python worker
CREATE TABLE IF NOT EXISTS analyzer (
    timestamp DateTime64(3) DEFAULT now64(),
    decision_id String,
    domain String,
    url String,
    screenshot_path String DEFAULT '',
    html_content String DEFAULT '',
    ocr_text String DEFAULT '',
    vlm_verdict String DEFAULT '',
    vlm_confidence Float32 DEFAULT 0,
    is_threat Bool DEFAULT false,
    threat_categories Array(String),
    processing_time_ms UInt32,
    error_message String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, decision_id)
TTL timestamp + INTERVAL 30 DAY;

-- Table for reinforcement learning rewards
CREATE TABLE IF NOT EXISTS rewards (
    timestamp DateTime64(3) DEFAULT now64(),
    decision_id String,
    reward Float32,
    actual_threat Bool,
    feedback_source String DEFAULT 'user',
    context Map(String, String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, decision_id)
TTL timestamp + INTERVAL 180 DAY;

-- Table for performance metrics
CREATE TABLE IF NOT EXISTS metrics (
    timestamp DateTime64(3) DEFAULT now64(),
    metric_name String,
    metric_value Float32,
    tags Map(String, String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, metric_name)
TTL timestamp + INTERVAL 7 DAY;

-- Materialized view for real-time threat statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS threat_stats_mv TO threat_stats AS
SELECT 
    toStartOfHour(timestamp) as hour,
    action,
    count() as decisions_count,
    avg(probability) as avg_probability,
    avg(latency_ms) as avg_latency_ms
FROM decisions
GROUP BY hour, action;

CREATE TABLE IF NOT EXISTS threat_stats (
    hour DateTime,
    action Enum8('ALLOW' = 1, 'WARN' = 2, 'BLOCK' = 3),
    decisions_count UInt64,
    avg_probability Float32,
    avg_latency_ms Float32
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, action);

-- Index for fast decision lookups
CREATE TABLE IF NOT EXISTS decision_index (
    decision_id String,
    timestamp DateTime64(3),
    domain String,
    action Enum8('ALLOW' = 1, 'WARN' = 2, 'BLOCK' = 3)
) ENGINE = MergeTree()
ORDER BY decision_id;

-- Insert some sample data for testing
INSERT INTO decisions (decision_id, domain, url, action, probability, reasons, latency_ms, hard_intel_match, student_score, linucb_score) VALUES
('test-001', 'google.com', 'https://google.com', 'ALLOW', 0.05, [], 0.8, '', 0.05, 0.02),
('test-002', 'malware-example.com', 'https://malware-example.com', 'BLOCK', 0.95, ['Hard intel match: Google Safe Browsing'], 1.2, 'gsb', 0.85, 0.10),
('test-003', 'g00gle.com', 'https://g00gle.com/login', 'WARN', 0.72, ['IDN homoglyph detected', 'Typosquatting suspected'], 1.1, '', 0.68, 0.04);