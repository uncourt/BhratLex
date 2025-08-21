#!/bin/bash

echo "Waiting for ClickHouse to be ready..."
sleep 10

echo "Initializing ClickHouse database..."
docker exec garuda-clickhouse clickhouse-client --query "
CREATE DATABASE IF NOT EXISTS garuda;
"

echo "Creating tables..."
docker exec garuda-clickhouse clickhouse-client --database=garuda --query "
-- Decisions table for hot path results
CREATE TABLE IF NOT EXISTS decisions (
    decision_id UUID,
    timestamp DateTime64(3),
    domain String,
    url Nullable(String),
    action Enum8('ALLOW' = 1, 'WARN' = 2, 'BLOCK' = 3),
    probability Float64,
    reasons Array(String),
    features Map(String, Float64),
    hard_intel_hits Array(String),
    cache_hit Bool,
    latency_ms Float64,
    model_version String
) ENGINE = MergeTree()
ORDER BY (timestamp, domain)
PARTITION BY toYYYYMM(timestamp);
"

docker exec garuda-clickhouse clickhouse-client --database=garuda --query "
-- Analyzer results from async analysis
CREATE TABLE IF NOT EXISTS analyzer (
    decision_id UUID,
    timestamp DateTime64(3),
    domain String,
    url Nullable(String),
    screenshot_path String,
    ocr_text String,
    vlm_verdict String,
    vlm_confidence Float64,
    vlm_reasons Array(String),
    analysis_duration_ms Float64,
    status Enum8('PENDING' = 1, 'COMPLETED' = 2, 'FAILED' = 3)
) ENGINE = MergeTree()
ORDER BY (timestamp, decision_id)
PARTITION BY toYYYYMM(timestamp);
"

docker exec garuda-clickhouse clickhouse-client --database=garuda --query "
-- Rewards for reinforcement learning
CREATE TABLE IF NOT EXISTS rewards (
    decision_id UUID,
    timestamp DateTime64(3),
    reward Float64,
    context String,
    user_id Nullable(String),
    feedback_type Enum8('EXPLICIT' = 1, 'IMPLICIT' = 2, 'AUTOMATED' = 3)
) ENGINE = MergeTree()
ORDER BY (timestamp, decision_id)
PARTITION BY toYYYYMM(timestamp);
"

docker exec garuda-clickhouse clickhouse-client --database=garuda --query "
-- Metrics aggregation table
CREATE TABLE IF NOT EXISTS metrics_hourly (
    timestamp DateTime,
    total_requests UInt64,
    cache_hits UInt64,
    avg_latency_ms Float64,
    p95_latency_ms Float64,
    p99_latency_ms Float64,
    action_counts Map(String, UInt64),
    error_count UInt64
) ENGINE = MergeTree()
ORDER BY timestamp
PARTITION BY toYYYYMM(timestamp);
"

docker exec garuda-clickhouse clickhouse-client --database=garuda --query "
-- Create materialized view for real-time metrics
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_mv TO metrics_hourly AS
SELECT
    toStartOfHour(timestamp) as timestamp,
    count() as total_requests,
    sum(cache_hit) as cache_hits,
    avg(latency_ms) as avg_latency_ms,
    quantile(0.95)(latency_ms) as p95_latency_ms,
    quantile(0.99)(latency_ms) as p99_latency_ms,
    map('ALLOW', countIf(action = 'ALLOW'), 'WARN', countIf(action = 'WARN'), 'BLOCK', countIf(action = 'BLOCK')) as action_counts,
    0 as error_count
FROM decisions
GROUP BY timestamp;
"

echo "ClickHouse initialization complete!"
echo "Database: garuda"
echo "Tables: decisions, analyzer, rewards, metrics_hourly"
echo "Materialized view: metrics_mv"