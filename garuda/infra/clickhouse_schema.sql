CREATE DATABASE IF NOT EXISTS garuda;

CREATE TABLE IF NOT EXISTS garuda.decisions (
  ts DateTime DEFAULT now(),
  decision_id String,
  domain String,
  url String,
  action String,
  prob Float64,
  reasons Array(String),
  features_json String
) ENGINE = MergeTree ORDER BY (ts, decision_id);

CREATE TABLE IF NOT EXISTS garuda.analyzer (
  ts DateTime DEFAULT now(),
  decision_id String,
  domain String,
  url String,
  ocr_text String,
  vlm_verdict String,
  vlm_reasons String,
  screenshot_base64 String,
  html_truncated String
) ENGINE = MergeTree ORDER BY (ts, decision_id);

CREATE TABLE IF NOT EXISTS garuda.rewards (
  ts DateTime DEFAULT now(),
  decision_id String,
  action String,
  reward Float64
) ENGINE = MergeTree ORDER BY (ts, decision_id);