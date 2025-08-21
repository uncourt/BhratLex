use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecisionAction {
    ALLOW,
    WARN,
    BLOCK,
}

impl DecisionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            DecisionAction::ALLOW => "ALLOW",
            DecisionAction::WARN => "WARN",
            DecisionAction::BLOCK => "BLOCK",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreRequest {
    pub domain: String,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResponse {
    pub action: DecisionAction,
    pub prob: f64,
    pub reasons: Vec<String>,
    pub decision_id: String,
}

impl ScoreResponse {
    pub fn error(err: &str) -> Self {
        Self { action: DecisionAction::WARN, prob: 0.0, reasons: vec![err.to_string()], decision_id: "".to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRequest {
    pub decision_id: String,
    pub reward: f64,
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub bind_addr: String,
    pub student_path: String,
    pub threshold_allow: f64,
    pub threshold_block: f64,
    pub redis_url: String,
    pub clickhouse_url: String,
}

impl EngineConfig {
    pub fn from_env() -> Self {
        Self {
            bind_addr: std::env::var("GARUDA_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            student_path: std::env::var("GARUDA_STUDENT").unwrap_or_else(|_| "./engine/student.json".to_string()),
            threshold_allow: std::env::var("GARUDA_THRESH_ALLOW").ok().and_then(|v| v.parse().ok()).unwrap_or(0.3),
            threshold_block: std::env::var("GARUDA_THRESH_BLOCK").ok().and_then(|v| v.parse().ok()).unwrap_or(0.8),
            redis_url: std::env::var("GARUDA_REDIS").unwrap_or_else(|_| "redis://127.0.0.1/".to_string()),
            clickhouse_url: std::env::var("GARUDA_CLICKHOUSE").unwrap_or_else(|_| "http://127.0.0.1:8123".to_string()),
        }
    }
}