use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Action {
    ALLOW,
    WARN,
    BLOCK,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreRequest {
    pub domain: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreResponse {
    pub action: Action,
    pub probability: f64,
    pub reasons: Vec<String>,
    pub decision_id: Uuid,
    pub features: HashMap<String, f64>,
    pub hard_intel_hits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackRequest {
    pub decision_id: Uuid,
    pub reward: f64,
    pub context: String,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub qps: f64,
    pub p95_latency_ms: f64,
    pub cache_hits: f64,
    pub total_requests: u64,
    pub action_counts: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub url: Option<String>,
    pub action: Action,
    pub probability: f64,
    pub reasons: Vec<String>,
    pub features: HashMap<String, f64>,
    pub hard_intel_hits: Vec<String>,
    pub cache_hit: bool,
    pub latency_ms: f64,
    pub model_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFeatures {
    pub length: f64,
    pub entropy: f64,
    pub consonant_ratio: f64,
    pub vowel_ratio: f64,
    pub digit_ratio: f64,
    pub special_char_ratio: f64,
    pub consecutive_consonants: f64,
    pub consecutive_vowels: f64,
    pub consecutive_digits: f64,
    pub consecutive_special_chars: f64,
    pub idn_homoglyph_score: f64,
    pub typosquatting_score: f64,
    pub dga_entropy: f64,
    pub nrd_flag: f64,
    pub dynamic_dns_flag: f64,
    pub parked_domain_flag: f64,
    pub cname_cloaking_flag: f64,
    pub dns_rebinding_flag: f64,
    pub cryptojacking_flag: f64,
}

impl Default for DomainFeatures {
    fn default() -> Self {
        Self {
            length: 0.0,
            entropy: 0.0,
            consonant_ratio: 0.0,
            vowel_ratio: 0.0,
            digit_ratio: 0.0,
            special_char_ratio: 0.0,
            consecutive_consonants: 0.0,
            consecutive_vowels: 0.0,
            consecutive_digits: 0.0,
            consecutive_special_chars: 0.0,
            idn_homoglyph_score: 0.0,
            typosquatting_score: 0.0,
            dga_entropy: 0.0,
            nrd_flag: 0.0,
            dynamic_dns_flag: 0.0,
            parked_domain_flag: 0.0,
            cname_cloaking_flag: 0.0,
            dns_rebinding_flag: 0.0,
            cryptojacking_flag: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardIntelResult {
    pub source: String,
    pub is_malicious: bool,
    pub confidence: f64,
    pub details: Option<String>,
}