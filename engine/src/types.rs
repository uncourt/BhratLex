use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
pub struct ScoreRequest {
    pub domain: String,
    pub url: Option<String>,
    pub context: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreResponse {
    pub action: Action,
    pub probability: f32,
    pub reasons: Vec<String>,
    pub decision_id: String,
    pub latency_ms: f32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    Allow,
    Warn,
    Block,
}

impl Action {
    pub fn from_probability(prob: f32, warn_threshold: f32, block_threshold: f32) -> Self {
        if prob >= block_threshold {
            Action::Block
        } else if prob >= warn_threshold {
            Action::Warn
        } else {
            Action::Allow
        }
    }

    pub fn as_arm_index(&self) -> usize {
        match self {
            Action::Allow => 0,
            Action::Warn => 1,
            Action::Block => 2,
        }
    }

    pub fn from_arm_index(index: usize) -> Self {
        match index {
            0 => Action::Allow,
            1 => Action::Warn,
            2 => Action::Block,
            _ => Action::Allow,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeedbackRequest {
    pub decision_id: String,
    pub reward: f32,
    pub actual_threat: bool,
    pub feedback_source: Option<String>,
    pub context: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FeedbackResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsResponse {
    pub qps: f32,
    pub p95_latency_ms: f32,
    pub cache_hit_rate: f32,
    pub decisions_today: u64,
    pub blocked_threats: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct ThreatFeatures {
    pub domain: String,
    pub url: Option<String>,
    pub features: HashMap<String, f32>,
}

#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub decision_id: String,
    pub domain: String,
    pub url: Option<String>,
    pub features: HashMap<String, f32>,
    pub hard_intel_match: Option<String>,
    pub student_score: f32,
    pub linucb_score: f32,
    pub final_probability: f32,
    pub action: Action,
    pub reasons: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct AnalyzerTask {
    pub decision_id: String,
    pub domain: String,
    pub url: String,
    pub features: HashMap<String, f32>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudentModel {
    pub weights: Vec<f32>,
    pub bias: f32,
    pub feature_names: Vec<String>,
    pub version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl StudentModel {
    pub fn predict(&self, features: &[f32]) -> f32 {
        let mut score = self.bias;
        for (i, &feature) in features.iter().enumerate() {
            if i < self.weights.len() {
                score += self.weights[i] * feature;
            }
        }
        // Apply sigmoid activation
        1.0 / (1.0 + (-score).exp())
    }
}

#[derive(Debug, Clone)]
pub struct HardIntelMatch {
    pub source: String,
    pub category: String,
    pub confidence: f32,
    pub details: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub domain: String,
    pub tld: String,
    pub sld: String,
    pub subdomain: Option<String>,
    pub is_idn: bool,
    pub punycode: Option<String>,
    pub registrar: Option<String>,
    pub creation_date: Option<chrono::DateTime<chrono::Utc>>,
    pub dns_records: HashMap<String, Vec<String>>,
}

// Feature extraction constants
pub const FEATURE_NAMES: &[&str] = &[
    "domain_length",
    "subdomain_count",
    "numeric_ratio",
    "special_char_ratio",
    "entropy",
    "vowel_consonant_ratio",
    "digit_letter_ratio",
    "consecutive_consonants",
    "dictionary_words",
    "tld_popularity",
    "alexa_rank_log",
    "domain_age_days",
    "is_idn",
    "homoglyph_score",
    "typosquatting_score",
    "dga_score",
    "dynamic_dns",
    "parked_domain",
    "suspicious_tld",
    "fast_flux",
    "dns_record_count",
    "mx_record_exists",
    "spf_record_exists",
    "dmarc_record_exists",
    "ssl_cert_valid",
    "whois_privacy",
    "registrar_reputation",
    "ip_reputation",
    "asn_reputation",
    "geolocation_risk",
    "url_length",
    "path_depth",
    "query_params_count",
    "fragment_exists",
    "suspicious_keywords",
    "phishing_keywords",
    "brand_impersonation",
    "url_shortener",
    "redirect_count",
    "response_time_ms",
    "content_type_suspicious",
    "javascript_obfuscated",
    "form_count",
    "input_field_count",
    "external_links_count",
    "suspicious_file_extensions",
    "crypto_mining_scripts",
    "social_engineering_indicators",
    "urgency_language",
    "trust_indicators_missing",
];

pub const FEATURE_COUNT: usize = FEATURE_NAMES.len();