use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub thresholds: ThresholdConfig,
    pub redis: RedisConfig,
    pub clickhouse: ClickHouseConfig,
    pub hard_intel: HardIntelConfig,
    pub features: FeatureConfig,
    pub linucb: LinUCBConfig,
    pub student_model: StudentModelConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThresholdConfig {
    pub block_threshold: f32,
    pub warn_threshold: f32,
    pub uncertainty_threshold: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub queue_name: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HardIntelConfig {
    pub google_safe_browsing_api_key: String,
    pub abuse_ch_enabled: bool,
    pub shadowserver_enabled: bool,
    pub spamhaus_enabled: bool,
    pub coinblocker_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FeatureConfig {
    pub check_idn_homoglyphs: bool,
    pub check_typosquatting: bool,
    pub check_dga: bool,
    pub check_nrd: bool,
    pub check_dynamic_dns: bool,
    pub check_parked_domains: bool,
    pub check_cname_cloaking: bool,
    pub feature_cache_ttl: u64,
    pub intel_cache_ttl: u64,
    pub max_dns_lookups: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinUCBConfig {
    pub alpha: f64,
    pub context_dimensions: usize,
    pub arms: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StudentModelConfig {
    pub path: String,
    pub feature_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config_path = std::env::var("GARUDA_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
        
        if !Path::new(&config_path).exists() {
            // Create default config if it doesn't exist
            let default_config = Self::default();
            let toml_content = toml::to_string_pretty(&default_config)?;
            std::fs::write(&config_path, toml_content)?;
            tracing::info!("Created default configuration file: {}", config_path);
        }

        let config_content = std::fs::read_to_string(&config_path)?;
        let config: Config = toml::from_str(&config_content)?;
        
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8000,
                workers: 4,
            },
            thresholds: ThresholdConfig {
                block_threshold: 0.8,
                warn_threshold: 0.5,
                uncertainty_threshold: 0.3,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                queue_name: "analyzer_queue".to_string(),
                max_connections: 10,
            },
            clickhouse: ClickHouseConfig {
                url: "http://localhost:8123".to_string(),
                database: "garuda".to_string(),
                username: "default".to_string(),
                password: "".to_string(),
            },
            hard_intel: HardIntelConfig {
                google_safe_browsing_api_key: "".to_string(),
                abuse_ch_enabled: true,
                shadowserver_enabled: true,
                spamhaus_enabled: true,
                coinblocker_enabled: true,
            },
            features: FeatureConfig {
                check_idn_homoglyphs: true,
                check_typosquatting: true,
                check_dga: true,
                check_nrd: true,
                check_dynamic_dns: true,
                check_parked_domains: true,
                check_cname_cloaking: true,
                feature_cache_ttl: 300,
                intel_cache_ttl: 3600,
                max_dns_lookups: 5,
            },
            linucb: LinUCBConfig {
                alpha: 1.0,
                context_dimensions: 20,
                arms: 3,
            },
            student_model: StudentModelConfig {
                path: "models/student.json".to_string(),
                feature_count: 50,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
            },
        }
    }
}