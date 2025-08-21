use serde::Deserialize;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub redis_url: String,
    pub clickhouse_url: String,
    pub model_version: String,
    pub cache_ttl_seconds: u64,
    pub max_concurrent_requests: usize,
}

impl Config {
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()
            .unwrap_or(3000);

        let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
        let clickhouse_url = env::var("CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://localhost:8123".to_string());

        let model_version = env::var("MODEL_VERSION").unwrap_or_else(|_| "v1.0.0".to_string());
        let cache_ttl_seconds = env::var("CACHE_TTL_SECONDS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .unwrap_or(3600);

        let max_concurrent_requests = env::var("MAX_CONCURRENT_REQUESTS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse()
            .unwrap_or(1000);

        Ok(Config {
            port,
            redis_url,
            clickhouse_url,
            model_version,
            cache_ttl_seconds,
            max_concurrent_requests,
        })
    }
}