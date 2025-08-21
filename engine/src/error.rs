use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("ClickHouse error: {0}")]
    ClickHouse(String),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DNS resolution error: {0}")]
    Dns(String),

    #[error("Feature extraction error: {0}")]
    FeatureExtraction(String),

    #[error("Model inference error: {0}")]
    ModelInference(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Hard intel lookup failed: {0}")]
    HardIntelLookup(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Rate limit exceeded")]
    RateLimit,

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::InvalidInput(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::RateLimit => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            _ => {
                tracing::error!("Internal server error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

impl From<clickhouse::error::Error> for AppError {
    fn from(err: clickhouse::error::Error) -> Self {
        AppError::ClickHouse(err.to_string())
    }
}

// Helper function for creating validation errors
pub fn validation_error(msg: &str) -> AppError {
    AppError::InvalidInput(msg.to_string())
}

// Helper function for creating internal errors
pub fn internal_error(msg: &str) -> AppError {
    AppError::Internal(msg.to_string())
}