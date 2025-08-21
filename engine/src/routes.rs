use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::Config,
    models::ThreatDetector,
    redis_client::RedisClient,
    types::{FeedbackRequest, FeedbackResponse, MetricsResponse, ScoreRequest, ScoreResponse},
};

pub type AppState = Arc<Mutex<RedisClient>>;

pub async fn score(
    State(state): State<Arc<Mutex<RedisClient>>>,
    Json(payload): Json<ScoreRequest>,
) -> Result<Json<ScoreResponse>, StatusCode> {
    let start_time = std::time::Instant::now();
    
    info!("Received score request for domain: {}", payload.domain);
    
    // Validate input
    if payload.domain.is_empty() {
        error!("Empty domain provided");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Check cache first
    let cache_key = format!("score:{}", payload.domain);
    let mut redis_client = state.lock().await;
    
    if let Ok(Some(cached_response)) = redis_client.get::<ScoreResponse>(&cache_key).await {
        info!("Cache hit for domain: {}", payload.domain);
        return Ok(Json(cached_response));
    }
    
    // Create threat detector
    let config = Config::load().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut detector = ThreatDetector::new(config.model_version);
    
    // Try to load student model
    if let Err(e) = detector.load_student_model("src/student.json") {
        warn!("Failed to load student model: {}, using default", e);
    }
    
    // Detect threat
    let response = detector.detect_threat(&payload.domain, payload.url.as_deref()).await;
    
    // Cache response
    let cache_ttl = std::time::Duration::from_secs(config.cache_ttl_seconds);
    if let Err(e) = redis_client.set(&cache_key, &response, cache_ttl).await {
        warn!("Failed to cache response: {}", e);
    }
    
    // Enqueue for async analysis if uncertain
    if response.probability < 0.8 && response.probability > 0.2 {
        let analysis_task = serde_json::json!({
            "decision_id": response.decision_id,
            "domain": payload.domain,
            "url": payload.url,
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        
        if let Err(e) = redis_client.enqueue("analysis_queue", &analysis_task.to_string()).await {
            warn!("Failed to enqueue analysis task: {}", e);
        }
    }
    
    // Update metrics
    let latency = start_time.elapsed().as_millis() as f64;
    if let Err(e) = redis_client.increment_counter("total_requests").await {
        warn!("Failed to update request counter: {}", e);
    }
    
    if let Err(e) = redis_client.increment_counter(&format!("action:{}", response.action)).await {
        warn!("Failed to update action counter: {}", e);
    }
    
    info!("Score request completed in {:.1}ms", latency);
    Ok(Json(response))
}

pub async fn feedback(
    State(state): State<Arc<Mutex<RedisClient>>>,
    Json(payload): Json<FeedbackRequest>,
) -> Result<Json<FeedbackResponse>, StatusCode> {
    info!("Received feedback for decision: {}", payload.decision_id);
    
    // Validate input
    if payload.reward < -1.0 || payload.reward > 1.0 {
        error!("Invalid reward value: {}", payload.reward);
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let mut redis_client = state.lock().await;
    
    // Store feedback in Redis for later processing
    let feedback_key = format!("feedback:{}", payload.decision_id);
    let feedback_data = serde_json::json!({
        "decision_id": payload.decision_id,
        "reward": payload.reward,
        "context": payload.context,
        "user_id": payload.user_id,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    if let Err(e) = redis_client.set(&feedback_key, &feedback_data, std::time::Duration::from_secs(86400)).await {
        error!("Failed to store feedback: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    
    // Enqueue for reward processing
    if let Err(e) = redis_client.enqueue("reward_queue", &feedback_data.to_string()).await {
        warn!("Failed to enqueue reward task: {}", e);
    }
    
    info!("Feedback stored successfully for decision: {}", payload.decision_id);
    
    Ok(Json(FeedbackResponse {
        success: true,
        message: "Feedback received successfully".to_string(),
    }))
}

pub async fn metrics(
    State(state): State<Arc<Mutex<RedisClient>>>,
) -> Result<Json<MetricsResponse>, StatusCode> {
    let mut redis_client = state.lock().await;
    
    // Get counters from Redis
    let total_requests = redis_client.get_counter("total_requests").await.unwrap_or(0);
    let cache_hits = redis_client.get_counter("cache_hits").await.unwrap_or(0);
    let allow_count = redis_client.get_counter("action:ALLOW").await.unwrap_or(0);
    let warn_count = redis_client.get_counter("action:WARN").await.unwrap_or(0);
    let block_count = redis_client.get_counter("action:BLOCK").await.unwrap_or(0);
    
    // Calculate QPS (simplified - would use proper time-based calculation)
    let qps = if total_requests > 0 { 1000.0 } else { 0.0 }; // Placeholder
    
    // Calculate p95 latency (simplified - would use proper percentile calculation)
    let p95_latency_ms = 1.2; // Placeholder
    
    // Calculate cache hit rate
    let cache_hit_rate = if total_requests > 0 {
        cache_hits as f64 / total_requests as f64
    } else {
        0.0
    };
    
    // Build action counts
    let mut action_counts = HashMap::new();
    action_counts.insert("ALLOW".to_string(), allow_count);
    action_counts.insert("WARN".to_string(), warn_count);
    action_counts.insert("BLOCK".to_string(), block_count);
    
    let response = MetricsResponse {
        qps,
        p95_latency_ms,
        cache_hits: cache_hit_rate,
        total_requests,
        action_counts,
    };
    
    Ok(Json(response))
}

pub async fn health_check() -> Result<Json<Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "garuda-engine"
    })))
}