use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::signal;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod detectors;
mod engine;
mod error;
mod features;
mod hard_intel;
mod linucb;
mod models;
mod storage;
mod types;

use config::Config;
use engine::ThreatEngine;
use error::AppError;
use types::*;

type AppState = Arc<ThreatEngine>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "garuda_engine=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::load()?;
    info!("Loaded configuration: {:?}", config);

    // Initialize threat engine
    let engine = ThreatEngine::new(config).await?;
    let app_state = Arc::new(engine);

    // Initialize metrics exporter
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .install()
        .expect("Failed to install Prometheus exporter");

    // Build router
    let app = Router::new()
        .route("/score", post(score_handler))
        .route("/feedback", post(feedback_handler))
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    info!("Starting Garuda Threat Detection Engine on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn score_handler(
    State(engine): State<AppState>,
    Json(request): Json<ScoreRequest>,
) -> Result<Json<ScoreResponse>, AppError> {
    let start = Instant::now();
    
    // Increment request counter
    metrics::counter!("requests_total").increment(1);
    
    let result = engine.score(request).await?;
    
    let latency = start.elapsed().as_millis() as f64;
    metrics::histogram!("request_duration_ms").record(latency);
    
    Ok(Json(result))
}

async fn feedback_handler(
    State(engine): State<AppState>,
    Json(request): Json<FeedbackRequest>,
) -> Result<Json<FeedbackResponse>, AppError> {
    engine.process_feedback(request).await?;
    
    Ok(Json(FeedbackResponse {
        success: true,
        message: "Feedback processed successfully".to_string(),
    }))
}

async fn metrics_handler(State(engine): State<AppState>) -> Result<Json<MetricsResponse>, AppError> {
    let metrics = engine.get_metrics().await?;
    Ok(Json(metrics))
}

async fn health_handler() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    })))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    warn!("Shutdown signal received, starting graceful shutdown");
}