use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::{info, Level};

mod config;
mod features;
mod hard_intel;
mod linucb;
mod models;
mod redis_client;
mod routes;
mod student_model;
mod types;

use config::Config;
use redis_client::RedisClient;
use routes::{feedback, metrics, score};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("Starting Garuda Threat Detection Engine...");

    // Load configuration
    let config = Config::load()?;
    info!("Configuration loaded");

    // Initialize Redis client
    let redis_client = RedisClient::new(&config.redis_url).await?;
    info!("Redis client initialized");

    // Build application
    let app = Router::new()
        .route("/score", post(score))
        .route("/feedback", post(feedback))
        .route("/metrics", get(metrics))
        .layer(CorsLayer::permissive())
        .with_state(redis_client);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Server listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}