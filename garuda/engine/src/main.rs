mod types;
mod features;
mod model;
mod bandit;
mod intel;
mod metrics;
mod storage;
mod queue;

use axum::{routing::{get, post}, Json, Router};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{info, error};
use uuid::Uuid;
use crate::types::{ScoreRequest, ScoreResponse, FeedbackRequest, EngineConfig, DecisionAction};
use crate::metrics::Metrics;
use crate::intel::Intel;
use crate::features::Featurizer;
use crate::model::StudentModel;
use crate::bandit::LinUcb;
use crate::storage::Storage;
use crate::queue::Queue;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    metrics: Arc<Metrics>,
    intel: Arc<Intel>,
    featurizer: Arc<Featurizer>,
    model: Arc<StudentModel>,
    bandit: Arc<RwLock<LinUcb>>, // protected for updates
    storage: Arc<Storage>,
    queue: Arc<Queue>,
    config: EngineConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = EngineConfig::from_env();

    let metrics = Arc::new(Metrics::new());
    let intel = Arc::new(Intel::load_default(&config).await?);
    let featurizer = Arc::new(Featurizer::new());
    let model = Arc::new(StudentModel::load(&config.student_path)?);
    let storage = Arc::new(Storage::connect(&config).await?);
    let queue = Arc::new(Queue::connect(&config).await?);

    let bandit = Arc::new(RwLock::new(LinUcb::load_or_init(&config, &queue).await?));

    let state = AppState {
        metrics: metrics.clone(),
        intel: intel.clone(),
        featurizer: featurizer.clone(),
        model: model.clone(),
        bandit: bandit.clone(),
        storage: storage.clone(),
        queue: queue.clone(),
        config: config.clone(),
    };

    let app = Router::new()
        .route("/score", post(score))
        .route("/feedback", post(feedback))
        .route("/metrics", get(metrics_endpoint))
        .with_state(state);

    let addr: SocketAddr = config.bind_addr.parse()?;
    info!("Starting Garuda engine on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(0)?
}

async fn score(State(state): State<AppState>, Json(req): Json<ScoreRequest>) -> Json<ScoreResponse> {
    let t0 = std::time::Instant::now();

    // Normalize domain
    let domain = match idna::domain_to_ascii(&req.domain) {
        Ok(d) => d,
        Err(_) => {
            return Json(ScoreResponse::error("invalid_domain"));
        }
    };

    let url = req.url.clone().unwrap_or_else(|| format!("http://{}", domain));

    // Hard intel gate
    if let Some(reason) = state.intel.check_block(&domain).await {
        let decision_id = Uuid::new_v4().to_string();
        let response = ScoreResponse {
            action: DecisionAction::BLOCK,
            prob: 1.0,
            reasons: vec![reason],
            decision_id: decision_id.clone(),
        };
        // Log and enqueue
        if let Err(e) = state.storage.insert_decision(&decision_id, &domain, &url, &response, &serde_json::json!({"intel": true})).await { error!(?e, "insert_decision failed"); }
        if let Err(e) = state.queue.enqueue_task(&decision_id, &domain, &url).await { error!(?e, "enqueue failed"); }
        state.metrics.observe_request(t0.elapsed());
        return Json(response);
    }

    // Features
    let (features, reasons_feat) = state.featurizer.extract(&domain, &url).await;

    // Student model
    let prob = state.model.predict_probability(&features);

    // Decision policy
    let mut reasons = reasons_feat;
    let action = if prob < state.config.threshold_allow {
        DecisionAction::ALLOW
    } else if prob > state.config.threshold_block {
        DecisionAction::BLOCK
    } else {
        // Uncertain: use LinUCB to choose among ALLOW/WARN/BLOCK
        let x = features.clone();
        let chosen = state.bandit.write().select_action(&x);
        reasons.push(format!("linucb:{}", chosen.as_str()));
        chosen
    };

    // Decision id and logging
    let decision_id = Uuid::new_v4().to_string();
    let response = ScoreResponse { action: action.clone(), prob, reasons: reasons.clone(), decision_id: decision_id.clone() };

    if let Err(e) = state.storage.insert_decision(&decision_id, &domain, &url, &response, &serde_json::to_value(&features).unwrap_or(serde_json::Value::Null)).await { error!(?e, "insert_decision failed"); }
    if action != DecisionAction::ALLOW {
        if let Err(e) = state.queue.enqueue_task(&decision_id, &domain, &url).await { error!(?e, "enqueue failed"); }
    }

    state.metrics.observe_request(t0.elapsed());
    Json(response)
}

async fn feedback(State(state): State<AppState>, Json(req): Json<FeedbackRequest>) -> Json<serde_json::Value> {
    match state.bandit.write().update_from_feedback(&req).await {
        Ok(_) => Json(serde_json::json!({"status":"ok"})),
        Err(e) => {
            error!(?e, "feedback error");
            Json(serde_json::json!({"status":"error","error":e.to_string()}))
        }
    }
}

async fn metrics_endpoint(State(state): State<AppState>) -> String {
    state.metrics.format()
}