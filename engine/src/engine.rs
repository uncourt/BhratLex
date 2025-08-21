use crate::{
    config::Config,
    detectors::ThreatDetectors,
    error::AppError,
    features::FeatureExtractor,
    hard_intel::HardIntelChecker,
    linucb::LinUCBBandit,
    models::StudentModel,
    storage::{ClickHouseClient, RedisClient},
    types::*,
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct ThreatEngine {
    config: Config,
    hard_intel: HardIntelChecker,
    feature_extractor: FeatureExtractor,
    detectors: ThreatDetectors,
    student_model: Arc<RwLock<StudentModel>>,
    linucb: Arc<Mutex<LinUCBBandit>>,
    redis_client: RedisClient,
    clickhouse_client: ClickHouseClient,
    metrics: Arc<Mutex<EngineMetrics>>,
    start_time: Instant,
}

#[derive(Debug, Default)]
struct EngineMetrics {
    total_requests: u64,
    total_latency_ms: f64,
    cache_hits: u64,
    cache_misses: u64,
    decisions_today: HashMap<Action, u64>,
    last_reset: Instant,
}

impl ThreatEngine {
    pub async fn new(config: Config) -> Result<Self, AppError> {
        info!("Initializing Threat Engine...");

        // Initialize hard intel checker
        let hard_intel = HardIntelChecker::new(&config.hard_intel).await?;
        
        // Initialize feature extractor
        let feature_extractor = FeatureExtractor::new(&config.features).await?;
        
        // Initialize threat detectors
        let detectors = ThreatDetectors::new(&config.features).await?;
        
        // Load student model
        let student_model = Self::load_student_model(&config.student_model.path).await?;
        let student_model = Arc::new(RwLock::new(student_model));
        
        // Initialize LinUCB bandit
        let linucb = LinUCBBandit::new(
            config.linucb.arms,
            config.linucb.context_dimensions,
            config.linucb.alpha,
        );
        let linucb = Arc::new(Mutex::new(linucb));
        
        // Initialize storage clients
        let redis_client = RedisClient::new(&config.redis).await?;
        let clickhouse_client = ClickHouseClient::new(&config.clickhouse).await?;
        
        let metrics = Arc::new(Mutex::new(EngineMetrics {
            last_reset: Instant::now(),
            ..Default::default()
        }));
        
        info!("Threat Engine initialized successfully");
        
        Ok(Self {
            config,
            hard_intel,
            feature_extractor,
            detectors,
            student_model,
            linucb,
            redis_client,
            clickhouse_client,
            metrics,
            start_time: Instant::now(),
        })
    }

    // Hot path - optimized for sub-1.5ms latency
    pub async fn score(&self, request: ScoreRequest) -> Result<ScoreResponse, AppError> {
        let start_time = Instant::now();
        let decision_id = Uuid::new_v4().to_string();
        
        // Validate input
        self.validate_request(&request)?;
        
        // Step 1: Hard intel gate (fastest check)
        if let Some(intel_match) = self.hard_intel.check_fast(&request.domain).await? {
            let action = Action::Block;
            let probability = intel_match.confidence;
            let reasons = vec![format!("Hard intel match: {}", intel_match.source)];
            
            // Log decision asynchronously
            let decision_context = DecisionContext {
                decision_id: decision_id.clone(),
                domain: request.domain.clone(),
                url: request.url.clone(),
                features: HashMap::new(),
                hard_intel_match: Some(intel_match.source),
                student_score: 0.0,
                linucb_score: 0.0,
                final_probability: probability,
                action,
                reasons: reasons.clone(),
                timestamp: chrono::Utc::now(),
            };
            
            tokio::spawn({
                let clickhouse = self.clickhouse_client.clone();
                let decision = decision_context.clone();
                async move {
                    if let Err(e) = clickhouse.log_decision(&decision).await {
                        warn!("Failed to log decision: {}", e);
                    }
                }
            });
            
            let latency_ms = start_time.elapsed().as_secs_f32() * 1000.0;
            self.update_metrics(latency_ms, true).await;
            
            return Ok(ScoreResponse {
                action,
                probability,
                reasons,
                decision_id,
                latency_ms,
            });
        }
        
        // Step 2: Feature extraction (cached)
        let features = self.feature_extractor.extract(&request.domain, request.url.as_deref()).await?;
        
        // Step 3: Student model inference
        let student_score = {
            let model = self.student_model.read().unwrap();
            let feature_vector = self.features_to_vector(&features.features);
            model.predict(&feature_vector)
        };
        
        // Step 4: LinUCB contextual bandit
        let context_vector = self.build_context_vector(&features.features);
        let linucb_action = {
            let mut bandit = self.linucb.lock().await;
            bandit.select_arm(&context_vector)
        };
        let linucb_score = linucb_action.1; // confidence score
        
        // Step 5: Final decision combining student model and LinUCB
        let combined_score = self.combine_scores(student_score, linucb_score);
        let action = Action::from_probability(
            combined_score,
            self.config.thresholds.warn_threshold,
            self.config.thresholds.block_threshold,
        );
        
        // Step 6: Generate explanations
        let reasons = self.generate_reasons(&features.features, &action, student_score);
        
        // Step 7: Log decision and enqueue for deep analysis if uncertain
        let decision_context = DecisionContext {
            decision_id: decision_id.clone(),
            domain: request.domain.clone(),
            url: request.url.clone(),
            features: features.features.clone(),
            hard_intel_match: None,
            student_score,
            linucb_score,
            final_probability: combined_score,
            action,
            reasons: reasons.clone(),
            timestamp: chrono::Utc::now(),
        };
        
        // Async logging and queuing
        tokio::spawn({
            let clickhouse = self.clickhouse_client.clone();
            let redis = self.redis_client.clone();
            let decision = decision_context.clone();
            let uncertainty_threshold = self.config.thresholds.uncertainty_threshold;
            
            async move {
                // Log decision
                if let Err(e) = clickhouse.log_decision(&decision).await {
                    warn!("Failed to log decision: {}", e);
                }
                
                // Enqueue for deep analysis if uncertain
                if Self::is_uncertain(combined_score, uncertainty_threshold) {
                    let analyzer_task = AnalyzerTask {
                        decision_id: decision.decision_id.clone(),
                        domain: decision.domain.clone(),
                        url: decision.url.unwrap_or_default(),
                        features: decision.features.clone(),
                        timestamp: decision.timestamp,
                    };
                    
                    if let Err(e) = redis.enqueue_analyzer_task(&analyzer_task).await {
                        warn!("Failed to enqueue analyzer task: {}", e);
                    }
                }
            }
        });
        
        let latency_ms = start_time.elapsed().as_secs_f32() * 1000.0;
        self.update_metrics(latency_ms, false).await;
        
        Ok(ScoreResponse {
            action,
            probability: combined_score,
            reasons,
            decision_id,
            latency_ms,
        })
    }
    
    pub async fn process_feedback(&self, request: FeedbackRequest) -> Result<(), AppError> {
        // Update LinUCB bandit with reward
        {
            let mut bandit = self.linucb.lock().await;
            // Note: In a real implementation, we'd need to store the context vector
            // used for the original decision to properly update LinUCB
            // For now, we'll just log the feedback
        }
        
        // Store reward in ClickHouse
        self.clickhouse_client.log_reward(&request).await?;
        
        Ok(())
    }
    
    pub async fn get_metrics(&self) -> Result<MetricsResponse, AppError> {
        let metrics = self.metrics.lock().await;
        let uptime = self.start_time.elapsed().as_secs();
        
        let qps = if uptime > 0 {
            metrics.total_requests as f32 / uptime as f32
        } else {
            0.0
        };
        
        let p95_latency = if metrics.total_requests > 0 {
            metrics.total_latency_ms as f32 / metrics.total_requests as f32
        } else {
            0.0
        };
        
        let cache_hit_rate = if metrics.cache_hits + metrics.cache_misses > 0 {
            metrics.cache_hits as f32 / (metrics.cache_hits + metrics.cache_misses) as f32
        } else {
            0.0
        };
        
        let blocked_threats = metrics.decisions_today.get(&Action::Block).unwrap_or(&0);
        let total_decisions: u64 = metrics.decisions_today.values().sum();
        
        Ok(MetricsResponse {
            qps,
            p95_latency_ms: p95_latency,
            cache_hit_rate,
            decisions_today: total_decisions,
            blocked_threats: *blocked_threats,
            uptime_seconds: uptime,
        })
    }
    
    // Helper methods
    
    async fn load_student_model(path: &str) -> Result<StudentModel, AppError> {
        if std::path::Path::new(path).exists() {
            let content = tokio::fs::read_to_string(path).await?;
            let model: StudentModel = serde_json::from_str(&content)?;
            info!("Loaded student model from {}", path);
            Ok(model)
        } else {
            warn!("Student model not found at {}, creating default", path);
            // Create default model
            let model = StudentModel {
                weights: vec![0.0; FEATURE_COUNT],
                bias: 0.0,
                feature_names: FEATURE_NAMES.iter().map(|s| s.to_string()).collect(),
                version: "default".to_string(),
                created_at: chrono::Utc::now(),
            };
            
            // Save default model
            if let Some(parent) = std::path::Path::new(path).parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let content = serde_json::to_string_pretty(&model)?;
            tokio::fs::write(path, content).await?;
            
            Ok(model)
        }
    }
    
    fn validate_request(&self, request: &ScoreRequest) -> Result<(), AppError> {
        if request.domain.is_empty() {
            return Err(AppError::InvalidInput("Domain cannot be empty".to_string()));
        }
        
        if request.domain.len() > 253 {
            return Err(AppError::InvalidInput("Domain too long".to_string()));
        }
        
        Ok(())
    }
    
    fn features_to_vector(&self, features: &HashMap<String, f32>) -> Vec<f32> {
        FEATURE_NAMES
            .iter()
            .map(|name| features.get(*name).copied().unwrap_or(0.0))
            .collect()
    }
    
    fn build_context_vector(&self, features: &HashMap<String, f32>) -> Vec<f64> {
        // Build a reduced context vector for LinUCB
        let key_features = [
            "entropy", "typosquatting_score", "dga_score", "homoglyph_score",
            "domain_age_days", "suspicious_tld", "dynamic_dns", "parked_domain",
        ];
        
        let mut context = Vec::with_capacity(self.config.linucb.context_dimensions);
        for feature in key_features.iter().take(self.config.linucb.context_dimensions) {
            context.push(features.get(*feature).copied().unwrap_or(0.0) as f64);
        }
        
        // Pad with zeros if needed
        while context.len() < self.config.linucb.context_dimensions {
            context.push(0.0);
        }
        
        context
    }
    
    fn combine_scores(&self, student_score: f32, linucb_score: f32) -> f32 {
        // Weighted combination of student model and LinUCB
        let alpha = 0.7; // Weight for student model
        let beta = 0.3;  // Weight for LinUCB
        
        alpha * student_score + beta * linucb_score
    }
    
    fn generate_reasons(&self, features: &HashMap<String, f32>, action: &Action, student_score: f32) -> Vec<String> {
        let mut reasons = Vec::new();
        
        // Add reasons based on feature values
        if features.get("homoglyph_score").unwrap_or(&0.0) > &0.5 {
            reasons.push("IDN homoglyph detected".to_string());
        }
        
        if features.get("typosquatting_score").unwrap_or(&0.0) > &0.6 {
            reasons.push("Typosquatting suspected".to_string());
        }
        
        if features.get("dga_score").unwrap_or(&0.0) > &0.7 {
            reasons.push("DGA-generated domain".to_string());
        }
        
        if features.get("entropy").unwrap_or(&0.0) > &4.5 {
            reasons.push("High entropy domain".to_string());
        }
        
        if features.get("dynamic_dns").unwrap_or(&0.0) > &0.5 {
            reasons.push("Dynamic DNS provider".to_string());
        }
        
        if features.get("parked_domain").unwrap_or(&0.0) > &0.5 {
            reasons.push("Parked domain detected".to_string());
        }
        
        if features.get("crypto_mining_scripts").unwrap_or(&0.0) > &0.5 {
            reasons.push("Cryptojacking indicators".to_string());
        }
        
        if student_score > 0.8 {
            reasons.push("High ML threat score".to_string());
        }
        
        if reasons.is_empty() && *action != Action::Allow {
            reasons.push("Aggregate risk factors".to_string());
        }
        
        reasons
    }
    
    fn is_uncertain(score: f32, threshold: f32) -> bool {
        // Check if score is in the uncertain region around thresholds
        (score - 0.5).abs() < threshold || 
        (score - 0.8).abs() < threshold
    }
    
    async fn update_metrics(&self, latency_ms: f32, cache_hit: bool) {
        let mut metrics = self.metrics.lock().await;
        metrics.total_requests += 1;
        metrics.total_latency_ms += latency_ms as f64;
        
        if cache_hit {
            metrics.cache_hits += 1;
        } else {
            metrics.cache_misses += 1;
        }
        
        // Reset daily counters if needed
        if metrics.last_reset.elapsed() > Duration::from_secs(86400) {
            metrics.decisions_today.clear();
            metrics.last_reset = Instant::now();
        }
    }
}