use crate::{
    config::{ClickHouseConfig, RedisConfig},
    error::AppError,
    types::{AnalyzerTask, DecisionContext, FeedbackRequest},
};
use clickhouse::Client;
use redis::{aio::Connection, AsyncCommands, Client as RedisClientInner};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct RedisClient {
    client: RedisClientInner,
    queue_name: String,
}

impl RedisClient {
    pub async fn new(config: &RedisConfig) -> Result<Self, AppError> {
        let client = RedisClientInner::open(config.url.as_str())?;
        
        // Test connection
        let mut conn = client.get_async_connection().await?;
        let _: String = conn.ping().await?;
        
        Ok(Self {
            client,
            queue_name: config.queue_name.clone(),
        })
    }
    
    pub async fn enqueue_analyzer_task(&self, task: &AnalyzerTask) -> Result<(), AppError> {
        let mut conn = self.client.get_async_connection().await?;
        let task_json = serde_json::to_string(task)?;
        
        let _: () = conn.lpush(&self.queue_name, task_json).await?;
        
        debug!("Enqueued analyzer task for domain: {}", task.domain);
        Ok(())
    }
    
    pub async fn dequeue_analyzer_task(&self) -> Result<Option<AnalyzerTask>, AppError> {
        let mut conn = self.client.get_async_connection().await?;
        
        let result: Option<String> = conn.brpop(&self.queue_name, 1.0).await?;
        
        if let Some(task_json) = result {
            let task: AnalyzerTask = serde_json::from_str(&task_json)?;
            Ok(Some(task))
        } else {
            Ok(None)
        }
    }
    
    pub async fn get_queue_length(&self) -> Result<usize, AppError> {
        let mut conn = self.client.get_async_connection().await?;
        let len: usize = conn.llen(&self.queue_name).await?;
        Ok(len)
    }
}

#[derive(Clone)]
pub struct ClickHouseClient {
    client: Client,
    database: String,
}

impl ClickHouseClient {
    pub async fn new(config: &ClickHouseConfig) -> Result<Self, AppError> {
        let client = Client::default()
            .with_url(&config.url)
            .with_database(&config.database)
            .with_user(&config.username);
        
        // Test connection
        let result = client
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await;
        
        match result {
            Ok(_) => {
                debug!("ClickHouse connection established");
            }
            Err(e) => {
                warn!("ClickHouse connection failed: {}", e);
                // Don't fail initialization, just warn
            }
        }
        
        Ok(Self {
            client,
            database: config.database.clone(),
        })
    }
    
    pub async fn log_decision(&self, decision: &DecisionContext) -> Result<(), AppError> {
        let features_json = serde_json::to_string(&decision.features)?;
        let reasons_str = decision.reasons.join(",");
        
        let query = format!(
            r#"
            INSERT INTO {}.decisions (
                timestamp, decision_id, domain, url, action, probability, reasons, 
                features, latency_ms, hard_intel_match, student_score, linucb_score
            ) VALUES (
                now64(), '{}', '{}', '{}', '{}', {}, [{}], '{}', 0, '{}', {}, {}
            )
            "#,
            self.database,
            decision.decision_id,
            decision.domain,
            decision.url.as_deref().unwrap_or(""),
            match decision.action {
                crate::types::Action::Allow => "ALLOW",
                crate::types::Action::Warn => "WARN",
                crate::types::Action::Block => "BLOCK",
            },
            decision.final_probability,
            decision.reasons.iter()
                .map(|r| format!("'{}'", r.replace("'", "''")))
                .collect::<Vec<_>>()
                .join(","),
            features_json.replace("'", "''"),
            decision.hard_intel_match.as_deref().unwrap_or(""),
            decision.student_score,
            decision.linucb_score,
        );
        
        match self.client.query(&query).execute().await {
            Ok(_) => {
                debug!("Logged decision: {}", decision.decision_id);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to log decision: {}", e);
                Err(AppError::Database(e.to_string()))
            }
        }
    }
    
    pub async fn log_analyzer_result(
        &self,
        decision_id: &str,
        domain: &str,
        url: &str,
        screenshot_path: &str,
        html_content: &str,
        ocr_text: &str,
        vlm_verdict: &str,
        vlm_confidence: f32,
        is_threat: bool,
        threat_categories: &[String],
        processing_time_ms: u32,
        error_message: &str,
    ) -> Result<(), AppError> {
        let categories_str = threat_categories.join(",");
        
        let query = format!(
            r#"
            INSERT INTO {}.analyzer (
                timestamp, decision_id, domain, url, screenshot_path, html_content,
                ocr_text, vlm_verdict, vlm_confidence, is_threat, threat_categories,
                processing_time_ms, error_message
            ) VALUES (
                now64(), '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, [{}], {}, '{}'
            )
            "#,
            self.database,
            decision_id,
            domain,
            url,
            screenshot_path.replace("'", "''"),
            html_content.replace("'", "''").chars().take(10000).collect::<String>(), // Truncate large content
            ocr_text.replace("'", "''"),
            vlm_verdict.replace("'", "''"),
            vlm_confidence,
            is_threat,
            threat_categories.iter()
                .map(|c| format!("'{}'", c.replace("'", "''")))
                .collect::<Vec<_>>()
                .join(","),
            processing_time_ms,
            error_message.replace("'", "''"),
        );
        
        match self.client.query(&query).execute().await {
            Ok(_) => {
                debug!("Logged analyzer result: {}", decision_id);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to log analyzer result: {}", e);
                Err(AppError::Database(e.to_string()))
            }
        }
    }
    
    pub async fn log_reward(&self, feedback: &FeedbackRequest) -> Result<(), AppError> {
        let context_json = feedback.context
            .as_ref()
            .map(|c| serde_json::to_string(c).unwrap_or_default())
            .unwrap_or_default();
        
        let query = format!(
            r#"
            INSERT INTO {}.rewards (
                timestamp, decision_id, reward, actual_threat, feedback_source, context
            ) VALUES (
                now64(), '{}', {}, {}, '{}', '{}'
            )
            "#,
            self.database,
            feedback.decision_id,
            feedback.reward,
            feedback.actual_threat,
            feedback.feedback_source.as_deref().unwrap_or("user"),
            context_json.replace("'", "''"),
        );
        
        match self.client.query(&query).execute().await {
            Ok(_) => {
                debug!("Logged reward: {}", feedback.decision_id);
                Ok(())
            }
            Err(e) => {
                warn!("Failed to log reward: {}", e);
                Err(AppError::Database(e.to_string()))
            }
        }
    }
    
    pub async fn get_decision_stats(&self, hours: u32) -> Result<DecisionStats, AppError> {
        let query = format!(
            r#"
            SELECT 
                action,
                count() as count,
                avg(probability) as avg_probability,
                avg(latency_ms) as avg_latency
            FROM {}.decisions 
            WHERE timestamp >= now() - INTERVAL {} HOUR
            GROUP BY action
            "#,
            self.database, hours
        );
        
        // This is a simplified implementation - in production you'd use proper ClickHouse types
        let mut stats = DecisionStats::default();
        
        match self.client.query(&query).fetch_all::<(String, u64, f64, f64)>().await {
            Ok(rows) => {
                for (action, count, avg_prob, avg_latency) in rows {
                    match action.as_str() {
                        "ALLOW" => {
                            stats.allow_count = count;
                            stats.avg_allow_probability = avg_prob as f32;
                        }
                        "WARN" => {
                            stats.warn_count = count;
                            stats.avg_warn_probability = avg_prob as f32;
                        }
                        "BLOCK" => {
                            stats.block_count = count;
                            stats.avg_block_probability = avg_prob as f32;
                        }
                        _ => {}
                    }
                    stats.avg_latency_ms = avg_latency as f32;
                }
                Ok(stats)
            }
            Err(e) => {
                warn!("Failed to get decision stats: {}", e);
                Ok(DecisionStats::default())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct DecisionStats {
    pub allow_count: u64,
    pub warn_count: u64,
    pub block_count: u64,
    pub avg_allow_probability: f32,
    pub avg_warn_probability: f32,
    pub avg_block_probability: f32,
    pub avg_latency_ms: f32,
}