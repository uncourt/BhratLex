use clickhouse::{Client};
use serde_json::Value;
use crate::types::{ScoreResponse};
use crate::types::EngineConfig;
use anyhow::Result;

#[derive(Clone)]
pub struct Storage {
    ch: Client,
}

impl Storage {
    pub async fn connect(cfg: &EngineConfig) -> Result<Self> {
        let ch = Client::default().with_url(&cfg.clickhouse_url);
        Ok(Self { ch })
    }

    pub async fn insert_decision(&self, decision_id: &str, domain: &str, url: &str, resp: &ScoreResponse, features_json: &Value) -> Result<()> {
        let mut insert = self.ch.insert("garuda.decisions");
        insert
            .write(&serde_json::json!({
                "decision_id": decision_id,
                "domain": domain,
                "url": url,
                "action": resp.action.as_str(),
                "prob": resp.prob,
                "reasons": resp.reasons,
                "features_json": features_json.to_string(),
            })).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_reward(&self, decision_id: &str, action: &str, reward: f64) -> Result<()> {
        let mut insert = self.ch.insert("garuda.rewards");
        insert
            .write(&serde_json::json!({
                "decision_id": decision_id,
                "action": action,
                "reward": reward,
            })).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn insert_analyzer(&self, decision_id: &str, domain: &str, url: &str, ocr_text: &str, vlm_verdict: &str, vlm_reasons: &str, screenshot_base64: &str, html_truncated: &str) -> Result<()> {
        let mut insert = self.ch.insert("garuda.analyzer");
        insert
            .write(&serde_json::json!({
                "decision_id": decision_id,
                "domain": domain,
                "url": url,
                "ocr_text": ocr_text,
                "vlm_verdict": vlm_verdict,
                "vlm_reasons": vlm_reasons,
                "screenshot_base64": screenshot_base64,
                "html_truncated": html_truncated,
            })).await?;
        insert.end().await?;
        Ok(())
    }
}