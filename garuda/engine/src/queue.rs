use anyhow::Result;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use crate::types::EngineConfig;

#[derive(Clone)]
pub struct Queue {
    client: redis::Client,
    manager: ConnectionManager,
    list_key: String,
}

impl Queue {
    pub async fn connect(cfg: &EngineConfig) -> Result<Self> {
        let client = redis::Client::open(cfg.redis_url.as_str())?;
        let manager = ConnectionManager::new(client.clone()).await?;
        Ok(Self { client, manager, list_key: "garuda:tasks".to_string() })
    }

    pub async fn enqueue_task(&self, decision_id: &str, domain: &str, url: &str) -> Result<()> {
        let mut conn = self.manager.clone();
        let payload = serde_json::json!({
            "decision_id": decision_id,
            "domain": domain,
            "url": url,
        }).to_string();
        conn.lpush::<_, _, ()>(&self.list_key, payload).await?;
        Ok(())
    }
}