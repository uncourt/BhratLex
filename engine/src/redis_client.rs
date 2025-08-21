use redis::{aio::ConnectionManager, AsyncCommands, RedisResult};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use tracing::{debug, error, info};

pub struct RedisClient {
    manager: ConnectionManager,
}

impl RedisClient {
    pub async fn new(redis_url: &str) -> RedisResult<Self> {
        let client = redis::Client::open(redis_url)?;
        let manager = ConnectionManager::new(client).await?;
        
        info!("Redis client initialized successfully");
        Ok(RedisClient { manager })
    }

    pub async fn get<T>(&mut self, key: &str) -> RedisResult<Option<T>>
    where
        T: DeserializeOwned,
    {
        let result: Option<String> = self.manager.get(key).await?;
        match result {
            Some(data) => {
                let parsed: T = serde_json::from_str(&data)
                    .map_err(|e| redis::RedisError::from((
                        redis::ErrorKind::Parse,
                        "JSON deserialization failed",
                        e.to_string(),
                    )))?;
                debug!("Cache hit for key: {}", key);
                Ok(Some(parsed))
            }
            None => {
                debug!("Cache miss for key: {}", key);
                Ok(None)
            }
        }
    }

    pub async fn set<T>(&mut self, key: &str, value: &T, ttl: Duration) -> RedisResult<()>
    where
        T: Serialize,
    {
        let serialized = serde_json::to_string(value)
            .map_err(|e| redis::RedisError::from((
                redis::ErrorKind::Parse,
                "JSON serialization failed",
                e.to_string(),
            )))?;

        let mut pipe = redis::pipe();
        pipe.atomic()
            .set(key, serialized)
            .expire(key, ttl.as_secs() as usize)
            .execute_async(&mut self.manager)
            .await?;

        debug!("Cached value for key: {} with TTL: {:?}", key, ttl);
        Ok(())
    }

    pub async fn enqueue(&mut self, queue: &str, value: &str) -> RedisResult<()> {
        let result: i64 = self.manager.lpush(queue, value).await?;
        debug!("Enqueued item to {} queue, length: {}", queue, result);
        Ok(())
    }

    pub async fn dequeue(&mut self, queue: &str) -> RedisResult<Option<String>> {
        let result: Option<String> = self.manager.brpop(queue, 1).await?.map(|(_, value)| value);
        if result.is_some() {
            debug!("Dequeued item from {} queue", queue);
        }
        Ok(result)
    }

    pub async fn queue_length(&mut self, queue: &str) -> RedisResult<i64> {
        let length: i64 = self.manager.llen(queue).await?;
        Ok(length)
    }

    pub async fn increment_counter(&mut self, key: &str) -> RedisResult<i64> {
        let result: i64 = self.manager.incr(key, 1).await?;
        Ok(result)
    }

    pub async fn get_counter(&mut self, key: &str) -> RedisResult<i64> {
        let result: i64 = self.manager.get(key).await?;
        Ok(result)
    }

    pub async fn set_expiry(&mut self, key: &str, ttl: Duration) -> RedisResult<bool> {
        let result: bool = self.manager.expire(key, ttl.as_secs() as usize).await?;
        Ok(result)
    }

    pub async fn health_check(&mut self) -> RedisResult<bool> {
        match self.manager.ping().await {
            Ok(_) => {
                debug!("Redis health check passed");
                Ok(true)
            }
            Err(e) => {
                error!("Redis health check failed: {}", e);
                Ok(false)
            }
        }
    }
}