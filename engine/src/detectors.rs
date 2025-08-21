use crate::{config::FeatureConfig, error::AppError};

pub struct ThreatDetectors {
    config: FeatureConfig,
}

impl ThreatDetectors {
    pub async fn new(config: &FeatureConfig) -> Result<Self, AppError> {
        Ok(Self {
            config: config.clone(),
        })
    }
}