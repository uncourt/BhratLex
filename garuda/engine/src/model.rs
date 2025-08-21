use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use crate::features::FeatureVector;
use std::fs;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StudentWeights {
    pub intercept: f64,
    pub weights: Vec<f64>,
    pub feature_order: Vec<String>,
}

#[derive(Clone)]
pub struct StudentModel {
    weights: StudentWeights,
}

impl StudentModel {
    pub fn load(path: &str) -> Result<Self> {
        let data = fs::read_to_string(path).map_err(|e| anyhow!("failed to read student.json: {}", e))?;
        let weights: StudentWeights = serde_json::from_str(&data)?;
        Ok(Self { weights })
    }

    pub fn predict_probability(&self, f: &FeatureVector) -> f64 {
        // Inline hot path: manually map fields without allocations
        let mut z = self.weights.intercept;
        for (i, name) in self.weights.feature_order.iter().enumerate() {
            let v = match name.as_str() {
                "len_domain" => f.len_domain,
                "num_dashes" => f.num_dashes,
                "num_digits" => f.num_digits,
                "entropy" => f.entropy,
                "idn_homoglyph" => f.idn_homoglyph,
                "typosquat_score" => f.typosquat_score,
                "nrd" => f.nrd,
                "dynamic_dns" => f.dynamic_dns,
                "parked" => f.parked,
                "cname_cloaking" => f.cname_cloaking,
                "dns_rebinding" => f.dns_rebinding,
                "coinblocklist_hit" => f.coinblocklist_hit,
                _ => 0.0,
            };
            z += self.weights.weights.get(i).copied().unwrap_or(0.0) * v;
        }
        1.0 / (1.0 + (-z).exp())
    }
}