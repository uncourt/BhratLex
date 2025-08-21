use crate::types::DomainFeatures;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudentModel {
    pub weights: HashMap<String, f64>,
    pub bias: f64,
    pub version: String,
    pub training_samples: u64,
}

impl StudentModel {
    pub fn new() -> Self {
        Self {
            weights: HashMap::new(),
            bias: 0.0,
            version: "v1.0.0".to_string(),
            training_samples: 0,
        }
    }

    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let model: StudentModel = serde_json::from_str(&content)?;
        debug!("Loaded student model from {}: version {}, {} samples", 
               path, model.version, model.training_samples);
        Ok(model)
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        debug!("Saved student model to {}: version {}, {} samples", 
               path, self.version, self.training_samples);
        Ok(())
    }

    pub fn predict(&self, features: &DomainFeatures) -> f64 {
        let mut score = self.bias;
        
        // Add weighted feature contributions
        score += self.weights.get("length").unwrap_or(&0.0) * features.length;
        score += self.weights.get("entropy").unwrap_or(&0.0) * features.entropy;
        score += self.weights.get("consonant_ratio").unwrap_or(&0.0) * features.consonant_ratio;
        score += self.weights.get("vowel_ratio").unwrap_or(&0.0) * features.vowel_ratio;
        score += self.weights.get("digit_ratio").unwrap_or(&0.0) * features.digit_ratio;
        score += self.weights.get("special_char_ratio").unwrap_or(&0.0) * features.special_char_ratio;
        score += self.weights.get("consecutive_consonants").unwrap_or(&0.0) * features.consecutive_consonants;
        score += self.weights.get("consecutive_vowels").unwrap_or(&0.0) * features.consecutive_vowels;
        score += self.weights.get("consecutive_digits").unwrap_or(&0.0) * features.consecutive_digits;
        score += self.weights.get("consecutive_special_chars").unwrap_or(&0.0) * features.consecutive_special_chars;
        score += self.weights.get("idn_homoglyph_score").unwrap_or(&0.0) * features.idn_homoglyph_score;
        score += self.weights.get("typosquatting_score").unwrap_or(&0.0) * features.typosquatting_score;
        score += self.weights.get("dga_entropy").unwrap_or(&0.0) * features.dga_entropy;
        score += self.weights.get("nrd_flag").unwrap_or(&0.0) * features.nrd_flag;
        score += self.weights.get("dynamic_dns_flag").unwrap_or(&0.0) * features.dynamic_dns_flag;
        score += self.weights.get("parked_domain_flag").unwrap_or(&0.0) * features.parked_domain_flag;
        score += self.weights.get("cname_cloaking_flag").unwrap_or(&0.0) * features.cname_cloaking_flag;
        score += self.weights.get("dns_rebinding_flag").unwrap_or(&0.0) * features.dns_rebinding_flag;
        score += self.weights.get("cryptojacking_flag").unwrap_or(&0.0) * features.cryptojacking_flag;
        
        // Apply sigmoid function to get probability
        self.sigmoid(score)
    }

    pub fn predict_threat_probability(&self, features: &DomainFeatures) -> f64 {
        self.predict(features)
    }

    pub fn get_feature_importance(&self) -> Vec<(String, f64)> {
        let mut importance: Vec<(String, f64)> = self.weights
            .iter()
            .map(|(feature, weight)| (feature.clone(), weight.abs()))
            .collect();
        
        importance.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        importance
    }

    pub fn update_weights(&mut self, features: &DomainFeatures, target: f64, learning_rate: f64) {
        let prediction = self.predict(features);
        let error = target - prediction;
        
        // Update bias
        self.bias += learning_rate * error;
        
        // Update weights
        let features_map = self.features_to_map(features);
        for (feature, value) in features_map {
            let weight = self.weights.entry(feature).or_insert(0.0);
            *weight += learning_rate * error * value;
        }
        
        self.training_samples += 1;
    }

    fn sigmoid(&self, x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    fn features_to_map(&self, features: &DomainFeatures) -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("length".to_string(), features.length);
        map.insert("entropy".to_string(), features.entropy);
        map.insert("consonant_ratio".to_string(), features.consonant_ratio);
        map.insert("vowel_ratio".to_string(), features.vowel_ratio);
        map.insert("digit_ratio".to_string(), features.digit_ratio);
        map.insert("special_char_ratio".to_string(), features.special_char_ratio);
        map.insert("consecutive_consonants".to_string(), features.consecutive_consonants);
        map.insert("consecutive_vowels".to_string(), features.consecutive_vowels);
        map.insert("consecutive_digits".to_string(), features.consecutive_digits);
        map.insert("consecutive_special_chars".to_string(), features.consecutive_special_chars);
        map.insert("idn_homoglyph_score".to_string(), features.idn_homoglyph_score);
        map.insert("typosquatting_score".to_string(), features.typosquatting_score);
        map.insert("dga_entropy".to_string(), features.dga_entropy);
        map.insert("nrd_flag".to_string(), features.nrd_flag);
        map.insert("dynamic_dns_flag".to_string(), features.dynamic_dns_flag);
        map.insert("parked_domain_flag".to_string(), features.parked_domain_flag);
        map.insert("cname_cloaking_flag".to_string(), features.cname_cloaking_flag);
        map.insert("dns_rebinding_flag".to_string(), features.dns_rebinding_flag);
        map.insert("cryptojacking_flag".to_string(), features.cryptojacking_flag);
        map
    }

    pub fn get_model_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("version".to_string(), self.version.clone());
        info.insert("training_samples".to_string(), self.training_samples.to_string());
        info.insert("num_features".to_string(), self.weights.len().to_string());
        info.insert("bias".to_string(), self.bias.to_string());
        
        let top_features = self.get_feature_importance().into_iter().take(5).collect::<Vec<_>>();
        info.insert("top_features".to_string(), format!("{:?}", top_features));
        
        info
    }
}

impl Default for StudentModel {
    fn default() -> Self {
        // Initialize with reasonable default weights
        let mut weights = HashMap::new();
        weights.insert("length".to_string(), 0.1);
        weights.insert("entropy".to_string(), 0.3);
        weights.insert("consonant_ratio".to_string(), 0.05);
        weights.insert("vowel_ratio".to_string(), -0.05);
        weights.insert("digit_ratio".to_string(), 0.2);
        weights.insert("special_char_ratio".to_string(), 0.4);
        weights.insert("consecutive_consonants".to_string(), 0.15);
        weights.insert("consecutive_vowels".to_string(), -0.1);
        weights.insert("consecutive_digits".to_string(), 0.25);
        weights.insert("consecutive_special_chars".to_string(), 0.35);
        weights.insert("idn_homoglyph_score".to_string(), 0.8);
        weights.insert("typosquatting_score".to_string(), 0.7);
        weights.insert("dga_entropy".to_string(), 0.6);
        weights.insert("nrd_flag".to_string(), 0.4);
        weights.insert("dynamic_dns_flag".to_string(), 0.5);
        weights.insert("parked_domain_flag".to_string(), 0.3);
        weights.insert("cname_cloaking_flag".to_string(), 0.6);
        weights.insert("dns_rebinding_flag".to_string(), 0.7);
        weights.insert("cryptojacking_flag".to_string(), 0.65);
        
        Self {
            weights,
            bias: -2.0, // Slight bias towards legitimate
            version: "v1.0.0".to_string(),
            training_samples: 0,
        }
    }
}