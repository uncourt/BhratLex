use crate::types::{Action, Decision, DomainFeatures, ScoreResponse, HardIntelResult};
use crate::features::FeatureExtractor;
use crate::hard_intel::HardIntelChecker;
use crate::student_model::StudentModel;
use crate::linucb::LinUCB;
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct ThreatDetector {
    feature_extractor: FeatureExtractor,
    hard_intel_checker: HardIntelChecker,
    student_model: StudentModel,
    linucb: LinUCB,
    model_version: String,
}

impl ThreatDetector {
    pub fn new(model_version: String) -> Self {
        Self {
            feature_extractor: FeatureExtractor::new(),
            hard_intel_checker: HardIntelChecker::new(),
            student_model: StudentModel::new(),
            linucb: LinUCB::default(),
            model_version,
        }
    }

    pub fn load_student_model(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.student_model = StudentModel::load_from_file(path)?;
        info!("Loaded student model from: {}", path);
        Ok(())
    }

    pub async fn detect_threat(&mut self, domain: &str, url: Option<&str>) -> ScoreResponse {
        let start_time = Instant::now();
        
        info!("Starting threat detection for domain: {}", domain);
        
        // Check cache first (would be implemented in main handler)
        let cache_hit = false; // Placeholder
        
        // Extract features
        let features = self.feature_extractor.extract_features(domain);
        debug!("Extracted features: {:?}", features);
        
        // Check hard intelligence
        let hard_intel_results = self.hard_intel_checker.check_domain(domain).await;
        let hard_intel_hits: Vec<String> = hard_intel_results
            .iter()
            .filter(|r| r.is_malicious)
            .map(|r| r.source.clone())
            .collect();
        
        // Check whitelist
        if self.hard_intel_checker.is_whitelisted(domain) {
            let latency = start_time.elapsed().as_millis() as f64;
            info!("Domain {} is whitelisted", domain);
            
            return ScoreResponse {
                action: Action::ALLOW,
                probability: 0.95,
                reasons: vec!["Domain is whitelisted".to_string()],
                decision_id: Uuid::new_v4(),
                features: self.features_to_map(&features),
                hard_intel_hits,
            };
        }
        
        // Check hard intel block
        if self.hard_intel_checker.should_block(&hard_intel_results) {
            let latency = start_time.elapsed().as_millis() as f64;
            let reasons = self.hard_intel_checker.get_block_reasons(&hard_intel_results);
            
            info!("Domain {} blocked by hard intel: {:?}", domain, reasons);
            
            return ScoreResponse {
                action: Action::BLOCK,
                probability: 0.99,
                reasons,
                decision_id: Uuid::new_v4(),
                features: self.features_to_map(&features),
                hard_intel_hits,
            };
        }
        
        // Get student model prediction
        let threat_probability = self.student_model.predict_threat_probability(&features);
        
        // Use LinUCB for action selection
        let context = self.features_to_vector(&features);
        let linucb_action = self.linucb.select_action(&context);
        
        // Determine final action and probability
        let (action, probability, reasons) = self.determine_action(
            threat_probability,
            &linucb_action,
            &hard_intel_results,
            &features,
        );
        
        let latency = start_time.elapsed().as_millis() as f64;
        
        // Log decision
        let decision = Decision {
            decision_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            domain: domain.to_string(),
            url: url.map(|u| u.to_string()),
            action: action.clone(),
            probability,
            reasons: reasons.clone(),
            features: self.features_to_map(&features),
            hard_intel_hits: hard_intel_hits.clone(),
            cache_hit,
            latency_ms: latency,
            model_version: self.model_version.clone(),
        };
        
        info!("Threat detection completed for {}: {:?} (prob: {:.3}, latency: {:.1}ms)", 
              domain, action, probability, latency);
        
        ScoreResponse {
            action,
            probability,
            reasons,
            decision_id: decision.decision_id,
            features: self.features_to_map(&features),
            hard_intel_hits,
        }
    }

    fn determine_action(
        &self,
        threat_probability: f64,
        linucb_action: &str,
        hard_intel_results: &[HardIntelResult],
        features: &DomainFeatures,
    ) -> (Action, f64, Vec<String>) {
        let mut reasons = Vec::new();
        
        // High confidence threats
        if threat_probability > 0.8 {
            reasons.push(format!("High threat probability: {:.1}%", threat_probability * 100.0));
            
            if features.idn_homoglyph_score > 0.7 {
                reasons.push("High IDN homoglyph score detected".to_string());
            }
            if features.typosquatting_score > 0.7 {
                reasons.push("High typosquatting score detected".to_string());
            }
            if features.dga_entropy > 0.7 {
                reasons.push("High DGA entropy detected".to_string());
            }
            
            return (Action::BLOCK, threat_probability, reasons);
        }
        
        // Medium confidence threats
        if threat_probability > 0.5 {
            reasons.push(format!("Medium threat probability: {:.1}%", threat_probability * 100.0));
            
            if features.idn_homoglyph_score > 0.5 {
                reasons.push("Moderate IDN homoglyph score".to_string());
            }
            if features.typosquatting_score > 0.5 {
                reasons.push("Moderate typosquatting score".to_string());
            }
            if features.dynamic_dns_flag > 0.5 {
                reasons.push("Dynamic DNS provider detected".to_string());
            }
            
            return (Action::WARN, threat_probability, reasons);
        }
        
        // Low confidence - use LinUCB recommendation
        match linucb_action {
            "BLOCK" => {
                reasons.push("LinUCB recommends BLOCK".to_string());
                reasons.push(format!("Low threat probability: {:.1}%", threat_probability * 100.0));
                (Action::BLOCK, threat_probability, reasons)
            }
            "WARN" => {
                reasons.push("LinUCB recommends WARN".to_string());
                reasons.push(format!("Low threat probability: {:.1}%", threat_probability * 100.0));
                (Action::WARN, threat_probability, reasons)
            }
            _ => {
                reasons.push("LinUCB recommends ALLOW".to_string());
                reasons.push(format!("Low threat probability: {:.1}%", threat_probability * 100.0));
                (Action::ALLOW, threat_probability, reasons)
            }
        }
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

    fn features_to_vector(&self, features: &DomainFeatures) -> Vec<f64> {
        vec![
            features.length,
            features.entropy,
            features.consonant_ratio,
            features.vowel_ratio,
            features.digit_ratio,
            features.special_char_ratio,
            features.consecutive_consonants,
            features.consecutive_vowels,
            features.consecutive_digits,
            features.consecutive_special_chars,
            features.idn_homoglyph_score,
            features.typosquatting_score,
            features.dga_entropy,
            features.nrd_flag,
            features.dynamic_dns_flag,
            features.parked_domain_flag,
            features.cname_cloaking_flag,
            features.dns_rebinding_flag,
            features.cryptojacking_flag,
        ]
    }

    pub fn update_models(&mut self, decision_id: Uuid, reward: f64, context: &[f64]) {
        // Update LinUCB
        self.linucb.update("ALLOW", context, reward); // Simplified - would use actual action
        
        // Update student model (simplified - would use actual features)
        let dummy_features = DomainFeatures::default();
        self.student_model.update_weights(&dummy_features, reward, 0.01);
        
        debug!("Updated models for decision {} with reward: {}", decision_id, reward);
    }

    pub fn get_model_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        
        // Student model info
        let student_info = self.student_model.get_model_info();
        for (key, value) in student_info {
            info.insert(format!("student_{}", key), value);
        }
        
        // LinUCB info
        info.insert("linucb_alpha".to_string(), self.linucb.get_alpha().to_string());
        info.insert("linucb_feature_dim".to_string(), self.linucb.get_feature_dimension().to_string());
        info.insert("linucb_num_actions".to_string(), self.linucb.get_num_actions().to_string());
        
        info
    }
}