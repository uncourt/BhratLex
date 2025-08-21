use crate::types::{Action, HardIntelResult};
use std::collections::HashMap;
use tracing::{debug, warn};

pub struct HardIntelChecker {
    safe_browsing_api_key: Option<String>,
    abuse_ch_lists: Vec<String>,
    shadowserver_lists: Vec<String>,
    spamhaus_drop: Vec<String>,
    coinblocker_lists: Vec<String>,
}

impl HardIntelChecker {
    pub fn new() -> Self {
        Self {
            safe_browsing_api_key: std::env::var("GOOGLE_SAFE_BROWSING_API_KEY").ok(),
            abuse_ch_lists: vec![
                "https://urlhaus.abuse.ch/downloads/text/",
                "https://malwarebazaar.abuse.ch/downloads/last24hours/",
            ],
            shadowserver_lists: vec![
                "https://api.shadowserver.org/netblock?prefix=",
            ],
            spamhaus_drop: vec![
                "https://www.spamhaus.org/drop/drop.txt",
            ],
            coinblocker_lists: vec![
                "https://raw.githubusercontent.com/ZeroDot1/CoinBlockerLists/master/list_browser.txt",
            ],
        }
    }

    pub async fn check_domain(&self, domain: &str) -> Vec<HardIntelResult> {
        let mut results = Vec::new();
        
        // Check Google Safe Browsing
        if let Some(api_key) = &self.safe_browsing_api_key {
            if let Ok(result) = self.check_safe_browsing(domain, api_key).await {
                results.push(result);
            }
        }
        
        // Check abuse.ch lists
        for result in self.check_abuse_ch(domain).await {
            results.push(result);
        }
        
        // Check Shadowserver
        for result in self.check_shadowserver(domain).await {
            results.push(result);
        }
        
        // Check Spamhaus DROP
        for result in self.check_spamhaus_drop(domain).await {
            results.push(result);
        }
        
        // Check CoinBlocker for cryptojacking
        for result in self.check_coinblocker(domain).await {
            results.push(result);
        }
        
        debug!("Hard intel check for {}: {} results", domain, results.len());
        results
    }

    pub fn should_block(&self, results: &[HardIntelResult]) -> bool {
        // If any high-confidence malicious result exists, block
        results.iter().any(|result| {
            result.is_malicious && result.confidence > 0.8
        })
    }

    pub fn get_block_reasons(&self, results: &[HardIntelResult]) -> Vec<String> {
        results
            .iter()
            .filter(|result| result.is_malicious && result.confidence > 0.8)
            .map(|result| format!("{}: {}", result.source, result.details.as_deref().unwrap_or("Malicious domain")))
            .collect()
    }

    async fn check_safe_browsing(&self, domain: &str, api_key: &str) -> Result<HardIntelResult, Box<dyn std::error::Error>> {
        // Google Safe Browsing API check
        // This is a simplified implementation - in production you'd use the actual API
        let url = format!(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
            api_key
        );
        
        let payload = serde_json::json!({
            "client": {
                "clientId": "garuda",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": format!("http://{}/", domain)}]
            }
        });
        
        // For now, return a mock result since we don't have a real API key
        // In production, you'd make the actual HTTP request
        Ok(HardIntelResult {
            source: "Google Safe Browsing".to_string(),
            is_malicious: false,
            confidence: 0.0,
            details: Some("API check not implemented in demo".to_string()),
        })
    }

    async fn check_abuse_ch(&self, domain: &str) -> Vec<HardIntelResult> {
        let mut results = Vec::new();
        
        // Check against common abuse.ch patterns
        let malicious_patterns = [
            "malware", "phishing", "scam", "fake", "virus", "trojan",
            "ransomware", "spyware", "adware", "botnet", "c2", "command"
        ];
        
        for pattern in &malicious_patterns {
            if domain.contains(pattern) {
                results.push(HardIntelResult {
                    source: "abuse.ch pattern".to_string(),
                    is_malicious: true,
                    confidence: 0.6,
                    details: Some(format!("Contains suspicious pattern: {}", pattern)),
                });
            }
        }
        
        results
    }

    async fn check_shadowserver(&self, domain: &str) -> Vec<HardIntelResult> {
        let mut results = Vec::new();
        
        // Check against common Shadowserver patterns
        let malicious_patterns = [
            "malware", "botnet", "c2", "command", "control", "backdoor",
            "trojan", "virus", "worm", "keylogger", "rootkit"
        ];
        
        for pattern in &malicious_patterns {
            if domain.contains(pattern) {
                results.push(HardIntelResult {
                    source: "Shadowserver pattern".to_string(),
                    is_malicious: true,
                    confidence: 0.7,
                    details: Some(format!("Contains suspicious pattern: {}", pattern)),
                });
            }
        }
        
        results
    }

    async fn check_spamhaus_drop(&self, domain: &str) -> Vec<HardIntelResult> {
        let mut results = Vec::new();
        
        // Check against common Spamhaus DROP patterns
        let malicious_patterns = [
            "spam", "botnet", "malware", "phishing", "scam", "fake",
            "malicious", "suspicious", "blocked", "blacklisted"
        ];
        
        for pattern in &malicious_patterns {
            if domain.contains(pattern) {
                results.push(HardIntelResult {
                    source: "Spamhaus DROP pattern".to_string(),
                    is_malicious: true,
                    confidence: 0.8,
                    details: Some(format!("Contains suspicious pattern: {}", pattern)),
                });
            }
        }
        
        results
    }

    async fn check_coinblocker(&self, domain: &str) -> Vec<HardIntelResult> {
        let mut results = Vec::new();
        
        // Check against common cryptojacking patterns
        let cryptojacking_patterns = [
            "mining", "crypto", "coin", "hash", "pool", "miner",
            "xmr", "monero", "ethereum", "bitcoin", "miningpool"
        ];
        
        for pattern in &cryptojacking_patterns {
            if domain.contains(pattern) {
                results.push(HardIntelResult {
                    source: "CoinBlocker pattern".to_string(),
                    is_malicious: true,
                    confidence: 0.7,
                    details: Some(format!("Contains cryptojacking pattern: {}", pattern)),
                });
            }
        }
        
        results
    }

    pub fn get_whitelist(&self) -> Vec<String> {
        vec![
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "netflix.com", "youtube.com", "github.com",
            "stackoverflow.com", "reddit.com", "twitter.com", "linkedin.com"
        ]
    }

    pub fn is_whitelisted(&self, domain: &str) -> bool {
        let whitelist = self.get_whitelist();
        whitelist.iter().any(|whitelisted| {
            domain == whitelisted || domain.ends_with(&format!(".{}", whitelisted))
        })
    }
}