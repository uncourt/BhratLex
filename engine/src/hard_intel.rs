use crate::{config::HardIntelConfig, error::AppError, types::HardIntelMatch};
use reqwest::Client;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub struct HardIntelChecker {
    config: HardIntelConfig,
    client: Client,
    cache: Arc<RwLock<IntelCache>>,
    
    // Hard intel lists (loaded at startup)
    malware_domains: Arc<RwLock<HashSet<String>>>,
    phishing_domains: Arc<RwLock<HashSet<String>>>,
    crypto_mining_domains: Arc<RwLock<HashSet<String>>>,
    spamhaus_drop: Arc<RwLock<HashSet<String>>>,
    dynamic_dns_providers: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    result: Option<HardIntelMatch>,
    timestamp: Instant,
    ttl: Duration,
}

#[derive(Debug, Default)]
struct IntelCache {
    entries: HashMap<String, CacheEntry>,
}

impl HardIntelChecker {
    pub async fn new(config: &HardIntelConfig) -> Result<Self, AppError> {
        info!("Initializing Hard Intel Checker...");
        
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        
        let cache = Arc::new(RwLock::new(IntelCache::default()));
        
        let checker = Self {
            config: config.clone(),
            client,
            cache,
            malware_domains: Arc::new(RwLock::new(HashSet::new())),
            phishing_domains: Arc::new(RwLock::new(HashSet::new())),
            crypto_mining_domains: Arc::new(RwLock::new(HashSet::new())),
            spamhaus_drop: Arc::new(RwLock::new(HashSet::new())),
            dynamic_dns_providers: Arc::new(RwLock::new(HashSet::new())),
        };
        
        // Load hard intel lists
        checker.load_intel_lists().await?;
        
        // Start background refresh task
        checker.start_refresh_task();
        
        info!("Hard Intel Checker initialized successfully");
        Ok(checker)
    }
    
    /// Fast check against cached hard intel (optimized for hot path)
    pub async fn check_fast(&self, domain: &str) -> Result<Option<HardIntelMatch>, AppError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.entries.get(domain) {
                if entry.timestamp.elapsed() < entry.ttl {
                    return Ok(entry.result.clone());
                }
            }
        }
        
        // Check local hard intel lists (fastest)
        if let Some(intel_match) = self.check_local_lists(domain).await {
            self.cache_result(domain, Some(intel_match.clone())).await;
            return Ok(Some(intel_match));
        }
        
        // Cache negative result for fast subsequent lookups
        self.cache_result(domain, None).await;
        Ok(None)
    }
    
    /// Comprehensive check including external APIs (for background analysis)
    pub async fn check_comprehensive(&self, domain: &str) -> Result<Option<HardIntelMatch>, AppError> {
        // First try fast check
        if let Some(intel_match) = self.check_fast(domain).await? {
            return Ok(Some(intel_match));
        }
        
        // Check external APIs if enabled
        if !self.config.google_safe_browsing_api_key.is_empty() {
            if let Some(intel_match) = self.check_google_safe_browsing(domain).await? {
                self.cache_result(domain, Some(intel_match.clone())).await;
                return Ok(Some(intel_match));
            }
        }
        
        Ok(None)
    }
    
    async fn check_local_lists(&self, domain: &str) -> Option<HardIntelMatch> {
        // Check malware domains
        {
            let malware_domains = self.malware_domains.read().await;
            if malware_domains.contains(domain) {
                return Some(HardIntelMatch {
                    source: "abuse.ch".to_string(),
                    category: "malware".to_string(),
                    confidence: 0.95,
                    details: Some("Listed in abuse.ch malware domains".to_string()),
                });
            }
        }
        
        // Check phishing domains
        {
            let phishing_domains = self.phishing_domains.read().await;
            if phishing_domains.contains(domain) {
                return Some(HardIntelMatch {
                    source: "phishtank".to_string(),
                    category: "phishing".to_string(),
                    confidence: 0.90,
                    details: Some("Listed in PhishTank".to_string()),
                });
            }
        }
        
        // Check crypto mining domains
        {
            let crypto_domains = self.crypto_mining_domains.read().await;
            if crypto_domains.contains(domain) {
                return Some(HardIntelMatch {
                    source: "coinblocker".to_string(),
                    category: "cryptojacking".to_string(),
                    confidence: 0.85,
                    details: Some("Listed in CoinBlockerLists".to_string()),
                });
            }
        }
        
        // Check Spamhaus DROP
        {
            let spamhaus_domains = self.spamhaus_drop.read().await;
            if spamhaus_domains.contains(domain) {
                return Some(HardIntelMatch {
                    source: "spamhaus".to_string(),
                    category: "spam".to_string(),
                    confidence: 0.92,
                    details: Some("Listed in Spamhaus DROP".to_string()),
                });
            }
        }
        
        None
    }
    
    async fn check_google_safe_browsing(&self, domain: &str) -> Result<Option<HardIntelMatch>, AppError> {
        let url = format!(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
            self.config.google_safe_browsing_api_key
        );
        
        let request_body = serde_json::json!({
            "client": {
                "clientId": "garuda-threat-engine",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": format!("http://{}", domain)},
                    {"url": format!("https://{}", domain)}
                ]
            }
        });
        
        match self.client
            .post(&url)
            .json(&request_body)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    let result: serde_json::Value = response.json().await?;
                    
                    if let Some(matches) = result.get("matches") {
                        if matches.as_array().map_or(false, |arr| !arr.is_empty()) {
                            return Ok(Some(HardIntelMatch {
                                source: "gsb".to_string(),
                                category: "malware".to_string(),
                                confidence: 0.98,
                                details: Some("Google Safe Browsing match".to_string()),
                            }));
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Google Safe Browsing API error: {}", e);
            }
        }
        
        Ok(None)
    }
    
    async fn load_intel_lists(&self) -> Result<(), AppError> {
        info!("Loading hard intel lists...");
        
        // Load abuse.ch malware domains
        if self.config.abuse_ch_enabled {
            if let Ok(domains) = self.fetch_abuse_ch_domains().await {
                let mut malware_domains = self.malware_domains.write().await;
                malware_domains.extend(domains);
                info!("Loaded {} malware domains from abuse.ch", malware_domains.len());
            }
        }
        
        // Load CoinBlockerLists crypto mining domains
        if self.config.coinblocker_enabled {
            if let Ok(domains) = self.fetch_coinblocker_domains().await {
                let mut crypto_domains = self.crypto_mining_domains.write().await;
                crypto_domains.extend(domains);
                info!("Loaded {} crypto mining domains from CoinBlockerLists", crypto_domains.len());
            }
        }
        
        // Load Spamhaus DROP list
        if self.config.spamhaus_enabled {
            if let Ok(domains) = self.fetch_spamhaus_drop().await {
                let mut spamhaus_domains = self.spamhaus_drop.write().await;
                spamhaus_domains.extend(domains);
                info!("Loaded {} domains from Spamhaus DROP", spamhaus_domains.len());
            }
        }
        
        // Load dynamic DNS providers list
        self.load_dynamic_dns_providers().await;
        
        Ok(())
    }
    
    async fn fetch_abuse_ch_domains(&self) -> Result<HashSet<String>, AppError> {
        let url = "https://urlhaus.abuse.ch/downloads/hostfile/";
        
        match self.client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;
                    let domains = text
                        .lines()
                        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
                        .filter_map(|line| {
                            // Parse hostfile format: "127.0.0.1 domain.com"
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                Some(parts[1].to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    
                    Ok(domains)
                } else {
                    Err(AppError::HardIntelLookup(format!("abuse.ch returned status: {}", response.status())))
                }
            }
            Err(e) => {
                warn!("Failed to fetch abuse.ch domains: {}", e);
                Ok(HashSet::new()) // Return empty set on error
            }
        }
    }
    
    async fn fetch_coinblocker_domains(&self) -> Result<HashSet<String>, AppError> {
        let url = "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser";
        
        match self.client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;
                    let domains = text
                        .lines()
                        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
                        .filter_map(|line| {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                Some(parts[1].to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    
                    Ok(domains)
                } else {
                    Err(AppError::HardIntelLookup(format!("CoinBlockerLists returned status: {}", response.status())))
                }
            }
            Err(e) => {
                warn!("Failed to fetch CoinBlockerLists: {}", e);
                Ok(HashSet::new())
            }
        }
    }
    
    async fn fetch_spamhaus_drop(&self) -> Result<HashSet<String>, AppError> {
        // Note: Spamhaus DROP is IP-based, but we can extract associated domains
        let url = "https://www.spamhaus.org/drop/drop.txt";
        
        match self.client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    let text = response.text().await?;
                    let domains = text
                        .lines()
                        .filter(|line| !line.starts_with(';') && !line.trim().is_empty())
                        .filter_map(|line| {
                            // Extract any domain names from comments
                            if let Some(comment_start) = line.find(';') {
                                let comment = &line[comment_start + 1..];
                                // Basic domain extraction from comments
                                if comment.contains('.') {
                                    let words: Vec<&str> = comment.split_whitespace().collect();
                                    for word in words {
                                        if word.contains('.') && !word.contains('/') {
                                            return Some(word.to_lowercase());
                                        }
                                    }
                                }
                            }
                            None
                        })
                        .collect();
                    
                    Ok(domains)
                } else {
                    Err(AppError::HardIntelLookup(format!("Spamhaus returned status: {}", response.status())))
                }
            }
            Err(e) => {
                warn!("Failed to fetch Spamhaus DROP: {}", e);
                Ok(HashSet::new())
            }
        }
    }
    
    async fn load_dynamic_dns_providers(&self) {
        // Static list of known dynamic DNS providers
        let providers = vec![
            "dyndns.org", "no-ip.com", "ddns.net", "freedns.afraid.org",
            "changeip.com", "dnsdynamic.org", "duckdns.org", "noip.me",
            "3utilities.com", "bounceme.net", "ddns.me", "gotdns.ch",
            "hopto.org", "myftp.biz", "myftp.org", "myftpaccess.com",
            "servebeer.com", "servecounterstrike.com", "serveftp.com",
            "servegame.com", "servehalflife.com", "servehttp.com",
            "serveirc.com", "serveminecraft.net", "servemp3.com",
            "servepics.com", "servequake.com", "sytes.net", "viewdns.net",
            "webhop.me", "zapto.org",
        ];
        
        let mut dns_providers = self.dynamic_dns_providers.write().await;
        dns_providers.extend(providers.into_iter().map(String::from));
    }
    
    async fn cache_result(&self, domain: &str, result: Option<HardIntelMatch>) {
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            domain.to_string(),
            CacheEntry {
                result,
                timestamp: Instant::now(),
                ttl: Duration::from_secs(3600), // 1 hour TTL
            },
        );
        
        // Clean up old entries if cache is getting large
        if cache.entries.len() > 10000 {
            let cutoff = Instant::now() - Duration::from_secs(3600);
            cache.entries.retain(|_, entry| entry.timestamp > cutoff);
        }
    }
    
    fn start_refresh_task(&self) {
        let checker = Arc::new(self.clone());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Refresh every hour
            
            loop {
                interval.tick().await;
                if let Err(e) = checker.load_intel_lists().await {
                    warn!("Failed to refresh intel lists: {}", e);
                }
            }
        });
    }
    
    pub async fn is_dynamic_dns(&self, domain: &str) -> bool {
        let providers = self.dynamic_dns_providers.read().await;
        
        // Check if domain ends with any known dynamic DNS provider
        providers.iter().any(|provider| domain.ends_with(provider))
    }
    
    pub async fn get_statistics(&self) -> IntelStatistics {
        let malware_count = self.malware_domains.read().await.len();
        let phishing_count = self.phishing_domains.read().await.len();
        let crypto_count = self.crypto_mining_domains.read().await.len();
        let spamhaus_count = self.spamhaus_drop.read().await.len();
        let cache_size = self.cache.read().await.entries.len();
        
        IntelStatistics {
            malware_domains: malware_count,
            phishing_domains: phishing_count,
            crypto_mining_domains: crypto_count,
            spamhaus_domains: spamhaus_count,
            cache_entries: cache_size,
        }
    }
}

// Clone implementation for background tasks
impl Clone for HardIntelChecker {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            cache: Arc::clone(&self.cache),
            malware_domains: Arc::clone(&self.malware_domains),
            phishing_domains: Arc::clone(&self.phishing_domains),
            crypto_mining_domains: Arc::clone(&self.crypto_mining_domains),
            spamhaus_drop: Arc::clone(&self.spamhaus_drop),
            dynamic_dns_providers: Arc::clone(&self.dynamic_dns_providers),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntelStatistics {
    pub malware_domains: usize,
    pub phishing_domains: usize,
    pub crypto_mining_domains: usize,
    pub spamhaus_domains: usize,
    pub cache_entries: usize,
}