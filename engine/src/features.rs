use crate::{
    config::FeatureConfig,
    error::AppError,
    types::{DomainInfo, ThreatFeatures, FEATURE_NAMES},
};
use publicsuffix::List;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver,
};
use url::Url;

pub struct FeatureExtractor {
    config: FeatureConfig,
    psl: List,
    resolver: Resolver,
    cache: Arc<RwLock<FeatureCache>>,
    popular_domains: Arc<RwLock<HashSet<String>>>,
    suspicious_tlds: Arc<RwLock<HashSet<String>>>,
    dictionary_words: Arc<RwLock<HashSet<String>>>,
}

#[derive(Debug, Default)]
struct FeatureCache {
    entries: HashMap<String, CachedFeatures>,
}

#[derive(Debug, Clone)]
struct CachedFeatures {
    features: HashMap<String, f32>,
    timestamp: Instant,
    ttl: Duration,
}

impl FeatureExtractor {
    pub async fn new(config: &FeatureConfig) -> Result<Self, AppError> {
        let psl = List::fetch()?;
        
        let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
        
        let cache = Arc::new(RwLock::new(FeatureCache::default()));
        
        let extractor = Self {
            config: config.clone(),
            psl,
            resolver,
            cache,
            popular_domains: Arc::new(RwLock::new(HashSet::new())),
            suspicious_tlds: Arc::new(RwLock::new(HashSet::new())),
            dictionary_words: Arc::new(RwLock::new(HashSet::new())),
        };
        
        // Load reference data
        extractor.load_reference_data().await;
        
        Ok(extractor)
    }
    
    pub async fn extract(&self, domain: &str, url: Option<&str>) -> Result<ThreatFeatures, AppError> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.entries.get(domain) {
                if cached.timestamp.elapsed() < cached.ttl {
                    return Ok(ThreatFeatures {
                        domain: domain.to_string(),
                        url: url.map(String::from),
                        features: cached.features.clone(),
                    });
                }
            }
        }
        
        // Extract features
        let mut features = HashMap::new();
        
        // Parse domain
        let domain_info = self.parse_domain(domain)?;
        
        // Basic domain features
        self.extract_basic_features(domain, &domain_info, &mut features);
        
        // Advanced threat detection features
        if self.config.check_idn_homoglyphs {
            self.extract_homoglyph_features(domain, &mut features);
        }
        
        if self.config.check_typosquatting {
            self.extract_typosquatting_features(domain, &mut features).await;
        }
        
        if self.config.check_dga {
            self.extract_dga_features(domain, &mut features).await;
        }
        
        // DNS-based features
        self.extract_dns_features(domain, &mut features).await;
        
        // URL features if provided
        if let Some(url_str) = url {
            self.extract_url_features(url_str, &mut features)?;
        }
        
        // Cache result
        self.cache_features(domain, &features).await;
        
        Ok(ThreatFeatures {
            domain: domain.to_string(),
            url: url.map(String::from),
            features,
        })
    }
    
    fn parse_domain(&self, domain: &str) -> Result<DomainInfo, AppError> {
        let domain_lower = domain.to_lowercase();
        
        // Parse using public suffix list
        let parsed = self.psl.parse_domain(&domain_lower)
            .map_err(|e| AppError::FeatureExtraction(format!("Failed to parse domain: {}", e)))?;
        
        let tld = parsed.suffix().unwrap_or("").to_string();
        let sld = parsed.root().unwrap_or(&domain_lower).to_string();
        
        // Extract subdomain
        let subdomain = if domain_lower.len() > sld.len() + tld.len() + 1 {
            let subdomain_part = &domain_lower[..domain_lower.len() - sld.len() - tld.len() - 1];
            if !subdomain_part.is_empty() {
                Some(subdomain_part.to_string())
            } else {
                None
            }
        } else {
            None
        };
        
        // Check if IDN
        let is_idn = domain.contains("xn--") || domain.chars().any(|c| !c.is_ascii());
        let punycode = if is_idn && !domain.contains("xn--") {
            idna::domain_to_ascii(domain).ok()
        } else {
            None
        };
        
        Ok(DomainInfo {
            domain: domain_lower,
            tld,
            sld,
            subdomain,
            is_idn,
            punycode,
            registrar: None,
            creation_date: None,
            dns_records: HashMap::new(),
        })
    }
    
    fn extract_basic_features(&self, domain: &str, domain_info: &DomainInfo, features: &mut HashMap<String, f32>) {
        // Domain length
        features.insert("domain_length".to_string(), domain.len() as f32);
        
        // Subdomain count
        let subdomain_count = domain_info.subdomain
            .as_ref()
            .map(|s| s.matches('.').count() + 1)
            .unwrap_or(0) as f32;
        features.insert("subdomain_count".to_string(), subdomain_count);
        
        // Character analysis
        let total_chars = domain.len() as f32;
        let numeric_count = domain.chars().filter(|c| c.is_numeric()).count() as f32;
        let special_count = domain.chars().filter(|c| !c.is_alphanumeric()).count() as f32;
        
        features.insert("numeric_ratio".to_string(), numeric_count / total_chars);
        features.insert("special_char_ratio".to_string(), special_count / total_chars);
        
        // Entropy calculation
        let entropy = self.calculate_entropy(domain);
        features.insert("entropy".to_string(), entropy);
        
        // Vowel/consonant ratio
        let vowels = "aeiou";
        let vowel_count = domain.chars().filter(|c| vowels.contains(*c)).count() as f32;
        let consonant_count = domain.chars().filter(|c| c.is_alphabetic() && !vowels.contains(*c)).count() as f32;
        let vowel_consonant_ratio = if consonant_count > 0.0 { vowel_count / consonant_count } else { 0.0 };
        features.insert("vowel_consonant_ratio".to_string(), vowel_consonant_ratio);
        
        // Digit/letter ratio
        let letter_count = domain.chars().filter(|c| c.is_alphabetic()).count() as f32;
        let digit_letter_ratio = if letter_count > 0.0 { numeric_count / letter_count } else { 0.0 };
        features.insert("digit_letter_ratio".to_string(), digit_letter_ratio);
        
        // Consecutive consonants
        let consecutive_consonants = self.count_consecutive_consonants(domain);
        features.insert("consecutive_consonants".to_string(), consecutive_consonants as f32);
        
        // IDN flag
        features.insert("is_idn".to_string(), if domain_info.is_idn { 1.0 } else { 0.0 });
        
        // TLD analysis
        let suspicious_tld = self.is_suspicious_tld(&domain_info.tld);
        features.insert("suspicious_tld".to_string(), if suspicious_tld { 1.0 } else { 0.0 });
    }
    
    fn extract_homoglyph_features(&self, domain: &str, features: &mut HashMap<String, f32>) {
        let homoglyph_score = self.calculate_homoglyph_score(domain);
        features.insert("homoglyph_score".to_string(), homoglyph_score);
    }
    
    async fn extract_typosquatting_features(&self, domain: &str, features: &mut HashMap<String, f32>) {
        let typosquatting_score = self.calculate_typosquatting_score(domain).await;
        features.insert("typosquatting_score".to_string(), typosquatting_score);
    }
    
    async fn extract_dga_features(&self, domain: &str, features: &mut HashMap<String, f32>) {
        let dga_score = self.calculate_dga_score(domain).await;
        features.insert("dga_score".to_string(), dga_score);
        
        // Dictionary word analysis
        let dictionary_words = self.count_dictionary_words(domain).await;
        features.insert("dictionary_words".to_string(), dictionary_words as f32);
    }
    
    async fn extract_dns_features(&self, domain: &str, features: &mut HashMap<String, f32>) {
        // DNS record count
        let mut dns_record_count = 0f32;
        let mut mx_exists = 0f32;
        let mut spf_exists = 0f32;
        let mut dmarc_exists = 0f32;
        
        // A record lookup
        if let Ok(_) = self.resolver.lookup_ip(domain).await {
            dns_record_count += 1.0;
        }
        
        // MX record lookup
        if let Ok(mx_records) = self.resolver.mx_lookup(domain).await {
            if !mx_records.is_empty() {
                mx_exists = 1.0;
                dns_record_count += 1.0;
            }
        }
        
        // TXT record lookup for SPF and DMARC
        if let Ok(txt_records) = self.resolver.txt_lookup(domain).await {
            for record in txt_records.iter() {
                let txt_data = record.to_string();
                if txt_data.starts_with("v=spf1") {
                    spf_exists = 1.0;
                }
            }
            dns_record_count += txt_records.len() as f32;
        }
        
        // DMARC lookup
        let dmarc_domain = format!("_dmarc.{}", domain);
        if let Ok(dmarc_records) = self.resolver.txt_lookup(&dmarc_domain).await {
            for record in dmarc_records.iter() {
                let txt_data = record.to_string();
                if txt_data.starts_with("v=DMARC1") {
                    dmarc_exists = 1.0;
                    break;
                }
            }
        }
        
        features.insert("dns_record_count".to_string(), dns_record_count);
        features.insert("mx_record_exists".to_string(), mx_exists);
        features.insert("spf_record_exists".to_string(), spf_exists);
        features.insert("dmarc_record_exists".to_string(), dmarc_exists);
    }
    
    fn extract_url_features(&self, url_str: &str, features: &mut HashMap<String, f32>) -> Result<(), AppError> {
        let url = Url::parse(url_str)
            .map_err(|e| AppError::FeatureExtraction(format!("Invalid URL: {}", e)))?;
        
        // URL length
        features.insert("url_length".to_string(), url_str.len() as f32);
        
        // Path depth
        let path_depth = url.path().matches('/').count() as f32;
        features.insert("path_depth".to_string(), path_depth);
        
        // Query parameters count
        let query_params_count = url.query_pairs().count() as f32;
        features.insert("query_params_count".to_string(), query_params_count);
        
        // Fragment exists
        let fragment_exists = if url.fragment().is_some() { 1.0 } else { 0.0 };
        features.insert("fragment_exists".to_string(), fragment_exists);
        
        // Suspicious keywords in URL
        let suspicious_keywords = self.count_suspicious_keywords(url_str);
        features.insert("suspicious_keywords".to_string(), suspicious_keywords as f32);
        
        // Phishing keywords
        let phishing_keywords = self.count_phishing_keywords(url_str);
        features.insert("phishing_keywords".to_string(), phishing_keywords as f32);
        
        Ok(())
    }
    
    // Helper methods
    
    fn calculate_entropy(&self, text: &str) -> f32 {
        let mut char_counts = HashMap::new();
        let total_chars = text.len() as f32;
        
        for ch in text.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        let mut entropy = 0.0f32;
        for count in char_counts.values() {
            let probability = *count as f32 / total_chars;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn count_consecutive_consonants(&self, text: &str) -> usize {
        let vowels = "aeiou";
        let mut max_consecutive = 0;
        let mut current_consecutive = 0;
        
        for ch in text.chars() {
            if ch.is_alphabetic() && !vowels.contains(ch) {
                current_consecutive += 1;
                max_consecutive = max_consecutive.max(current_consecutive);
            } else {
                current_consecutive = 0;
            }
        }
        
        max_consecutive
    }
    
    fn calculate_homoglyph_score(&self, domain: &str) -> f32 {
        // Simple homoglyph detection - count suspicious Unicode characters
        let suspicious_chars = "αβγδεζηθικλμνξοπρστυφχψωабвгдеёжзийклмнопрстуфхцчшщъыьэюя";
        let suspicious_count = domain.chars().filter(|c| suspicious_chars.contains(*c)).count();
        
        (suspicious_count as f32 / domain.len() as f32).min(1.0)
    }
    
    async fn calculate_typosquatting_score(&self, domain: &str) -> f32 {
        let popular_domains = self.popular_domains.read().await;
        
        let mut min_distance = f32::MAX;
        for popular in popular_domains.iter() {
            let distance = strsim::normalized_levenshtein(domain, popular) as f32;
            min_distance = min_distance.min(distance);
        }
        
        // Convert similarity to suspicion score (higher similarity = higher suspicion)
        if min_distance < f32::MAX {
            1.0 - min_distance
        } else {
            0.0
        }
    }
    
    async fn calculate_dga_score(&self, domain: &str) -> f32 {
        // Multiple DGA detection heuristics
        let mut score = 0.0f32;
        
        // High entropy indicates randomness
        let entropy = self.calculate_entropy(domain);
        if entropy > 4.0 {
            score += 0.3;
        }
        
        // Lack of vowels
        let vowel_count = domain.chars().filter(|c| "aeiou".contains(*c)).count();
        if vowel_count as f32 / domain.len() as f32 < 0.2 {
            score += 0.2;
        }
        
        // Consecutive consonants
        if self.count_consecutive_consonants(domain) > 4 {
            score += 0.2;
        }
        
        // Character patterns
        if domain.chars().filter(|c| c.is_numeric()).count() > domain.len() / 3 {
            score += 0.3;
        }
        
        score.min(1.0)
    }
    
    async fn count_dictionary_words(&self, domain: &str) -> usize {
        let dictionary = self.dictionary_words.read().await;
        
        // Simple word matching - could be improved with better tokenization
        dictionary.iter().filter(|word| domain.contains(*word)).count()
    }
    
    fn is_suspicious_tld(&self, tld: &str) -> bool {
        // List of TLDs commonly used for malicious purposes
        let suspicious_tlds = [
            "tk", "ml", "ga", "cf", "pw", "bit", "click", "download",
            "link", "racing", "review", "science", "work", "party",
        ];
        
        suspicious_tlds.contains(&tld)
    }
    
    fn count_suspicious_keywords(&self, url: &str) -> usize {
        let keywords = [
            "login", "signin", "account", "verify", "secure", "update",
            "confirm", "suspended", "blocked", "urgent", "immediate",
            "click", "download", "free", "winner", "prize", "offer",
        ];
        
        let url_lower = url.to_lowercase();
        keywords.iter().filter(|keyword| url_lower.contains(*keyword)).count()
    }
    
    fn count_phishing_keywords(&self, url: &str) -> usize {
        let phishing_keywords = [
            "paypal", "amazon", "apple", "microsoft", "google", "facebook",
            "twitter", "instagram", "linkedin", "ebay", "banking", "bank",
            "visa", "mastercard", "creditcard", "wallet", "bitcoin",
        ];
        
        let url_lower = url.to_lowercase();
        phishing_keywords.iter().filter(|keyword| url_lower.contains(*keyword)).count()
    }
    
    async fn load_reference_data(&self) {
        // Load popular domains (simplified - in production would load from file)
        let popular = vec![
            "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
            "linkedin.com", "reddit.com", "wikipedia.org", "amazon.com", "apple.com",
            "microsoft.com", "netflix.com", "paypal.com", "ebay.com", "yahoo.com",
        ];
        
        {
            let mut popular_domains = self.popular_domains.write().await;
            popular_domains.extend(popular.into_iter().map(String::from));
        }
        
        // Load dictionary words (simplified)
        let words = vec![
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
            "her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
            "how", "man", "new", "now", "old", "see", "two", "way", "who", "boy",
            "did", "its", "let", "put", "say", "she", "too", "use",
        ];
        
        {
            let mut dictionary = self.dictionary_words.write().await;
            dictionary.extend(words.into_iter().map(String::from));
        }
    }
    
    async fn cache_features(&self, domain: &str, features: &HashMap<String, f32>) {
        let mut cache = self.cache.write().await;
        cache.entries.insert(
            domain.to_string(),
            CachedFeatures {
                features: features.clone(),
                timestamp: Instant::now(),
                ttl: Duration::from_secs(self.config.feature_cache_ttl),
            },
        );
        
        // Clean up old entries
        if cache.entries.len() > 5000 {
            let cutoff = Instant::now() - Duration::from_secs(self.config.feature_cache_ttl);
            cache.entries.retain(|_, entry| entry.timestamp > cutoff);
        }
    }
}

impl From<trust_dns_resolver::error::ResolveError> for AppError {
    fn from(err: trust_dns_resolver::error::ResolveError) -> Self {
        AppError::Dns(err.to_string())
    }
}