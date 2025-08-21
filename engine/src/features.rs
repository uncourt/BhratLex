use crate::types::DomainFeatures;
use publicsuffix::PublicSuffix;
use std::collections::HashMap;
use tracing::debug;

pub struct FeatureExtractor {
    suspicious_tlds: Vec<String>,
    dynamic_dns_providers: Vec<String>,
    parked_domain_indicators: Vec<String>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            suspicious_tlds: vec![
                "tk", "ml", "ga", "cf", "gq", "cc", "xyz", "top", "club", "online"
            ],
            dynamic_dns_providers: vec![
                "no-ip.com", "dyndns.org", "freedns.afraid.org", "duckdns.org"
            ],
            parked_domain_indicators: vec![
                "parked", "domain", "for sale", "buy this domain", "domain parking"
            ],
        }
    }

    pub fn extract_features(&self, domain: &str) -> DomainFeatures {
        let mut features = DomainFeatures::default();
        
        // Basic length features
        features.length = domain.len() as f64;
        
        // Character distribution features
        let (consonants, vowels, digits, special_chars) = self.analyze_character_distribution(domain);
        features.consonant_ratio = consonants / domain.len() as f64;
        features.vowel_ratio = vowels / domain.len() as f64;
        features.digit_ratio = digits / domain.len() as f64;
        features.special_char_ratio = special_chars / domain.len() as f64;
        
        // Entropy calculation
        features.entropy = self.calculate_entropy(domain);
        
        // Consecutive character features
        let (max_consonants, max_vowels, max_digits, max_special) = self.analyze_consecutive_chars(domain);
        features.consecutive_consonants = max_consonants as f64;
        features.consecutive_vowels = max_vowels as f64;
        features.consecutive_digits = max_digits as f64;
        features.consecutive_special_chars = max_special as f64;
        
        // Threat-specific features
        features.idn_homoglyph_score = self.calculate_idn_homoglyph_score(domain);
        features.typosquatting_score = self.calculate_typosquatting_score(domain);
        features.dga_entropy = self.calculate_dga_entropy(domain);
        features.nrd_flag = self.check_nrd_flag(domain);
        features.dynamic_dns_flag = self.check_dynamic_dns_flag(domain);
        features.parked_domain_flag = self.check_parked_domain_flag(domain);
        features.cname_cloaking_flag = self.check_cname_cloaking_flag(domain);
        features.dns_rebinding_flag = self.check_dns_rebinding_flag(domain);
        features.cryptojacking_flag = self.check_cryptojacking_flag(domain);
        
        debug!("Extracted features for domain {}: {:?}", domain, features);
        features
    }

    fn analyze_character_distribution(&self, domain: &str) -> (usize, usize, usize, usize) {
        let mut consonants = 0;
        let mut vowels = 0;
        let mut digits = 0;
        let mut special_chars = 0;
        
        for ch in domain.chars() {
            match ch {
                'a' | 'e' | 'i' | 'o' | 'u' => vowels += 1,
                'b' | 'c' | 'd' | 'f' | 'g' | 'h' | 'j' | 'k' | 'l' | 'm' |
                'n' | 'p' | 'q' | 'r' | 's' | 't' | 'v' | 'w' | 'x' | 'y' | 'z' => consonants += 1,
                '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => digits += 1,
                _ => special_chars += 1,
            }
        }
        
        (consonants, vowels, digits, special_chars)
    }

    fn calculate_entropy(&self, domain: &str) -> f64 {
        let mut char_counts = HashMap::new();
        let total_chars = domain.len() as f64;
        
        for ch in domain.chars() {
            *char_counts.entry(ch).or_insert(0) += 1;
        }
        
        char_counts.values().fold(0.0, |entropy, &count| {
            let probability = count as f64 / total_chars;
            entropy - probability * probability.log2()
        })
    }

    fn analyze_consecutive_chars(&self, domain: &str) -> (usize, usize, usize, usize) {
        let mut max_consonants = 0;
        let mut max_vowels = 0;
        let mut max_digits = 0;
        let mut max_special = 0;
        
        let mut current_consonants = 0;
        let mut current_vowels = 0;
        let mut current_digits = 0;
        let mut current_special = 0;
        
        for ch in domain.chars() {
            match ch {
                'a' | 'e' | 'i' | 'o' | 'u' => {
                    current_vowels += 1;
                    current_consonants = 0;
                    current_digits = 0;
                    current_special = 0;
                    max_vowels = max_vowels.max(current_vowels);
                }
                'b' | 'c' | 'd' | 'f' | 'g' | 'h' | 'j' | 'k' | 'l' | 'm' |
                'n' | 'p' | 'q' | 'r' | 's' | 't' | 'v' | 'w' | 'x' | 'y' | 'z' => {
                    current_consonants += 1;
                    current_vowels = 0;
                    current_digits = 0;
                    current_special = 0;
                    max_consonants = max_consonants.max(current_consonants);
                }
                '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                    current_digits += 1;
                    current_consonants = 0;
                    current_vowels = 0;
                    current_special = 0;
                    max_digits = max_digits.max(current_digits);
                }
                _ => {
                    current_special += 1;
                    current_consonants = 0;
                    current_vowels = 0;
                    current_digits = 0;
                    max_special = max_special.max(current_special);
                }
            }
        }
        
        (max_consonants, max_vowels, max_digits, max_special)
    }

    fn calculate_idn_homoglyph_score(&self, domain: &str) -> f64 {
        // Simple heuristic for IDN homoglyph detection
        let mut score = 0.0;
        
        // Check for mixed scripts
        let has_latin = domain.chars().any(|c| c.is_ascii_lowercase());
        let has_cyrillic = domain.chars().any(|c| {
            matches!(c, 'а'..='я' | 'А'..='Я')
        });
        let has_greek = domain.chars().any(|c| {
            matches!(c, 'α'..='ω' | 'Α'..='Ω')
        });
        
        if has_latin && (has_cyrillic || has_greek) {
            score += 0.8;
        }
        
        // Check for visually similar characters
        let similar_chars = ['0', 'o', '1', 'l', '5', 's', '8', 'b'];
        let mut similar_count = 0;
        for ch in domain.chars() {
            if similar_chars.contains(&ch) {
                similar_count += 1;
            }
        }
        
        if similar_count > 2 {
            score += 0.3;
        }
        
        score.min(1.0)
    }

    fn calculate_typosquatting_score(&self, domain: &str) -> f64 {
        // Simple typosquatting detection based on common patterns
        let mut score = 0.0;
        
        // Check for common typos
        let typos = [
            ("google", "g00gle"), ("google", "go0gle"), ("google", "g0ogle"),
            ("facebook", "faceb00k"), ("facebook", "facebo0k"),
            ("amazon", "amaz0n"), ("amazon", "amaz0n"),
        ];
        
        for (legitimate, typo) in typos.iter() {
            if domain.contains(typo) {
                score += 0.7;
                break;
            }
        }
        
        // Check for character transposition
        if domain.len() > 3 {
            for i in 0..domain.len() - 1 {
                let mut chars: Vec<char> = domain.chars().collect();
                chars.swap(i, i + 1);
                let swapped: String = chars.into_iter().collect();
                
                // Check if swapped version matches common domains
                if swapped.contains("google") || swapped.contains("facebook") || swapped.contains("amazon") {
                    score += 0.6;
                    break;
                }
            }
        }
        
        score.min(1.0)
    }

    fn calculate_dga_entropy(&self, domain: &str) -> f64 {
        // Domain Generation Algorithm entropy detection
        let entropy = self.calculate_entropy(domain);
        let length = domain.len() as f64;
        
        // DGA domains typically have high entropy and random character distribution
        if entropy > 4.0 && length > 10.0 {
            let consonant_vowel_ratio = (self.analyze_character_distribution(domain).0 as f64) / 
                                      (self.analyze_character_distribution(domain).1 as f64);
            
            if consonant_vowel_ratio > 2.0 || consonant_vowel_ratio < 0.5 {
                return 0.8;
            }
        }
        
        0.0
    }

    fn check_nrd_flag(&self, domain: &str) -> f64 {
        // Newly Registered Domain flag
        // This would typically check against a database of domain registration dates
        // For now, use a simple heuristic based on domain characteristics
        if domain.len() > 20 || domain.contains("new") || domain.contains("2024") {
            0.6
        } else {
            0.0
        }
    }

    fn check_dynamic_dns_flag(&self, domain: &str) -> f64 {
        // Check if domain is from a dynamic DNS provider
        for provider in &self.dynamic_dns_providers {
            if domain.ends_with(provider) {
                return 0.7;
            }
        }
        0.0
    }

    fn check_parked_domain_flag(&self, domain: &str) -> f64 {
        // Check for parked domain indicators
        // This would typically require DNS resolution and content analysis
        // For now, return 0.0 as this requires async analysis
        0.0
    }

    fn check_cname_cloaking_flag(&self, domain: &str) -> f64 {
        // CNAME cloaking detection
        // This would require DNS resolution and CNAME chain analysis
        // For now, return 0.0 as this requires async analysis
        0.0
    }

    fn check_dns_rebinding_flag(&self, domain: &str) -> f64 {
        // DNS rebinding detection
        // This would require DNS resolution and TTL analysis
        // For now, return 0.0 as this requires async analysis
        0.0
    }

    fn check_cryptojacking_flag(&self, domain: &str) -> f64 {
        // Cryptojacking detection
        // This would require content analysis and mining script detection
        // For now, return 0.0 as this requires async analysis
        0.0
    }
}