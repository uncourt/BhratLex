use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use publicsuffix::List;
use strsim::jaro_winkler;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Features {
    pub len_domain: f64,
    pub num_dashes: f64,
    pub num_digits: f64,
    pub entropy: f64,
    pub idn_homoglyph: f64,
    pub typosquat_score: f64,
    pub nrd: f64,
    pub dynamic_dns: f64,
    pub parked: f64,
    pub cname_cloaking: f64,
    pub dns_rebinding: f64,
    pub coinblocklist_hit: f64,
}

pub struct Featurizer {
    ps_list: List,
    popular_brands: Vec<&'static str>,
    dynamic_dns_suffixes: HashSet<&'static str>,
    parked_keywords: Vec<&'static str>,
    coinblock_hosts: HashSet<&'static str>,
}

impl Featurizer {
    pub fn new() -> Self {
        let ps_list = List::fetch().expect("publicsuffix");
        let popular_brands = vec!["google", "apple", "microsoft", "facebook", "amazon", "paypal", "bank", "github"];
        let dynamic_dns_suffixes = HashSet::from([
            "duckdns.org", "no-ip.org", "ddns.net", "dynu.net", "hopto.org"
        ]);
        let parked_keywords = vec!["buy this domain", "sedo", "parkingcrew", "bodis", "parked"];
        let coinblock_hosts = HashSet::from([
            "coinhive.com", "webminepool.com", "coinimp.com"
        ]);
        Self { ps_list, popular_brands, dynamic_dns_suffixes, parked_keywords, coinblock_hosts }
    }

    pub async fn extract(&self, domain: &str, url: &str) -> (Features, Vec<String>) {
        let mut reasons = Vec::new();
        let len_domain = domain.len() as f64;
        let num_dashes = domain.matches('-').count() as f64;
        let num_digits = domain.chars().filter(|c| c.is_ascii_digit()).count() as f64;
        let entropy = shannon_entropy(domain) as f64;

        let idn_homoglyph = if looks_like_homoglyph(domain) { reasons.push("idn_homoglyph".into()); 1.0 } else { 0.0 };

        let typosquat_score = self.typosquat_score(domain);
        if typosquat_score > 0.9 { reasons.push("typosquat_brand".into()); }

        // Hot path avoids network I/O; approximate using suffix lists only
        let nrd = 0.0; // unknown without WHOIS
        let dynamic_dns = self.dynamic_dns_suffixes.iter().any(|s| domain.ends_with(s)) as i32 as f64;
        if dynamic_dns > 0.5 { reasons.push("dynamic_dns_provider".into()); }

        let cname_cloaking = 0.0; // DNS-only, deferred to analyzer
        let dns_rebinding = 0.0; // DNS-only, deferred to analyzer

        let parked = 0.0; // requires HTTP fetch, deferred
        let coinblocklist_hit = if self.coinblock_hosts.iter().any(|h| domain.contains(h)) { 1.0 } else { 0.0 };
        if coinblocklist_hit > 0.5 { reasons.push("cryptojacking_host".into()); }

        (Features { len_domain, num_dashes, num_digits, entropy, idn_homoglyph, typosquat_score, nrd, dynamic_dns, parked, cname_cloaking, dns_rebinding, coinblocklist_hit }, reasons)
    }

    fn typosquat_score(&self, domain: &str) -> f64 {
        let sld = self.ps_list.parse_dns_name(domain).ok().and_then(|d| d.root().and_then(|r| r.subdomain(1))).map(|s| s.to_string()).unwrap_or_else(|| domain.to_string());
        let mut best = 0.0;
        for b in &self.popular_brands {
            let score = jaro_winkler(&sld, b);
            if score > best { best = score; }
        }
        best
    }
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    for b in s.bytes() { *counts.entry(b).or_insert(0usize) += 1; }
    let len = s.len() as f64;
    counts.values().map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

fn looks_like_homoglyph(s: &str) -> bool {
    if s.contains("xn--") { return true; }
    !s.is_ascii()
}

pub use Features as FeatureVector;