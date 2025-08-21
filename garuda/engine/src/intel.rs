use anyhow::Result;
use crate::types::EngineConfig;
use moka::future::Cache;
use std::time::Duration;
use std::fs;
use std::path::Path;

pub struct Intel {
    cache: Cache<String, bool>,
    sets: Vec<std::collections::HashSet<String>>, // multiple lists
}

impl Intel {
    pub async fn load_default(_cfg: &EngineConfig) -> Result<Self> {
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(3600))
            .max_capacity(100_000)
            .build();
        let mut sets = Vec::new();
        for file in [
            "./engine/data/intel/abuse_ch.txt",
            "./engine/data/intel/shadowserver.txt",
            "./engine/data/intel/spamhaus_drop.txt",
            "./engine/data/intel/gsb.txt",
        ] {
            if Path::new(file).exists() {
                let content = fs::read_to_string(file).unwrap_or_default();
                let set = content.lines().filter_map(|l| {
                    let t = l.trim(); if t.is_empty() || t.starts_with('#') { None } else { Some(t.to_string()) }
                }).collect();
                sets.push(set);
            }
        }
        Ok(Self { cache, sets })
    }

    pub async fn check_block(&self, domain: &str) -> Option<String> {
        if let Some(v) = self.cache.get(domain).await { if v { return Some("hard_intel".to_string()); } }
        for (i, set) in self.sets.iter().enumerate() {
            if exact_or_suffix_match(domain, set) {
                let _ = self.cache.insert(domain.to_string(), true).await;
                return Some(format!("hard_intel_list_{}", i));
            }
        }
        None
    }
}

fn exact_or_suffix_match(domain: &str, set: &std::collections::HashSet<String>) -> bool {
    if set.contains(domain) { return true; }
    // check suffixes like bad.example.com if list has example.com
    let parts: Vec<&str> = domain.split('.').collect();
    for i in 1..parts.len() {
        let suffix = parts[i..].join(".");
        if set.contains(&suffix) { return true; }
    }
    false
}