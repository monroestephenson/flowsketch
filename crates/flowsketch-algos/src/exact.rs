//! Exact hash-map counter. Unbounded memory — never planned for production
//! queries; exists as the ground-truth baseline for accuracy benchmarks and
//! tests.

use std::collections::{HashMap, HashSet};

use flowsketch_core::hash::HashSpec;
use flowsketch_core::{Sketch, SketchCompatibility, SketchError};

pub const ALGORITHM: &str = "exact";

#[derive(Debug, Clone, Default)]
pub struct ExactCounter {
    counts: HashMap<Vec<u8>, u64>,
    distinct: HashMap<Vec<u8>, HashSet<Vec<u8>>>,
    total_weight: u64,
    updates: u64,
}

impl ExactCounter {
    pub fn new() -> Self {
        ExactCounter::default()
    }

    pub fn add(&mut self, key: &[u8], weight: u64) {
        self.total_weight += weight;
        self.updates += 1;
        *self.counts.entry(key.to_vec()).or_insert(0) += weight;
    }

    /// Ground truth for distinct-count queries.
    pub fn insert_distinct(&mut self, key: &[u8], item: &[u8]) {
        self.updates += 1;
        self.distinct
            .entry(key.to_vec())
            .or_default()
            .insert(item.to_vec());
    }

    pub fn get(&self, key: &[u8]) -> u64 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    pub fn distinct_count(&self, key: &[u8]) -> u64 {
        self.distinct.get(key).map(|s| s.len() as u64).unwrap_or(0)
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    pub fn top_k(&self, limit: usize) -> Vec<(Vec<u8>, u64)> {
        let mut all: Vec<(Vec<u8>, u64)> = self
            .counts
            .iter()
            .map(|(k, &c)| (k.clone(), c))
            .collect();
        all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        all.truncate(limit);
        all
    }

    pub fn keys(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.counts.keys()
    }
}

impl Sketch for ExactCounter {
    fn update(&mut self, key: &[u8], value: u64) {
        self.add(key, value);
    }

    fn estimate(&self, key: &[u8]) -> f64 {
        self.get(key) as f64
    }

    fn merge_from(&mut self, other: &Self) -> Result<(), SketchError> {
        for (k, &c) in &other.counts {
            *self.counts.entry(k.clone()).or_insert(0) += c;
        }
        for (k, items) in &other.distinct {
            let mine = self.distinct.entry(k.clone()).or_default();
            for item in items {
                mine.insert(item.clone());
            }
        }
        self.total_weight += other.total_weight;
        self.updates += other.updates;
        Ok(())
    }

    fn memory_bytes(&self) -> usize {
        let counts: usize = self.counts.keys().map(|k| k.len() + 8 + 32).sum();
        let distinct: usize = self
            .distinct
            .iter()
            .map(|(k, s)| k.len() + s.iter().map(|i| i.len() + 32).sum::<usize>())
            .sum();
        counts + distinct + std::mem::size_of::<Self>()
    }

    fn reset(&mut self) {
        self.counts.clear();
        self.distinct.clear();
        self.total_weight = 0;
        self.updates = 0;
    }

    fn update_count(&self) -> u64 {
        self.updates
    }

    fn compatibility(&self) -> SketchCompatibility {
        SketchCompatibility {
            algorithm: ALGORITHM.to_string(),
            version: 1,
            hash: HashSpec::new(0),
            params_hash: 0,
        }
    }
}
