//! Reputation system for compute workers.
//!
//! Tracks job success rates, latency, uptime, and detects sybil behavior.
//! Reputation scores determine worker eligibility and payment rates.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

/// Reputation record for a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub address: String,
    pub score: f64,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub jobs_disputed: u64,
    pub total_compute_time_ms: u64,
    pub avg_latency_ms: f64,
    pub first_seen: u64,
    pub last_active: u64,
    pub ip_hash: Option<String>,
}

impl ReputationRecord {
    pub fn new(address: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            address: address.to_string(),
            score: 50.0, // neutral starting score
            jobs_completed: 0,
            jobs_failed: 0,
            jobs_disputed: 0,
            total_compute_time_ms: 0,
            avg_latency_ms: 0.0,
            first_seen: now,
            last_active: now,
            ip_hash: None,
        }
    }

    /// Recalculate reputation score from metrics.
    pub fn recalculate(&mut self) {
        let total_jobs = self.jobs_completed + self.jobs_failed + self.jobs_disputed;
        if total_jobs == 0 {
            self.score = 50.0;
            return;
        }

        // Success rate: 0-100 (weight: 50%)
        let success_rate = self.jobs_completed as f64 / total_jobs as f64 * 100.0;

        // Longevity bonus: up to 10 points based on time active
        let age_ms = self.last_active.saturating_sub(self.first_seen);
        let age_days = age_ms as f64 / 86_400_000.0;
        let longevity = (age_days / 30.0 * 10.0).min(10.0); // max at 30 days

        // Volume bonus: up to 10 points based on jobs completed
        let volume = (self.jobs_completed as f64 / 100.0 * 10.0).min(10.0);

        // Dispute penalty: -5 per dispute
        let dispute_penalty = self.jobs_disputed as f64 * 5.0;

        // Latency bonus: lower is better, up to 10 points
        let latency_score = if self.avg_latency_ms > 0.0 {
            (10.0 - self.avg_latency_ms / 1000.0).max(0.0).min(10.0)
        } else {
            5.0
        };

        self.score = (success_rate * 0.5 + longevity + volume + latency_score - dispute_penalty)
            .max(0.0)
            .min(100.0);
    }
}

/// Reputation oracle — manages reputation records for all workers.
pub struct ReputationOracle {
    records: RwLock<HashMap<String, ReputationRecord>>,
}

impl ReputationOracle {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create a reputation record for a worker.
    pub fn get_or_create(&self, address: &str) -> ReputationRecord {
        let mut records = self.records.write();
        records
            .entry(address.to_string())
            .or_insert_with(|| ReputationRecord::new(address))
            .clone()
    }

    /// Get reputation score for a worker (0-100).
    pub fn get_score(&self, address: &str) -> f64 {
        self.records
            .read()
            .get(address)
            .map(|r| r.score)
            .unwrap_or(50.0)
    }

    /// Record a successful job completion.
    pub fn record_success(&self, address: &str, execution_time_ms: u64) {
        let mut records = self.records.write();
        let record = records
            .entry(address.to_string())
            .or_insert_with(|| ReputationRecord::new(address));

        record.jobs_completed += 1;
        record.total_compute_time_ms += execution_time_ms;
        record.avg_latency_ms = record.total_compute_time_ms as f64 / record.jobs_completed as f64;
        record.last_active = now_ms();
        record.recalculate();

        info!(
            "Reputation update: {} completed job (score: {:.1})",
            &address[..12.min(address.len())],
            record.score
        );
    }

    /// Record a failed job.
    pub fn record_failure(&self, address: &str) {
        let mut records = self.records.write();
        let record = records
            .entry(address.to_string())
            .or_insert_with(|| ReputationRecord::new(address));

        record.jobs_failed += 1;
        record.last_active = now_ms();
        record.recalculate();
    }

    /// Record a disputed job.
    pub fn record_dispute(&self, address: &str) {
        let mut records = self.records.write();
        let record = records
            .entry(address.to_string())
            .or_insert_with(|| ReputationRecord::new(address));

        record.jobs_disputed += 1;
        record.last_active = now_ms();
        record.recalculate();
    }

    /// Get all reputation records sorted by score (highest first).
    pub fn leaderboard(&self) -> Vec<ReputationRecord> {
        let mut records: Vec<ReputationRecord> = self.records.read().values().cloned().collect();
        records.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        records
    }

    /// Detect potential sybil behavior: multiple nodes from the same IP.
    pub fn detect_sybils(&self) -> Vec<Vec<String>> {
        let records = self.records.read();
        let mut ip_groups: HashMap<&str, Vec<&str>> = HashMap::new();

        for record in records.values() {
            if let Some(ref ip_hash) = record.ip_hash {
                ip_groups
                    .entry(ip_hash.as_str())
                    .or_default()
                    .push(&record.address);
            }
        }

        ip_groups
            .into_values()
            .filter(|group| group.len() > 3)
            .map(|group| group.into_iter().map(String::from).collect())
            .collect()
    }

    /// Number of tracked workers.
    pub fn worker_count(&self) -> usize {
        self.records.read().len()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
