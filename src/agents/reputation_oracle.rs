//! ReputationOracle Agent — tracks worker performance and detects sybils.
//!
//! Wraps the ReputationOracle from the compute module and adds
//! agent lifecycle management and event broadcasting.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

use crate::compute::reputation::ReputationOracle;

/// Events emitted by the ReputationOracle agent.
#[derive(Debug, Clone)]
pub enum ReputationEvent {
    ScoreUpdated(String, f64),
    SybilDetected(Vec<String>),
}

/// ReputationOracle agent — manages reputation scoring and sybil detection.
pub struct ReputationOracleAgent {
    oracle: Arc<ReputationOracle>,
    running: AtomicBool,
    event_tx: broadcast::Sender<ReputationEvent>,
}

impl ReputationOracleAgent {
    pub fn new(oracle: Arc<ReputationOracle>) -> Self {
        let (event_tx, _) = broadcast::channel(128);
        Self {
            oracle,
            running: AtomicBool::new(false),
            event_tx,
        }
    }

    /// Start the agent background tasks.
    pub fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        info!("ReputationOracle Agent started");
    }

    /// Stop the agent.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("ReputationOracle Agent stopped");
    }

    /// Get a reference to the underlying oracle.
    pub fn oracle(&self) -> &Arc<ReputationOracle> {
        &self.oracle
    }

    /// Subscribe to reputation events.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<ReputationEvent> {
        self.event_tx.subscribe()
    }

    /// Run a sybil detection scan and broadcast any findings.
    #[allow(dead_code)]
    pub fn scan_sybils(&self) -> Vec<Vec<String>> {
        let sybils = self.oracle.detect_sybils();
        for group in &sybils {
            let _ = self
                .event_tx
                .send(ReputationEvent::SybilDetected(group.clone()));
        }
        sybils
    }

    /// Get the leaderboard.
    #[allow(dead_code)]
    pub fn leaderboard(&self) -> Vec<crate::compute::reputation::ReputationRecord> {
        self.oracle.leaderboard()
    }

    /// Get worker count.
    #[allow(dead_code)]
    pub fn worker_count(&self) -> usize {
        self.oracle.worker_count()
    }

    /// Whether the agent is running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
