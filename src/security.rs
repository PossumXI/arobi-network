//! Security Monitor
//!
//! Lightweight security status aggregator for the Arobi Network node.
//! Collects anomaly reports from the Records Keeper and threat intelligence
//! from the Firecrawler to provide an overall security assessment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::agents::records_keeper::AnomalyFlag;

const MAX_RECENT: usize = 500;

// ---------------------------------------------------------------------------
// Security status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Green,
    Yellow,
    Red,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatus {
    pub level: SecurityLevel,
    pub recent_anomaly_count: usize,
    pub high_severity_count: usize,
    pub last_check: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Security Monitor
// ---------------------------------------------------------------------------

pub struct SecurityMonitor {
    recent_anomalies: Arc<RwLock<VecDeque<AnomalyFlag>>>,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        Self {
            recent_anomalies: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Report an anomaly detected by the Records Keeper.
    pub async fn report_anomaly(&self, anomaly: AnomalyFlag) {
        let mut anomalies = self.recent_anomalies.write().await;
        anomalies.push_front(anomaly);
        while anomalies.len() > MAX_RECENT {
            anomalies.pop_back();
        }
    }

    /// Get the most recent anomalies.
    pub async fn recent_anomalies(&self, limit: usize) -> Vec<AnomalyFlag> {
        let anomalies = self.recent_anomalies.read().await;
        anomalies.iter().take(limit).cloned().collect()
    }

    /// Compute the current security status.
    pub async fn status(&self) -> SecurityStatus {
        let anomalies = self.recent_anomalies.read().await;

        let high_severity_count = anomalies.iter().filter(|a| a.severity >= 0.8).count();

        let level = if high_severity_count >= 5 {
            SecurityLevel::Red
        } else if anomalies.len() >= 10 || high_severity_count >= 2 {
            SecurityLevel::Yellow
        } else {
            SecurityLevel::Green
        };

        SecurityStatus {
            level,
            recent_anomaly_count: anomalies.len(),
            high_severity_count,
            last_check: Utc::now(),
        }
    }
}
