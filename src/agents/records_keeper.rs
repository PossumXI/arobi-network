//! Records Keeper Agent
//!
//! Autonomous agent for transaction validation, anomaly detection,
//! and blockchain record keeping. Adapted from the apex-os-project
//! RecordsKeeperAgent, using arobi-network's native types and sled storage.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tokio::time::{interval, Duration};

use crate::block::Transaction;
use crate::store::Store;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordsKeeperConfig {
    pub enabled: bool,
    pub validation_threads: usize,
    pub batch_size: usize,
    pub max_pending_records: usize,
    pub validation_interval_secs: u64,
    pub persistence_interval_secs: u64,
    /// Flag transactions above this amount (in base units)
    pub unusual_amount_threshold: u64,
    /// Flag addresses with more than this many txs per minute
    pub high_frequency_threshold: usize,
}

impl Default for RecordsKeeperConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validation_threads: 4,
            batch_size: 100,
            max_pending_records: 10_000,
            validation_interval_secs: 5,
            persistence_interval_secs: 30,
            unusual_amount_threshold: 100_000_000_000, // 1000 AURA
            high_frequency_threshold: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub tx_id: String,
    pub transaction: Transaction,
    pub validation_status: ValidationStatus,
    pub processed_at: DateTime<Utc>,
    pub intelligence_score: f64,
    pub anomaly_flags: Vec<AnomalyFlag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationStatus {
    Pending,
    Valid,
    Invalid(String),
    Suspicious(String),
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyFlag {
    pub flag_type: AnomalyType,
    pub severity: f64,
    pub description: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    UnusualAmount,
    HighFrequency,
    SuspiciousPattern,
    UnknownAddress,
    IntelligenceThreshold,
    NetworkAnomaly,
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RecordsEvent {
    RecordProcessed(String),
    AnomalyDetected(AnomalyFlag),
    ValidationComplete(String, ValidationStatus),
}

// ---------------------------------------------------------------------------
// Agent statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStats {
    pub processed_count: u64,
    pub pending_count: usize,
    pub validated_count: usize,
    pub anomaly_count: u64,
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Records Keeper Agent
// ---------------------------------------------------------------------------

pub struct RecordsKeeperAgent {
    config: RecordsKeeperConfig,
    store: Arc<Store>,
    active: Arc<AtomicBool>,
    processed_count: Arc<AtomicU64>,
    anomaly_count: Arc<AtomicU64>,

    /// Pending records awaiting processing
    pending_records: Arc<RwLock<HashMap<String, TransactionRecord>>>,
    /// Completed records (ring buffer, most recent first)
    validated_records: Arc<RwLock<VecDeque<TransactionRecord>>>,
    /// Per-address activity tracker: address → list of timestamps (ms)
    address_activity: Arc<DashMap<String, Vec<u64>>>,

    event_tx: broadcast::Sender<RecordsEvent>,
}

impl RecordsKeeperAgent {
    /// Create a new Records Keeper Agent.
    pub fn new(store: Arc<Store>, config: RecordsKeeperConfig) -> Self {
        let (event_tx, _) = broadcast::channel(1024);

        Self {
            config,
            store,
            active: Arc::new(AtomicBool::new(false)),
            processed_count: Arc::new(AtomicU64::new(0)),
            anomaly_count: Arc::new(AtomicU64::new(0)),
            pending_records: Arc::new(RwLock::new(HashMap::new())),
            validated_records: Arc::new(RwLock::new(VecDeque::new())),
            address_activity: Arc::new(DashMap::new()),
            event_tx,
        }
    }

    /// Start background processing workers.
    pub fn start(&self) {
        if self.active.load(Ordering::Relaxed) {
            return;
        }
        self.active.store(true, Ordering::Relaxed);

        // Validation worker
        {
            let agent = self.clone_refs();
            tokio::spawn(async move {
                agent.validation_worker().await;
            });
        }

        // Persistence worker
        {
            let agent = self.clone_refs();
            tokio::spawn(async move {
                agent.persistence_worker().await;
            });
        }

        // Activity cleanup worker
        {
            let active = self.active.clone();
            let activity = self.address_activity.clone();
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(60));
                while active.load(Ordering::Relaxed) {
                    ticker.tick().await;
                    let cutoff = now_ms().saturating_sub(120_000); // 2 min window
                    activity.retain(|_, timestamps| {
                        timestamps.retain(|&ts| ts > cutoff);
                        !timestamps.is_empty()
                    });
                }
            });
        }
    }

    /// Submit a transaction for processing by the Records Keeper.
    #[allow(dead_code)]
    pub async fn process_transaction(&self, tx: Transaction) {
        let record = TransactionRecord {
            tx_id: tx.id.clone(),
            transaction: tx,
            validation_status: ValidationStatus::Pending,
            processed_at: Utc::now(),
            intelligence_score: 0.0,
            anomaly_flags: Vec::new(),
        };

        let mut pending = self.pending_records.write().await;
        if pending.len() < self.config.max_pending_records {
            pending.insert(record.tx_id.clone(), record);
        }
    }

    /// Get current agent statistics.
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> AgentStats {
        AgentStats {
            processed_count: self.processed_count.load(Ordering::Relaxed),
            pending_count: self.pending_records.read().await.len(),
            validated_count: self.validated_records.read().await.len(),
            anomaly_count: self.anomaly_count.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
        }
    }

    /// Subscribe to records events.
    pub fn subscribe(&self) -> broadcast::Receiver<RecordsEvent> {
        self.event_tx.subscribe()
    }

    /// Gracefully stop the agent.
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        self.active.store(false, Ordering::Relaxed);
        tracing::info!("Records Keeper Agent shutdown");
    }

    // ── Internal workers ────────────────────────────────────────────────────

    async fn validation_worker(&self) {
        let mut ticker = interval(Duration::from_secs(self.config.validation_interval_secs));

        while self.active.load(Ordering::Relaxed) {
            ticker.tick().await;

            // Collect pending record IDs
            let pending_ids: Vec<String> = {
                let pending = self.pending_records.read().await;
                pending
                    .iter()
                    .filter(|(_, r)| matches!(r.validation_status, ValidationStatus::Pending))
                    .take(self.config.batch_size)
                    .map(|(id, _)| id.clone())
                    .collect()
            };

            for tx_id in pending_ids {
                let record = {
                    let pending = self.pending_records.read().await;
                    pending.get(&tx_id).cloned()
                };

                if let Some(record) = record {
                    let (status, flags, score) =
                        self.evaluate_transaction(&record.transaction).await;

                    // Update the record
                    {
                        let mut pending = self.pending_records.write().await;
                        if let Some(r) = pending.get_mut(&tx_id) {
                            r.validation_status = status.clone();
                            r.anomaly_flags = flags.clone();
                            r.intelligence_score = score;
                        }
                    }

                    // Move to validated if no longer pending
                    if !matches!(status, ValidationStatus::Pending) {
                        if let Some(record) = self.pending_records.write().await.remove(&tx_id) {
                            let mut validated = self.validated_records.write().await;
                            validated.push_front(record);
                            // Keep ring buffer bounded
                            while validated.len() > 10_000 {
                                validated.pop_back();
                            }
                        }
                        self.processed_count.fetch_add(1, Ordering::Relaxed);

                        let _ = self
                            .event_tx
                            .send(RecordsEvent::RecordProcessed(tx_id.clone()));
                        let _ = self
                            .event_tx
                            .send(RecordsEvent::ValidationComplete(tx_id, status));

                        for flag in flags {
                            self.anomaly_count.fetch_add(1, Ordering::Relaxed);
                            let _ = self.event_tx.send(RecordsEvent::AnomalyDetected(flag));
                        }
                    }
                }
            }
        }
    }

    async fn persistence_worker(&self) {
        let mut ticker = interval(Duration::from_secs(self.config.persistence_interval_secs));

        while self.active.load(Ordering::Relaxed) {
            ticker.tick().await;

            // Persist validated records to sled
            let records_to_persist: Vec<TransactionRecord> = {
                let validated = self.validated_records.read().await;
                validated
                    .iter()
                    .take(self.config.batch_size)
                    .cloned()
                    .collect()
            };

            if records_to_persist.is_empty() {
                continue;
            }

            let db = self.store.db();
            let tree = match db.open_tree("agent_records") {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("Failed to open agent_records tree: {e}");
                    continue;
                }
            };

            for record in &records_to_persist {
                if let Ok(data) = serde_json::to_vec(record) {
                    let _ = tree.insert(record.tx_id.as_bytes(), data);
                }
            }

            if let Err(e) = tree.flush() {
                tracing::error!("Failed to flush agent_records: {e}");
            } else {
                tracing::debug!("Persisted {} agent records", records_to_persist.len());
            }
        }
    }

    // ── Evaluation logic ────────────────────────────────────────────────────

    /// Evaluate a transaction: validate + detect anomalies + score.
    async fn evaluate_transaction(
        &self,
        tx: &Transaction,
    ) -> (ValidationStatus, Vec<AnomalyFlag>, f64) {
        // Basic validation
        let status = match tx.validate_basic() {
            Ok(()) => ValidationStatus::Valid,
            Err(e) => ValidationStatus::Invalid(e.to_string()),
        };

        // Detect anomalies (even if basic validation fails, for monitoring)
        let flags = self.detect_anomalies(tx).await;

        // Quarantine if too many anomalies
        let status = if flags.iter().any(|f| f.severity >= 0.9) {
            ValidationStatus::Quarantined
        } else if !flags.is_empty() {
            match &status {
                ValidationStatus::Valid => ValidationStatus::Suspicious(format!(
                    "{} anomaly flag(s) detected",
                    flags.len()
                )),
                other => other.clone(),
            }
        } else {
            status
        };

        // Calculate intelligence score
        let score = self.calculate_score(tx, &flags);

        (status, flags, score)
    }

    /// Detect anomalies in a transaction.
    async fn detect_anomalies(&self, tx: &Transaction) -> Vec<AnomalyFlag> {
        let mut flags = Vec::new();
        let now = Utc::now();
        let now_ms_val = now_ms();

        // 1. Unusual amount
        if tx.amount > self.config.unusual_amount_threshold {
            flags.push(AnomalyFlag {
                flag_type: AnomalyType::UnusualAmount,
                severity: 0.7,
                description: format!(
                    "Large transfer: {} base units ({:.4} AURA)",
                    tx.amount,
                    tx.amount as f64 / 100_000_000.0
                ),
                detected_at: now,
            });
        }

        // 2. High frequency
        if tx.from != "GENESIS" {
            // Record this transaction
            self.address_activity
                .entry(tx.from.clone())
                .or_default()
                .push(now_ms_val);

            // Count recent txs from this address
            let cutoff = now_ms_val.saturating_sub(60_000); // 1 min
            let recent_count = self
                .address_activity
                .get(&tx.from)
                .map(|ts| ts.iter().filter(|&&t| t > cutoff).count())
                .unwrap_or(0);

            if recent_count > self.config.high_frequency_threshold {
                flags.push(AnomalyFlag {
                    flag_type: AnomalyType::HighFrequency,
                    severity: 0.6,
                    description: format!(
                        "High frequency: {} txs from {} in 1 minute",
                        recent_count,
                        &tx.from[..12.min(tx.from.len())]
                    ),
                    detected_at: now,
                });
            }
        }

        // 3. Suspicious pattern: self-referencing data
        if tx.from == "GENESIS" && tx.fee > 0 {
            flags.push(AnomalyFlag {
                flag_type: AnomalyType::SuspiciousPattern,
                severity: 0.8,
                description: "Genesis tx with non-zero fee".into(),
                detected_at: now,
            });
        }

        // 4. Unknown address check (very short addresses)
        if tx.to.len() < 5 && tx.to != "GENESIS" {
            flags.push(AnomalyFlag {
                flag_type: AnomalyType::UnknownAddress,
                severity: 0.5,
                description: format!("Suspiciously short recipient address: {}", tx.to),
                detected_at: now,
            });
        }

        // 5. Zero-fee check (below minimum)
        if tx.from != "GENESIS" && tx.fee == 0 {
            flags.push(AnomalyFlag {
                flag_type: AnomalyType::SuspiciousPattern,
                severity: 0.9,
                description: "Zero fee transaction from non-genesis address".into(),
                detected_at: now,
            });
        }

        flags
    }

    /// Calculate an intelligence score for the transaction.
    fn calculate_score(&self, tx: &Transaction, flags: &[AnomalyFlag]) -> f64 {
        let mut score = 100.0;

        // Deduct for anomalies
        for flag in flags {
            score -= flag.severity * 20.0;
        }

        // Bonus for generous fees
        if tx.fee > 2000 {
            score += 5.0;
        }

        // Penalty for very large data payloads
        if let Some(ref data) = tx.data {
            if data.len() > 256 {
                score -= 5.0;
            }
        }

        score.clamp(0.0, 100.0)
    }

    /// Clone shared references for spawning async tasks.
    fn clone_refs(&self) -> Self {
        Self {
            config: self.config.clone(),
            store: self.store.clone(),
            active: self.active.clone(),
            processed_count: self.processed_count.clone(),
            anomaly_count: self.anomaly_count.clone(),
            pending_records: self.pending_records.clone(),
            validated_records: self.validated_records.clone(),
            address_activity: self.address_activity.clone(),
            event_tx: self.event_tx.clone(),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
