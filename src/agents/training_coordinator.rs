//! TrainingCoordinator Agent — manages federated training rounds.
//!
//! Wraps FederatedCoordinator, manages training rounds, checkpoint
//! save/load via ArobiFS, and gradient aggregation across network peers.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::audit::ledger::{AuditLedger, DecisionSource, DecisionType};
use crate::fs::local_store::ChunkStore;
use crate::p2p::P2p;
use crate::store::Store;

/// Events emitted by the TrainingCoordinator.
#[derive(Debug, Clone)]
pub enum TrainingEvent {
    RoundStarted(String, u64),                 // model_id, round_id
    GradientReceived(String, u64, String),     // model_id, round_id, worker
    GradientQuorumReached(String, u64, usize), // model_id, round_id, worker_count
    RoundCompleted(String, u64, f64),          // model_id, round_id, loss
}

/// Gradient data received from a worker.
#[derive(Debug, Clone)]
struct PendingGradient {
    worker: String,
    gradient_data_b64: String,
    num_samples: u64,
    gradient_hash: String,
}

/// Per-model training state.
struct ModelTrainingState {
    current_round: u64,
    pending_gradients: Vec<PendingGradient>,
    checkpoint_file_id: String,
    min_workers: usize,
}

#[derive(Clone)]
struct TrainingAuditSink {
    ledger: Arc<AuditLedger>,
    store: Arc<Store>,
}

struct TrainingAuditEvent<'a> {
    event: &'a str,
    model_id: &'a str,
    round_id: u64,
    decision: &'a str,
    confidence: f64,
    factors: Vec<String>,
    metadata: HashMap<String, String>,
}

/// TrainingCoordinator agent — manages federated training lifecycle.
pub struct TrainingCoordinatorAgent {
    #[allow(dead_code)]
    chunk_store: Arc<ChunkStore>,
    #[allow(dead_code)]
    p2p: Arc<P2p>,
    #[allow(dead_code)]
    node_address: String,
    running: AtomicBool,
    /// Per-model training state
    models: RwLock<std::collections::HashMap<String, ModelTrainingState>>,
    event_tx: broadcast::Sender<TrainingEvent>,
    audit_sink: Option<TrainingAuditSink>,
}

impl TrainingCoordinatorAgent {
    pub fn new(chunk_store: Arc<ChunkStore>, p2p: Arc<P2p>, node_address: String) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            chunk_store,
            p2p,
            node_address,
            running: AtomicBool::new(false),
            models: RwLock::new(std::collections::HashMap::new()),
            event_tx,
            audit_sink: None,
        }
    }

    pub fn with_audit_sink(
        chunk_store: Arc<ChunkStore>,
        p2p: Arc<P2p>,
        node_address: String,
        audit_ledger: Arc<AuditLedger>,
        store: Arc<Store>,
    ) -> Self {
        let mut agent = Self::new(chunk_store, p2p, node_address);
        agent.audit_sink = Some(TrainingAuditSink {
            ledger: audit_ledger,
            store,
        });
        agent
    }

    /// Start the training coordinator.
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        info!("TrainingCoordinator Agent started");
    }

    /// Stop the training coordinator.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("TrainingCoordinator Agent stopped");
    }

    /// Start a new training round for a model.
    pub fn start_round(&self, model_id: &str, checkpoint_file_id: &str, min_workers: usize) -> u64 {
        let mut models = self.models.write();
        let state = models
            .entry(model_id.to_string())
            .or_insert(ModelTrainingState {
                current_round: 0,
                pending_gradients: Vec::new(),
                checkpoint_file_id: checkpoint_file_id.to_string(),
                min_workers,
            });
        state.current_round += 1;
        state.pending_gradients.clear();
        state.checkpoint_file_id = checkpoint_file_id.to_string();
        let round_id = state.current_round;

        info!("Training round {round_id} started for model {model_id} (min_workers={min_workers})");
        let _ = self
            .event_tx
            .send(TrainingEvent::RoundStarted(model_id.to_string(), round_id));

        self.record_training_audit_event(TrainingAuditEvent {
            event: "round_started",
            model_id,
            round_id,
            decision: "Federated training round started",
            confidence: 1.0,
            factors: vec![
                format!("checkpoint:{checkpoint_file_id}"),
                format!("min_workers:{min_workers}"),
            ],
            metadata: HashMap::from([
                (
                    "checkpoint_file_id".to_string(),
                    checkpoint_file_id.to_string(),
                ),
                ("min_workers".to_string(), min_workers.to_string()),
            ]),
        });

        // Broadcast TrainingRoundStart to peers
        self.p2p
            .broadcast_gossip(crate::p2p::P2pMessage::TrainingRoundStart {
                model_id: model_id.to_string(),
                round_id,
                checkpoint_file_id: checkpoint_file_id.to_string(),
                dataset_shard_ids: Vec::new(),
                learning_rate: 0.001,
                batch_size: 32,
            });

        round_id
    }

    /// Receive a gradient from a worker.
    pub fn receive_gradient(
        &self,
        model_id: &str,
        round_id: u64,
        worker: &str,
        gradient_data_b64: &str,
        num_samples: u64,
        gradient_hash: &str,
    ) {
        let mut models = self.models.write();
        if let Some(state) = models.get_mut(model_id) {
            if state.current_round != round_id {
                info!(
                    "Gradient for round {round_id} but current round is {} — ignoring",
                    state.current_round
                );
                return;
            }

            let pending_before = state.pending_gradients.len();
            state.pending_gradients.push(PendingGradient {
                worker: worker.to_string(),
                gradient_data_b64: gradient_data_b64.to_string(),
                num_samples,
                gradient_hash: gradient_hash.to_string(),
            });

            let _ = self.event_tx.send(TrainingEvent::GradientReceived(
                model_id.to_string(),
                round_id,
                worker.to_string(),
            ));

            self.record_training_audit_event(TrainingAuditEvent {
                event: "gradient_received",
                model_id,
                round_id,
                decision: "Federated training gradient received",
                confidence: 0.95,
                factors: vec![
                    format!("worker:{worker}"),
                    format!("num_samples:{num_samples}"),
                    format!("gradient_hash:{gradient_hash}"),
                ],
                metadata: HashMap::from([
                    ("worker".to_string(), worker.to_string()),
                    ("num_samples".to_string(), num_samples.to_string()),
                    ("gradient_hash".to_string(), gradient_hash.to_string()),
                    (
                        "pending_workers".to_string(),
                        state.pending_gradients.len().to_string(),
                    ),
                    (
                        "required_workers".to_string(),
                        state.min_workers.to_string(),
                    ),
                ]),
            });

            info!(
                "Gradient received from {} for model {model_id} round {round_id} ({}/{} workers)",
                &worker[..12.min(worker.len())],
                state.pending_gradients.len(),
                state.min_workers
            );

            let required_workers = state.min_workers.max(1);
            if pending_before < required_workers
                && state.pending_gradients.len() >= required_workers
            {
                let workers: Vec<String> = state
                    .pending_gradients
                    .iter()
                    .map(|g| g.worker.clone())
                    .collect();
                let gradient_hashes: Vec<String> = state
                    .pending_gradients
                    .iter()
                    .map(|g| g.gradient_hash.clone())
                    .collect();
                let total_samples: u64 =
                    state.pending_gradients.iter().map(|g| g.num_samples).sum();

                info!(
                    "Gradient quorum reached for round {round_id} model {model_id}; aggregation pending ({} workers)",
                    workers.len()
                );

                let _ = self.event_tx.send(TrainingEvent::GradientQuorumReached(
                    model_id.to_string(),
                    round_id,
                    workers.len(),
                ));

                self.record_training_audit_event(TrainingAuditEvent {
                    event: "gradient_quorum_reached",
                    model_id,
                    round_id,
                    decision: "Federated training gradient quorum reached; aggregation pending",
                    confidence: 0.97,
                    factors: vec![
                        format!("participating_workers:{}", workers.len()),
                        format!("required_workers:{required_workers}"),
                        format!("checkpoint:{}", state.checkpoint_file_id),
                    ],
                    metadata: HashMap::from([
                        (
                            "participating_workers_count".to_string(),
                            workers.len().to_string(),
                        ),
                        ("required_workers".to_string(), required_workers.to_string()),
                        ("total_samples".to_string(), total_samples.to_string()),
                        ("gradient_hashes".to_string(), gradient_hashes.join(",")),
                        (
                            "checkpoint_file_id".to_string(),
                            state.checkpoint_file_id.clone(),
                        ),
                        (
                            "aggregation_metric_status".to_string(),
                            "pending_aggregation".to_string(),
                        ),
                    ]),
                });
            }
        }
    }

    /// Complete a round after an external aggregation/checkpoint step produced
    /// real output. Quorum alone is not completion.
    pub fn complete_round_after_aggregation(
        &self,
        model_id: &str,
        round_id: u64,
        new_checkpoint_file_id: &str,
        aggregated_loss: f64,
        aggregation_hash: &str,
        checkpoint_hash: &str,
    ) -> Result<(), String> {
        if new_checkpoint_file_id.trim().is_empty() {
            return Err("new checkpoint file id is required".to_string());
        }
        if aggregation_hash.trim().is_empty() {
            return Err("aggregation hash is required".to_string());
        }
        if checkpoint_hash.trim().is_empty() {
            return Err("checkpoint hash is required".to_string());
        }
        if !aggregated_loss.is_finite() {
            return Err("aggregated loss must be finite".to_string());
        }

        let (
            old_checkpoint_file_id,
            participating_workers,
            worker_count,
            required_workers,
            total_samples,
            gradient_hashes,
        ) = {
            let mut models = self.models.write();
            let Some(state) = models.get_mut(model_id) else {
                return Err(format!("model {model_id} has no active training round"));
            };
            if state.current_round != round_id {
                return Err(format!(
                    "completion for round {round_id} but current round is {}",
                    state.current_round
                ));
            }

            let required_workers = state.min_workers.max(1);
            if state.pending_gradients.len() < required_workers {
                return Err(format!(
                    "completion requires {required_workers} worker gradient(s), found {}",
                    state.pending_gradients.len()
                ));
            }

            let old_checkpoint_file_id = state.checkpoint_file_id.clone();
            let participating_workers: Vec<String> = state
                .pending_gradients
                .iter()
                .map(|g| g.worker.clone())
                .collect();
            let total_samples: u64 = state.pending_gradients.iter().map(|g| g.num_samples).sum();
            let gradient_hashes: Vec<String> = state
                .pending_gradients
                .iter()
                .map(|g| g.gradient_hash.clone())
                .collect();

            state.checkpoint_file_id = new_checkpoint_file_id.to_string();
            state.pending_gradients.clear();

            (
                old_checkpoint_file_id,
                participating_workers,
                gradient_hashes.len(),
                required_workers,
                total_samples,
                gradient_hashes,
            )
        };

        let _ = self.event_tx.send(TrainingEvent::RoundCompleted(
            model_id.to_string(),
            round_id,
            aggregated_loss,
        ));

        self.record_training_audit_event(TrainingAuditEvent {
            event: "round_completed",
            model_id,
            round_id,
            decision: "Federated training round completed with real aggregation output",
            confidence: 0.99,
            factors: vec![
                format!("participating_workers:{worker_count}"),
                format!("required_workers:{required_workers}"),
                format!("new_checkpoint:{new_checkpoint_file_id}"),
                format!("aggregation_hash:{aggregation_hash}"),
                format!("checkpoint_hash:{checkpoint_hash}"),
            ],
            metadata: HashMap::from([
                (
                    "participating_workers_count".to_string(),
                    worker_count.to_string(),
                ),
                ("required_workers".to_string(), required_workers.to_string()),
                ("total_samples".to_string(), total_samples.to_string()),
                ("gradient_hashes".to_string(), gradient_hashes.join(",")),
                ("old_checkpoint_file_id".to_string(), old_checkpoint_file_id),
                (
                    "new_checkpoint_file_id".to_string(),
                    new_checkpoint_file_id.to_string(),
                ),
                ("aggregated_loss".to_string(), aggregated_loss.to_string()),
                ("aggregation_hash".to_string(), aggregation_hash.to_string()),
                ("checkpoint_hash".to_string(), checkpoint_hash.to_string()),
                (
                    "aggregation_metric_status".to_string(),
                    "completed".to_string(),
                ),
            ]),
        });

        self.p2p
            .broadcast_gossip(crate::p2p::P2pMessage::TrainingRoundComplete {
                model_id: model_id.to_string(),
                round_id,
                new_checkpoint_file_id: new_checkpoint_file_id.to_string(),
                aggregated_loss,
                participating_workers,
            });

        Ok(())
    }

    /// Get training status for a model.
    pub fn training_status(&self, model_id: &str) -> Option<serde_json::Value> {
        let models = self.models.read();
        models.get(model_id).map(|state| {
            serde_json::json!({
                "model_id": model_id,
                "current_round": state.current_round,
                "pending_gradients": state.pending_gradients.len(),
                "min_workers": state.min_workers,
                "checkpoint_file_id": state.checkpoint_file_id,
            })
        })
    }

    /// Subscribe to training events.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<TrainingEvent> {
        self.event_tx.subscribe()
    }

    /// Whether the coordinator is running.
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn record_training_audit_event(&self, mut audit_event: TrainingAuditEvent<'_>) {
        let Some(sink) = &self.audit_sink else {
            return;
        };

        audit_event
            .metadata
            .insert("lane".to_string(), "private".to_string());
        audit_event.metadata.insert(
            "source_system".to_string(),
            "training_coordinator".to_string(),
        );
        audit_event
            .metadata
            .insert("event".to_string(), audit_event.event.to_string());
        audit_event
            .metadata
            .insert("round_id".to_string(), audit_event.round_id.to_string());
        audit_event
            .metadata
            .insert("node_address".to_string(), self.node_address.clone());

        let input_summary = format!(
            "Training coordinator {} event for model {} round {}",
            audit_event.event, audit_event.model_id, audit_event.round_id
        );
        let input_data = serde_json::json!({
            "event": audit_event.event,
            "model_id": audit_event.model_id,
            "round_id": audit_event.round_id,
            "node_address": &self.node_address,
        })
        .to_string();

        let entry = sink.ledger.record_decision_with_metadata(
            DecisionSource::External("training_coordinator".to_string()),
            DecisionType::TrainingDecision,
            audit_event.model_id,
            "federated-training-v1",
            &input_summary,
            input_data.as_bytes(),
            audit_event.decision,
            audit_event.confidence,
            "Training lifecycle event recorded for durable LaaS audit and Q corpus evidence.",
            audit_event.factors,
            true,
            vec![
                "arobi-network".to_string(),
                "laas".to_string(),
                "q-training".to_string(),
            ],
            "arobi-network-private-training",
            0.0,
            audit_event.metadata,
        );

        if let Err(err) = sink.store.append_audit_entry(&entry) {
            let rolled_back = sink.ledger.rollback_latest(&entry.entry_id);
            warn!(
                "Failed to durably append training audit entry {} (rolled_back={}): {err}",
                entry.entry_id, rolled_back
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ledger::AuditLedger;
    use crate::block::Block;
    use crate::fs::local_store::ChunkStore;
    use crate::p2p::P2p;
    use crate::store::Store;
    use std::fs;
    use tokio::sync::broadcast;

    fn temp_store_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "arobi-training-audit-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn training_round_events_are_durably_audited_for_q_training() {
        let dir = temp_store_dir("round-lifecycle");
        let store = Arc::new(Store::open(&dir).expect("store should open"));
        let chunk_store =
            Arc::new(ChunkStore::open(&dir, store.db().clone()).expect("chunk store should open"));
        let (block_tx, _) = broadcast::channel::<Block>(16);
        let p2p = P2p::new(block_tx);
        let audit_ledger = Arc::new(AuditLedger::new());
        let coordinator = TrainingCoordinatorAgent::with_audit_sink(
            chunk_store,
            p2p,
            "NODE_PUBLIC".to_string(),
            audit_ledger.clone(),
            store.clone(),
        );

        let round_id = coordinator.start_round("q-main", "checkpoint-001", 1);
        coordinator.receive_gradient(
            "q-main",
            round_id,
            "worker-001",
            "Z3JhZGllbnQ=",
            128,
            "gradient-hash-001",
        );

        let entries = store
            .load_audit_entries()
            .expect("audit entries should reload from durable store");
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|entry| entry.lane.lane_id == "private"));

        let public_export = audit_ledger.export_training_corpus_with_manifest(false);
        assert_eq!(public_export.records.len(), 0);
        assert_eq!(public_export.manifest.private_skipped, 3);

        let internal_export = audit_ledger.export_training_corpus_with_manifest(true);
        assert_eq!(internal_export.records.len(), 3);
        assert!(internal_export.records.iter().all(|record| record
            .metadata
            .get("source_system")
            .map(String::as_str)
            == Some("training_coordinator")));
        assert!(internal_export.records.iter().any(|record| record
            .metadata
            .get("event")
            .map(String::as_str)
            == Some("gradient_quorum_reached")));
        assert!(internal_export.records.iter().all(|record| record
            .metadata
            .get("event")
            .map(String::as_str)
            != Some("round_completed")));
        assert!(internal_export.records.iter().any(|record| record
            .metadata
            .get("aggregation_metric_status")
            .map(String::as_str)
            == Some("pending_aggregation")));

        drop(coordinator);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn gradient_quorum_does_not_emit_completion_without_real_aggregation() {
        let dir = temp_store_dir("quorum-not-complete");
        let store = Arc::new(Store::open(&dir).expect("store should open"));
        let chunk_store =
            Arc::new(ChunkStore::open(&dir, store.db().clone()).expect("chunk store should open"));
        let (block_tx, _) = broadcast::channel::<Block>(16);
        let p2p = P2p::new(block_tx);
        let coordinator =
            TrainingCoordinatorAgent::new(chunk_store, p2p.clone(), "NODE_PUBLIC".to_string());
        let mut events = coordinator.subscribe();
        let mut gossip = p2p.subscribe_gossip();

        let round_id = coordinator.start_round("q-main", "checkpoint-001", 1);
        coordinator.receive_gradient(
            "q-main",
            round_id,
            "worker-001",
            "Z3JhZGllbnQ=",
            128,
            "gradient-hash-001",
        );

        let mut saw_started = false;
        let mut saw_gradient = false;
        let mut saw_quorum = false;
        while let Ok(event) = events.try_recv() {
            match event {
                TrainingEvent::RoundStarted(model_id, event_round_id) => {
                    saw_started = model_id == "q-main" && event_round_id == round_id;
                }
                TrainingEvent::GradientReceived(model_id, event_round_id, worker) => {
                    saw_gradient = model_id == "q-main"
                        && event_round_id == round_id
                        && worker == "worker-001";
                }
                TrainingEvent::GradientQuorumReached(model_id, event_round_id, worker_count) => {
                    saw_quorum =
                        model_id == "q-main" && event_round_id == round_id && worker_count == 1;
                }
                TrainingEvent::RoundCompleted(..) => {
                    panic!("round completion must wait for real aggregation output")
                }
            }
        }
        assert!(saw_started, "round start event should still be emitted");
        assert!(
            saw_gradient,
            "gradient receipt event should still be emitted"
        );
        assert!(
            saw_quorum,
            "quorum event should describe aggregation-pending state"
        );

        let mut saw_round_start_gossip = false;
        while let Ok(message) = gossip.try_recv() {
            match message {
                crate::p2p::P2pMessage::TrainingRoundStart {
                    model_id,
                    round_id: gossip_round_id,
                    ..
                } => {
                    saw_round_start_gossip = model_id == "q-main" && gossip_round_id == round_id;
                }
                crate::p2p::P2pMessage::TrainingRoundComplete { .. } => {
                    panic!("completion gossip must wait for real aggregation output")
                }
                _ => {}
            }
        }
        assert!(
            saw_round_start_gossip,
            "round start gossip should still be broadcast"
        );

        drop(coordinator);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn completion_requires_real_aggregation_output() {
        let dir = temp_store_dir("completion-output");
        let store = Arc::new(Store::open(&dir).expect("store should open"));
        let chunk_store =
            Arc::new(ChunkStore::open(&dir, store.db().clone()).expect("chunk store should open"));
        let (block_tx, _) = broadcast::channel::<Block>(16);
        let p2p = P2p::new(block_tx);
        let audit_ledger = Arc::new(AuditLedger::new());
        let coordinator = TrainingCoordinatorAgent::with_audit_sink(
            chunk_store,
            p2p.clone(),
            "NODE_PUBLIC".to_string(),
            audit_ledger.clone(),
            store.clone(),
        );
        let mut events = coordinator.subscribe();
        let mut gossip = p2p.subscribe_gossip();

        let round_id = coordinator.start_round("q-main", "checkpoint-001", 1);
        coordinator.receive_gradient(
            "q-main",
            round_id,
            "worker-001",
            "Z3JhZGllbnQ=",
            128,
            "gradient-hash-001",
        );
        coordinator
            .complete_round_after_aggregation(
                "q-main",
                round_id,
                "checkpoint-002",
                0.123,
                "aggregation-hash-001",
                "checkpoint-hash-002",
            )
            .expect("real aggregation output should complete the round");

        let mut saw_completed = false;
        while let Ok(event) = events.try_recv() {
            if let TrainingEvent::RoundCompleted(model_id, event_round_id, loss) = event {
                saw_completed = model_id == "q-main"
                    && event_round_id == round_id
                    && (loss - 0.123).abs() < f64::EPSILON;
            }
        }
        assert!(
            saw_completed,
            "completion event should be emitted only after real aggregation output"
        );

        let mut saw_completion_gossip = false;
        while let Ok(message) = gossip.try_recv() {
            if let crate::p2p::P2pMessage::TrainingRoundComplete {
                model_id,
                round_id: gossip_round_id,
                new_checkpoint_file_id,
                aggregated_loss,
                participating_workers,
            } = message
            {
                saw_completion_gossip = model_id == "q-main"
                    && gossip_round_id == round_id
                    && new_checkpoint_file_id == "checkpoint-002"
                    && (aggregated_loss - 0.123).abs() < f64::EPSILON
                    && participating_workers == vec!["worker-001".to_string()];
            }
        }
        assert!(
            saw_completion_gossip,
            "completion gossip should carry the real checkpoint and worker list"
        );

        let status = coordinator
            .training_status("q-main")
            .expect("status should remain visible");
        assert_eq!(status["checkpoint_file_id"], "checkpoint-002");
        assert_eq!(status["pending_gradients"], 0);

        let entries = store
            .load_audit_entries()
            .expect("audit entries should reload from durable store");
        assert_eq!(entries.len(), 4);

        let internal_export = audit_ledger.export_training_corpus_with_manifest(true);
        let completion = internal_export
            .records
            .iter()
            .find(|record| {
                record.metadata.get("event").map(String::as_str) == Some("round_completed")
            })
            .expect("completion audit record should exist");
        assert_eq!(
            completion
                .metadata
                .get("aggregation_metric_status")
                .map(String::as_str),
            Some("completed")
        );
        assert_eq!(
            completion
                .metadata
                .get("new_checkpoint_file_id")
                .map(String::as_str),
            Some("checkpoint-002")
        );
        assert_eq!(
            completion
                .metadata
                .get("aggregation_hash")
                .map(String::as_str),
            Some("aggregation-hash-001")
        );
        assert_eq!(
            completion
                .metadata
                .get("checkpoint_hash")
                .map(String::as_str),
            Some("checkpoint-hash-002")
        );

        drop(coordinator);
        drop(store);
        let _ = fs::remove_dir_all(dir);
    }
}
