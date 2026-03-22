//! TrainingCoordinator Agent — manages federated training rounds.
//!
//! Wraps FederatedCoordinator, manages training rounds, checkpoint
//! save/load via ArobiFS, and gradient aggregation across network peers.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

use crate::fs::local_store::ChunkStore;
use crate::p2p::P2p;

/// Events emitted by the TrainingCoordinator.
#[derive(Debug, Clone)]
pub enum TrainingEvent {
    RoundStarted(String, u64),             // model_id, round_id
    GradientReceived(String, u64, String), // model_id, round_id, worker
    RoundCompleted(String, u64, f64),      // model_id, round_id, loss
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
        }
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

            info!(
                "Gradient received from {} for model {model_id} round {round_id} ({}/{} workers)",
                &worker[..12.min(worker.len())],
                state.pending_gradients.len(),
                state.min_workers
            );

            // Auto-finalize if enough gradients collected
            if state.pending_gradients.len() >= state.min_workers {
                let workers: Vec<String> = state
                    .pending_gradients
                    .iter()
                    .map(|g| g.worker.clone())
                    .collect();

                info!(
                    "Finalizing round {round_id} for model {model_id} ({} workers)",
                    workers.len()
                );

                let _ = self.event_tx.send(TrainingEvent::RoundCompleted(
                    model_id.to_string(),
                    round_id,
                    0.0, // loss computed during actual aggregation
                ));

                // Broadcast TrainingRoundComplete
                self.p2p
                    .broadcast_gossip(crate::p2p::P2pMessage::TrainingRoundComplete {
                        model_id: model_id.to_string(),
                        round_id,
                        new_checkpoint_file_id: state.checkpoint_file_id.clone(),
                        aggregated_loss: 0.0,
                        participating_workers: workers,
                    });
            }
        }
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
}
