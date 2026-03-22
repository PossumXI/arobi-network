//! InferenceRouter Agent — routes inference requests through the pipeline.
//!
//! Maintains a live routing table, queues incoming requests, dispatches
//! them through the correct pipeline stages, and handles failover.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

use crate::llm::registry::ModelRegistry;
use crate::llm::types as llm_types;

/// Events emitted by the InferenceRouter.
#[derive(Debug, Clone)]
pub enum InferenceEvent {
    RequestQueued(String),
    RequestCompleted(String),
    RequestFailed(String, String),
    ModelRegistered(String),
    StageReady(String, u32),
}

/// Configuration for the InferenceRouter agent.
#[derive(Debug, Clone)]
pub struct InferenceRouterConfig {
    /// Maximum concurrent inference requests
    pub max_concurrent: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Heartbeat check interval in seconds
    pub heartbeat_interval_secs: u64,
}

impl Default for InferenceRouterConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 16,
            request_timeout_secs: 120,
            heartbeat_interval_secs: 30,
        }
    }
}

/// InferenceRouter agent — manages LLM inference lifecycle.
pub struct InferenceRouterAgent {
    registry: Arc<ModelRegistry>,
    config: InferenceRouterConfig,
    running: Arc<AtomicBool>,
    event_tx: broadcast::Sender<InferenceEvent>,
}

impl InferenceRouterAgent {
    pub fn new(registry: Arc<ModelRegistry>, config: InferenceRouterConfig) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            registry,
            config,
            running: Arc::new(AtomicBool::new(false)),
            event_tx,
        }
    }

    /// Start the inference router background tasks.
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }
        info!(
            "InferenceRouter Agent started (max_concurrent={}, timeout={}s)",
            self.config.max_concurrent, self.config.request_timeout_secs
        );

        // Heartbeat monitor: check stage health periodically
        let running = self.running.clone();
        let registry = self.registry.clone();
        let interval = self.config.heartbeat_interval_secs;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
            while running.load(Ordering::Relaxed) {
                ticker.tick().await;
                let models = registry.list_models();
                let ready = registry.ready_model_count();
                if !models.is_empty() {
                    info!(
                        "InferenceRouter: {}/{} models fully served, {} total stages",
                        ready,
                        models.len(),
                        registry.stage_count()
                    );
                }
            }
        });
    }

    /// Stop the inference router.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("InferenceRouter Agent stopped");
    }

    /// Subscribe to inference events.
    #[allow(dead_code)]
    pub fn subscribe(&self) -> broadcast::Receiver<InferenceEvent> {
        self.event_tx.subscribe()
    }

    /// Submit an inference request.
    pub fn submit_request(&self, request: &llm_types::InferenceRequest) -> Result<(), String> {
        if !self.running.load(Ordering::Relaxed) {
            return Err("InferenceRouter is not running".to_string());
        }

        // Verify model exists and is ready
        let model = self
            .registry
            .get_model(&request.model_id)
            .ok_or_else(|| format!("Model {} not found", request.model_id))?;

        if !self.registry.is_model_ready(&request.model_id) {
            return Err(format!(
                "Model {} is not fully served (status: {:?})",
                request.model_id, model.status
            ));
        }

        let _ = self
            .event_tx
            .send(InferenceEvent::RequestQueued(request.request_id.clone()));
        Ok(())
    }

    /// Get the model registry.
    pub fn registry(&self) -> &Arc<ModelRegistry> {
        &self.registry
    }

    /// Whether the router is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
