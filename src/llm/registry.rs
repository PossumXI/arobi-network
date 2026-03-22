//! Model Registry — on-chain model registration, discovery, and stage tracking.
//!
//! Models are registered with their ArobiFS weight file IDs. Nodes can claim
//! pipeline stages and advertise readiness. The registry maintains a live
//! view of which models are available and which nodes serve them.

use dashmap::DashMap;
use std::sync::Arc;
use tracing::info;

use super::types::{ModelRegistryEntry, ModelStatus, StageAssignment, StageHeartbeat};

/// In-memory model registry backed by sled for persistence.
pub struct ModelRegistry {
    /// model_id -> ModelRegistryEntry
    models: Arc<DashMap<String, ModelRegistryEntry>>,
    /// "model_id:stage_index" -> StageAssignment
    stages: Arc<DashMap<String, StageAssignment>>,
    /// "model_id:stage_index" -> latest StageHeartbeat
    heartbeats: Arc<DashMap<String, StageHeartbeat>>,
}

impl ModelRegistry {
    pub fn new() -> Self {
        Self {
            models: Arc::new(DashMap::new()),
            stages: Arc::new(DashMap::new()),
            heartbeats: Arc::new(DashMap::new()),
        }
    }

    /// Register a new model on the network.
    pub fn register_model(&self, entry: ModelRegistryEntry) -> Result<(), String> {
        if entry.model_id.is_empty() {
            return Err("model_id cannot be empty".to_string());
        }
        if entry.stage_weight_file_ids.len() != entry.config.pipeline_stages {
            return Err(format!(
                "stage_weight_file_ids count ({}) does not match pipeline_stages ({})",
                entry.stage_weight_file_ids.len(),
                entry.config.pipeline_stages
            ));
        }
        info!(
            "Model registered: {} ({} stages, ~{} bytes)",
            entry.config.name,
            entry.config.pipeline_stages,
            entry.config.estimated_size_bytes()
        );
        self.models.insert(entry.model_id.clone(), entry);
        Ok(())
    }

    /// Get a model record by ID.
    pub fn get_model(&self, model_id: &str) -> Option<ModelRegistryEntry> {
        self.models.get(model_id).map(|r| r.clone())
    }

    /// List all registered models.
    pub fn list_models(&self) -> Vec<ModelRegistryEntry> {
        self.models.iter().map(|r| r.value().clone()).collect()
    }

    /// Claim a pipeline stage for a model.
    pub fn claim_stage(&self, assignment: StageAssignment) -> Result<(), String> {
        let model = self
            .models
            .get(&assignment.model_id)
            .ok_or_else(|| format!("Model {} not found", assignment.model_id))?;

        if assignment.stage_index as usize >= model.config.pipeline_stages {
            return Err(format!(
                "Stage index {} out of range (model has {} stages)",
                assignment.stage_index, model.config.pipeline_stages
            ));
        }

        let key = format!("{}:{}", assignment.model_id, assignment.stage_index);
        info!(
            "Stage claimed: model={} stage={} node={}",
            assignment.model_id, assignment.stage_index, assignment.node_address
        );
        self.stages.insert(key, assignment);

        // Update model status
        self.update_model_status(&model.model_id);
        Ok(())
    }

    /// Get all stage assignments for a model.
    pub fn get_stages(&self, model_id: &str) -> Vec<StageAssignment> {
        self.stages
            .iter()
            .filter(|r| r.value().model_id == model_id)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Check if all stages for a model have ready nodes.
    pub fn is_model_ready(&self, model_id: &str) -> bool {
        let model = match self.models.get(model_id) {
            Some(m) => m,
            None => return false,
        };

        for i in 0..model.config.pipeline_stages {
            let key = format!("{model_id}:{i}");
            match self.stages.get(&key) {
                Some(s) if s.loaded => {}
                _ => return false,
            }
        }
        true
    }

    /// Get the ordered pipeline route: list of (stage_index, node_address) for a model.
    pub fn get_pipeline_route(&self, model_id: &str) -> Result<Vec<(u32, String)>, String> {
        let model = self
            .models
            .get(model_id)
            .ok_or_else(|| format!("Model {model_id} not found"))?;

        let mut route = Vec::with_capacity(model.config.pipeline_stages);
        for i in 0..model.config.pipeline_stages {
            let key = format!("{model_id}:{i}");
            let assignment = self
                .stages
                .get(&key)
                .ok_or_else(|| format!("Stage {i} not assigned for model {model_id}"))?;
            if !assignment.loaded {
                return Err(format!(
                    "Stage {i} node {} not ready",
                    assignment.node_address
                ));
            }
            route.push((i as u32, assignment.node_address.clone()));
        }
        Ok(route)
    }

    /// Record a heartbeat from a stage node.
    pub fn record_heartbeat(&self, heartbeat: StageHeartbeat) {
        let key = format!("{}:{}", heartbeat.model_id, heartbeat.stage_index);
        // Update the loaded status on the assignment
        if let Some(mut assignment) = self.stages.get_mut(&key) {
            assignment.loaded = heartbeat.loaded;
            assignment.last_heartbeat = heartbeat.timestamp;
        }
        self.heartbeats.insert(key, heartbeat);
    }

    /// Mark a stage as loaded and ready.
    pub fn mark_stage_ready(&self, model_id: &str, stage_index: u32) {
        let key = format!("{model_id}:{stage_index}");
        if let Some(mut s) = self.stages.get_mut(&key) {
            s.loaded = true;
            info!("Stage {stage_index} for model {model_id} is READY");
        }
        self.update_model_status(model_id);
    }

    /// Update the model's serving status based on current stage assignments.
    fn update_model_status(&self, model_id: &str) {
        if let Some(mut model) = self.models.get_mut(model_id) {
            let total = model.config.pipeline_stages;
            let assigned = (0..total)
                .filter(|i| {
                    let key = format!("{model_id}:{i}");
                    self.stages.contains_key(&key)
                })
                .count();
            let ready = (0..total)
                .filter(|i| {
                    let key = format!("{model_id}:{i}");
                    self.stages.get(&key).map(|s| s.loaded).unwrap_or(false)
                })
                .count();

            model.status = if ready == total {
                ModelStatus::FullyServed
            } else if assigned > 0 {
                ModelStatus::PartiallyServed
            } else {
                ModelStatus::Registered
            };
        }
    }

    /// Count of registered models.
    pub fn model_count(&self) -> usize {
        self.models.len()
    }

    /// Count of active stage assignments.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Count of models that are fully online (all stages ready).
    pub fn ready_model_count(&self) -> usize {
        self.models
            .iter()
            .filter(|r| self.is_model_ready(&r.model_id))
            .count()
    }
}
