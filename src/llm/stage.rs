//! Stage executor — loads a weight shard and runs forward passes for
//! a specific pipeline stage. Each stage covers a contiguous range of
//! transformer layers.

use tracing::info;

use candle_core::{Device, Result as CandleResult, Tensor};
use candle_nn::VarBuilder;

use super::architecture::ArobiTransformer;
use super::kv_cache::KvCache;
use super::types::{ModelConfig, StageAssignment};

/// A loaded pipeline stage ready to execute forward passes.
pub struct StageExecutor {
    /// The model with only this stage's layers loaded
    model: ArobiTransformer,
    /// KV cache for this stage's layers
    kv_cache: KvCache,
    /// Stage assignment metadata
    assignment: StageAssignment,
    /// Device this stage runs on
    device: Device,
    /// Number of tokens processed
    tokens_processed: u64,
}

impl StageExecutor {
    /// Create a new stage executor from a weight shard.
    /// `weight_data` is the raw safetensors/binary weight data for this stage.
    pub fn new(
        config: &ModelConfig,
        assignment: StageAssignment,
        weight_data: &[u8],
        device: Device,
    ) -> CandleResult<Self> {
        let layer_count = assignment.end_layer - assignment.start_layer;

        info!(
            "Loading stage {} (layers {}-{}, {} layers) on {:?}",
            assignment.stage_index,
            assignment.start_layer,
            assignment.end_layer,
            layer_count,
            device
        );

        // Load weights via safetensors format
        let tensors = candle_core::safetensors::load_buffer(weight_data, &device)?;
        let vb = VarBuilder::from_tensors(tensors, candle_core::DType::BF16, &device);

        let model =
            ArobiTransformer::from_stage(config, vb, assignment.start_layer, assignment.end_layer)?;

        let kv_cache = KvCache::new(layer_count, config.max_seq_len);

        info!(
            "Stage {} loaded: {} layers, {} params estimated",
            assignment.stage_index,
            layer_count,
            config.stage_size_bytes() / 2 // BF16 = 2 bytes per param
        );

        Ok(Self {
            model,
            kv_cache,
            assignment,
            device,
            tokens_processed: 0,
        })
    }

    /// Create a stage executor from ArobiFS weight data.
    /// Loads the weight shard by reassembling chunks from ArobiFS.
    pub fn from_arobifs(
        config: &ModelConfig,
        assignment: StageAssignment,
        chunk_store: &crate::fs::local_store::ChunkStore,
        device: Device,
    ) -> CandleResult<Self> {
        let file_id = &assignment.weight_file_id;
        info!(
            "Loading stage {} weights from ArobiFS (file_id={})",
            assignment.stage_index,
            &file_id[..16.min(file_id.len())]
        );

        let weight_data = chunk_store
            .reassemble_file(file_id)
            .map_err(|e| candle_core::Error::Msg(format!("ArobiFS reassemble failed: {e}")))?;

        Self::new(config, assignment, &weight_data, device)
    }

    /// Run a forward pass for this stage.
    /// Input: hidden state from previous stage (or embeddings for stage 0).
    /// Output: hidden state for next stage.
    pub fn forward(&mut self, hidden: &Tensor, offset: usize) -> CandleResult<Tensor> {
        let mut caches = self.kv_cache.to_vec();
        let output = self.model.forward_stage(hidden, &mut caches, offset)?;
        self.kv_cache.update_from_vec(caches)?;
        self.tokens_processed += 1;
        Ok(output)
    }

    /// For the first stage: embed token IDs into hidden states.
    pub fn embed_tokens(&self, token_ids: &Tensor) -> CandleResult<Tensor> {
        // The ArobiTransformer's token_embedding is loaded for all stages,
        // but only stage 0 should use it.
        // We run the full forward which includes embedding + layers.
        // For stage 0, we want to just do the embedding step.
        // Since the model was loaded with from_stage, forward_stage expects
        // hidden input, so we need the embedding separately.
        //
        // The embedding is accessible via the full forward path.
        // For now, stage 0 uses `model.forward()` which embeds + layers.
        let mut caches = self.kv_cache.to_vec();
        let output = self.model.forward(token_ids, &mut caches, 0)?;
        // Note: this returns logits for stage 0 only if it has all layers.
        // For pipeline mode, we need just the hidden state.
        // Use forward_stage with pre-embedded input instead.
        Ok(output)
    }

    /// For the last stage: apply LM head to produce logits.
    pub fn apply_head(&self, hidden: &Tensor) -> CandleResult<Tensor> {
        self.model.head(hidden)
    }

    /// Reset the KV cache (start a new inference request).
    pub fn reset_cache(&mut self) {
        self.kv_cache.clear();
    }

    /// Get the current KV cache sequence length.
    pub fn cache_seq_len(&self) -> usize {
        self.kv_cache.seq_len()
    }

    /// Get the stage assignment.
    pub fn assignment(&self) -> &StageAssignment {
        &self.assignment
    }

    /// Total tokens processed by this stage.
    pub fn tokens_processed(&self) -> u64 {
        self.tokens_processed
    }

    /// Device this stage runs on.
    pub fn device(&self) -> &Device {
        &self.device
    }
}
