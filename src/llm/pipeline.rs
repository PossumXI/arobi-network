//! Pipeline parallelism coordinator.
//!
//! Routes inference requests through the pipeline stages. For local-only
//! execution (single node serving all stages), runs stages sequentially.
//! For distributed execution, coordinates hidden state transfer via P2P.

use std::sync::Arc;
use std::time::Instant;

use candle_core::{Device, Result as CandleResult, Tensor};

use super::architecture::ArobiTransformer;
use super::kv_cache::KvCache;
use super::registry::ModelRegistry;
use super::sampler::{Sampler, SamplerConfig};

/// Result of a complete inference run.
pub struct InferenceResult {
    pub generated_tokens: Vec<u32>,
    pub generated_text: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_time_ms: u64,
    pub tokens_per_second: f64,
}

/// Pipeline coordinator managing inference execution across stages.
pub struct PipelineCoordinator {
    registry: Arc<ModelRegistry>,
    device: Device,
}

impl PipelineCoordinator {
    pub fn new(registry: Arc<ModelRegistry>, device: Device) -> Self {
        Self { registry, device }
    }

    /// Run local inference (all stages on this node).
    /// The model must be fully loaded with all layers.
    pub fn run_local(
        &self,
        model: &ArobiTransformer,
        token_ids: &[u32],
        config: &SamplerConfig,
        max_tokens: u32,
        eos_token_id: u32,
        stop_sequences: &[Vec<u32>],
    ) -> CandleResult<InferenceResult> {
        let start = Instant::now();
        let prompt_len = token_ids.len();

        // Create input tensor: [1, seq_len]
        let input = Tensor::from_vec(token_ids.to_vec(), (1, prompt_len), &self.device)?;

        // First forward pass (prefill): process full prompt
        let mut kv_caches: Vec<(Tensor, Tensor)> = Vec::new();
        let logits = model.forward(&input, &mut kv_caches, 0)?;

        // Sample first token from last position
        let last_logits = logits.narrow(1, prompt_len - 1, 1)?;
        let mut sampler = Sampler::new(config.clone());

        // Record prompt tokens in sampler for repetition penalty
        for &t in token_ids {
            sampler.record_token(t);
        }

        let first_token = sampler.sample(&last_logits)?;
        let mut generated = vec![first_token];

        // Check early termination
        if first_token == eos_token_id {
            let elapsed = start.elapsed().as_millis() as u64;
            return Ok(InferenceResult {
                generated_tokens: generated,
                generated_text: String::new(),
                prompt_tokens: prompt_len as u32,
                completion_tokens: 1,
                total_time_ms: elapsed,
                tokens_per_second: if elapsed > 0 {
                    1000.0 / elapsed as f64
                } else {
                    0.0
                },
            });
        }

        // Autoregressive generation loop
        let mut offset = prompt_len;
        for _ in 1..max_tokens {
            let last_token = *generated.last().unwrap();
            let input = Tensor::from_vec(vec![last_token], (1, 1), &self.device)?;

            let logits = model.forward(&input, &mut kv_caches, offset)?;
            offset += 1;

            let token = sampler.sample(&logits)?;
            generated.push(token);

            // Check EOS
            if token == eos_token_id {
                break;
            }

            // Check stop sequences
            if Self::check_stop_sequences(&generated, stop_sequences) {
                break;
            }
        }

        let elapsed = start.elapsed().as_millis() as u64;
        let completion_tokens = generated.len() as u32;
        let tps = if elapsed > 0 {
            (completion_tokens as f64 * 1000.0) / elapsed as f64
        } else {
            0.0
        };

        Ok(InferenceResult {
            generated_tokens: generated,
            generated_text: String::new(), // Caller decodes via tokenizer
            prompt_tokens: prompt_len as u32,
            completion_tokens,
            total_time_ms: elapsed,
            tokens_per_second: tps,
        })
    }

    /// Run a single pipeline stage forward pass (for distributed execution).
    /// Takes hidden state from previous stage, runs through local layers,
    /// returns hidden state for next stage.
    pub fn run_stage(
        &self,
        model: &ArobiTransformer,
        hidden: &Tensor,
        kv_cache: &mut KvCache,
        offset: usize,
    ) -> CandleResult<Tensor> {
        let mut caches = kv_cache.to_vec();
        let output = model.forward_stage(hidden, &mut caches, offset)?;
        kv_cache.update_from_vec(caches)?;
        Ok(output)
    }

    /// Run the final stage: apply LM head to get logits from hidden state.
    pub fn run_final_stage(
        &self,
        model: &ArobiTransformer,
        hidden: &Tensor,
        kv_cache: &mut KvCache,
        offset: usize,
    ) -> CandleResult<Tensor> {
        let mut caches = kv_cache.to_vec();
        let output = model.forward_stage(hidden, &mut caches, offset)?;
        kv_cache.update_from_vec(caches)?;
        model.head(&output)
    }

    /// Check if any stop sequence appears at the end of generated tokens.
    fn check_stop_sequences(generated: &[u32], stop_sequences: &[Vec<u32>]) -> bool {
        for stop in stop_sequences {
            if generated.len() >= stop.len()
                && &generated[generated.len() - stop.len()..] == stop.as_slice()
            {
                return true;
            }
        }
        false
    }

    /// Get the current device.
    pub fn device(&self) -> &Device {
        &self.device
    }
}
