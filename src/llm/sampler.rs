//! Token sampling strategies for autoregressive generation.
//!
//! Supports temperature scaling, top-k filtering, top-p (nucleus) sampling,
//! and repetition penalty. All sampling operates on logits tensors.

use candle_core::{Result, Tensor};

/// Configuration for token sampling.
#[derive(Debug, Clone)]
pub struct SamplerConfig {
    pub temperature: f32,
    pub top_p: f32,
    pub top_k: u32,
    pub repetition_penalty: f32,
}

impl Default for SamplerConfig {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            top_p: 0.9,
            top_k: 50,
            repetition_penalty: 1.1,
        }
    }
}

/// Token sampler that applies temperature, top-k, top-p, and repetition penalty.
pub struct Sampler {
    config: SamplerConfig,
    /// Tokens already generated (for repetition penalty)
    generated_tokens: Vec<u32>,
}

impl Sampler {
    pub fn new(config: SamplerConfig) -> Self {
        Self {
            config,
            generated_tokens: Vec::new(),
        }
    }

    /// Sample a token from logits tensor of shape [batch=1, seq=1, vocab].
    /// Returns the sampled token ID.
    pub fn sample(&mut self, logits: &Tensor) -> Result<u32> {
        // Get last position logits: [vocab]
        let logits = logits.squeeze(0)?.squeeze(0)?;
        let vocab_size = logits.dim(0)?;

        // Convert to f32 vec for sampling
        let mut logits_vec: Vec<f32> = logits.to_vec1()?;

        // Apply repetition penalty
        if self.config.repetition_penalty != 1.0 {
            for &token_id in &self.generated_tokens {
                if (token_id as usize) < vocab_size {
                    let logit = logits_vec[token_id as usize];
                    logits_vec[token_id as usize] = if logit > 0.0 {
                        logit / self.config.repetition_penalty
                    } else {
                        logit * self.config.repetition_penalty
                    };
                }
            }
        }

        // Greedy decoding for temperature == 0
        if self.config.temperature == 0.0 {
            let token_id = logits_vec
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                .map(|(i, _)| i as u32)
                .unwrap_or(0);
            self.generated_tokens.push(token_id);
            return Ok(token_id);
        }

        // Apply temperature
        for logit in &mut logits_vec {
            *logit /= self.config.temperature;
        }

        // Apply top-k filtering
        if self.config.top_k > 0 && (self.config.top_k as usize) < vocab_size {
            let mut indexed: Vec<(usize, f32)> = logits_vec.iter().copied().enumerate().collect();
            indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            let threshold = indexed[self.config.top_k as usize - 1].1;
            for logit in &mut logits_vec {
                if *logit < threshold {
                    *logit = f32::NEG_INFINITY;
                }
            }
        }

        // Softmax
        let max_logit = logits_vec.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let mut probs: Vec<f32> = logits_vec.iter().map(|&l| (l - max_logit).exp()).collect();
        let sum: f32 = probs.iter().sum();
        for p in &mut probs {
            *p /= sum;
        }

        // Apply top-p (nucleus) filtering
        if self.config.top_p < 1.0 {
            let mut indexed: Vec<(usize, f32)> = probs.iter().copied().enumerate().collect();
            indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

            let mut cumsum = 0.0;
            let mut cutoff_idx = indexed.len();
            for (i, &(_, p)) in indexed.iter().enumerate() {
                cumsum += p;
                if cumsum > self.config.top_p {
                    cutoff_idx = i + 1;
                    break;
                }
            }

            let allowed: std::collections::HashSet<usize> =
                indexed[..cutoff_idx].iter().map(|&(i, _)| i).collect();
            for (i, p) in probs.iter_mut().enumerate() {
                if !allowed.contains(&i) {
                    *p = 0.0;
                }
            }

            // Re-normalize
            let sum: f32 = probs.iter().sum();
            if sum > 0.0 {
                for p in &mut probs {
                    *p /= sum;
                }
            }
        }

        // Weighted random sampling
        let token_id = Self::weighted_sample(&probs);
        self.generated_tokens.push(token_id);
        Ok(token_id)
    }

    /// Simple weighted random sampling using the rand crate.
    fn weighted_sample(probs: &[f32]) -> u32 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let r: f32 = rng.gen();
        let mut cumsum = 0.0;
        for (i, &p) in probs.iter().enumerate() {
            cumsum += p;
            if r < cumsum {
                return i as u32;
            }
        }
        (probs.len() - 1) as u32
    }

    /// Record a token as generated (for repetition penalty tracking).
    pub fn record_token(&mut self, token_id: u32) {
        self.generated_tokens.push(token_id);
    }

    /// Reset the sampler state (clear generated token history).
    pub fn reset(&mut self) {
        self.generated_tokens.clear();
    }

    /// Get the list of generated tokens.
    pub fn generated_tokens(&self) -> &[u32] {
        &self.generated_tokens
    }
}
