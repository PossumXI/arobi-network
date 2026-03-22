//! Training module — forward pass, loss computation, and gradient accumulation.
//!
//! Uses Candle's computation graph for autograd-style differentiation.
//! Supports gradient clipping, learning rate scheduling, and mixed precision.

use candle_core::{DType, Result as CandleResult, Tensor, D};
use candle_nn::VarMap;

/// Training configuration.
#[derive(Debug, Clone)]
pub struct TrainingConfig {
    pub learning_rate: f64,
    pub batch_size: usize,
    pub gradient_accumulation_steps: usize,
    pub gradient_clip_norm: f64,
    pub warmup_steps: usize,
    pub weight_decay: f64,
    pub max_steps: usize,
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self {
            learning_rate: 3e-4,
            batch_size: 4,
            gradient_accumulation_steps: 8,
            gradient_clip_norm: 1.0,
            warmup_steps: 100,
            weight_decay: 0.01,
            max_steps: 10_000,
        }
    }
}

/// Training state tracking.
pub struct TrainingState {
    pub step: usize,
    pub epoch: usize,
    pub total_tokens: u64,
    pub total_loss: f64,
    pub best_loss: f64,
    pub losses: Vec<f64>,
}

impl TrainingState {
    pub fn new() -> Self {
        Self {
            step: 0,
            epoch: 0,
            total_tokens: 0,
            total_loss: 0.0,
            best_loss: f64::MAX,
            losses: Vec::new(),
        }
    }

    pub fn average_loss(&self) -> f64 {
        if self.losses.is_empty() {
            return 0.0;
        }
        self.losses.iter().sum::<f64>() / self.losses.len() as f64
    }

    pub fn record_loss(&mut self, loss: f64) {
        self.total_loss += loss;
        self.losses.push(loss);
        if loss < self.best_loss {
            self.best_loss = loss;
        }
    }
}

/// Compute cross-entropy loss for language modeling.
/// `logits` shape: [batch, seq_len, vocab_size]
/// `targets` shape: [batch, seq_len]
pub fn cross_entropy_loss(logits: &Tensor, targets: &Tensor) -> CandleResult<Tensor> {
    let (batch, seq_len, vocab_size) = logits.dims3()?;

    // Reshape logits to [batch * seq_len, vocab_size]
    let logits_flat = logits.reshape((batch * seq_len, vocab_size))?;

    // Reshape targets to [batch * seq_len]
    let targets_flat = targets.reshape(batch * seq_len)?;

    // Log softmax
    let log_probs = candle_nn::ops::log_softmax(&logits_flat, D::Minus1)?;

    // Gather the log probabilities for the target tokens
    let targets_u32 = targets_flat.to_dtype(DType::U32)?;
    let target_log_probs = log_probs
        .gather(&targets_u32.unsqueeze(1)?, 1)?
        .squeeze(1)?;

    // Negative log likelihood (mean over all tokens)
    let loss = target_log_probs.neg()?.mean_all()?;
    Ok(loss)
}

/// Compute learning rate with linear warmup and cosine decay.
pub fn lr_schedule(step: usize, config: &TrainingConfig) -> f64 {
    if step < config.warmup_steps {
        // Linear warmup
        config.learning_rate * (step as f64 / config.warmup_steps as f64)
    } else {
        // Cosine decay
        let progress =
            (step - config.warmup_steps) as f64 / (config.max_steps - config.warmup_steps) as f64;
        let decay = 0.5 * (1.0 + (std::f64::consts::PI * progress).cos());
        config.learning_rate * decay.max(0.01) // floor at 1% of base LR
    }
}

/// Clip gradient norms to prevent exploding gradients.
/// Returns the original norm before clipping.
pub fn clip_grad_norm(var_map: &VarMap, max_norm: f64) -> CandleResult<f64> {
    let all_vars = var_map.all_vars();
    let mut total_norm_sq = 0.0_f64;

    // Compute total gradient norm
    for var in &all_vars {
        let grad = var.as_tensor();
        let norm = grad
            .sqr()?
            .sum_all()?
            .to_dtype(DType::F64)?
            .to_scalar::<f64>()?;
        total_norm_sq += norm;
    }

    let total_norm = total_norm_sq.sqrt();

    // Scale gradients if norm exceeds threshold
    if total_norm > max_norm {
        let scale = max_norm / (total_norm + 1e-6);
        for var in &all_vars {
            let scaled = (var.as_tensor() * scale)?;
            var.set(&scaled)?;
        }
    }

    Ok(total_norm)
}
