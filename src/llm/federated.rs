//! Federated Learning — gradient aggregation with differential privacy.
//!
//! Implements Federated Averaging (FedAvg) with optional Gaussian noise
//! for differential privacy. Workers compute local gradients and submit
//! them to the coordinator, who aggregates and applies them.

use candle_core::{Device, Result as CandleResult, Tensor};
use rand::Rng;
use tracing::info;

/// Configuration for federated learning.
#[derive(Debug, Clone)]
pub struct FederatedConfig {
    /// Minimum number of workers required per round
    pub min_workers: usize,
    /// Maximum number of workers per round
    pub max_workers: usize,
    /// Differential privacy: noise scale (0.0 = no DP)
    pub dp_noise_scale: f64,
    /// Differential privacy: gradient clipping norm
    pub dp_clip_norm: f64,
    /// Whether to use secure aggregation (gradients are masked)
    pub secure_aggregation: bool,
    /// Number of rounds before a checkpoint is saved
    pub checkpoint_interval: u64,
}

impl Default for FederatedConfig {
    fn default() -> Self {
        Self {
            min_workers: 3,
            max_workers: 50,
            dp_noise_scale: 0.01,
            dp_clip_norm: 1.0,
            secure_aggregation: false,
            checkpoint_interval: 10,
        }
    }
}

/// A gradient update from a single worker.
pub struct GradientUpdate {
    /// Worker's Arobi address
    pub worker_address: String,
    /// Gradient tensors (one per model parameter)
    pub gradients: Vec<Tensor>,
    /// Number of samples this gradient was computed over
    pub num_samples: usize,
    /// Training round ID
    pub round_id: u64,
    /// blake3 hash of the gradients for verification
    pub gradient_hash: String,
}

/// Federated averaging coordinator.
pub struct FederatedCoordinator {
    config: FederatedConfig,
    device: Device,
    /// Accumulated gradients from workers (per round)
    pending_gradients: Vec<GradientUpdate>,
    /// Current round ID
    current_round: u64,
}

impl FederatedCoordinator {
    pub fn new(config: FederatedConfig, device: Device) -> Self {
        Self {
            config,
            device,
            pending_gradients: Vec::new(),
            current_round: 0,
        }
    }

    /// Start a new training round.
    pub fn start_round(&mut self) -> u64 {
        self.current_round += 1;
        self.pending_gradients.clear();
        info!(
            "Federated round {} started (min_workers={})",
            self.current_round, self.config.min_workers
        );
        self.current_round
    }

    /// Submit a gradient update from a worker.
    pub fn submit_gradient(&mut self, update: GradientUpdate) -> Result<(), String> {
        if update.round_id != self.current_round {
            return Err(format!(
                "Gradient for round {} but current round is {}",
                update.round_id, self.current_round
            ));
        }
        if self.pending_gradients.len() >= self.config.max_workers {
            return Err("Maximum workers reached for this round".to_string());
        }

        info!(
            "Received gradient from {} ({} samples, round {})",
            update.worker_address, update.num_samples, update.round_id
        );
        self.pending_gradients.push(update);
        Ok(())
    }

    /// Check if enough gradients have been collected to aggregate.
    pub fn can_aggregate(&self) -> bool {
        self.pending_gradients.len() >= self.config.min_workers
    }

    /// Perform federated averaging on collected gradients.
    /// Returns the averaged gradient tensors.
    pub fn aggregate(&self) -> CandleResult<Vec<Tensor>> {
        if self.pending_gradients.is_empty() {
            return Err(candle_core::Error::Msg(
                "No gradients to aggregate".to_string(),
            ));
        }

        let num_workers = self.pending_gradients.len();
        let num_params = self.pending_gradients[0].gradients.len();

        // Weighted average by number of samples
        let total_samples: usize = self.pending_gradients.iter().map(|g| g.num_samples).sum();

        let mut averaged = Vec::with_capacity(num_params);

        for param_idx in 0..num_params {
            let mut acc = self.pending_gradients[0].gradients[param_idx].zeros_like()?;

            for update in &self.pending_gradients {
                let weight = update.num_samples as f64 / total_samples as f64;
                let weighted_grad = (&update.gradients[param_idx] * weight)?;
                acc = (&acc + &weighted_grad)?;
            }

            // Apply differential privacy noise if configured
            if self.config.dp_noise_scale > 0.0 {
                acc = self.add_dp_noise(&acc)?;
            }

            averaged.push(acc);
        }

        info!(
            "Federated averaging complete: {} workers, {} total samples, {} params",
            num_workers, total_samples, num_params
        );

        Ok(averaged)
    }

    /// Add Gaussian noise to a gradient tensor for differential privacy.
    fn add_dp_noise(&self, gradient: &Tensor) -> CandleResult<Tensor> {
        let shape = gradient.dims();
        let num_elements: usize = shape.iter().product();

        // Generate Gaussian noise
        let mut rng = rand::thread_rng();
        let noise: Vec<f32> = (0..num_elements)
            .map(|_| {
                let u1: f64 = rng.gen::<f64>().max(1e-10);
                let u2: f64 = rng.gen();
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                (z * self.config.dp_noise_scale) as f32
            })
            .collect();

        let noise_tensor =
            Tensor::from_vec(noise, shape, &self.device)?.to_dtype(gradient.dtype())?;
        let noisy = (gradient + &noise_tensor)?;
        Ok(noisy)
    }

    /// Current round ID.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// Number of pending gradient updates.
    pub fn pending_count(&self) -> usize {
        self.pending_gradients.len()
    }

    /// Whether a checkpoint should be saved after this round.
    pub fn should_checkpoint(&self) -> bool {
        self.current_round
            .is_multiple_of(self.config.checkpoint_interval)
    }
}
