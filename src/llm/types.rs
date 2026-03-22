//! Core types for ArobiLLM — the decentralized language model layer.

use serde::{Deserialize, Serialize};

// ─── Model Configuration ─────────────────────────────────────────────────────

/// Architecture configuration for the Arobi Transformer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Model identifier (blake3 hash of initial weights)
    pub model_id: String,
    /// Human-readable model name
    pub name: String,
    /// Number of transformer layers
    pub num_layers: usize,
    /// Hidden dimension size
    pub hidden_dim: usize,
    /// Number of attention heads
    pub num_heads: usize,
    /// Number of key-value heads (for grouped-query attention)
    pub num_kv_heads: usize,
    /// Intermediate dimension in FFN (typically 4 * hidden_dim)
    pub intermediate_dim: usize,
    /// Vocabulary size
    pub vocab_size: usize,
    /// Maximum context length in tokens
    pub max_seq_len: usize,
    /// RoPE theta for positional encoding
    pub rope_theta: f64,
    /// RMS norm epsilon
    pub rms_norm_eps: f64,
    /// Precision for weights
    pub precision: Precision,
    /// Number of pipeline stages this model is split into
    pub pipeline_stages: usize,
    /// Layers per pipeline stage
    pub layers_per_stage: usize,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model_id: String::new(),
            name: "arobi-transformer-1.3b".to_string(),
            num_layers: 24,
            hidden_dim: 2048,
            num_heads: 16,
            num_kv_heads: 4,        // GQA: 4 KV heads shared across 16 query heads
            intermediate_dim: 8192, // 4x hidden
            vocab_size: 32_000,
            max_seq_len: 4096,
            rope_theta: 10_000.0,
            rms_norm_eps: 1e-5,
            precision: Precision::BF16,
            pipeline_stages: 4,
            layers_per_stage: 6,
        }
    }
}

impl ModelConfig {
    /// Estimated model size in bytes at the configured precision.
    pub fn estimated_size_bytes(&self) -> u64 {
        let bytes_per_param = match self.precision {
            Precision::FP32 => 4,
            Precision::BF16 | Precision::FP16 => 2,
            Precision::INT8 => 1,
            Precision::INT4 => 1, // 4-bit packed, but stored as bytes
        };

        // Rough parameter count estimate:
        // Embedding: vocab_size * hidden_dim
        // Per layer: 4 * hidden_dim^2 (attn) + 3 * hidden_dim * intermediate_dim (ffn) + norms
        // Output head: hidden_dim * vocab_size (tied with embedding)
        let embedding_params = (self.vocab_size * self.hidden_dim) as u64;
        let attn_params_per_layer = (4 * self.hidden_dim * self.hidden_dim) as u64;
        let ffn_params_per_layer = (3 * self.hidden_dim * self.intermediate_dim) as u64;
        let norm_params_per_layer = (2 * self.hidden_dim) as u64;
        let per_layer = attn_params_per_layer + ffn_params_per_layer + norm_params_per_layer;
        let total_params = embedding_params + per_layer * self.num_layers as u64 + embedding_params;

        total_params * bytes_per_param
    }

    /// Size of a single pipeline stage in bytes.
    pub fn stage_size_bytes(&self) -> u64 {
        self.estimated_size_bytes() / self.pipeline_stages as u64
    }
}

/// Precision format for model weights and activations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Precision {
    FP32,
    FP16,
    BF16,
    INT8,
    INT4,
}

// ─── Model Registry ──────────────────────────────────────────────────────────

/// A registered model in the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRegistryEntry {
    pub model_id: String,
    pub config: ModelConfig,
    /// ArobiFS file IDs for each stage's weights
    pub stage_weight_file_ids: Vec<String>,
    /// ArobiFS file ID for the tokenizer
    pub tokenizer_file_id: Option<String>,
    /// Who registered this model
    pub registrant: String,
    /// Block height at registration
    pub registered_at_block: u64,
    /// Current serving status
    pub status: ModelStatus,
    /// Number of active pipeline instances serving this model
    pub active_pipelines: u32,
}

/// Model serving status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelStatus {
    /// Model registered but no stages assigned yet
    Registered,
    /// Some stages assigned, not fully served
    PartiallyServed,
    /// All pipeline stages assigned and ready
    FullyServed,
    /// Model is actively being trained
    Training,
    /// Model deprecated
    Deprecated,
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

/// Assignment of a pipeline stage to a specific node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageAssignment {
    pub model_id: String,
    pub stage_index: u32,
    /// Layers this stage covers: [start_layer, end_layer)
    pub start_layer: usize,
    pub end_layer: usize,
    /// Node serving this stage
    pub node_address: String,
    /// ArobiFS file ID for this stage's weights
    pub weight_file_id: String,
    /// Whether weights are loaded and ready
    pub loaded: bool,
    pub assigned_at: u64,
    pub last_heartbeat: u64,
}

/// An inference request submitted to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub request_id: String,
    pub model_id: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub top_p: f32,
    pub top_k: u32,
    pub repetition_penalty: f32,
    pub requester: String,
    pub submitted_at: u64,
    pub status: InferenceStatus,
}

/// Status of an inference request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InferenceStatus {
    Queued,
    Processing,
    Streaming,
    Completed,
    Failed(String),
}

/// Response from a completed inference request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponse {
    pub request_id: String,
    pub model_id: String,
    pub generated_text: String,
    pub tokens_generated: u32,
    pub total_time_ms: u64,
    pub tokens_per_second: f64,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub pipeline_stages_used: u32,
    pub completed_at: u64,
}

/// Hidden state passed between pipeline stages via P2P.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineHiddenState {
    pub request_id: String,
    pub model_id: String,
    pub stage_index: u32,
    /// Serialized tensor data (zstd compressed)
    pub tensor_data: Vec<u8>,
    /// Shape: [batch_size, seq_len, hidden_dim]
    pub shape: Vec<usize>,
    /// KV cache data for this stage (zstd compressed)
    pub kv_cache_data: Option<Vec<u8>>,
    pub token_position: usize,
}

/// Heartbeat from a stage-serving node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageHeartbeat {
    pub model_id: String,
    pub stage_index: u32,
    pub node_address: String,
    pub loaded: bool,
    pub current_requests: u32,
    pub tokens_served: u64,
    pub avg_latency_ms: f64,
    pub timestamp: u64,
}
