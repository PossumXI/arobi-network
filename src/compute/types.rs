//! Core types for ArobiCompute — the distributed compute layer.

use serde::{Deserialize, Serialize};

// ─── Node Capabilities ───────────────────────────────────────────────────────

/// Hardware and software capabilities of a compute node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapability {
    pub node_address: String,
    pub cpu_cores: u16,
    pub cpu_model: String,
    pub ram_mb: u64,
    pub gpu: Option<GpuCapability>,
    pub storage_available_mb: u64,
    pub network_bandwidth_mbps: u32,
    pub os: String,
    pub supported_runtimes: Vec<ComputeRuntime>,
    pub registered_at: u64,
    pub last_heartbeat: u64,
    pub reputation_score: f64,
}

/// GPU hardware details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuCapability {
    pub model: String,
    pub vram_mb: u64,
    pub cuda_cores: u32,
    pub compute_capability: String,
    pub supports_f16: bool,
    pub supports_int8: bool,
}

/// Supported compute runtimes on a node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComputeRuntime {
    /// WebAssembly sandboxed execution
    Wasm,
    /// Rust compiled tasks (native speed)
    NativeRust,
    /// ONNX Runtime for ML inference
    Onnx,
    /// Hugging Face Candle for Rust-native ML
    Candle,
    /// Custom runtime identifier
    Custom(String),
}

// ─── Compute Jobs ────────────────────────────────────────────────────────────

/// A compute job submitted to the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    pub job_id: String,
    pub submitter: String,
    pub task: ComputeTask,
    pub requirements: JobRequirements,
    pub budget: JobBudget,
    pub status: JobStatus,
    pub created_at: u64,
    pub deadline_ms: u64,
    pub assigned_workers: Vec<String>,
    pub results: Vec<WorkerResult>,
}

/// The type of compute task to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputeTask {
    /// Execute a WebAssembly module
    Wasm {
        /// ArobiFS file ID containing the .wasm module
        module_file_id: String,
        entry_function: String,
        input_data_file_id: Option<String>,
        max_memory_pages: u32,
    },
    /// Run ONNX model inference
    OnnxInference {
        model_file_id: String,
        input_tensor_file_id: String,
        output_names: Vec<String>,
    },
    /// LLM inference (routed to ArobiLLM subsystem)
    LlmInference {
        model_id: String,
        prompt: String,
        max_tokens: u32,
        temperature: f32,
        top_p: f32,
    },
    /// Generic deterministic computation
    Deterministic {
        /// blake3 hash of the function to execute
        function_hash: String,
        /// Serialized input data
        input_data: Vec<u8>,
        /// Expected output size hint
        output_size_hint: u64,
    },
}

/// Hardware requirements for a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequirements {
    pub min_cpu_cores: u16,
    pub min_ram_mb: u64,
    pub requires_gpu: bool,
    pub min_gpu_vram_mb: u64,
    pub min_reputation: f64,
    /// Number of workers that must execute (for redundant verification)
    pub redundancy: u8,
}

impl Default for JobRequirements {
    fn default() -> Self {
        Self {
            min_cpu_cores: 1,
            min_ram_mb: 256,
            requires_gpu: false,
            min_gpu_vram_mb: 0,
            min_reputation: 0.0,
            redundancy: 3,
        }
    }
}

/// Budget allocation for a compute job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobBudget {
    /// Maximum total AURA to spend (base units)
    pub max_cost_aura: u64,
    /// Price willing to pay per CPU-second
    pub cost_per_cpu_sec: u64,
    /// Price willing to pay per GPU-second
    pub cost_per_gpu_sec: u64,
}

/// Current status of a compute job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Verifying,
    Completed,
    Failed(String),
    Disputed,
}

/// Result submitted by a worker for a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub worker: String,
    pub output_file_id: Option<String>,
    pub output_data: Option<Vec<u8>>,
    pub execution_time_ms: u64,
    pub cpu_time_ms: u64,
    pub peak_memory_mb: u64,
    /// blake3(output) — used for redundant verification
    pub result_hash: String,
    pub submitted_at: u64,
}

// ─── Marketplace ─────────────────────────────────────────────────────────────

/// A bid from a worker offering to execute a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBid {
    pub job_id: String,
    pub worker: String,
    pub bid_aura: u64,
    pub estimated_time_ms: u64,
    pub reputation_score: f64,
    pub submitted_at: u64,
}

/// Network-wide compute marketplace statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceStats {
    pub total_nodes: u64,
    pub total_cpu_cores: u64,
    pub total_gpu_nodes: u64,
    pub total_ram_mb: u64,
    pub active_jobs: u64,
    pub completed_jobs: u64,
    pub total_aura_spent: u64,
}
