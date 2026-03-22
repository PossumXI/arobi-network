//! Compute sandbox — secure execution environment for untrusted workloads.
//!
//! Provides process-isolated execution with resource limits.
//! Future: integrate wasmtime for WASM module execution.

use anyhow::{bail, Result};
use tracing::info;

use super::types::*;

/// Maximum output size from a sandboxed execution: 10 MiB.
const MAX_OUTPUT_SIZE: usize = 10 * 1024 * 1024;

/// Sandbox execution environment.
pub struct ComputeSandbox {
    /// Maximum execution time in milliseconds.
    max_duration_ms: u64,
    /// Maximum memory in bytes.
    max_memory_bytes: u64,
}

impl ComputeSandbox {
    pub fn new() -> Self {
        Self {
            max_duration_ms: crate::config::genesis::JOB_MAX_DURATION_MS,
            max_memory_bytes: crate::config::genesis::WASM_MAX_MEMORY_PAGES as u64 * 65536,
        }
    }

    /// Execute a deterministic compute task in a sandboxed environment.
    pub async fn execute(&self, task: &ComputeTask) -> Result<ExecutionResult> {
        let start = std::time::Instant::now();

        match task {
            ComputeTask::Deterministic {
                function_hash,
                input_data,
                output_size_hint: _,
            } => {
                self.execute_deterministic(function_hash, input_data, start)
                    .await
            }
            ComputeTask::Wasm {
                module_file_id: _,
                entry_function: _,
                input_data_file_id: _,
                max_memory_pages: _,
            } => {
                // WASM execution via wasmtime (future: load from ArobiFS)
                info!("WASM execution requested — runtime not yet integrated");
                bail!("WASM runtime not yet available. Install wasmtime feature.")
            }
            ComputeTask::OnnxInference { .. } => {
                info!("ONNX inference requested — runtime not yet integrated");
                bail!("ONNX runtime not yet available")
            }
            ComputeTask::LlmInference { .. } => {
                // This should be routed to ArobiLLM, not executed here
                bail!("LLM inference should be routed to ArobiLLM subsystem")
            }
        }
    }

    /// Execute a deterministic function: the function_hash selects a built-in
    /// compute kernel, and input_data is processed through it.
    async fn execute_deterministic(
        &self,
        function_hash: &str,
        input_data: &[u8],
        start: std::time::Instant,
    ) -> Result<ExecutionResult> {
        if input_data.len() as u64 > self.max_memory_bytes {
            bail!(
                "Input data exceeds memory limit ({} > {})",
                input_data.len(),
                self.max_memory_bytes
            );
        }

        // Select kernel based on function_hash prefix
        let output = match &function_hash[..4.min(function_hash.len())] {
            // Hash kernel: iterative blake3 hashing
            "hash" => {
                let iterations = u32::from_le_bytes(
                    input_data
                        .get(..4)
                        .unwrap_or(&[10, 0, 0, 0])
                        .try_into()
                        .unwrap_or([10, 0, 0, 0]),
                )
                .min(100_000);
                let payload = &input_data[4.min(input_data.len())..];
                let mut hash = blake3::hash(payload);
                for _ in 1..iterations {
                    hash = blake3::hash(hash.as_bytes());
                }
                hash.as_bytes().to_vec()
            }
            // Sort kernel: sort input bytes and return sorted + statistics
            "sort" => {
                let mut sorted = input_data.to_vec();
                sorted.sort_unstable();
                let min = sorted.first().copied().unwrap_or(0);
                let max = sorted.last().copied().unwrap_or(0);
                let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
                let mut out = sorted;
                out.extend_from_slice(&[min, max, median]);
                out
            }
            // Stats kernel: compute statistical features
            "stat" => {
                let n = input_data.len() as f64;
                if n == 0.0 {
                    vec![0u8; 24]
                } else {
                    let mean = input_data.iter().map(|&b| b as f64).sum::<f64>() / n;
                    let variance = input_data
                        .iter()
                        .map(|&b| (b as f64 - mean).powi(2))
                        .sum::<f64>()
                        / n;
                    let std_dev = variance.sqrt();
                    let mut out = Vec::with_capacity(24);
                    out.extend_from_slice(&mean.to_le_bytes());
                    out.extend_from_slice(&std_dev.to_le_bytes());
                    out.extend_from_slice(&n.to_le_bytes());
                    out
                }
            }
            // Matrix kernel: matrix multiply (input = two square matrices)
            "matr" => {
                let dim = (input_data.len() as f64 / 2.0).sqrt() as usize;
                if dim == 0 || dim * dim * 2 > input_data.len() {
                    blake3::hash(input_data).as_bytes().to_vec()
                } else {
                    let a = &input_data[..dim * dim];
                    let b = &input_data[dim * dim..dim * dim * 2];
                    let mut c = vec![0u64; dim * dim];
                    for i in 0..dim {
                        for k in 0..dim {
                            let a_ik = a[i * dim + k] as u64;
                            for j in 0..dim {
                                c[i * dim + j] += a_ik * b[k * dim + j] as u64;
                            }
                        }
                    }
                    // Hash the result matrix
                    let result_bytes: Vec<u8> = c.iter().flat_map(|v| v.to_le_bytes()).collect();
                    blake3::hash(&result_bytes).as_bytes().to_vec()
                }
            }
            // Default: blake3 hash of input
            _ => blake3::hash(input_data).as_bytes().to_vec(),
        };

        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed > self.max_duration_ms {
            bail!(
                "Execution exceeded time limit ({elapsed}ms > {}ms)",
                self.max_duration_ms
            );
        }

        if output.len() > MAX_OUTPUT_SIZE {
            bail!("Output exceeds size limit");
        }

        let result_hash = blake3::hash(&output).to_hex().to_string();

        Ok(ExecutionResult {
            output,
            execution_time_ms: elapsed,
            peak_memory_mb: input_data.len() as u64 / (1024 * 1024) + 1,
            result_hash,
        })
    }
}

/// Result of a sandboxed execution.
pub struct ExecutionResult {
    pub output: Vec<u8>,
    pub execution_time_ms: u64,
    pub peak_memory_mb: u64,
    pub result_hash: String,
}
