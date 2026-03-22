//! ArobiLLM — Decentralized Language Model
//!
//! Custom "Arobi Transformer" architecture designed for pipeline parallelism
//! across network peers. Each peer serves one or more pipeline stages,
//! passing hidden states via P2P to produce inference results.
//!
//! Features:
//! - Custom transformer architecture (1.3B params, 24 layers, 2048 hidden dim)
//! - Pipeline parallelism: split into 4 stages of 6 layers each
//! - KV cache for autoregressive generation
//! - Token sampling with temperature, top-p, top-k
//! - Model weights stored/loaded via ArobiFS
//! - BPE tokenizer loaded from ArobiFS

#[allow(dead_code)]
pub mod architecture;
#[allow(dead_code)]
pub mod checkpoint;
#[allow(dead_code)]
pub mod dataset;
#[allow(dead_code)]
pub mod federated;
#[allow(dead_code)]
pub mod kv_cache;
#[allow(dead_code)]
pub mod pipeline;
#[allow(dead_code)]
pub mod registry;
#[allow(dead_code)]
pub mod sampler;
#[allow(dead_code)]
pub mod stage;
#[allow(dead_code)]
pub mod tensor_io;
#[allow(dead_code)]
pub mod tokenizer;
#[allow(dead_code)]
pub mod training;
#[allow(dead_code)]
pub mod types;
