//! ArobiFS — Decentralized Distributed File System
//!
//! Content-addressed chunked storage with Reed-Solomon erasure coding,
//! Kademlia-lite DHT for chunk discovery, and cryptographic storage proofs.
//! This is the data layer that model weights, training data, and compute
//! artifacts are stored on across the Arobi Network.

#[allow(dead_code)]
pub mod chunker;
#[allow(dead_code)]
pub mod dht;
#[allow(dead_code)]
pub mod local_store;
#[allow(dead_code)]
pub mod proof;
#[allow(dead_code)]
pub mod types;

pub use types::*;
