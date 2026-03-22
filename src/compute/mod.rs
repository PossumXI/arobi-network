//! ArobiCompute — Decentralized Distributed Compute Network
//!
//! Allows peers to contribute CPU/GPU compute capacity, receive tasks,
//! execute them in sandboxed environments, and earn AURA rewards.
//! Features job scheduling, redundant execution for verification,
//! and a reputation system for worker reliability.

#[allow(dead_code)]
pub mod reputation;
#[allow(dead_code)]
pub mod sandbox;
#[allow(dead_code)]
pub mod scheduler;
#[allow(dead_code)]
pub mod types;
