//! Core types for ArobiFS — the decentralized file system layer.

use serde::{Deserialize, Serialize};

/// Content-addressed chunk identifier: blake3 hash of raw chunk bytes (64-char hex).
pub type ChunkId = String;

/// Content-addressed file identifier: blake3 hash of the canonical manifest bytes.
pub type FileId = String;

/// Fixed chunk size: 256 KiB.
/// - Small enough to fit in memory for erasure coding operations
/// - Large enough to avoid excessive metadata overhead
/// - Aligns well with typical network streaming patterns
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Reed-Solomon erasure coding: 4 data shards + 2 parity shards.
/// Any 4 of 6 shards can reconstruct the original data (33% overhead).
pub const RS_DATA_SHARDS: usize = 4;
pub const RS_PARITY_SHARDS: usize = 2;
pub const RS_TOTAL_SHARDS: usize = RS_DATA_SHARDS + RS_PARITY_SHARDS;

/// Default replication factor — each chunk stored on at least this many peers.
pub const DEFAULT_REPLICAS: u8 = 3;

/// Maximum file size: 10 GiB (enforced at upload time).
pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Maximum chunks a single node will store (configurable, default ~100 GiB worth).
pub const MAX_LOCAL_CHUNKS: u64 = 400_000;

// ─── Chunk ───────────────────────────────────────────────────────────────────

/// Shard type within a Reed-Solomon erasure coding group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShardType {
    /// Original data shard.
    Data,
    /// Parity shard with its index within the parity set.
    Parity { parity_index: u32 },
}

/// Metadata about a single chunk stored locally.
/// The actual bytes live on the filesystem; this is the sled index entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMeta {
    pub chunk_id: ChunkId,
    pub file_id: FileId,
    pub index: u32,
    pub shard_type: ShardType,
    pub size: u32,
    pub stored_at: u64,
}

// ─── File Manifest ───────────────────────────────────────────────────────────

/// Reference to a chunk within a file manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub chunk_id: ChunkId,
    pub index: u32,
    pub shard_type: ShardType,
    pub size: u32,
}

/// Encryption metadata for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionMeta {
    /// No encryption — file is stored in cleartext.
    None,
    /// AES-256-GCM encryption.
    Aes256Gcm {
        /// blake3 hash of the encryption key (NOT the key itself).
        key_hash: String,
        /// Nonce prefix used for chunk-level encryption.
        nonce_prefix: Vec<u8>,
    },
}

/// Pinning policy — controls replication and storage incentives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinPolicy {
    /// Minimum copies of each chunk across the network.
    pub min_replicas: u8,
    /// Maximum copies (to bound storage costs).
    pub max_replicas: u8,
    /// How long to guarantee storage (0 = permanent until unpinned).
    pub pin_duration_secs: u64,
    /// AURA base units paid per storage epoch (1 epoch = 1440 blocks ≈ 1 day).
    pub reward_per_epoch: u64,
}

impl Default for PinPolicy {
    fn default() -> Self {
        Self {
            min_replicas: DEFAULT_REPLICAS,
            max_replicas: 10,
            pin_duration_secs: 0,
            reward_per_epoch: 0,
        }
    }
}

/// File manifest — describes a complete file and its chunk layout.
/// The FileId is `blake3(canonical_json_bytes_of_manifest_without_file_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub file_id: FileId,
    pub name: String,
    pub total_size: u64,
    pub chunk_count: u32,
    pub parity_count: u32,
    pub chunks: Vec<ChunkRef>,
    pub owner: String,
    pub encryption: EncryptionMeta,
    pub created_at: u64,
    pub pin_policy: PinPolicy,
}

// ─── DHT Types ───────────────────────────────────────────────────────────────

/// A peer entry in the DHT routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPeer {
    /// Node ID: blake3(arobi_address) — 32 bytes.
    pub node_id: [u8; 32],
    /// AROBI address of the peer.
    pub arobi_address: String,
    /// TCP address for direct P2P connection.
    pub p2p_addr: String,
    /// Total storage capacity in bytes.
    pub storage_capacity: u64,
    /// Number of chunks this peer holds.
    pub stored_chunks: u64,
    /// Unix timestamp ms of last contact.
    pub last_seen: u64,
}

/// DHT record: maps a ChunkId to the list of peers that hold it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    pub chunk_id: ChunkId,
    pub holders: Vec<DhtPeer>,
    pub last_verified: u64,
}

// ─── Storage Proof Types ─────────────────────────────────────────────────────

/// Challenge issued to a peer to prove they hold a specific chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChallenge {
    pub challenge_id: String,
    pub chunk_id: ChunkId,
    /// Random byte ranges within the chunk that must be proven.
    pub byte_ranges: Vec<(u64, u64)>,
    /// Random nonce mixed into the proof hash.
    pub nonce: Vec<u8>,
    /// Deadline (unix ms) — proof must arrive before this.
    pub deadline_ms: u64,
}

/// Proof submitted in response to a storage challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    pub challenge_id: String,
    pub chunk_id: ChunkId,
    /// blake3(nonce || bytes_at_range_0 || bytes_at_range_1 || ...)
    pub proof_hash: String,
    /// AROBI address of the prover.
    pub prover: String,
    pub timestamp: u64,
}

// ─── Pin Record ──────────────────────────────────────────────────────────────

/// On-chain pin record — tracks who pinned a file and the deposit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinRecord {
    pub file_id: FileId,
    pub pinner: String,
    pub deposit_aura: u64,
    pub pin_policy: PinPolicy,
    pub pinned_at: u64,
    pub expires_at: u64,
}

// ─── Upload / Download Progress ──────────────────────────────────────────────

/// Status of an ongoing file upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadStatus {
    pub file_id: FileId,
    pub total_chunks: u32,
    pub chunks_stored: u32,
    pub chunks_replicated: u32,
    pub status: TransferStatus,
}

/// Status of an ongoing file download.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadStatus {
    pub file_id: FileId,
    pub total_chunks: u32,
    pub chunks_retrieved: u32,
    pub status: TransferStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferStatus {
    InProgress,
    Completed,
    Failed(String),
}

// ─── Storage Statistics ──────────────────────────────────────────────────────

/// Local node storage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub total_files: u64,
    pub total_pins: u64,
    pub available_bytes: u64,
    pub storage_proofs_passed: u64,
    pub storage_proofs_failed: u64,
}
