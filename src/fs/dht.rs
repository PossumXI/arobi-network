//! Kademlia-lite DHT for chunk discovery.
//!
//! Each node's ID is `blake3(arobi_address)`. Routing uses XOR distance.
//! K-buckets (K=20) organize peers by distance. Chunk location records
//! map chunk IDs to the set of peers that hold them.

use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info};

use super::types::*;

/// K-bucket size — maximum peers per distance bucket.
pub const K_BUCKET_SIZE: usize = 20;

/// Number of buckets (one per bit of the 256-bit node ID).
const NUM_BUCKETS: usize = 256;

/// Maximum number of DHT records (chunk → holders mapping) to keep in memory.
const MAX_DHT_RECORDS: usize = 100_000;

/// Replication factor — how many closest nodes to store a record on.
pub const REPLICATION_FACTOR: usize = 3;

/// DHT routing table + chunk location records.
pub struct DhtTable {
    /// Our own node ID: blake3(arobi_address).
    local_id: [u8; 32],
    /// Our AROBI address.
    local_address: String,
    /// K-buckets indexed by XOR distance prefix length.
    buckets: RwLock<Vec<Vec<DhtPeer>>>,
    /// Chunk location records: chunk_id → peers that hold it.
    records: RwLock<HashMap<ChunkId, DhtRecord>>,
}

impl DhtTable {
    /// Create a new DHT table for the given local node address.
    pub fn new(arobi_address: &str) -> Self {
        let local_id = node_id_from_address(arobi_address);
        let buckets = (0..NUM_BUCKETS).map(|_| Vec::new()).collect();

        info!("DHT initialized: local_id={}", hex::encode(&local_id[..8]));

        Self {
            local_id,
            local_address: arobi_address.to_string(),
            buckets: RwLock::new(buckets),
            records: RwLock::new(HashMap::new()),
        }
    }

    // ── Routing ───────────────────────────────────────────────────────────────

    /// Add or update a peer in the routing table.
    pub fn add_peer(&self, peer: DhtPeer) {
        let distance = xor_distance(&self.local_id, &peer.node_id);
        let bucket_idx = leading_zeros(&distance);
        if bucket_idx >= NUM_BUCKETS {
            return; // Same node ID as us
        }

        let mut buckets = self.buckets.write();
        let bucket = &mut buckets[bucket_idx];

        // Update if already present
        if let Some(existing) = bucket.iter_mut().find(|p| p.node_id == peer.node_id) {
            existing.last_seen = peer.last_seen;
            existing.storage_capacity = peer.storage_capacity;
            existing.stored_chunks = peer.stored_chunks;
            existing.p2p_addr = peer.p2p_addr.clone();
            return;
        }

        // Add if bucket has room
        if bucket.len() < K_BUCKET_SIZE {
            bucket.push(peer);
        } else {
            // Evict the least recently seen peer
            if let Some((idx, oldest)) = bucket.iter().enumerate().min_by_key(|(_, p)| p.last_seen)
            {
                if oldest.last_seen < peer.last_seen {
                    bucket[idx] = peer;
                }
            }
        }
    }

    /// Remove a peer from the routing table.
    pub fn remove_peer(&self, node_id: &[u8; 32]) {
        let distance = xor_distance(&self.local_id, node_id);
        let bucket_idx = leading_zeros(&distance);
        if bucket_idx >= NUM_BUCKETS {
            return;
        }
        let mut buckets = self.buckets.write();
        buckets[bucket_idx].retain(|p| &p.node_id != node_id);
    }

    /// Find the K closest peers to a target ID.
    pub fn find_closest(&self, target: &[u8; 32], count: usize) -> Vec<DhtPeer> {
        let buckets = self.buckets.read();
        let mut all_peers: Vec<(u32, &DhtPeer)> = Vec::new();

        for bucket in buckets.iter() {
            for peer in bucket.iter() {
                let dist = xor_distance_leading_zeros(&peer.node_id, target);
                all_peers.push((dist, peer));
            }
        }

        // Sort by distance (highest leading zeros = closest)
        all_peers.sort_by(|a, b| b.0.cmp(&a.0));
        all_peers
            .into_iter()
            .take(count)
            .map(|(_, p)| p.clone())
            .collect()
    }

    /// Find peers responsible for storing a chunk (closest to chunk_id hash).
    pub fn find_chunk_holders_candidates(&self, chunk_id: &str) -> Vec<DhtPeer> {
        let target = chunk_id_to_node_id(chunk_id);
        self.find_closest(&target, REPLICATION_FACTOR)
    }

    /// Get total number of peers in the routing table.
    pub fn peer_count(&self) -> usize {
        self.buckets.read().iter().map(|b| b.len()).sum()
    }

    /// Get all known peers.
    pub fn all_peers(&self) -> Vec<DhtPeer> {
        self.buckets
            .read()
            .iter()
            .flat_map(|b| b.iter().cloned())
            .collect()
    }

    // ── Chunk Location Records ────────────────────────────────────────────────

    /// Record that a peer holds a specific chunk.
    pub fn announce_chunk(&self, chunk_id: &ChunkId, holder: DhtPeer) {
        let mut records = self.records.write();

        // Enforce max records limit
        if records.len() >= MAX_DHT_RECORDS && !records.contains_key(chunk_id) {
            // Evict oldest record
            if let Some(oldest_key) = records
                .iter()
                .min_by_key(|(_, r)| r.last_verified)
                .map(|(k, _)| k.clone())
            {
                records.remove(&oldest_key);
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let record = records
            .entry(chunk_id.clone())
            .or_insert_with(|| DhtRecord {
                chunk_id: chunk_id.clone(),
                holders: Vec::new(),
                last_verified: now,
            });

        // Update or add holder
        if let Some(existing) = record
            .holders
            .iter_mut()
            .find(|h| h.node_id == holder.node_id)
        {
            existing.last_seen = holder.last_seen;
        } else {
            record.holders.push(holder);
        }
        record.last_verified = now;

        debug!(
            "DHT: chunk {} now has {} holders",
            chunk_id,
            record.holders.len()
        );
    }

    /// Look up which peers hold a specific chunk.
    pub fn find_chunk_holders(&self, chunk_id: &ChunkId) -> Option<DhtRecord> {
        self.records.read().get(chunk_id).cloned()
    }

    /// Remove stale holders (peers not seen in `max_age_ms`).
    pub fn evict_stale_holders(&self, max_age_ms: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut records = self.records.write();
        let cutoff = now.saturating_sub(max_age_ms);

        // Remove stale holders from each record
        for record in records.values_mut() {
            record.holders.retain(|h| h.last_seen >= cutoff);
        }

        // Remove records with no holders
        records.retain(|_, r| !r.holders.is_empty());
    }

    /// Total chunk records tracked.
    pub fn record_count(&self) -> usize {
        self.records.read().len()
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    pub fn local_id(&self) -> &[u8; 32] {
        &self.local_id
    }

    pub fn local_address(&self) -> &str {
        &self.local_address
    }

    /// Build a DhtPeer for ourselves.
    pub fn local_peer(&self, p2p_addr: &str, storage_capacity: u64, stored_chunks: u64) -> DhtPeer {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        DhtPeer {
            node_id: self.local_id,
            arobi_address: self.local_address.clone(),
            p2p_addr: p2p_addr.to_string(),
            storage_capacity,
            stored_chunks,
            last_seen: now,
        }
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Compute node ID from an AROBI address.
pub fn node_id_from_address(address: &str) -> [u8; 32] {
    *blake3::hash(address.as_bytes()).as_bytes()
}

/// Compute a node-ID-space key for a chunk (for DHT routing).
fn chunk_id_to_node_id(chunk_id: &str) -> [u8; 32] {
    *blake3::hash(chunk_id.as_bytes()).as_bytes()
}

/// XOR distance between two 256-bit IDs.
fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Count leading zeros in a 256-bit value (higher = closer in XOR space).
fn leading_zeros(value: &[u8; 32]) -> usize {
    let mut count = 0;
    for byte in value {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

/// Combined: compute leading zeros of XOR distance (convenience).
fn xor_distance_leading_zeros(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    leading_zeros(&xor_distance(a, b)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_deterministic() {
        let id1 = node_id_from_address("ARLPh1Z6SqWTf6DxoMoekbYoqAbBzLDgn8v");
        let id2 = node_id_from_address("ARLPh1Z6SqWTf6DxoMoekbYoqAbBzLDgn8v");
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_xor_distance_self_is_zero() {
        let id = node_id_from_address("test");
        let dist = xor_distance(&id, &id);
        assert_eq!(dist, [0u8; 32]);
        assert_eq!(leading_zeros(&dist), 256);
    }

    #[test]
    fn test_add_and_find_peer() {
        let dht = DhtTable::new("local_node");
        let peer = DhtPeer {
            node_id: node_id_from_address("remote_node"),
            arobi_address: "remote_node".to_string(),
            p2p_addr: "127.0.0.1:30334".to_string(),
            storage_capacity: 1_000_000,
            stored_chunks: 0,
            last_seen: 1000,
        };
        dht.add_peer(peer.clone());
        assert_eq!(dht.peer_count(), 1);

        let closest = dht.find_closest(&peer.node_id, 5);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].arobi_address, "remote_node");
    }

    #[test]
    fn test_chunk_announce_and_lookup() {
        let dht = DhtTable::new("local_node");
        let peer = DhtPeer {
            node_id: node_id_from_address("holder_node"),
            arobi_address: "holder_node".to_string(),
            p2p_addr: "127.0.0.1:30335".to_string(),
            storage_capacity: 1_000_000,
            stored_chunks: 1,
            last_seen: 1000,
        };

        let chunk_id = "abc123".to_string();
        dht.announce_chunk(&chunk_id, peer);

        let record = dht.find_chunk_holders(&chunk_id).unwrap();
        assert_eq!(record.holders.len(), 1);
        assert_eq!(record.holders[0].arobi_address, "holder_node");
    }
}
