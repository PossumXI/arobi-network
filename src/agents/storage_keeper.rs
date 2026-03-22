//! StorageKeeper Agent — manages ArobiFS local storage, DHT participation,
//! chunk replication, and storage proof responses.

use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::fs::dht::DhtTable;
use crate::fs::local_store::ChunkStore;
use crate::fs::proof::{StorageChallenger, StorageVerifier};
use crate::fs::types::*;

/// Events emitted by the StorageKeeper agent.
#[derive(Debug, Clone)]
pub enum StorageEvent {
    ChunkStored(ChunkId),
    ChunkReplicated(ChunkId, String), // chunk_id, peer_address
    StorageProofPassed(String),       // challenge_id
    StorageProofFailed(String),       // challenge_id
}

/// Configuration for the StorageKeeper agent.
pub struct StorageKeeperConfig {
    /// Maximum storage this node will contribute (bytes).
    pub max_storage_bytes: u64,
    /// How often to run DHT maintenance (seconds).
    pub dht_maintenance_secs: u64,
    /// How often to check for stale DHT entries (seconds).
    pub dht_eviction_secs: u64,
    /// Maximum age for DHT entries before eviction (milliseconds).
    pub dht_max_age_ms: u64,
}

impl Default for StorageKeeperConfig {
    fn default() -> Self {
        Self {
            max_storage_bytes: 100 * 1024 * 1024 * 1024, // 100 GiB
            dht_maintenance_secs: 60,
            dht_eviction_secs: 300,
            dht_max_age_ms: 3_600_000, // 1 hour
        }
    }
}

/// StorageKeeper agent — runs as background tasks within the node.
pub struct StorageKeeperAgent {
    pub chunk_store: Arc<ChunkStore>,
    pub dht: Arc<DhtTable>,
    config: StorageKeeperConfig,
    event_tx: broadcast::Sender<StorageEvent>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl StorageKeeperAgent {
    pub fn new(
        chunk_store: Arc<ChunkStore>,
        dht: Arc<DhtTable>,
        config: StorageKeeperConfig,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        let (shutdown, _) = tokio::sync::watch::channel(false);

        Self {
            chunk_store,
            dht,
            config,
            event_tx,
            shutdown,
        }
    }

    /// Subscribe to storage events.
    pub fn subscribe(&self) -> broadcast::Receiver<StorageEvent> {
        self.event_tx.subscribe()
    }

    /// Start background tasks.
    pub fn start(&self) {
        info!("StorageKeeper Agent starting");

        // DHT maintenance — evict stale entries periodically
        {
            let dht = self.dht.clone();
            let max_age = self.config.dht_max_age_ms;
            let interval = self.config.dht_eviction_secs;
            let mut shutdown_rx = self.shutdown.subscribe();

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(interval));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            dht.evict_stale_holders(max_age);
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
                info!("StorageKeeper DHT maintenance stopped");
            });
        }

        // Storage stats logging
        {
            let chunk_store = self.chunk_store.clone();
            let dht = self.dht.clone();
            let mut shutdown_rx = self.shutdown.subscribe();

            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let chunks = chunk_store.chunk_count().unwrap_or(0);
                            let files = chunk_store.manifest_count().unwrap_or(0);
                            let dht_peers = dht.peer_count();
                            let dht_records = dht.record_count();
                            if chunks > 0 || dht_peers > 0 {
                                info!(
                                    "ArobiFS: {chunks} chunks, {files} files, \
                                     DHT: {dht_peers} peers, {dht_records} records"
                                );
                            }
                        }
                        _ = shutdown_rx.changed() => break,
                    }
                }
            });
        }

        info!("StorageKeeper Agent started — DHT maintenance active");
    }

    /// Handle a storage proof challenge — generate and return the proof.
    pub fn handle_challenge(
        &self,
        challenge: &StorageChallenge,
        prover_address: &str,
    ) -> Option<StorageProof> {
        // Read the challenged chunk data
        let data = match self.chunk_store.get_chunk_data(&challenge.chunk_id) {
            Ok(Some(data)) => data,
            Ok(None) => {
                warn!(
                    "StorageKeeper: challenged for chunk {} but we don't have it",
                    challenge.chunk_id
                );
                return None;
            }
            Err(e) => {
                error!(
                    "StorageKeeper: failed to read chunk {}: {e}",
                    challenge.chunk_id
                );
                return None;
            }
        };

        // Generate proof
        match StorageVerifier::generate_proof(&data, challenge, prover_address) {
            Ok(proof) => {
                let _ = self.event_tx.send(StorageEvent::StorageProofPassed(
                    challenge.challenge_id.clone(),
                ));
                Some(proof)
            }
            Err(e) => {
                error!("StorageKeeper: failed to generate proof: {e}");
                let _ = self.event_tx.send(StorageEvent::StorageProofFailed(
                    challenge.challenge_id.clone(),
                ));
                None
            }
        }
    }

    /// Store a chunk and announce it to the DHT.
    pub fn store_chunk(
        &self,
        meta: &ChunkMeta,
        data: &[u8],
        local_p2p_addr: &str,
    ) -> anyhow::Result<()> {
        self.chunk_store.put_chunk(meta, data)?;

        // Announce to DHT
        let local_peer = self.dht.local_peer(
            local_p2p_addr,
            self.config.max_storage_bytes,
            self.chunk_store.chunk_count()?,
        );
        self.dht.announce_chunk(&meta.chunk_id, local_peer);

        let _ = self
            .event_tx
            .send(StorageEvent::ChunkStored(meta.chunk_id.clone()));
        Ok(())
    }

    /// Generate a storage challenge for a random locally-stored chunk.
    pub fn generate_random_challenge(&self) -> Option<StorageChallenge> {
        let chunk_ids = self.chunk_store.list_chunk_ids().ok()?;
        if chunk_ids.is_empty() {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..chunk_ids.len());
        let chunk_id = &chunk_ids[idx];

        let meta = self.chunk_store.get_chunk_meta(chunk_id).ok()??;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Some(StorageChallenger::generate(
            chunk_id,
            meta.size,
            3,            // 3 byte ranges
            now + 30_000, // 30 second deadline
        ))
    }

    /// Shutdown the agent.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        info!("StorageKeeper Agent shutdown");
    }
}
