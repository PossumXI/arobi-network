use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};

use crate::block::{Block, Transaction};
use crate::compute::reputation::ReputationOracle;
use crate::compute::scheduler::Scheduler;
use crate::compute::types::*;
use crate::config::genesis;
use crate::fs;
use crate::llm::registry::ModelRegistry;
use crate::mempool::Mempool;
use crate::peer::{is_public_peer_endpoint, normalize_peer_endpoint};
use crate::store::Store;

const MAX_PEERS: usize = 50;
const MAX_BLOCK_RANGE: u64 = 100; // max blocks served per GetBlocks request
const DIAL_TIMEOUT_SECS: u64 = 8;
const DIAL_BACKOFF_BASE_SECS: u64 = 5;
const DIAL_BACKOFF_MAX_SECS: u64 = 300;

// ─── Wire protocol ─────────────────────────────────────────────────────────────

/// All messages exchanged between peers — newline-delimited JSON over TCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum P2pMessage {
    /// First message after connection — identify network and sync state.
    Handshake {
        version: String,
        height: u64,
        #[serde(default)]
        peer_addr: String,
        #[serde(default)]
        advertised_addrs: Vec<String>,
    },
    /// Newly produced block — gossip to all connected peers.
    NewBlock(Block),
    /// Newly submitted transaction — gossip to all connected peers.
    NewTransaction(Transaction),
    /// Request a range of blocks (for chain sync).
    GetBlocks { from: u64, to: u64 },
    /// Response to GetBlocks.
    Blocks(Vec<Block>),
    /// Keepalive.
    Ping,
    /// Keepalive reply.
    Pong,
    /// Share intelligence proof for verification (future multi-validator PoI).
    IntelligenceProofShare {
        block_height: u64,
        proof: crate::poi::IntelligenceProof,
        validator: String,
    },

    // ─── ArobiFS messages ────────────────────────────────────────────────────
    /// Announce that this node stores specific chunks.
    ChunkAnnounce {
        chunk_ids: Vec<fs::ChunkId>,
        node_address: String,
        p2p_addr: String,
    },
    /// Request a chunk by its content-addressed ID.
    ChunkRequest {
        chunk_id: fs::ChunkId,
        requester: String,
    },
    /// Response with chunk data (base64-encoded for JSON wire format).
    ChunkResponse {
        chunk_id: fs::ChunkId,
        data_b64: String,
    },
    /// DHT lookup: find peers that hold a specific chunk.
    DhtFindChunk {
        chunk_id: fs::ChunkId,
        requester_id: String,
    },
    /// DHT response: peers that hold the requested chunk.
    DhtChunkHolders {
        chunk_id: fs::ChunkId,
        holders: Vec<fs::DhtPeer>,
    },
    /// Request a file manifest by FileId.
    ManifestRequest { file_id: fs::FileId },
    /// Response with a file manifest.
    ManifestResponse { manifest: fs::FileManifest },
    /// Storage challenge issued by a verifier.
    StorageChallengeMsg { challenge: fs::StorageChallenge },
    /// Storage proof submitted in response.
    StorageProofMsg { proof: fs::StorageProof },

    // ─── ArobiCompute messages (Phase 3) ─────────────────────────────────────
    /// Announce node compute capabilities (sent periodically).
    CapabilityAnnounce {
        capabilities: serde_json::Value,
        node_address: String,
    },

    // ─── Autonomo messages (Phase 5 integration) ────────────────────────────
    /// Broadcast an agent's heartbeat across the network.
    AutonomoHeartbeatGossip {
        payload_b64: String, // encrypted gibbertalk
        sender_wallet: String,
    },
    /// Broadcast a chat message across the network.
    AutonomoChatGossip {
        from_wallet: String,
        to_wallet: String,
        message: String,
        msg_type: String,
        timestamp: String,
    },
    /// Broadcast a signed opaque relay envelope across the network.
    AutonomoSecureRelayGossip { relay: serde_json::Value },

    /// Broadcast a new compute job to the network.
    JobBroadcast { job: serde_json::Value },
    /// Worker claiming a job.
    JobClaim {
        job_id: String,
        worker: String,
        bid_aura: u64,
    },
    /// Job result from a worker.
    JobResultMsg {
        job_id: String,
        result: serde_json::Value,
    },

    // ─── ArobiLLM messages (Phase 4) ─────────────────────────────────────────
    /// Announce that this node serves specific model stages.
    ModelAnnounce {
        model_id: String,
        stages_served: Vec<u32>,
        node_address: String,
    },
    /// Forward hidden state through inference pipeline.
    InferencePipelineForward {
        request_id: String,
        model_id: String,
        stage_index: u32,
        hidden_state_b64: String,
        position_ids: Vec<u32>,
        is_prefill: bool,
    },
    /// Result from the final pipeline stage.
    InferencePipelineResult {
        request_id: String,
        next_token: u32,
        is_done: bool,
        logit_hash: String,
    },
    /// Stage heartbeat: "I am alive and serving stage X of model Y".
    StageHeartbeat {
        model_id: String,
        stage_index: u32,
        node_address: String,
        gpu_utilization: f32,
        active_requests: u32,
    },

    // ─── Federated Training messages (Phase 5) ───────────────────────────
    /// Coordinator announces a new training round.
    TrainingRoundStart {
        model_id: String,
        round_id: u64,
        checkpoint_file_id: String,
        dataset_shard_ids: Vec<String>,
        learning_rate: f64,
        batch_size: u32,
    },
    /// Worker submits computed gradients for a round.
    GradientSubmit {
        model_id: String,
        round_id: u64,
        worker: String,
        gradient_data_b64: String,
        num_samples: u64,
        gradient_hash: String,
    },
    /// Coordinator announces round completion with new checkpoint.
    TrainingRoundComplete {
        model_id: String,
        round_id: u64,
        new_checkpoint_file_id: String,
        aggregated_loss: f64,
        participating_workers: Vec<String>,
    },

    // ─── Tool execution messages (Phase 6) ───────────────────────────────
    /// Request tool execution on a remote node.
    ToolExecutionRequest {
        task_id: String,
        tool_name: String,
        parameters: serde_json::Value,
        requester: String,
        timeout_ms: u64,
    },
    /// Result of tool execution.
    ToolExecutionResult {
        task_id: String,
        success: bool,
        result: serde_json::Value,
        execution_time_ms: u64,
    },
}

// ─── P2P events for subsystem channels ──────────────────────────────────────

/// Events forwarded to the InferenceRouter agent via channel.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum InferenceP2pEvent {
    PipelineForward {
        request_id: String,
        model_id: String,
        stage_index: u32,
        hidden_state_b64: String,
        position_ids: Vec<u32>,
        is_prefill: bool,
        peer_addr: String,
    },
    PipelineResult {
        request_id: String,
        next_token: u32,
        is_done: bool,
        logit_hash: String,
    },
}

/// Events forwarded to the TrainingCoordinator agent via channel.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TrainingP2pEvent {
    RoundStart {
        model_id: String,
        round_id: u64,
        checkpoint_file_id: String,
        dataset_shard_ids: Vec<String>,
        learning_rate: f64,
        batch_size: u32,
    },
    GradientReceived {
        model_id: String,
        round_id: u64,
        worker: String,
        gradient_data_b64: String,
        num_samples: u64,
        gradient_hash: String,
    },
    RoundComplete {
        model_id: String,
        round_id: u64,
        new_checkpoint_file_id: String,
        aggregated_loss: f64,
        participating_workers: Vec<String>,
    },
}

// ─── PeerContext ────────────────────────────────────────────────────────────

/// Shared context passed to P2P message handlers — replaces the growing
/// parameter list with a single struct.
#[allow(dead_code)]
pub struct PeerContext {
    pub store: Arc<Store>,
    pub mempool: Arc<Mempool>,
    pub compute_scheduler: Arc<Scheduler>,
    pub reputation_oracle: Arc<ReputationOracle>,
    pub model_registry: Arc<ModelRegistry>,
    pub inference_tx: mpsc::Sender<InferenceP2pEvent>,
    pub training_tx: mpsc::Sender<TrainingP2pEvent>,
    pub node_address: String,
    pub advertised_addrs: Vec<String>,
}

// ─── P2p struct ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct DialState {
    failures: u32,
    next_attempt_ms: u64,
    in_flight: bool,
}

pub struct P2p {
    /// Addresses of currently connected peers.
    pub connected_peers: RwLock<Vec<String>>,
    /// Sender used to subscribe new receivers for block gossip.
    block_tx: broadcast::Sender<Block>,
    /// Gossip channel for compute/LLM/training messages.
    gossip_tx: broadcast::Sender<P2pMessage>,
    /// Backoff tracker for dial attempts.
    dial_state: RwLock<HashMap<String, DialState>>,
}

impl P2p {
    pub fn new(block_tx: broadcast::Sender<Block>) -> Arc<Self> {
        let (gossip_tx, _) = broadcast::channel::<P2pMessage>(256);
        Arc::new(Self {
            connected_peers: RwLock::new(Vec::new()),
            block_tx,
            gossip_tx,
            dial_state: RwLock::new(HashMap::new()),
        })
    }

    /// Best-effort peer count without async (for API responses).
    pub fn peer_count(&self) -> usize {
        self.connected_peers
            .try_read()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    /// Snapshot connected peer list.
    pub async fn connected_peer_snapshot(&self) -> Vec<String> {
        self.connected_peers.read().await.clone()
    }

    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    async fn reserve_dial_slot(&self, addr: &str) -> bool {
        {
            let peers = self.connected_peers.read().await;
            if peers.iter().any(|p| p == addr) {
                return false;
            }
        }

        let now = Self::unix_ms();
        let mut state = self.dial_state.write().await;
        let entry = state.entry(addr.to_string()).or_insert(DialState {
            failures: 0,
            next_attempt_ms: 0,
            in_flight: false,
        });

        if entry.in_flight || entry.next_attempt_ms > now {
            return false;
        }

        entry.in_flight = true;
        true
    }

    async fn mark_dial_success(&self, addr: &str) {
        let mut state = self.dial_state.write().await;
        state.insert(
            addr.to_string(),
            DialState {
                failures: 0,
                next_attempt_ms: 0,
                in_flight: false,
            },
        );
    }

    async fn mark_dial_failure(&self, addr: &str) {
        let now = Self::unix_ms();
        let mut state = self.dial_state.write().await;
        let entry = state.entry(addr.to_string()).or_insert(DialState {
            failures: 0,
            next_attempt_ms: 0,
            in_flight: false,
        });

        entry.failures = entry.failures.saturating_add(1);
        let backoff_secs = (DIAL_BACKOFF_BASE_SECS.saturating_mul(1u64 << entry.failures.min(8)))
            .min(DIAL_BACKOFF_MAX_SECS);
        entry.next_attempt_ms = now.saturating_add(backoff_secs.saturating_mul(1000));
        entry.in_flight = false;
    }

    /// Broadcast a gossip message to all connected peers.
    pub fn broadcast_gossip(&self, msg: P2pMessage) {
        let _ = self.gossip_tx.send(msg);
    }

    /// Subscribe to gossip messages.
    #[allow(dead_code)]
    pub fn subscribe_gossip(&self) -> broadcast::Receiver<P2pMessage> {
        self.gossip_tx.subscribe()
    }

    // ── Inbound listener ───────────────────────────────────────────────────────

    /// Bind and accept incoming TCP connections forever.
    pub async fn listen(self: Arc<Self>, port: u16, ctx: Arc<PeerContext>) {
        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("P2P listen failed on {addr}: {e}");
                return;
            }
        };
        info!("⛓  P2P listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((stream, remote)) => {
                    let p2p = self.clone();
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        p2p.handle(stream, remote.to_string(), false, ctx).await;
                    });
                }
                Err(e) => error!("P2P accept error: {e}"),
            }
        }
    }

    // ── Outbound dialer ────────────────────────────────────────────────────────

    /// Connect to a peer; reconnects are handled at the node level.
    pub async fn dial(self: Arc<Self>, addr: String, ctx: Arc<PeerContext>) {
        let Some(normalized) = normalize_peer_endpoint(&addr) else {
            warn!("Could not dial invalid peer endpoint '{addr}'");
            return;
        };

        if !self.reserve_dial_slot(&normalized).await {
            return;
        }

        match tokio::time::timeout(
            tokio::time::Duration::from_secs(DIAL_TIMEOUT_SECS),
            TcpStream::connect(&normalized),
        )
        .await
        {
            Ok(Ok(stream)) => {
                self.mark_dial_success(&normalized).await;
                if let Err(e) = ctx.store.mark_peer_connected(&normalized, "dial") {
                    warn!("Failed to persist connected peer {normalized}: {e}");
                }
                info!("⛓  Dialed peer {normalized}");
                self.handle(stream, normalized, true, ctx).await;
            }
            Ok(Err(e)) => {
                self.mark_dial_failure(&normalized).await;
                if let Err(store_err) = ctx.store.mark_peer_failed(&normalized, "dial") {
                    warn!("Failed to persist failed peer {normalized}: {store_err}");
                }
                warn!("Could not connect to peer {normalized}: {e}");
            }
            Err(_) => {
                self.mark_dial_failure(&normalized).await;
                if let Err(store_err) = ctx.store.mark_peer_failed(&normalized, "dial") {
                    warn!("Failed to persist failed peer {normalized}: {store_err}");
                }
                warn!("Dial timeout connecting to peer {normalized}");
            }
        }
    }

    // ── Per-connection handler ─────────────────────────────────────────────────

    async fn handle(
        self: Arc<Self>,
        stream: TcpStream,
        peer_addr: String,
        is_outbound: bool,
        ctx: Arc<PeerContext>,
    ) {
        // Register peer
        {
            let mut peers = self.connected_peers.write().await;
            if peers.len() >= MAX_PEERS {
                warn!("Peer limit reached, rejecting {peer_addr}");
                return;
            }
            if peers.contains(&peer_addr) {
                return; // already tracked
            }
            peers.push(peer_addr.clone());
        }

        if is_outbound {
            let _ = ctx.store.mark_peer_connected(&peer_addr, "outbound");
        }

        let (read_half, write_half) = stream.into_split();
        let mut lines = BufReader::new(read_half).lines();

        // Channel for the write task to drain
        let (write_tx, write_rx) = mpsc::channel::<String>(128);
        // Subscribe this connection to the block-broadcast channel
        let block_rx = self.block_tx.subscribe();
        // Subscribe to gossip channel for compute/LLM/training
        let gossip_rx = self.gossip_tx.subscribe();

        // Send our handshake immediately
        let height = ctx.store.chain_height().unwrap_or(0);
        let advertised_addrs = ctx.advertised_addrs.clone();
        let handshake_addr = advertised_addrs
            .first()
            .cloned()
            .unwrap_or_else(String::new);
        let hs = P2pMessage::Handshake {
            version: genesis::NETWORK_MAGIC.to_string(),
            height,
            peer_addr: handshake_addr,
            advertised_addrs,
        };
        send_msg(&write_tx, &hs).await;

        // Spawn write task — handles reply messages, block gossip, and compute/LLM gossip
        let write_handle = tokio::spawn(write_task(write_half, write_rx, block_rx, gossip_rx));

        // ── Read loop ──────────────────────────────────────────────────────────
        loop {
            match lines.next_line().await {
                Ok(Some(text)) => {
                    let msg = match serde_json::from_str::<P2pMessage>(&text) {
                        Ok(m) => m,
                        Err(_) => continue, // malformed — ignore
                    };
                    handle_msg(msg, &peer_addr, &ctx, &write_tx).await;
                }
                Ok(None) => break, // peer closed connection
                Err(e) => {
                    error!("Read error from {peer_addr}: {e}");
                    break;
                }
            }
        }

        write_handle.abort();
        self.connected_peers
            .write()
            .await
            .retain(|p| p != &peer_addr);
        info!("⛓  Peer disconnected: {peer_addr}");
    }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/// Serialise a P2pMessage and push to the write channel (best-effort).
async fn send_msg(tx: &mpsc::Sender<String>, msg: &P2pMessage) {
    if let Ok(line) = serde_json::to_string(msg) {
        let _ = tx.send(format!("{line}\n")).await;
    }
}

/// Write task: drains the outbound channel, gossips new blocks, and forwards compute/LLM gossip.
async fn write_task(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut write_rx: mpsc::Receiver<String>,
    mut block_rx: broadcast::Receiver<Block>,
    mut gossip_rx: broadcast::Receiver<P2pMessage>,
) {
    loop {
        tokio::select! {
            line = write_rx.recv() => {
                match line {
                    Some(l) => {
                        if writer.write_all(l.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    None => break, // sender dropped — read loop exited
                }
            }
            result = block_rx.recv() => {
                match result {
                    Ok(block) => {
                        let msg = P2pMessage::NewBlock(block);
                        if let Ok(line) = serde_json::to_string(&msg) {
                            if writer.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            result = gossip_rx.recv() => {
                match result {
                    Ok(msg) => {
                        if let Ok(line) = serde_json::to_string(&msg) {
                            if writer.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

/// Handle one inbound message and send any replies via write_tx.
async fn handle_msg(
    msg: P2pMessage,
    peer_addr: &str,
    ctx: &Arc<PeerContext>,
    write_tx: &mpsc::Sender<String>,
) {
    let store = &ctx.store;
    let mempool = &ctx.mempool;

    match msg {
        P2pMessage::Handshake {
            version,
            height: peer_height,
            peer_addr: advertised_primary,
            advertised_addrs,
        } => {
            if version != genesis::NETWORK_MAGIC {
                warn!("Peer {peer_addr} wrong network magic: {version}");
                return;
            }

            let mut discovered = Vec::new();
            if let Some(addr) = normalize_peer_endpoint(&advertised_primary) {
                discovered.push(addr);
            }
            for advertised in advertised_addrs {
                if let Some(addr) = normalize_peer_endpoint(&advertised) {
                    discovered.push(addr);
                }
            }

            if discovered.is_empty() {
                if let Ok(socket_peer) = peer_addr.parse::<SocketAddr>() {
                    let fallback = SocketAddr::new(socket_peer.ip(), 30333).to_string();
                    if let Some(addr) = normalize_peer_endpoint(&fallback) {
                        discovered.push(addr);
                    }
                }
            }

            discovered.sort();
            discovered.dedup();

            let local_advertised: HashSet<String> = ctx
                .advertised_addrs
                .iter()
                .filter_map(|a| normalize_peer_endpoint(a))
                .collect();

            for addr in discovered {
                if local_advertised.contains(&addr) {
                    continue;
                }
                if !is_public_peer_endpoint(&addr) {
                    continue;
                }
                if let Err(e) = store.remember_peer(&addr, "handshake") {
                    warn!("Failed to persist discovered peer {addr}: {e}");
                }
            }

            let our_height = store.chain_height().unwrap_or(0);
            if peer_height > our_height {
                let req = P2pMessage::GetBlocks {
                    from: our_height + 1,
                    to: peer_height,
                };
                send_msg(write_tx, &req).await;
            }
        }

        P2pMessage::NewBlock(block) => {
            if !block.verify_hash() {
                warn!(
                    "Block {} from {peer_addr} has invalid hash — dropping",
                    block.height
                );
                return;
            }
            let cur = store.chain_height().unwrap_or(0);
            if block.height == cur + 1 {
                if let Err(e) = store.apply_block(&block) {
                    warn!("Block {} from {peer_addr} rejected: {e}", block.height);
                }
            } else if block.height > cur + 1 {
                let req = P2pMessage::GetBlocks {
                    from: cur + 1,
                    to: block.height,
                };
                send_msg(write_tx, &req).await;
            }
        }

        P2pMessage::NewTransaction(tx) => {
            let _ = mempool.add(tx, store).await;
        }

        P2pMessage::GetBlocks { from, to } => {
            let to_clamped = to.min(from + MAX_BLOCK_RANGE);
            if let Ok(blocks) = store.get_blocks(from, to_clamped) {
                if !blocks.is_empty() {
                    send_msg(write_tx, &P2pMessage::Blocks(blocks)).await;
                }
            }
        }

        P2pMessage::Blocks(blocks) => {
            for block in blocks {
                if !block.verify_hash() {
                    warn!(
                        "Sync block {} from {peer_addr} has invalid hash — stopping sync",
                        block.height
                    );
                    break;
                }
                let _ = store.apply_block(&block);
            }
        }

        P2pMessage::Ping => {
            send_msg(write_tx, &P2pMessage::Pong).await;
        }

        P2pMessage::Pong => {}

        P2pMessage::IntelligenceProofShare {
            block_height,
            proof,
            validator,
        } => match crate::poi::PoiEngine::verify_proof(&proof) {
            Ok(()) => {
                info!(
                    "Valid PoI proof from {} for block {block_height} (score {:.2})",
                    &validator[..12.min(validator.len())],
                    proof.intelligence_score,
                );
            }
            Err(e) => {
                warn!(
                    "Invalid PoI proof from {}: {e}",
                    &validator[..12.min(validator.len())]
                );
            }
        },

        // ─── ArobiFS handlers ────────────────────────────────────────────────
        P2pMessage::ChunkAnnounce {
            chunk_ids,
            node_address,
            p2p_addr,
        } => {
            info!(
                "Peer {peer_addr} announces {} chunks from {node_address}",
                chunk_ids.len()
            );
            let _ = (chunk_ids, node_address, p2p_addr);
        }

        P2pMessage::ChunkRequest {
            chunk_id,
            requester,
        } => {
            let chunks_dir = store.data_dir().join("chunks");
            let blob_path = chunks_dir.join(&chunk_id);
            if let Ok(data) = std::fs::read(&blob_path) {
                let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                send_msg(write_tx, &P2pMessage::ChunkResponse { chunk_id, data_b64 }).await;
            } else {
                warn!("Chunk {chunk_id} requested by {requester} — not found locally");
            }
        }

        P2pMessage::ChunkResponse { chunk_id, data_b64 } => {
            match base64::engine::general_purpose::STANDARD.decode(&data_b64) {
                Ok(data) => {
                    let computed_id = blake3::hash(&data).to_hex().to_string();
                    if computed_id == chunk_id {
                        let chunks_dir = store.data_dir().join("chunks");
                        let _ = std::fs::create_dir_all(&chunks_dir);
                        let blob_path = chunks_dir.join(&chunk_id);
                        if let Err(e) = std::fs::write(&blob_path, &data) {
                            error!("Failed to write received chunk {chunk_id}: {e}");
                        } else {
                            info!(
                                "Stored chunk {chunk_id} ({} bytes) from {peer_addr}",
                                data.len()
                            );
                        }
                    } else {
                        warn!("Chunk content mismatch from {peer_addr}: expected {chunk_id}, got {computed_id}");
                    }
                }
                Err(e) => warn!("Invalid base64 in ChunkResponse from {peer_addr}: {e}"),
            }
        }

        P2pMessage::DhtFindChunk {
            chunk_id,
            requester_id,
        } => {
            let chunks_dir = store.data_dir().join("chunks");
            let blob_path = chunks_dir.join(&chunk_id);
            if blob_path.exists() {
                info!("DHT: we hold chunk {chunk_id}, responding to {requester_id}");
            }
        }

        P2pMessage::DhtChunkHolders { chunk_id, holders } => {
            info!(
                "DHT: received {} holders for chunk {chunk_id}",
                holders.len()
            );
        }

        P2pMessage::ManifestRequest { file_id } => {
            if let Ok(tree) = store.db().open_tree("fs_manifests") {
                if let Ok(Some(data)) = tree.get(file_id.as_bytes()) {
                    if let Ok(manifest) = serde_json::from_slice::<fs::FileManifest>(&data) {
                        send_msg(write_tx, &P2pMessage::ManifestResponse { manifest }).await;
                    }
                }
            }
        }

        P2pMessage::ManifestResponse { manifest } => {
            info!(
                "Received manifest for file {} ({} chunks, {} bytes)",
                manifest.file_id, manifest.chunk_count, manifest.total_size
            );
            if let Ok(tree) = store.db().open_tree("fs_manifests") {
                if let Ok(json) = serde_json::to_vec(&manifest) {
                    let _ = tree.insert(manifest.file_id.as_bytes(), json);
                }
            }
        }

        P2pMessage::StorageChallengeMsg { challenge } => {
            info!(
                "Storage challenge received: chunk {} ({} ranges)",
                challenge.chunk_id,
                challenge.byte_ranges.len()
            );
        }

        P2pMessage::StorageProofMsg { proof } => {
            info!(
                "Storage proof received from {} for chunk {}",
                proof.prover, proof.chunk_id
            );
            if let Ok(tree) = store.db().open_tree("fs_storage_proofs") {
                if let Ok(json) = serde_json::to_vec(&proof) {
                    let _ = tree.insert(proof.challenge_id.as_bytes(), json);
                }
            }
        }

        // ─── ArobiCompute handlers (Phase 3) ────────────────────────────────
        P2pMessage::CapabilityAnnounce {
            capabilities,
            node_address,
        } => {
            info!("Compute capability announced by {node_address}");
            if let Ok(cap) = serde_json::from_value::<NodeCapability>(capabilities) {
                ctx.compute_scheduler.register_capability(cap);
            }
        }

        P2pMessage::JobBroadcast { job } => {
            info!("Compute job broadcast received from {peer_addr}");
            if let Ok(compute_job) = serde_json::from_value::<ComputeJob>(job) {
                let _ = ctx.compute_scheduler.submit_job(compute_job);
            }
        }

        P2pMessage::JobClaim {
            job_id,
            worker,
            bid_aura,
        } => {
            info!(
                "Job {} claimed by {} for {bid_aura} AURA",
                &job_id[..16.min(job_id.len())],
                &worker[..12.min(worker.len())]
            );
            let reputation_score = ctx.reputation_oracle.get_score(&worker);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let bid = WorkerBid {
                job_id,
                worker,
                bid_aura,
                estimated_time_ms: 0,
                reputation_score,
                submitted_at: now,
            };
            let _ = ctx.compute_scheduler.submit_bid(bid);
        }

        P2pMessage::JobResultMsg { job_id, result } => {
            info!(
                "Job {} result received from {peer_addr}",
                &job_id[..16.min(job_id.len())]
            );
            if let Ok(worker_result) = serde_json::from_value::<WorkerResult>(result) {
                let _ = ctx.compute_scheduler.submit_result(&job_id, worker_result);
            }
        }

        // ─── ArobiLLM handlers (Phase 4) ────────────────────────────────────
        P2pMessage::ModelAnnounce {
            model_id,
            stages_served,
            node_address,
        } => {
            info!(
                "Model {model_id} stages {:?} served by {node_address}",
                stages_served
            );
            // Persist to sled for discovery
            if let Ok(tree) = store.db().open_tree("llm_stages") {
                for &stage in &stages_served {
                    let key = format!("{model_id}:{stage}:{node_address}");
                    let _ = tree.insert(key.as_bytes(), node_address.as_bytes());
                }
            }
        }

        P2pMessage::InferencePipelineForward {
            request_id,
            model_id,
            stage_index,
            hidden_state_b64,
            position_ids,
            is_prefill,
        } => {
            info!(
                "Pipeline forward: request {} model {model_id} stage {stage_index}",
                &request_id[..16.min(request_id.len())]
            );
            let _ = ctx
                .inference_tx
                .send(InferenceP2pEvent::PipelineForward {
                    request_id,
                    model_id,
                    stage_index,
                    hidden_state_b64,
                    position_ids,
                    is_prefill,
                    peer_addr: peer_addr.to_string(),
                })
                .await;
        }

        P2pMessage::InferencePipelineResult {
            request_id,
            next_token,
            is_done,
            logit_hash,
        } => {
            info!(
                "Pipeline result: request {} token {next_token} done={is_done}",
                &request_id[..16.min(request_id.len())]
            );
            let _ = ctx
                .inference_tx
                .send(InferenceP2pEvent::PipelineResult {
                    request_id,
                    next_token,
                    is_done,
                    logit_hash,
                })
                .await;
        }

        P2pMessage::StageHeartbeat {
            model_id,
            stage_index,
            node_address,
            gpu_utilization: _,
            active_requests,
        } => {
            let hb = crate::llm::types::StageHeartbeat {
                model_id: model_id.clone(),
                stage_index,
                node_address: node_address.clone(),
                loaded: true,
                current_requests: active_requests,
                tokens_served: 0,
                avg_latency_ms: 0.0,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };
            ctx.model_registry.record_heartbeat(hb);
        }

        // ─── Federated Training handlers (Phase 5) ──────────────────────────
        P2pMessage::TrainingRoundStart {
            model_id,
            round_id,
            checkpoint_file_id,
            dataset_shard_ids,
            learning_rate,
            batch_size,
        } => {
            info!("Training round {round_id} started for model {model_id}");
            let _ = ctx
                .training_tx
                .send(TrainingP2pEvent::RoundStart {
                    model_id,
                    round_id,
                    checkpoint_file_id,
                    dataset_shard_ids,
                    learning_rate,
                    batch_size,
                })
                .await;
        }

        P2pMessage::GradientSubmit {
            model_id,
            round_id,
            worker,
            gradient_data_b64,
            num_samples,
            gradient_hash,
        } => {
            info!(
                "Gradient received from {} for round {round_id}",
                &worker[..12.min(worker.len())]
            );
            let _ = ctx
                .training_tx
                .send(TrainingP2pEvent::GradientReceived {
                    model_id,
                    round_id,
                    worker,
                    gradient_data_b64,
                    num_samples,
                    gradient_hash,
                })
                .await;
        }

        P2pMessage::TrainingRoundComplete {
            model_id,
            round_id,
            new_checkpoint_file_id,
            aggregated_loss,
            participating_workers,
        } => {
            info!(
                "Training round {round_id} complete for model {model_id} (loss={aggregated_loss:.4}, {} workers)",
                participating_workers.len()
            );
            let _ = ctx
                .training_tx
                .send(TrainingP2pEvent::RoundComplete {
                    model_id,
                    round_id,
                    new_checkpoint_file_id,
                    aggregated_loss,
                    participating_workers,
                })
                .await;
        }

        // ─── Tool execution handlers (Phase 6) ─────────────────────────────
        P2pMessage::ToolExecutionRequest {
            task_id,
            tool_name,
            parameters: _,
            requester,
            timeout_ms: _,
        } => {
            info!(
                "Tool execution request {} from {}: {tool_name}",
                &task_id[..16.min(task_id.len())],
                &requester[..12.min(requester.len())]
            );
            // ToolExecutorAgent handles execution via API
        }

        P2pMessage::ToolExecutionResult {
            task_id,
            success,
            result: _,
            execution_time_ms,
        } => {
            info!(
                "Tool result for {}: success={success} ({execution_time_ms}ms)",
                &task_id[..16.min(task_id.len())]
            );
        }

        // ─── Autonomo handlers (Phase 5 integration) ──────────────────────────
        P2pMessage::AutonomoHeartbeatGossip {
            payload_b64,
            sender_wallet,
        } => {
            let data = serde_json::json!({
                "wallet": sender_wallet,
                "gibbertalk_payload": payload_b64,
                "last_seen": chrono::Utc::now().to_rfc3339(),
            });
            let _ = store.put_heartbeat(&sender_wallet, &data);
        }

        P2pMessage::AutonomoChatGossip {
            from_wallet,
            to_wallet,
            message,
            msg_type,
            timestamp,
        } => {
            let msg_id = format!("{}_{}", chrono::Utc::now().timestamp_millis(), from_wallet);
            let data = serde_json::json!({
                "id": msg_id,
                "from_wallet": from_wallet,
                "to_wallet": to_wallet,
                "message": message,
                "msg_type": msg_type,
                "timestamp": timestamp,
            });
            let _ = store.put_agent_message(&msg_id, &data);
        }

        P2pMessage::AutonomoSecureRelayGossip { relay } => {
            if let Some(message_id) = relay.get("id").and_then(|v| v.as_str()) {
                let _ = store.put_secure_relay_message(message_id, &relay);
            }
        }
    }
}
