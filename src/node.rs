use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{info, warn};

use crate::agents::compute_scheduler::{ComputeSchedulerAgent, ComputeSchedulerConfig};
use crate::agents::inference_router::{InferenceRouterAgent, InferenceRouterConfig};
use crate::agents::reputation_oracle::ReputationOracleAgent;
use crate::agents::storage_keeper::{StorageKeeperAgent, StorageKeeperConfig};
use crate::agents::tool_executor::ToolExecutorAgent;
use crate::agents::training_coordinator::TrainingCoordinatorAgent;
use crate::agents::AgentManager;
use crate::api::{self, AppState};
use crate::audit::ledger::AuditLedger;
use crate::block::Block;
use crate::compute::reputation::ReputationOracle;
use crate::compute::scheduler::Scheduler;
use crate::config::{genesis, NodeConfig};
use crate::consensus;
use crate::crypto::Wallet;
use crate::fs::dht::DhtTable;
use crate::fs::local_store::ChunkStore;
use crate::llm::registry::ModelRegistry;
use crate::mempool::Mempool;
use crate::p2p::{InferenceP2pEvent, P2p, PeerContext, TrainingP2pEvent};
use crate::peer::normalize_peer_endpoint;
use crate::poi::PoiEngine;
use crate::security::SecurityMonitor;
use crate::store::Store;

const BLOCK_BROADCAST_CAP: usize = 64;
const MEMPOOL_EVICTION_SECS: u64 = 300; // evict stale txs every 5 minutes
const KNOWN_PEER_BOOTSTRAP_LIMIT: usize = 256;

fn dedup_preserve_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

pub struct Node {
    config: NodeConfig,
    store: Arc<Store>,
    mempool: Arc<Mempool>,
    p2p: Arc<P2p>,
    block_tx: broadcast::Sender<Block>,
    wallet: Option<Wallet>,
    poi_engine: Arc<PoiEngine>,
}

impl Node {
    /// Create and initialise all node components.
    pub fn new(config: NodeConfig, wallet: Option<Wallet>) -> anyhow::Result<Self> {
        // Persistent chain storage (creates + bootstraps genesis on first run)
        let store = Arc::new(Store::open(&config.data_dir)?);

        // In-memory transaction pool
        let mempool = Mempool::new();

        // Broadcast channel: block_producer → P2P gossip (and future subscribers)
        let (block_tx, _) = broadcast::channel::<Block>(BLOCK_BROADCAST_CAP);

        // P2P layer — holds its own clone of block_tx so it can subscribe per-connection
        let p2p = P2p::new(block_tx.clone());

        // Proof of Intelligence consensus engine
        let poi_engine = Arc::new(PoiEngine::new());

        Ok(Self {
            config,
            store,
            mempool,
            p2p,
            block_tx,
            wallet,
            poi_engine,
        })
    }

    /// Start all subsystems. Runs until the process is killed.
    pub async fn run(self) -> anyhow::Result<()> {
        let Self {
            config,
            store,
            mempool,
            p2p,
            block_tx,
            wallet,
            poi_engine,
        } = self;
        let api_wallet = wallet.clone();
        let treasury_wallet_path = config.data_dir.join("mission_treasury_wallet.json");
        let mission_treasury_wallet = if treasury_wallet_path.exists() {
            Wallet::load_from_file(&treasury_wallet_path)
                .map(Some)
                .map_err(|e| anyhow::anyhow!("Failed to load mission treasury wallet: {e}"))?
        } else {
            let generated = Wallet::generate();
            generated
                .save_to_file(&treasury_wallet_path)
                .map_err(|e| anyhow::anyhow!("Failed to save mission treasury wallet: {e}"))?;
            Some(generated)
        };

        info!("Arobi Network node starting up");
        info!("   Consensus : Proof of Intelligence (PoI)");
        info!("   Data dir  : {}", config.data_dir.display());
        info!("   P2P port  : {}", config.p2p_port);
        info!("   API port  : {}", config.api_port);
        info!("   Mining    : {}", config.mine);
        info!("   Redial    : {}s", config.redial_interval_secs.max(5));
        info!("   Chain tip : {}", store.chain_height().unwrap_or(0));
        if !config.advertised_addrs.is_empty() {
            info!("   Advertise : {}", config.advertised_addrs.join(", "));
        }
        if let Some(ref treasury) = mission_treasury_wallet {
            info!("   Treasury  : {}", treasury.address);
        }

        // ── ArobiFS: distributed file system ─────────────────────────────
        let chunk_store = Arc::new(
            ChunkStore::open(&config.data_dir, store.db().clone())
                .expect("Failed to initialize ArobiFS chunk store"),
        );
        let dht_address = wallet
            .as_ref()
            .map(|w| w.address.clone())
            .unwrap_or_else(|| format!("relay_{}", config.p2p_port));
        let dht = Arc::new(DhtTable::new(&dht_address));
        info!(
            "   ArobiFS  : initialized (DHT node {})",
            &dht_address[..12.min(dht_address.len())]
        );

        // ── Agents: Records Keeper + Firecrawler + StorageKeeper ──────────
        let mut agent_manager = AgentManager::new();
        agent_manager
            .initialize(store.clone(), mempool.clone())
            .await?;

        // StorageKeeper agent
        let storage_keeper = StorageKeeperAgent::new(
            chunk_store.clone(),
            dht.clone(),
            StorageKeeperConfig::default(),
        );
        agent_manager.initialize_storage_keeper(storage_keeper);

        // ── ArobiCompute: distributed compute marketplace ─────────────────
        let compute_scheduler = Arc::new(Scheduler::new());
        let reputation_oracle = Arc::new(ReputationOracle::new());
        let compute_agent = ComputeSchedulerAgent::new(
            compute_scheduler.clone(),
            reputation_oracle.clone(),
            ComputeSchedulerConfig::default(),
        );
        agent_manager.initialize_compute_scheduler(compute_agent);
        let reputation_agent = ReputationOracleAgent::new(reputation_oracle.clone());
        agent_manager.initialize_reputation_oracle(reputation_agent);
        info!("   Compute  : marketplace initialized");

        // ── ArobiLLM: decentralized language model ────────────────────────────
        let model_registry = Arc::new(ModelRegistry::new());
        let inference_agent = Arc::new(InferenceRouterAgent::new(
            model_registry.clone(),
            InferenceRouterConfig::default(),
        ));
        agent_manager.initialize_inference_router(inference_agent.clone());
        info!("   LLM      : inference router initialized");

        // ── Tool Executor Agent (Phase 6) ──────────────────────────────────
        let tool_executor = Arc::new(ToolExecutorAgent::new(store.db().clone()));
        agent_manager.initialize_tool_executor(tool_executor.clone());
        info!(
            "   Tools    : executor initialized ({} tools)",
            tool_executor.list_tools().len()
        );

        // ── Security Monitor ────────────────────────────────────────────────
        let security = Arc::new(SecurityMonitor::new());

        // Wire Records Keeper anomaly events to Security Monitor
        if let Some(rk) = agent_manager.get_records_keeper() {
            let sec = security.clone();
            let mut rx = rk.subscribe();
            tokio::spawn(async move {
                while let Ok(event) = rx.recv().await {
                    if let crate::agents::records_keeper::RecordsEvent::AnomalyDetected(flag) =
                        event
                    {
                        sec.report_anomaly(flag).await;
                    }
                }
            });
        }

        // ── Channels for subsystem P2P events ───────────────────────────────
        let (inference_tx, mut inference_rx) = mpsc::channel::<InferenceP2pEvent>(256);
        let (training_tx, mut training_rx) = mpsc::channel::<TrainingP2pEvent>(256);

        // Build PeerContext for P2P handlers
        let node_address = wallet
            .as_ref()
            .map(|w| w.address.clone())
            .unwrap_or_else(|| format!("relay_{}", config.p2p_port));

        if let Some(ref w) = wallet {
            store.set_node_address(&w.address)?;
        }
        if let Some(ref treasury) = mission_treasury_wallet {
            store.set_mission_treasury_address(&treasury.address)?;
        }

        let peer_ctx = Arc::new(PeerContext {
            store: store.clone(),
            mempool: mempool.clone(),
            compute_scheduler: compute_scheduler.clone(),
            reputation_oracle: reputation_oracle.clone(),
            model_registry: model_registry.clone(),
            inference_tx,
            training_tx,
            node_address: node_address.clone(),
            advertised_addrs: config.advertised_addrs.clone(),
        });

        // ── Federated Training Coordinator ──────────────────────────────────
        let training_coordinator = Arc::new(TrainingCoordinatorAgent::new(
            chunk_store.clone(),
            p2p.clone(),
            node_address.clone(),
        ));
        agent_manager.initialize_training_coordinator(training_coordinator.clone());
        info!("   Training : federated coordinator initialized");

        // Spawn inference P2P event processor
        {
            let _inference_agent = inference_agent.clone();
            tokio::spawn(async move {
                while let Some(event) = inference_rx.recv().await {
                    match event {
                        InferenceP2pEvent::PipelineForward {
                            request_id,
                            model_id,
                            stage_index,
                            ..
                        } => {
                            info!(
                                "Inference P2P: forward request {} model {} stage {}",
                                &request_id[..16.min(request_id.len())],
                                model_id,
                                stage_index
                            );
                        }
                        InferenceP2pEvent::PipelineResult {
                            request_id,
                            next_token,
                            is_done,
                            ..
                        } => {
                            info!(
                                "Inference P2P: result request {} token {} done={}",
                                &request_id[..16.min(request_id.len())],
                                next_token,
                                is_done
                            );
                        }
                    }
                }
            });
        }

        // Spawn training P2P event processor
        {
            let coordinator = training_coordinator.clone();
            tokio::spawn(async move {
                while let Some(event) = training_rx.recv().await {
                    match event {
                        TrainingP2pEvent::RoundStart {
                            model_id, round_id, ..
                        } => {
                            info!("Training P2P: round {round_id} started for model {model_id}");
                        }
                        TrainingP2pEvent::GradientReceived {
                            model_id,
                            round_id,
                            worker,
                            gradient_data_b64,
                            num_samples,
                            gradient_hash,
                        } => {
                            coordinator.receive_gradient(
                                &model_id,
                                round_id,
                                &worker,
                                &gradient_data_b64,
                                num_samples,
                                &gradient_hash,
                            );
                        }
                        TrainingP2pEvent::RoundComplete {
                            model_id,
                            round_id,
                            aggregated_loss,
                            ..
                        } => {
                            info!("Training P2P: round {round_id} complete for model {model_id} (loss={aggregated_loss:.4})");
                        }
                    }
                }
            });
        }

        // ── P2P: accept inbound connections ───────────────────────────────────
        {
            let p2p = p2p.clone();
            let ctx = peer_ctx.clone();
            let port = config.p2p_port;
            tokio::spawn(async move {
                p2p.listen(port, ctx).await;
            });
        }

        // Persist configured static seeds so they survive process restarts.
        let mut configured_bootstrap: Vec<String> = genesis::DEFAULT_SEEDS
            .iter()
            .map(|s| s.to_string())
            .chain(config.seed_nodes.iter().cloned())
            .collect();
        dedup_preserve_order(&mut configured_bootstrap);

        let mut local_bootstrap_aliases: HashSet<String> = config
            .advertised_addrs
            .iter()
            .filter_map(|addr| normalize_peer_endpoint(addr))
            .collect();
        for implicit_local in [
            format!("127.0.0.1:{}", config.p2p_port),
            format!("localhost:{}", config.p2p_port),
        ] {
            if let Some(addr) = normalize_peer_endpoint(&implicit_local) {
                local_bootstrap_aliases.insert(addr);
            }
        }

        let ignored_local_bootstrap: Vec<String> = configured_bootstrap
            .iter()
            .filter(|addr| local_bootstrap_aliases.contains(addr.as_str()))
            .cloned()
            .collect();
        if !ignored_local_bootstrap.is_empty() {
            warn!(
                "Ignoring bootstrap endpoints that resolve back to this node: {}",
                ignored_local_bootstrap.join(", ")
            );
        }

        let static_bootstrap: Vec<String> = configured_bootstrap
            .into_iter()
            .filter(|addr| !local_bootstrap_aliases.contains(addr))
            .collect();

        for seed in &static_bootstrap {
            let _ = store.remember_peer(seed, "bootstrap");
        }
        let removed_bootstrap = store
            .sync_bootstrap_peers(&static_bootstrap)
            .unwrap_or_else(|e| {
                warn!("Failed to reconcile persisted bootstrap peers: {e}");
                0
            });
        let removed_poisoned = store
            .prune_known_peers(&local_bootstrap_aliases)
            .unwrap_or_else(|e| {
                warn!("Failed to prune poisoned/local peers from peer book: {e}");
                0
            });
        if removed_bootstrap > 0 || removed_poisoned > 0 {
            info!(
                "   Peer book : removed {removed_bootstrap} stale bootstrap and {removed_poisoned} local/non-routable peer(s)"
            );
        }

        // ── P2P: initial bootstrap dials from static + persisted peers ───────
        let persisted_bootstrap = match store
            .list_bootstrap_peer_addresses(KNOWN_PEER_BOOTSTRAP_LIMIT, &local_bootstrap_aliases)
        {
            Ok(peers) => peers,
            Err(e) => {
                warn!("Failed to load persisted peers for bootstrap: {e}");
                Vec::new()
            }
        };

        let mut initial_targets = static_bootstrap.clone();
        initial_targets.extend(persisted_bootstrap.clone());
        dedup_preserve_order(&mut initial_targets);

        if initial_targets.is_empty() {
            warn!(
                "No bootstrap peers available (static seeds empty and peerbook empty). \
                 Configure seeds/advertise endpoints so peers can discover this node."
            );
        } else {
            info!(
                "   Bootstrap : {} target(s) ({} static, {} persisted)",
                initial_targets.len(),
                static_bootstrap.len(),
                persisted_bootstrap.len()
            );
        }

        for seed in initial_targets {
            let p2p = p2p.clone();
            let ctx = peer_ctx.clone();
            tokio::spawn(async move {
                p2p.dial(seed, ctx).await;
            });
        }

        // Retry dials periodically so peers that come online later are discovered.
        let redial_secs = config.redial_interval_secs.max(5);
        if redial_secs > 0 {
            let p2p_reconnect = p2p.clone();
            let ctx_reconnect = peer_ctx.clone();
            let store_reconnect = store.clone();
            let static_reconnect = static_bootstrap.clone();
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(tokio::time::Duration::from_secs(redial_secs));
                // Consume immediate tick; initial dials were already dispatched above.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let mut reconnect_targets = static_reconnect.clone();
                    if let Ok(mut peers) = store_reconnect.list_bootstrap_peer_addresses(
                        KNOWN_PEER_BOOTSTRAP_LIMIT,
                        &local_bootstrap_aliases,
                    ) {
                        reconnect_targets.append(&mut peers);
                    }
                    dedup_preserve_order(&mut reconnect_targets);

                    for seed in reconnect_targets {
                        let p2p = p2p_reconnect.clone();
                        let ctx = ctx_reconnect.clone();
                        tokio::spawn(async move {
                            p2p.dial(seed, ctx).await;
                        });
                    }
                }
            });
        }

        // ── Mempool: periodic eviction of expired transactions ─────────────────
        {
            let mempool = mempool.clone();
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(tokio::time::Duration::from_secs(MEMPOOL_EVICTION_SECS));
                loop {
                    ticker.tick().await;
                    mempool.evict_expired().await;
                }
            });
        }

        // ── Block producer ────────────────────────────────────────────────────
        if config.mine {
            match wallet {
                Some(w) => {
                    let store = store.clone();
                    let mempool = mempool.clone();
                    let tx = block_tx.clone();
                    let poi = poi_engine.clone();
                    tokio::spawn(async move {
                        consensus::block_producer(w, store, mempool, tx, poi).await;
                    });
                }
                None => {
                    anyhow::bail!(
                        "Mining is enabled but no wallet found.\n\
                         Run `arobi-network wallet new` to create one, \
                         then restart with the wallet file in your data directory."
                    );
                }
            }
        } else {
            info!("Mining disabled — running as relay node");
        }

        // ── Audit Ledger for AI decisions ────────────────────────────────────────
        let audit_ledger = Arc::new(AuditLedger::new());
        info!("AI Decision Audit Ledger initialized");

        // ── HTTP API (runs in foreground, blocks until shutdown) ───────────────
        let api_state = AppState {
            store: store.clone(),
            mempool: mempool.clone(),
            p2p: p2p.clone(),
            poi_engine: poi_engine.clone(),
            node_wallet: api_wallet,
            mission_treasury_wallet,
            security: security.clone(),
            chunk_store: chunk_store.clone(),
            dht: dht.clone(),
            compute_scheduler: compute_scheduler.clone(),
            reputation_oracle: reputation_oracle.clone(),
            model_registry: model_registry.clone(),
            inference_router: inference_agent.clone(),
            tool_executor: tool_executor.clone(),
            audit_ledger: audit_ledger.clone(),
            // Admin signing key for ledger writes — hex-encoded Ed25519 private key
            admin_signing_key: std::env::var("AROBL_ADMIN_SIGNING_KEY").ok(),
        };
        api::serve(api_state, config.api_port).await;

        Ok(())
    }
}
