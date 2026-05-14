use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::info;

use crate::audit::ledger::{migrate_legacy_lane_entries, AuditEntry, AuditLane};
use crate::block::{genesis_block, Block, Transaction};
use crate::config::genesis;
use crate::crypto::Wallet;
use crate::peer::{is_public_peer_endpoint, normalize_peer_endpoint};

/// Returns true if the address is a no-private-key consensus pool.
/// Pool addresses can only spend through consensus-created transactions.
fn is_consensus_pool_address(addr: &str) -> bool {
    addr.starts_with("PUBLICP00L") || addr.starts_with("NODEOP00L")
}

const KNOWN_PEER_FAILURE_QUARANTINE_THRESHOLD: u64 = 3;
const KNOWN_PEER_QUARANTINE_BASE_MS: u64 = 15 * 60 * 1000;
const KNOWN_PEER_PRUNE_FAILURES: u64 = 8;

/// Persistent blockchain store backed by sled (pure-Rust embedded KV database).
/// All data survives process restarts.
pub struct Store {
    db: Db,
    data_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownPeerRecord {
    pub addr: String,
    pub source: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub successful_connects: u64,
    pub last_connected_ms: u64,
    #[serde(default)]
    pub failed_connects: u64,
    #[serde(default)]
    pub last_failed_ms: u64,
    #[serde(default)]
    pub quarantined_until_ms: u64,
}

// sled::Db is Send + Sync — Store is too.
unsafe impl Send for Store {}
unsafe impl Sync for Store {}

impl Store {
    /// Access the underlying sled database (used by agents for custom trees).
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Access the data directory path.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Open (or create) the store. Writes genesis block if the chain is empty.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let db = sled::open(data_dir.join("chain.db")).context("Failed to open sled database")?;
        let store = Self {
            db,
            data_dir: data_dir.to_path_buf(),
        };

        // Bootstrap genesis if this is a fresh node
        if store.get_block(0)?.is_none() {
            info!("Fresh node detected — writing genesis block...");
            let genesis = genesis_block();
            store.write_genesis(&genesis)?;
            info!("Genesis: {}", genesis.hash);
        } else {
            let h = store.chain_height()?;
            info!("Chain loaded from disk: height {h}");
        }

        Ok(store)
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    fn blocks(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("blocks")?)
    }
    fn meta(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("meta")?)
    }
    fn balances(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("balances")?)
    }
    fn nonces(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("nonces")?)
    }
    fn txs(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("transactions")?)
    }
    fn peer_book(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("peer_book")?)
    }
    fn audit_entries(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("audit_entries")?)
    }

    fn write_genesis(&self, g: &Block) -> Result<()> {
        // Store block
        self.blocks()?
            .insert(0u64.to_be_bytes(), serde_json::to_vec(g)?)?;
        // Update tip
        self.meta()?.insert("tip_height", &0u64.to_be_bytes())?;
        self.meta()?.insert("tip_hash", g.hash.as_bytes())?;
        // Apply genesis mints
        for tx in &g.transactions {
            let current = self.get_balance(&tx.to)?;
            self.set_balance_raw(&tx.to, current + tx.amount)?;
            // Index transaction
            self.txs()?
                .insert(tx.id.as_bytes(), serde_json::to_vec(tx)?)?;
        }
        self.db.flush()?;
        Ok(())
    }

    fn set_balance_raw(&self, address: &str, balance: u64) -> Result<()> {
        self.balances()?
            .insert(address.as_bytes(), &balance.to_be_bytes())?;
        Ok(())
    }

    fn set_nonce_raw(&self, address: &str, nonce: u64) -> Result<()> {
        self.nonces()?
            .insert(address.as_bytes(), &nonce.to_be_bytes())?;
        Ok(())
    }

    fn u64_from_tree(tree: &sled::Tree, key: &[u8]) -> Result<u64> {
        match tree.get(key)? {
            Some(b) => {
                let arr: [u8; 8] = b
                    .as_ref()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Bad u64 bytes in sled"))?;
                Ok(u64::from_be_bytes(arr))
            }
            None => Ok(0),
        }
    }

    // ── Public reads ───────────────────────────────────────────────────────────

    pub fn chain_height(&self) -> Result<u64> {
        Self::u64_from_tree(&self.meta()?, b"tip_height")
    }

    pub fn tip_hash(&self) -> Result<String> {
        match self.meta()?.get(b"tip_hash")? {
            Some(b) => Ok(String::from_utf8(b.to_vec())?),
            None => Ok("0".repeat(64)),
        }
    }

    pub fn get_block(&self, height: u64) -> Result<Option<Block>> {
        match self.blocks()?.get(height.to_be_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    pub fn get_blocks(&self, from: u64, to: u64) -> Result<Vec<Block>> {
        let tree = self.blocks()?;
        let mut out = Vec::new();
        for h in from..=to {
            if let Some(b) = tree.get(h.to_be_bytes())? {
                out.push(serde_json::from_slice(&b)?);
            }
        }
        Ok(out)
    }

    /// Latest N blocks, newest first.
    #[allow(dead_code)]
    pub fn latest_blocks(&self, n: usize) -> Result<Vec<Block>> {
        let tip = self.chain_height()?;
        let from = tip.saturating_sub(n as u64 - 1);
        let mut blocks = self.get_blocks(from, tip)?;
        blocks.reverse();
        Ok(blocks)
    }

    pub fn get_balance(&self, address: &str) -> Result<u64> {
        Self::u64_from_tree(&self.balances()?, address.as_bytes())
    }

    pub fn get_nonce(&self, address: &str) -> Result<u64> {
        Self::u64_from_tree(&self.nonces()?, address.as_bytes())
    }

    pub fn get_transaction(&self, id: &str) -> Result<Option<Transaction>> {
        match self.txs()?.get(id.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    pub fn tx_exists(&self, id: &str) -> Result<bool> {
        Ok(self.txs()?.contains_key(id.as_bytes())?)
    }

    pub fn append_audit_entry(&self, entry: &AuditEntry) -> Result<()> {
        self.audit_entries()?
            .insert(entry.block_height.to_be_bytes(), serde_json::to_vec(entry)?)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_audit_entries(&self) -> Result<Vec<AuditEntry>> {
        let tree = self.audit_entries()?;
        let mut entries: Vec<(AuditEntry, bool)> = Vec::new();
        for item in tree.iter() {
            let (_, bytes) = item?;
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            let missing_lane = value.get("lane").is_none();
            if missing_lane {
                let metadata = value
                    .get("metadata")
                    .cloned()
                    .map(serde_json::from_value::<HashMap<String, String>>)
                    .transpose()?
                    .unwrap_or_default();
                let network_context = value
                    .get("network_context")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("private");
                value["lane"] =
                    serde_json::to_value(AuditLane::from_context(network_context, &metadata))?;
            }

            entries.push((serde_json::from_value(value)?, missing_lane));
        }

        let (entries, migrated) = migrate_legacy_lane_entries(entries)
            .map_err(|err| anyhow::anyhow!(err))
            .context("Failed to migrate legacy audit lane entries")?;
        if migrated {
            self.replace_audit_entries(&entries)?;
        }

        Ok(entries)
    }

    fn replace_audit_entries(&self, entries: &[AuditEntry]) -> Result<()> {
        let tree = self.audit_entries()?;
        tree.clear()?;
        for entry in entries {
            tree.insert(entry.block_height.to_be_bytes(), serde_json::to_vec(entry)?)?;
        }
        self.db.flush()?;
        Ok(())
    }

    // ── Block application ──────────────────────────────────────────────────────

    /// Validate all transactions against current state, then atomically commit
    /// the block and update balances, nonces, and the chain tip.
    ///
    /// Special addresses:
    /// - GENESIS:   Mint-only at block 0. Can fund accounts but never spends.
    /// - PUBLICP00L/NODEOP00L: no private key. Consensus-created pool txs skip
    ///   nonce checks and debit only the pool balance.
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        let cur_height = self.chain_height()?;
        if block.height != cur_height + 1 {
            anyhow::bail!(
                "Height mismatch: expected {}, got {}",
                cur_height + 1,
                block.height
            );
        }
        if block.prev_hash != self.tip_hash()? {
            anyhow::bail!("prev_hash does not match current tip");
        }

        // --- Validate pass (no writes) ---
        let mut in_block_nonces: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut in_block_debits: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        for tx in &block.transactions {
            // GENESIS and consensus pools are special: no nonce or user signature.
            if tx.from == "GENESIS" || is_consensus_pool_address(&tx.from) {
                continue;
            }
            let expected_nonce = {
                let stored = self.get_nonce(&tx.from)?;
                stored + *in_block_nonces.get(&tx.from).unwrap_or(&0)
            };
            if tx.nonce != expected_nonce {
                anyhow::bail!(
                    "Tx {} nonce invalid: expected {expected_nonce}, got {}",
                    &tx.id[..8],
                    tx.nonce
                );
            }
            *in_block_nonces.entry(tx.from.clone()).or_insert(0) += 1;

            let total_cost = tx.amount + tx.fee;
            let balance = self.get_balance(&tx.from)?;

            // Founder vesting enforcement: cap spendable balance at vested total.
            // The founder has 500M immediate + up to 2B vesting over 8 years.
            // Any transaction spending more than the vested total is rejected.
            let spendable_balance = if tx.from == genesis::FOUNDER_ADDRESS {
                genesis::founder_total_balance(tx.timestamp)
            } else {
                balance
            };

            let already_spent = *in_block_debits.get(&tx.from).unwrap_or(&0);
            if spendable_balance < already_spent + total_cost {
                anyhow::bail!(
                    "Tx {} insufficient balance: have {:.4} AURA, need {:.4} AURA (founder vesting: {:.4} AURA available)",
                    &tx.id[..8],
                    spendable_balance as f64 / genesis::DECIMAL_FACTOR as f64,
                    total_cost as f64 / genesis::DECIMAL_FACTOR as f64,
                    spendable_balance as f64 / genesis::DECIMAL_FACTOR as f64
                );
            }
            *in_block_debits.entry(tx.from.clone()).or_insert(0) += total_cost;
        }

        // --- Write pass ---
        for tx in &block.transactions {
            if tx.from == "GENESIS" {
                // Genesis mint: no sender debit, just credit recipient
                let rbal = self.get_balance(&tx.to)?;
                self.set_balance_raw(&tx.to, rbal + tx.amount)?;
            } else if is_consensus_pool_address(&tx.from) {
                // Consensus pools send governance or node-ops emissions.
                // Consensus already capped the amount at pool_balance.
                let pool_bal = self.get_balance(&tx.from)?;
                self.set_balance_raw(&tx.from, pool_bal.saturating_sub(tx.amount))?;
                let rbal = self.get_balance(&tx.to)?;
                self.set_balance_raw(&tx.to, rbal + tx.amount)?;
            } else {
                // Normal user transaction
                let bal = self.get_balance(&tx.from)?;
                self.set_balance_raw(&tx.from, bal - tx.amount - tx.fee)?;
                let n = self.get_nonce(&tx.from)?;
                self.set_nonce_raw(&tx.from, n + 1)?;
                if tx.fee > 0 && block.validator != "GENESIS" {
                    let vbal = self.get_balance(&block.validator)?;
                    self.set_balance_raw(&block.validator, vbal + tx.fee)?;
                }
                let rbal = self.get_balance(&tx.to)?;
                self.set_balance_raw(&tx.to, rbal + tx.amount)?;
            }
            // Store transaction
            self.txs()?
                .insert(tx.id.as_bytes(), serde_json::to_vec(tx)?)?;
        }

        // Block reward: consensus already created the reward tx from PUBLICP00L
        // to the validator. No duplicate credit needed here.

        // Store block and update tip
        self.blocks()?
            .insert(block.height.to_be_bytes(), serde_json::to_vec(block)?)?;
        self.meta()?
            .insert("tip_height", &block.height.to_be_bytes())?;
        self.meta()?.insert("tip_hash", block.hash.as_bytes())?;

        // fsync — guarantees durability before returning
        self.db.flush()?;

        Ok(())
    }

    // ── ArobiFS tree accessors ────────────────────────────────────────────────

    #[allow(dead_code)]
    pub fn fs_chunks(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_chunks")?)
    }

    #[allow(dead_code)]
    pub fn fs_manifests(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_manifests")?)
    }

    #[allow(dead_code)]
    pub fn fs_dht(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_dht")?)
    }

    #[allow(dead_code)]
    pub fn fs_pins(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_pins")?)
    }

    #[allow(dead_code)]
    pub fn fs_storage_proofs(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_storage_proofs")?)
    }

    // ── ArobiCompute tree accessors (Phase 3) ─────────────────────────────────

    #[allow(dead_code)]
    pub fn compute_capabilities(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("compute_capabilities")?)
    }

    #[allow(dead_code)]
    pub fn compute_jobs(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("compute_jobs")?)
    }

    #[allow(dead_code)]
    pub fn compute_results(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("compute_results")?)
    }

    #[allow(dead_code)]
    pub fn compute_reputation(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("compute_reputation")?)
    }

    // ── ArobiLLM tree accessors (Phase 4) ─────────────────────────────────────

    #[allow(dead_code)]
    pub fn llm_models(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("llm_models")?)
    }

    #[allow(dead_code)]
    pub fn llm_stages(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("llm_stages")?)
    }

    #[allow(dead_code)]
    pub fn llm_requests(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("llm_requests")?)
    }

    #[allow(dead_code)]
    pub fn llm_responses(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("llm_responses")?)
    }

    // ── Autonomo tree accessors ──────────────────────────────────────────────

    fn autonomo_nodes(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_nodes")?)
    }

    /// Get this node's wallet address from config
    pub fn get_node_address(&self) -> Result<String> {
        match self.meta()?.get("node_address")? {
            Some(b) => Ok(String::from_utf8_lossy(&b).to_string()),
            None => {
                // Backward-compatible fallback: infer address from wallet.json
                // for nodes started before node_address metadata existed.
                let wallet_path = self.data_dir.join("wallet.json");
                if wallet_path.exists() {
                    if let Ok(wallet) = Wallet::load_from_file(&wallet_path) {
                        let addr = wallet.address;
                        let _ = self.meta()?.insert("node_address", addr.as_bytes());
                        let _ = self.db.flush();
                        return Ok(addr);
                    }
                }
                Ok(String::new())
            }
        }
    }

    /// Persist this node's wallet address into metadata.
    pub fn set_node_address(&self, address: &str) -> Result<()> {
        self.meta()?.insert("node_address", address.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Get the dedicated Autonomo mission treasury wallet address.
    pub fn get_mission_treasury_address(&self) -> Result<String> {
        match self.meta()?.get("mission_treasury_address")? {
            Some(b) => Ok(String::from_utf8_lossy(&b).to_string()),
            None => Ok(String::new()),
        }
    }

    /// Persist the dedicated Autonomo mission treasury wallet address.
    pub fn set_mission_treasury_address(&self, address: &str) -> Result<()> {
        self.meta()?
            .insert("mission_treasury_address", address.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    // ── Peer discovery + persistence ──────────────────────────────────────────

    fn unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn quarantine_backoff_ms(failed_connects: u64) -> u64 {
        let multiplier = 1u64
            << failed_connects
                .saturating_sub(KNOWN_PEER_FAILURE_QUARANTINE_THRESHOLD)
                .min(6);
        KNOWN_PEER_QUARANTINE_BASE_MS.saturating_mul(multiplier)
    }

    fn should_replace_source(current: &str, incoming: &str) -> bool {
        if incoming.is_empty() {
            return false;
        }
        if incoming == "bootstrap" {
            return true;
        }
        current.trim().is_empty() || current != "bootstrap"
    }

    fn upsert_known_peer(
        &self,
        addr: &str,
        source: &str,
        mark_connected: bool,
        mark_failed: bool,
    ) -> Result<()> {
        let addr = addr.trim();
        if addr.is_empty() {
            return Ok(());
        }

        let now = Self::unix_ms();
        let tree = self.peer_book()?;
        let mut record = match tree.get(addr.as_bytes())? {
            Some(bytes) => {
                serde_json::from_slice::<KnownPeerRecord>(&bytes).unwrap_or(KnownPeerRecord {
                    addr: addr.to_string(),
                    source: source.to_string(),
                    first_seen_ms: now,
                    last_seen_ms: now,
                    successful_connects: 0,
                    last_connected_ms: 0,
                    failed_connects: 0,
                    last_failed_ms: 0,
                    quarantined_until_ms: 0,
                })
            }
            None => KnownPeerRecord {
                addr: addr.to_string(),
                source: source.to_string(),
                first_seen_ms: now,
                last_seen_ms: now,
                successful_connects: 0,
                last_connected_ms: 0,
                failed_connects: 0,
                last_failed_ms: 0,
                quarantined_until_ms: 0,
            },
        };

        record.addr = addr.to_string();
        record.last_seen_ms = now;
        if Self::should_replace_source(&record.source, source.trim()) {
            record.source = source.to_string();
        }

        if mark_connected {
            record.successful_connects = record.successful_connects.saturating_add(1);
            record.last_connected_ms = now;
            record.failed_connects = 0;
            record.last_failed_ms = 0;
            record.quarantined_until_ms = 0;
        }

        if mark_failed {
            record.failed_connects = record.failed_connects.saturating_add(1);
            record.last_failed_ms = now;
            if record.failed_connects >= KNOWN_PEER_FAILURE_QUARANTINE_THRESHOLD {
                record.quarantined_until_ms =
                    now.saturating_add(Self::quarantine_backoff_ms(record.failed_connects));
            }
        }

        tree.insert(addr.as_bytes(), serde_json::to_vec(&record)?)?;
        self.db.flush()?;
        Ok(())
    }

    /// Store a discovered peer endpoint for future bootstrap attempts.
    pub fn remember_peer(&self, addr: &str, source: &str) -> Result<()> {
        self.upsert_known_peer(addr, source, false, false)
    }

    /// Mark a peer endpoint as successfully connected.
    pub fn mark_peer_connected(&self, addr: &str, source: &str) -> Result<()> {
        self.upsert_known_peer(addr, source, true, false)
    }

    /// Mark a peer endpoint as failed/unreachable.
    pub fn mark_peer_failed(&self, addr: &str, source: &str) -> Result<()> {
        self.upsert_known_peer(addr, source, false, true)
    }

    /// Remove a persisted peer endpoint from the peer book.
    pub fn remove_known_peer(&self, addr: &str) -> Result<bool> {
        let addr = addr.trim();
        if addr.is_empty() {
            return Ok(false);
        }

        let removed = self.peer_book()?.remove(addr.as_bytes())?.is_some();
        if removed {
            self.db.flush()?;
        }
        Ok(removed)
    }

    /// Remove bootstrap records that are no longer present in the current seed set.
    pub fn sync_bootstrap_peers(&self, current_bootstrap: &[String]) -> Result<usize> {
        let desired: HashSet<String> = current_bootstrap
            .iter()
            .filter_map(|addr| normalize_peer_endpoint(addr))
            .collect();
        let tree = self.peer_book()?;
        let mut to_remove = Vec::new();

        for item in tree.iter() {
            let (_, value) = item?;
            let Ok(record) = serde_json::from_slice::<KnownPeerRecord>(&value) else {
                continue;
            };

            if record.source == "bootstrap" && !desired.contains(record.addr.trim()) {
                to_remove.push(record.addr);
            }
        }

        for addr in &to_remove {
            tree.remove(addr.as_bytes())?;
        }
        if !to_remove.is_empty() {
            self.db.flush()?;
        }
        Ok(to_remove.len())
    }

    /// Return known peer records sorted by most recently connected/seen first.
    pub fn list_known_peers(&self, limit: usize) -> Result<Vec<KnownPeerRecord>> {
        let tree = self.peer_book()?;
        let mut peers = Vec::new();

        for item in tree.iter() {
            let (_, v) = item?;
            if let Ok(mut rec) = serde_json::from_slice::<KnownPeerRecord>(&v) {
                rec.addr = rec.addr.trim().to_string();
                if !rec.addr.is_empty() {
                    peers.push(rec);
                }
            }
        }

        peers.sort_by(|a, b| {
            b.last_connected_ms
                .cmp(&a.last_connected_ms)
                .then_with(|| b.last_seen_ms.cmp(&a.last_seen_ms))
        });

        if limit == 0 {
            return Ok(Vec::new());
        }

        if peers.len() > limit {
            peers.truncate(limit);
        }

        Ok(peers)
    }

    /// Remove local aliases, poisoned private discoveries, and permanently dead peers.
    pub fn prune_known_peers(&self, local_aliases: &HashSet<String>) -> Result<usize> {
        let peers = self.list_known_peers(usize::MAX)?;
        let mut removed = 0usize;

        for peer in peers {
            let should_remove = local_aliases.contains(peer.addr.trim())
                || (peer.source != "bootstrap" && !is_public_peer_endpoint(&peer.addr))
                || (peer.successful_connects == 0
                    && peer.failed_connects >= KNOWN_PEER_PRUNE_FAILURES);

            if should_remove && self.remove_known_peer(&peer.addr)? {
                removed = removed.saturating_add(1);
            }
        }

        Ok(removed)
    }

    /// Return persisted bootstrap candidates that are healthy and externally routable.
    pub fn list_bootstrap_peer_addresses(
        &self,
        limit: usize,
        local_aliases: &HashSet<String>,
    ) -> Result<Vec<String>> {
        let now = Self::unix_ms();
        let mut peers = self.list_known_peers(usize::MAX)?;
        peers.retain(|peer| {
            !local_aliases.contains(peer.addr.trim())
                && (peer.quarantined_until_ms == 0 || peer.quarantined_until_ms <= now)
                && (peer.source == "bootstrap" || is_public_peer_endpoint(&peer.addr))
        });

        if limit == 0 {
            return Ok(Vec::new());
        }

        if peers.len() > limit {
            peers.truncate(limit);
        }

        Ok(peers.into_iter().map(|peer| peer.addr).collect())
    }

    /// Store an Autonomo node registration
    pub fn put_autonomo_node(&self, node_id: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_nodes()?.insert(node_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// List all registered Autonomo nodes
    pub fn list_autonomo_nodes(&self) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_nodes()?;
        let mut nodes = Vec::new();
        for item in tree.iter() {
            let (_, v) = item?;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                nodes.push(val);
            }
        }
        Ok(nodes)
    }

    // ── Autonomo heartbeats ───────────────────────────────────────────────────

    fn autonomo_heartbeats(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_heartbeats")?)
    }

    fn autonomo_messages(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_messages")?)
    }

    fn autonomo_secure_relay_messages(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_secure_relay_messages")?)
    }

    fn autonomo_spaces(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_spaces")?)
    }

    fn agent_knowledge(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("agent_knowledge")?)
    }

    fn autonomo_access_profiles(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_access_profiles")?)
    }

    fn autonomo_secure_memory(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_secure_memory")?)
    }

    fn autonomo_openclaw_bindings(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_openclaw_bindings")?)
    }

    /// Store agent heartbeat (position, status, room)
    pub fn put_heartbeat(&self, wallet: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_heartbeats()?
            .insert(wallet.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get agent heartbeat
    pub fn get_heartbeat(&self, wallet: &str) -> Result<Option<serde_json::Value>> {
        match self.autonomo_heartbeats()?.get(wallet.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// List all recent heartbeats
    pub fn list_heartbeats(&self) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_heartbeats()?;
        let mut out = Vec::new();
        for item in tree.iter() {
            let (_, v) = item?;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                out.push(val);
            }
        }
        Ok(out)
    }

    /// Store agent-to-agent message
    pub fn put_agent_message(&self, message_id: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_messages()?
            .insert(message_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// List recent agent messages
    pub fn list_agent_messages(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_messages()?;
        let mut out = Vec::new();
        for item in tree.iter().rev() {
            let (_, v) = item?;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                out.push(val);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Store a signed secure relay envelope for webclient apps.
    pub fn put_secure_relay_message(
        &self,
        message_id: &str,
        data: &serde_json::Value,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_secure_relay_messages()?
            .insert(message_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// List relay envelopes for one app/channel, newest first.
    pub fn list_secure_relay_messages(
        &self,
        app: &str,
        channel_tag: &str,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_secure_relay_messages()?;
        let mut out = Vec::new();
        for item in tree.iter().rev() {
            let (_, v) = item?;
            let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) else {
                continue;
            };
            let same_app = val.get("app").and_then(|v| v.as_str()) == Some(app);
            let same_channel = val.get("channel_tag").and_then(|v| v.as_str()) == Some(channel_tag);
            if same_app && same_channel {
                out.push(val);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Store a virtual space/room
    pub fn put_space(&self, space_id: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_spaces()?.insert(space_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get a virtual space
    pub fn get_space(&self, space_id: &str) -> Result<Option<serde_json::Value>> {
        match self.autonomo_spaces()?.get(space_id.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// List all virtual spaces
    pub fn list_spaces(&self) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_spaces()?;
        let mut out = Vec::new();
        for item in tree.iter() {
            let (_, v) = item?;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                out.push(val);
            }
        }
        Ok(out)
    }

    /// Store agent knowledge/memory
    pub fn put_knowledge(&self, key: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.agent_knowledge()?.insert(key.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get agent knowledge
    pub fn get_knowledge(&self, key: &str) -> Result<Option<serde_json::Value>> {
        match self.agent_knowledge()?.get(key.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// Store mission access profile bound to a wallet.
    pub fn put_access_profile(&self, wallet: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_access_profiles()?
            .insert(wallet.as_bytes(), bytes)?;
        Ok(())
    }

    /// Fetch mission access profile for a wallet.
    pub fn get_access_profile(&self, wallet: &str) -> Result<Option<serde_json::Value>> {
        match self.autonomo_access_profiles()?.get(wallet.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// Store secure memory metadata and ciphertext envelope.
    pub fn put_secure_memory(&self, key: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_secure_memory()?
            .insert(key.as_bytes(), bytes)?;
        Ok(())
    }

    /// Fetch secure memory metadata and ciphertext envelope.
    pub fn get_secure_memory(&self, key: &str) -> Result<Option<serde_json::Value>> {
        match self.autonomo_secure_memory()?.get(key.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// Store OpenClaw employee wallet binding.
    pub fn put_openclaw_binding(&self, employee_id: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_openclaw_bindings()?
            .insert(employee_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get OpenClaw employee wallet binding.
    pub fn get_openclaw_binding(&self, employee_id: &str) -> Result<Option<serde_json::Value>> {
        match self
            .autonomo_openclaw_bindings()?
            .get(employee_id.as_bytes())?
        {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    /// List all OpenClaw employee wallet bindings.
    pub fn list_openclaw_bindings(&self) -> Result<Vec<serde_json::Value>> {
        let tree = self.autonomo_openclaw_bindings()?;
        let mut out = Vec::new();
        for item in tree.iter() {
            let (_, v) = item?;
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&v) {
                out.push(val);
            }
        }
        Ok(out)
    }

    /// List OpenClaw employee wallet bindings filtered by master wallet.
    pub fn list_openclaw_bindings_for_master(
        &self,
        master_wallet: &str,
    ) -> Result<Vec<serde_json::Value>> {
        let mut out = Vec::new();
        for binding in self.list_openclaw_bindings()? {
            let is_match = binding
                .get("master_wallet")
                .and_then(|v| v.as_str())
                .map(|v| v == master_wallet)
                .unwrap_or(false);
            if is_match {
                out.push(binding);
            }
        }
        Ok(out)
    }

    // ── Autonomo vault limits ─────────────────────────────────────────────────

    fn autonomo_vault_limits(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("autonomo_vault_limits")?)
    }

    /// Store vault spending limits for a wallet
    pub fn put_vault_limits(&self, wallet: &str, data: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(data)?;
        self.autonomo_vault_limits()?
            .insert(wallet.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get vault spending limits for a wallet
    pub fn get_vault_limits(&self, wallet: &str) -> Result<Option<serde_json::Value>> {
        match self.autonomo_vault_limits()?.get(wallet.as_bytes())? {
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    // ── Autonomo action log listing ───────────────────────────────────────────

    /// List recent Autonomo actions from the transaction store
    pub fn list_autonomo_actions(
        &self,
        limit: usize,
        wallet_filter: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let tree = self.txs()?;
        let mut actions = Vec::new();

        for item in tree.iter().rev() {
            let (_, v) = item?;
            if let Ok(tx) = serde_json::from_slice::<Transaction>(&v) {
                if tx.to == "autonomo_action_ledger" {
                    let parsed_data = tx
                        .data
                        .as_ref()
                        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
                        .unwrap_or_else(|| serde_json::json!({}));
                    let actor_wallet = parsed_data
                        .get("actor_wallet")
                        .and_then(|w| w.as_str())
                        .unwrap_or(&tx.from)
                        .to_string();

                    if let Some(wf) = wallet_filter {
                        if actor_wallet != wf {
                            continue;
                        }
                    }
                    let action = serde_json::json!({
                        "id": tx.id,
                        "actor_wallet": actor_wallet,
                        "action_type": parsed_data
                            .get("action_type")
                            .and_then(|a| a.as_str())
                            .unwrap_or("unknown"),
                        "payload": parsed_data
                            .get("payload")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "risk_score": parsed_data
                            .get("risk_score")
                            .and_then(|r| r.as_f64())
                            .unwrap_or(0.0),
                        "chain_tx_hash": tx.id,
                        "timestamp": tx.timestamp,
                    });
                    actions.push(action);
                    if actions.len() >= limit {
                        break;
                    }
                }
            }
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ledger::{AuditLedger, DecisionSource, DecisionType};
    use sha3::{Digest, Keccak256};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store_dir(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "arobi-network-{name}-{}-{unique}",
            std::process::id()
        ))
    }

    fn legacy_pre_lane_hash(entry: &AuditEntry) -> String {
        let mut hasher = Keccak256::new();
        hasher.update(entry.entry_id.as_bytes());
        hasher.update(entry.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{}", entry.block_height).as_bytes());
        hasher.update(entry.previous_hash.as_bytes());
        hasher.update(format!("{:?}", entry.source).as_bytes());
        hasher.update(format!("{:?}", entry.decision_type).as_bytes());
        hasher.update(entry.model_id.as_bytes());
        hasher.update(entry.model_version.as_bytes());
        hasher.update(entry.input_hash.as_bytes());
        hasher.update(entry.decision.as_bytes());
        hasher.update(format!("{}", entry.confidence).as_bytes());
        hasher.update(entry.reasoning.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn write_legacy_audit_entry_without_lane(store: &Store, mut entry: AuditEntry) -> Result<()> {
        entry.hash = legacy_pre_lane_hash(&entry);
        let legacy_hash = entry.hash.clone();
        let mut value = serde_json::to_value(&entry)?;
        value
            .as_object_mut()
            .expect("audit entry serializes as object")
            .remove("lane");
        value["hash"] = serde_json::Value::String(legacy_hash);

        store.audit_entries()?.insert(
            entry.block_height.to_be_bytes(),
            serde_json::to_vec(&value)?,
        )?;
        store.db.flush()?;
        Ok(())
    }

    #[test]
    fn audit_entries_survive_store_reopen_and_rehydrate_ledger() -> Result<()> {
        let dir = temp_store_dir("audit-store");
        let entry_id;

        {
            let store = Store::open(&dir)?;
            let ledger = AuditLedger::new();
            let entry = ledger.record_decision_with_metadata(
                DecisionSource::Cortex,
                DecisionType::NetworkRouting,
                "q-ledger",
                "1.0.0",
                "Persist a public lane audit record",
                b"persist a public lane audit record",
                "persist",
                0.94,
                "The entry must survive process restart before public surfaces rely on it.",
                vec!["durable_laas".to_string()],
                true,
                vec!["laas".to_string(), "arobi-network".to_string()],
                "public",
                18.0,
                std::collections::HashMap::from([("lane".to_string(), "public".to_string())]),
            );
            entry_id = entry.entry_id.clone();
            store.append_audit_entry(&entry)?;
        }

        {
            let store = Store::open(&dir)?;
            let entries = store.load_audit_entries()?;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].entry_id, entry_id);
            assert_eq!(entries[0].lane.lane_id, "public");

            let ledger = AuditLedger::from_entries(entries);
            assert_eq!(ledger.len(), 1);
            assert!(ledger.verify_chain());
            assert!(ledger.get_entry(&entry_id).is_some());
        }

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }

    #[test]
    fn legacy_audit_entries_without_lane_are_migrated_on_load() -> Result<()> {
        let dir = temp_store_dir("legacy-audit-lane");

        {
            let store = Store::open(&dir)?;
            let first = AuditEntry::new_with_metadata(
                1,
                "0".repeat(64),
                DecisionSource::Cortex,
                DecisionType::NetworkRouting,
                "q-ledger",
                "0.3.1",
                "Legacy public route",
                b"legacy public route",
                "allow_with_audit",
                0.91,
                "Older node recorded the decision before lane policy existed.",
                vec!["legacy_route".to_string()],
                true,
                vec!["laas".to_string(), "arobi-network".to_string()],
                "public",
                21.0,
                std::collections::HashMap::from([(
                    "source_system".to_string(),
                    "legacy-node".to_string(),
                )]),
            );
            let first_legacy_hash = legacy_pre_lane_hash(&first);

            let second = AuditEntry::new_with_metadata(
                2,
                first_legacy_hash,
                DecisionSource::Ability,
                DecisionType::TrainingDecision,
                "q-ledger",
                "0.3.1",
                "Legacy sealed route",
                b"legacy sealed route",
                "block_training_export",
                0.96,
                "Older node recorded a sealed 00 decision before lane policy existed.",
                vec!["sealed_route".to_string()],
                true,
                vec!["laas".to_string(), "zero-zero".to_string()],
                "mission-control-00",
                44.0,
                std::collections::HashMap::from([(
                    "source_system".to_string(),
                    "legacy-node".to_string(),
                )]),
            );

            write_legacy_audit_entry_without_lane(&store, first)?;
            write_legacy_audit_entry_without_lane(&store, second)?;
        }

        {
            let store = Store::open(&dir)?;
            let entries = store.load_audit_entries()?;
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].lane.lane_id, "public");
            assert_eq!(entries[1].lane.lane_id, "zero-zero");
            assert!(entries.iter().all(AuditEntry::verify));
            assert_eq!(entries[0].previous_hash, "0".repeat(64));
            assert_eq!(entries[1].previous_hash, entries[0].hash);

            let ledger = AuditLedger::try_from_entries(entries)
                .expect("migrated legacy entries must rehydrate as a verified chain");
            assert!(ledger.verify_chain());
        }

        let _ = fs::remove_dir_all(dir);
        Ok(())
    }
}
