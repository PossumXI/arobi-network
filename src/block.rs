use crate::config::genesis;
use crate::crypto;
use crate::poi::IntelligenceProof;
use serde::{Deserialize, Serialize};

// ─── Transaction ──────────────────────────────────────────────────────────────

/// A signed value transfer on the Arobi Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// tx_id = hex(blake3( from||to||amount||fee||nonce||timestamp ))
    pub id: String,
    /// Sender AROBI address (or "GENESIS" for genesis/block-reward txs)
    pub from: String,
    /// Recipient AROBI address
    pub to: String,
    /// Amount in base units (divide by 10^8 for AURA)
    pub amount: u64,
    /// Fee in base units (goes to block validator)
    pub fee: u64,
    /// Sender account nonce — prevents replay attacks
    pub nonce: u64,
    /// Optional UTF-8 data payload (max 512 bytes)
    pub data: Option<String>,
    /// Hex-encoded Ed25519 signature over tx_sign_msg(...)
    pub signature: String,
    /// Hex-encoded Ed25519 public key of the sender
    pub public_key: String,
    /// Unix timestamp in milliseconds when tx was created
    pub timestamp: u64,
}

impl Transaction {
    /// Deterministic transaction ID from its fields.
    pub fn compute_id(
        from: &str,
        to: &str,
        amount: u64,
        fee: u64,
        nonce: u64,
        timestamp: u64,
    ) -> String {
        let data = format!("{from}{to}{amount}{fee}{nonce}{timestamp}");
        hex::encode(blake3::hash(data.as_bytes()).as_bytes())
    }

    /// True if the Ed25519 signature is valid (genesis txs are always valid).
    pub fn verify_sig(&self) -> bool {
        if self.from == "GENESIS" || self.from.starts_with("PUBLICP00L") {
            return true;
        }
        let msg = crypto::tx_sign_msg(
            &self.from,
            &self.to,
            self.amount,
            self.fee,
            self.nonce,
            self.timestamp,
        );
        crypto::verify_tx_sig(&self.public_key, &self.signature, &msg)
    }

    /// Quick sanity checks (does not touch chain state).
    pub fn validate_basic(&self) -> Result<(), &'static str> {
        // Genesis transactions: always valid (no signature needed)
        if self.from == "GENESIS" {
            return Ok(());
        }
        // PUBLIC_POOL transactions: valid without signature (no private key exists)
        // Used for block rewards from the public node runner fund.
        if self.from.starts_with("PUBLICP00L") {
            // PUBLICP00L transactions must go TO a real wallet address (not back to itself)
            if self.to.starts_with("PUBLICP00L") {
                return Err("PUBLIC_POOL cannot transfer to itself");
            }
            return Ok(());
        }
        if self.from.is_empty() || self.to.is_empty() {
            return Err("Empty address");
        }
        // Allow zero-amount self-transfers for data embedding (e.g., audit ledger logging)
        if self.from == self.to && !(self.amount == 0 && self.data.is_some()) {
            return Err("Cannot send to self");
        }
        if self.amount == 0 && self.data.is_none() {
            return Err("Amount must be > 0 (or provide data for zero-amount embedding)");
        }
        if self.fee < genesis::MIN_FEE {
            return Err("Fee below minimum");
        }
        if let Some(ref d) = self.data {
            if d.len() > 512 {
                return Err("Data payload exceeds 512 bytes");
            }
        }
        if !self.verify_sig() {
            return Err("Invalid signature");
        }
        Ok(())
    }
}

// ─── Block ────────────────────────────────────────────────────────────────────

/// A confirmed block in the Arobi blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block height (genesis = 0)
    pub height: u64,
    /// hex(blake3( height||prev_hash||timestamp||merkle_root||nonce||validator ))
    pub hash: String,
    /// Hash of the previous block
    pub prev_hash: String,
    /// Unix timestamp in milliseconds when block was produced
    pub timestamp: u64,
    /// Transactions included in this block
    pub transactions: Vec<Transaction>,
    /// Merkle root of all transaction IDs
    pub merkle_root: String,
    /// AROBI address of the node that produced this block
    pub validator: String,
    /// Ed25519 signature of the validator over the block header fields
    pub validator_signature: String,
    /// Reserved for future PoI difficulty nonce
    pub nonce: u64,
    /// Proof of Intelligence — present in blocks produced after PoI activation.
    /// `None` for pre-PoI blocks and genesis. Backwards-compatible via serde defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_proof: Option<IntelligenceProof>,
}

impl Block {
    /// Compute the canonical block hash.
    /// When `proof_hash` is `None`, output matches the pre-PoI hash for backwards compat.
    pub fn compute_hash(
        height: u64,
        prev_hash: &str,
        timestamp: u64,
        merkle_root: &str,
        nonce: u64,
        validator: &str,
        proof_hash: Option<&str>,
    ) -> String {
        let mut data = format!("{height}{prev_hash}{timestamp}{merkle_root}{nonce}{validator}");
        if let Some(ph) = proof_hash {
            data.push_str(ph);
        }
        hex::encode(blake3::hash(data.as_bytes()).as_bytes())
    }

    /// Compute the merkle root from the block's transaction IDs.
    pub fn compute_merkle_root(txs: &[Transaction]) -> String {
        if txs.is_empty() {
            return "0".repeat(64);
        }
        let ids: Vec<&str> = txs.iter().map(|t| t.id.as_str()).collect();
        let combined = ids.join("|");
        hex::encode(blake3::hash(combined.as_bytes()).as_bytes())
    }

    /// Verify that block.hash matches the computed hash.
    pub fn verify_hash(&self) -> bool {
        let proof_hash = self
            .intelligence_proof
            .as_ref()
            .map(|p| p.computation_hash.as_str());
        let expected = Self::compute_hash(
            self.height,
            &self.prev_hash,
            self.timestamp,
            &self.merkle_root,
            self.nonce,
            &self.validator,
            proof_hash,
        );
        self.hash == expected
    }

    /// Fully validate this block against the known previous block.
    #[allow(dead_code)]
    pub fn validate(&self, prev: &Block) -> Result<(), String> {
        if self.height != prev.height + 1 {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                prev.height + 1,
                self.height
            ));
        }
        if self.prev_hash != prev.hash {
            return Err("prev_hash does not match tip hash".to_string());
        }
        if self.timestamp <= prev.timestamp {
            return Err("Block timestamp must be strictly after previous block".to_string());
        }
        if !self.verify_hash() {
            return Err("Block hash is invalid".to_string());
        }
        let computed_merkle = Self::compute_merkle_root(&self.transactions);
        if self.merkle_root != computed_merkle {
            return Err("Merkle root mismatch".to_string());
        }
        for tx in &self.transactions {
            if let Err(e) = tx.validate_basic() {
                return Err(format!("Invalid tx {}: {e}", &tx.id[..8]));
            }
        }
        // Verify PoI proof if present
        if let Some(ref proof) = self.intelligence_proof {
            crate::poi::PoiEngine::verify_proof(proof)
                .map_err(|e| format!("Invalid intelligence proof: {e}"))?;
        }
        Ok(())
    }
}

// ─── Genesis ────────────────────────────────────────────────────────────────

/// Build the one-and-only genesis block.
/// Deterministic — every node produces the same block 0.
/// Initializes ALL initial token allocations:
///   1. Founder:           500M AURA  (immediate, no restrictions)
///   2. Mission Treasury:    4B AURA   (governance controlled)
///   3. Public Pool (DEX): 15B AURA   (DEX liquidity + bridge — governance controlled)
///   4. Node Ops Pool:      2.5B AURA (node runner rewards via PoI halving — NO single entity)
/// Total: 22B genesis mint + 2B vesting = 24B AURA
pub fn genesis_block() -> Block {
    // Transaction IDs are sequential "GENESIS" + index
    fn gtx(id: &str, to: &str, amount: u64, data: &str) -> Transaction {
        Transaction {
            id: id.to_string(),
            from: "GENESIS".to_string(),
            to: to.to_string(),
            amount,
            fee: 0,
            nonce: 0,
            data: Some(data.to_string()),
            signature: "GENESIS".to_string(),
            public_key: "GENESIS".to_string(),
            timestamp: genesis::TIMESTAMP_MS,
        }
    }

    let txs = vec![
        // 1. Founder: 500M AURA immediate allocation
        gtx(
            "GENESIS00000000000000000000000000000001",
            genesis::FOUNDER_ADDRESS,
            genesis::FOUNDER_GENESIS_ALLOCATION,
            "Founder Genesis — Arobi Network v3.2.0. 500M AURA immediate allocation. Vesting: 2B AURA over 8 years via consensus.",
        ),
        // 2. Mission Treasury: 4B AURA
        gtx(
            "GENESIS00000000000000000000000000000002",
            genesis::MISSION_TREASURY_ADDRESS,
            genesis::MISSION_TREASURY_ALLOCATION,
            "Mission Treasury Genesis — 4B AURA for Arobi ecosystem governance and operations.",
        ),
        // 3. Public Pool (DEX): 15B AURA — governance-controlled DEX liquidity and bridge.
        // NO single entity can withdraw. Only governance multisig controls bridge withdrawals.
        gtx(
            "GENESIS00000000000000000000000000000003",
            genesis::PUBLIC_POOL_ADDRESS,
            genesis::PUBLIC_POOL_ALLOCATION,
            "PUBLIC POOL (DEX) — 15B AURA for DEX liquidity and governance-approved bridge contracts. Governance multisig required for all withdrawals. NO node runner rewards from this pool.",
        ),
        // 4. Node Ops Pool: 2.5B AURA — PoI node runner rewards via 20-year halving.
        // NO private key. Only consensus can emit from this pool. Pool exhausted = rewards end.
        gtx(
            "GENESIS00000000000000000000000000000004",
            genesis::NODE_OPS_POOL_ADDRESS,
            genesis::NODE_OPS_POOL_ALLOCATION,
            "NODE OPS POOL — 2.5B AURA for PoI node runner rewards. 20-year halving emission (BASE: ~595 AURA/block at Y1-2, halves every 2 years). Pool empty = rewards stop. NO private key — consensus only.",
        ),
    ];

    let merkle_root = Block::compute_merkle_root(&txs);
    let hash = Block::compute_hash(
        0,
        &"0".repeat(64),
        genesis::TIMESTAMP_MS,
        &merkle_root,
        0,
        "GENESIS",
        None,
    );

    Block {
        height: 0,
        hash,
        prev_hash: "0".repeat(64),
        timestamp: genesis::TIMESTAMP_MS,
        transactions: txs,
        merkle_root,
        validator: "GENESIS".to_string(),
        validator_signature: "GENESIS".to_string(),
        nonce: 0,
        intelligence_proof: None,
    }
}
