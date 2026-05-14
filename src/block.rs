use crate::config::genesis;
use crate::crypto;
use crate::poi::IntelligenceProof;
use serde::{Deserialize, Serialize};

// ─── Transaction ──────────────────────────────────────────────────────────────

/// A signed value transfer on the Arobi Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// tx_id = hex(blake3( from||to||amount||fee||nonce||timestamp||data_hash ))
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
        data: Option<&str>,
    ) -> String {
        let data_hash = data.map(|payload| blake3::hash(payload.as_bytes()).to_hex().to_string());
        let signing_data = format!(
            "{from}{to}{amount}{fee}{nonce}{timestamp}{}",
            data_hash.as_deref().unwrap_or_default()
        );
        hex::encode(blake3::hash(signing_data.as_bytes()).as_bytes())
    }

    /// True if the Ed25519 signature is valid (genesis txs are always valid).
    pub fn verify_sig(&self) -> bool {
        if self.from == "GENESIS" || is_consensus_pool_address(&self.from) {
            return true;
        }
        let msg = crypto::tx_sign_msg(
            &self.from,
            &self.to,
            self.amount,
            self.fee,
            self.nonce,
            self.timestamp,
            self.data.as_deref(),
        );
        crypto::verify_tx_sig(&self.public_key, &self.signature, &msg)
    }

    /// Quick sanity checks (does not touch chain state).
    pub fn validate_basic(&self) -> Result<(), &'static str> {
        // Genesis transactions: always valid (no signature needed)
        if self.from == "GENESIS" {
            return Ok(());
        }
        // Consensus pool transactions are valid without a private-key signature.
        if is_consensus_pool_address(&self.from) {
            if is_consensus_pool_address(&self.to) {
                return Err("Consensus pool cannot transfer to itself");
            }
            if !self.has_expected_id() {
                return Err("Transaction id mismatch");
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
        if !self.has_expected_id() {
            return Err("Transaction id mismatch");
        }
        if !self.verify_sig() {
            return Err("Invalid signature");
        }
        Ok(())
    }

    fn has_expected_id(&self) -> bool {
        self.id
            == Self::compute_id(
                &self.from,
                &self.to,
                self.amount,
                self.fee,
                self.nonce,
                self.timestamp,
                self.data.as_deref(),
            )
    }
}

fn is_consensus_pool_address(addr: &str) -> bool {
    addr.starts_with("PUBLICP00L") || addr.starts_with("NODEOP00L")
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
///
/// Total: 22B genesis mint + 2B vesting = 24B AURA.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{self, Wallet};

    #[test]
    fn data_payload_is_bound_to_transaction_signature_and_id() {
        let wallet = Wallet::generate();
        let timestamp = genesis::TIMESTAMP_MS + 1;
        let data = Some("public lane audit memo".to_string());
        let mut tx = Transaction {
            id: Transaction::compute_id(
                &wallet.address,
                "ARLPh1111111111111111111111111111111111111",
                1,
                genesis::MIN_FEE,
                1,
                timestamp,
                data.as_deref(),
            ),
            from: wallet.address.clone(),
            to: "ARLPh1111111111111111111111111111111111111".to_string(),
            amount: 1,
            fee: genesis::MIN_FEE,
            nonce: 1,
            data,
            signature: String::new(),
            public_key: wallet.verifying_key_hex.clone(),
            timestamp,
        };
        let sign_msg = crypto::tx_sign_msg(
            &tx.from,
            &tx.to,
            tx.amount,
            tx.fee,
            tx.nonce,
            tx.timestamp,
            tx.data.as_deref(),
        );
        tx.signature = wallet.sign(&sign_msg).expect("sign transaction");

        assert!(tx.verify_sig());
        assert!(tx.validate_basic().is_ok());

        let mut tampered = tx.clone();
        tampered.data = Some("00 lane audit memo".to_string());
        assert!(
            !tampered.verify_sig(),
            "changing data must invalidate the transaction signature"
        );
        assert!(
            tampered.validate_basic().is_err(),
            "changing data must make transaction validation fail"
        );
        assert_ne!(
            tx.id,
            Transaction::compute_id(
                &tampered.from,
                &tampered.to,
                tampered.amount,
                tampered.fee,
                tampered.nonce,
                tampered.timestamp,
                tampered.data.as_deref(),
            ),
            "changing data must produce a different transaction id"
        );

        let mut tampered = tx.clone();
        tampered.id = "not-the-derived-transaction-id".to_string();
        assert!(
            tampered.validate_basic().is_err(),
            "changing the transaction id must make validation fail"
        );
    }

    #[test]
    fn node_ops_pool_reward_is_valid_without_private_key_signature() {
        let data = Some("PoI block reward h=1".to_string());
        let tx = Transaction {
            id: Transaction::compute_id(
                genesis::NODE_OPS_POOL_ADDRESS,
                "ARLPh1111111111111111111111111111111111111",
                genesis::NODE_REWARD_MIN,
                0,
                1,
                genesis::TIMESTAMP_MS + 1,
                data.as_deref(),
            ),
            from: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
            to: "ARLPh1111111111111111111111111111111111111".to_string(),
            amount: genesis::NODE_REWARD_MIN,
            fee: 0,
            nonce: 1,
            data,
            signature: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
            public_key: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
            timestamp: genesis::TIMESTAMP_MS + 1,
        };

        assert!(
            tx.validate_basic().is_ok(),
            "consensus node-ops reward pool has no private key and must validate through the pool rule"
        );
    }
}
