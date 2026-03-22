use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::block::Transaction;
use crate::store::Store;

const MAX_SIZE: usize = 10_000;
const MAX_AGE_MS: u64 = 3_600_000; // 1 hour

/// Thread-safe pending transaction pool.
pub struct Mempool {
    txs: RwLock<HashMap<String, Transaction>>,
}

impl Mempool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            txs: RwLock::new(HashMap::new()),
        })
    }

    /// Validate and add a transaction. Returns error string if rejected.
    pub async fn add(&self, tx: Transaction, store: &Store) -> Result<(), String> {
        tx.validate_basic()?;

        let txs = self.txs.read().await;
        if txs.len() >= MAX_SIZE {
            return Err("Mempool full".into());
        }
        if txs.contains_key(&tx.id) {
            return Err("Already in mempool".into());
        }
        drop(txs);

        if store.tx_exists(&tx.id).map_err(|e| e.to_string())? {
            return Err("Already confirmed".into());
        }

        if tx.from != "GENESIS" {
            let expected = store.get_nonce(&tx.from).map_err(|e| e.to_string())?;
            if tx.nonce != expected {
                return Err(format!(
                    "Nonce invalid: expected {expected}, got {}",
                    tx.nonce
                ));
            }
            let balance = store.get_balance(&tx.from).map_err(|e| e.to_string())?;
            if balance < tx.amount + tx.fee {
                return Err(format!("Insufficient balance: have {balance}"));
            }
        }

        self.txs.write().await.insert(tx.id.clone(), tx);
        Ok(())
    }

    /// Take up to `limit` transactions for block production, highest fee first.
    pub async fn take_for_block(&self, limit: usize) -> Vec<Transaction> {
        let txs = self.txs.read().await;
        let mut sorted: Vec<&Transaction> = txs.values().collect();
        sorted.sort_by(|a, b| b.fee.cmp(&a.fee));
        sorted.into_iter().take(limit).cloned().collect()
    }

    /// Remove transactions that were included in a confirmed block.
    pub async fn remove_confirmed(&self, ids: &[String]) {
        let mut txs = self.txs.write().await;
        for id in ids {
            txs.remove(id);
        }
    }

    /// Drop transactions older than MAX_AGE_MS.
    pub async fn evict_expired(&self) {
        let now = now_ms();
        self.txs
            .write()
            .await
            .retain(|_, tx| now.saturating_sub(tx.timestamp) < MAX_AGE_MS);
    }

    pub async fn size(&self) -> usize {
        self.txs.read().await.len()
    }

    pub async fn all(&self) -> Vec<Transaction> {
        self.txs.read().await.values().cloned().collect()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
