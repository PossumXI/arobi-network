use std::sync::Arc;
use tokio::{sync::broadcast, time};
use tracing::{error, info};

use crate::{
    block::{Block, Transaction},
    config::genesis,
    crypto::Wallet,
    mempool::Mempool,
    poi::PoiEngine,
    store::Store,
};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Build and sign a new block from the current mempool + block reward.
/// Generates a Proof of Intelligence before computing the block hash.
pub async fn produce_block(
    wallet: &Wallet,
    store: &Arc<Store>,
    mempool: &Arc<Mempool>,
    poi_engine: &Arc<PoiEngine>,
) -> anyhow::Result<Block> {
    let height = store.chain_height()? + 1;
    let prev_hash = store.tip_hash()?;
    let timestamp = now_ms();

    // Collect pending transactions (highest fee first)
    let mut txs: Vec<Transaction> = mempool.take_for_block(genesis::MAX_TXS_PER_BLOCK - 1).await;

    // Block reward from NODE_OPS_POOL (node operator emission fund).
    // Pool halves every 2 years. 2.5B AURA lasts 20 years max.
    // NODE_OPS_POOL_ADDRESS has no private key — consensus controls emissions only.
    // PUBLIC_POOL (DEX) is separate — governance-only, no node rewards from it.
    let ops_pool_balance = store.get_balance(genesis::NODE_OPS_POOL_ADDRESS)?;
    let reward_amount = genesis::current_block_reward(height, ops_pool_balance);

    // Node Ops Pool reward transaction (validator earns from emission pool).
    // Source: NODEOP00L… (no private key exists).
    // This is the ONLY way tokens leave NODE_OPS_POOL — through consensus.
    let ops_pool_aura = ops_pool_balance as f64 / genesis::DECIMAL_FACTOR as f64;
    let reward_aura = reward_amount as f64 / genesis::DECIMAL_FACTOR as f64;
    let reward_data = if reward_amount > 0 {
        Some(format!(
            "PoI block reward h={height} {:.2} AURA from Node Ops Pool. Pool: {:.0}AURA remaining. Halving exp={}",
            reward_aura,
            ops_pool_aura,
            genesis::halving_exp(height)
        ))
    } else {
        Some("Node Ops Pool exhausted — PoI block rewards ended at this block".to_string())
    };
    let reward_tx = Transaction {
        id: Transaction::compute_id(
            genesis::NODE_OPS_POOL_ADDRESS,
            &wallet.address,
            reward_amount,
            0,
            height,
            timestamp,
            reward_data.as_deref(),
        ),
        from: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
        to: wallet.address.clone(),
        amount: reward_amount,
        fee: 0,
        nonce: height,
        data: reward_data,
        signature: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
        public_key: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
        timestamp,
    };
    txs.insert(0, reward_tx); // reward tx always first

    // Generate Proof of Intelligence
    let proof = poi_engine.generate_proof(height).await?;
    let proof_hash = Some(proof.computation_hash.as_str());

    let merkle_root = Block::compute_merkle_root(&txs);
    let hash = Block::compute_hash(
        height,
        &prev_hash,
        timestamp,
        &merkle_root,
        0,
        &wallet.address,
        proof_hash,
    );

    // Validator signs the block header
    let header_msg = format!("{height}{prev_hash}{timestamp}{merkle_root}");
    let validator_signature = wallet.sign(header_msg.as_bytes())?;

    info!(
        "PoI challenge solved — score {:.2}, type {:?}",
        proof.intelligence_score,
        bincode::deserialize::<crate::poi::IntelligenceChallenge>(&proof.challenge_bytes)
            .map(|c| c.challenge_type)
            .unwrap_or(crate::poi::ChallengeType::DataAnalysis),
    );

    Ok(Block {
        height,
        hash,
        prev_hash,
        timestamp,
        transactions: txs,
        merkle_root,
        validator: wallet.address.clone(),
        validator_signature,
        nonce: 0,
        intelligence_proof: Some(proof),
    })
}

/// Runs forever — produces a block every BLOCK_TIME_SECS seconds.
/// Broadcasts each new block via `block_tx` so the P2P layer gossips it.
pub async fn block_producer(
    wallet: Wallet,
    store: Arc<Store>,
    mempool: Arc<Mempool>,
    block_tx: broadcast::Sender<Block>,
    poi_engine: Arc<PoiEngine>,
) {
    let mut ticker = time::interval(time::Duration::from_secs(genesis::BLOCK_TIME_SECS));
    loop {
        ticker.tick().await;
        match produce_block(&wallet, &store, &mempool, &poi_engine).await {
            Ok(block) => {
                let confirmed_ids: Vec<String> =
                    block.transactions.iter().map(|t| t.id.clone()).collect();
                match store.apply_block(&block) {
                    Ok(()) => {
                        info!(
                            "⛏  Block {} | hash {} | txs {}",
                            block.height,
                            &block.hash[..16],
                            block.transactions.len()
                        );
                        mempool.remove_confirmed(&confirmed_ids).await;
                        let _ = block_tx.send(block);
                    }
                    Err(e) => error!("apply_block failed: {e}"),
                }
            }
            Err(e) => error!("produce_block failed: {e}"),
        }
    }
}
