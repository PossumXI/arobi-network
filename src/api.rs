use axum::{
    body::Body,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};
use tracing::info;

use crate::agents::inference_router::InferenceRouterAgent;
use crate::agents::tool_executor::ToolExecutorAgent;
use crate::audit::ledger::{
    AuditLedger, DecisionSource, DecisionType, TrainingCorpusExport, TrainingExportManifest,
    TrainingExportRecord, TribunalFormat,
};
use crate::block::{Block, Transaction};
use crate::compute::reputation::ReputationOracle;
use crate::compute::scheduler::Scheduler;
use crate::compute::types as compute_types;
use crate::config::genesis;
use crate::crypto::{self, Wallet};
use crate::fs::chunker::Chunker;
use crate::fs::dht::DhtTable;
use crate::fs::local_store::ChunkStore;
use crate::fs::types::*;
use crate::llm::registry::ModelRegistry;
use crate::llm::types as llm_types;
use crate::mempool::Mempool;
use crate::p2p::P2p;
use crate::poi::PoiEngine;
use crate::rate_limit::rate_limit_middleware;
use crate::security::SecurityMonitor;
use crate::store::Store;
use ed25519_dalek::Signer;

// ─── Shared state ──────────────────────────────────────────────────────────────

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub store: Arc<Store>,
    pub mempool: Arc<Mempool>,
    pub p2p: Arc<P2p>,
    pub poi_engine: Arc<PoiEngine>,
    pub node_wallet: Option<Wallet>,
    pub mission_treasury_wallet: Option<Wallet>,
    pub security: Arc<SecurityMonitor>,
    pub chunk_store: Arc<ChunkStore>,
    pub dht: Arc<DhtTable>,
    pub compute_scheduler: Arc<Scheduler>,
    pub reputation_oracle: Arc<ReputationOracle>,
    pub model_registry: Arc<ModelRegistry>,
    pub inference_router: Arc<InferenceRouterAgent>,
    pub tool_executor: Arc<ToolExecutorAgent>,
    pub audit_ledger: Arc<AuditLedger>,
    /// Admin signing key for ledger writes (hex-encoded Ed25519 private key, set via AROBL_ADMIN_SIGNING_KEY env)
    pub admin_signing_key: Option<String>,
}

// ─── Error helpers ─────────────────────────────────────────────────────────────

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiError>)>;

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn api_err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (code, Json(ApiError { error: msg.into() }))
}

fn internal(e: impl std::fmt::Display) -> (StatusCode, Json<ApiError>) {
    api_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    api_err(StatusCode::NOT_FOUND, msg)
}

fn bad_req(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    api_err(StatusCode::BAD_REQUEST, msg)
}

const CLEARANCE_PUBLIC: &str = "public";
const CLEARANCE_INTERNAL: &str = "internal";
const CLEARANCE_MISSION_CONTROL: &str = "mission_control";
const PRIVATE_LAYER_CODENAME_00: &str = "00";
const TOOL_ORCHESTRATION_MAX_JOBS: usize = 64;
const SECURE_RELAY_MAX_BYTES: usize = 24 * 1024;
const SECURE_RELAY_ALLOWED_APPS: &[&str] = &["shadow_chat", "aegis_mail"];

#[derive(Debug, Clone, Default)]
struct RequestAccessContext {
    wallet: Option<String>,
    device_hash: Option<String>,
    access_token: Option<String>,
    clearance_hint: Option<String>,
}

fn access_context_from_headers(headers: &HeaderMap) -> RequestAccessContext {
    let read_header = |name: &'static str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
    };

    RequestAccessContext {
        wallet: read_header("x-arobi-wallet"),
        device_hash: read_header("x-arobi-device-hash"),
        access_token: read_header("x-arobi-access-token"),
        clearance_hint: read_header("x-arobi-clearance"),
    }
}

fn normalize_clearance(raw: Option<&str>) -> &'static str {
    match raw
        .unwrap_or(CLEARANCE_INTERNAL)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        CLEARANCE_PUBLIC => CLEARANCE_PUBLIC,
        CLEARANCE_MISSION_CONTROL
        | "mission-control"
        | "missioncontrol"
        | PRIVATE_LAYER_CODENAME_00
        | "private"
        | "private_00"
        | "private-00" => CLEARANCE_MISSION_CONTROL,
        _ => CLEARANCE_INTERNAL,
    }
}

fn is_hex_string(raw: &str, expected_len: usize) -> bool {
    raw.len() == expected_len && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

fn normalize_secure_relay_app(raw: &str) -> Option<&'static str> {
    let normalized = raw.trim().to_ascii_lowercase();
    SECURE_RELAY_ALLOWED_APPS
        .iter()
        .copied()
        .find(|candidate| *candidate == normalized.as_str())
}

fn secure_relay_signing_message(
    app: &str,
    sender_wallet: &str,
    channel_tag: &str,
    ciphertext_b64: &str,
    created_at: &str,
    nonce: &str,
) -> Vec<u8> {
    let ciphertext_hash = hex::encode(Sha256::digest(ciphertext_b64.as_bytes()));
    let signing_text =
        format!("{app}\n{sender_wallet}\n{channel_tag}\n{ciphertext_hash}\n{created_at}\n{nonce}");
    Sha256::digest(signing_text.as_bytes()).to_vec()
}

fn normalize_sensitivity(raw: Option<&str>) -> &'static str {
    match raw
        .unwrap_or(CLEARANCE_INTERNAL)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        CLEARANCE_PUBLIC => CLEARANCE_PUBLIC,
        "sensitive"
        | CLEARANCE_MISSION_CONTROL
        | "mission-control"
        | "missioncontrol"
        | PRIVATE_LAYER_CODENAME_00
        | "private"
        | "private_00"
        | "private-00" => "sensitive",
        _ => CLEARANCE_INTERNAL,
    }
}

fn compute_pairing_hash(wallet: &str, device_hash: &str, access_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(wallet.as_bytes());
    hasher.update(b":");
    hasher.update(device_hash.as_bytes());
    hasher.update(b":");
    hasher.update(access_code.as_bytes());
    hex::encode(hasher.finalize())
}

fn derive_memory_key_material(
    wallet: &str,
    key: &str,
    sensitivity: &str,
    access_token: Option<&str>,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(wallet.as_bytes());
    hasher.update(b":");
    hasher.update(key.as_bytes());
    hasher.update(b":");
    hasher.update(sensitivity.as_bytes());
    hasher.update(b":");
    if sensitivity == "sensitive" {
        if let Some(token) = access_token {
            hasher.update(token.as_bytes());
        } else {
            hasher.update(b"sensitive-missing-token");
        }
    } else {
        hasher.update(b"nonsensitive-shared-key");
    }
    hasher.finalize().to_vec()
}

fn normalize_employee_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn derive_openclaw_employee_wallet(master_wallet: &str, employee_id: &str) -> String {
    let seed = format!(
        "openclaw:{master_wallet}:{}",
        normalize_employee_id(employee_id)
    );
    let digest = Sha256::digest(seed.as_bytes());
    crypto::derive_address(&digest)
}

fn xor_stream_cipher(data: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter: u64 = 0;

    while out.len() < data.len() {
        let mut block_hasher = blake3::Hasher::new();
        block_hasher.update(key);
        block_hasher.update(nonce);
        block_hasher.update(&counter.to_le_bytes());
        let block = block_hasher.finalize();
        let block_bytes = block.as_bytes();

        let remaining = data.len() - out.len();
        let take = remaining.min(block_bytes.len());
        for byte in block_bytes.iter().take(take) {
            out.push(data[out.len()] ^ *byte);
        }
        counter = counter.saturating_add(1);
    }

    out
}

#[derive(Debug, Clone)]
struct MemoryEnvelope {
    ciphertext_b64: String,
    nonce_b64: String,
    payload_hash: String,
    compressed_bytes: usize,
    original_bytes: usize,
}

fn encrypt_memory_payload(
    payload: &[u8],
    key_material: &[u8],
) -> Result<MemoryEnvelope, (StatusCode, Json<ApiError>)> {
    let compressed = zstd::stream::encode_all(Cursor::new(payload), 3)
        .map_err(|e| internal(format!("memory compression failed: {e}")))?;

    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = xor_stream_cipher(&compressed, key_material, &nonce);

    Ok(MemoryEnvelope {
        ciphertext_b64: B64.encode(ciphertext),
        nonce_b64: B64.encode(nonce),
        payload_hash: hex::encode(Sha256::digest(payload)),
        compressed_bytes: compressed.len(),
        original_bytes: payload.len(),
    })
}

fn decrypt_memory_payload(
    envelope: &serde_json::Value,
    key_material: &[u8],
) -> Result<Vec<u8>, (StatusCode, Json<ApiError>)> {
    let ciphertext_b64 = envelope
        .get("ciphertext_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| internal("memory envelope missing ciphertext_b64"))?;
    let nonce_b64 = envelope
        .get("nonce_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| internal("memory envelope missing nonce_b64"))?;

    let ciphertext = B64
        .decode(ciphertext_b64.as_bytes())
        .map_err(|e| bad_req(format!("invalid memory ciphertext encoding: {e}")))?;
    let nonce = B64
        .decode(nonce_b64.as_bytes())
        .map_err(|e| bad_req(format!("invalid memory nonce encoding: {e}")))?;

    let decompressed = xor_stream_cipher(&ciphertext, key_material, &nonce);
    zstd::stream::decode_all(Cursor::new(decompressed))
        .map_err(|e| internal(format!("memory decompression failed: {e}")))
}

fn is_mission_control_authorized(
    s: &AppState,
    headers: &HeaderMap,
    wallet_hint: Option<&str>,
) -> Result<bool, (StatusCode, Json<ApiError>)> {
    let ctx = access_context_from_headers(headers);
    let wallet = wallet_hint
        .filter(|v| !v.trim().is_empty())
        .map(ToString::to_string)
        .or(ctx.wallet.clone());
    let Some(wallet) = wallet else {
        return Ok(false);
    };

    let profile = s.store.get_access_profile(&wallet).map_err(internal)?;
    let Some(profile) = profile else {
        return Ok(false);
    };

    let mission_control = profile
        .get("mission_control")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let gov_portal_onboarded = profile
        .get("gov_portal_onboarded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !(mission_control && gov_portal_onboarded) {
        return Ok(false);
    }

    let expected_pairing = profile
        .get("pairing_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_device_hash = profile
        .get("device_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let provided_pairing = ctx.access_token.unwrap_or_default();
    let provided_device_hash = ctx.device_hash.unwrap_or_default();

    if expected_pairing.is_empty() || expected_device_hash.is_empty() {
        return Ok(false);
    }

    Ok(expected_pairing == provided_pairing && expected_device_hash == provided_device_hash)
}

fn can_read_sensitive_scope(
    s: &AppState,
    headers: &HeaderMap,
    wallet_hint: Option<&str>,
) -> Result<bool, (StatusCode, Json<ApiError>)> {
    is_mission_control_authorized(s, headers, wallet_hint)
}

fn is_allowed_cors_origin(origin: &str) -> bool {
    let normalized = origin.trim().to_ascii_lowercase();

    if normalized == "https://aura-genesis.org"
        || normalized == "https://www.aura-genesis.org"
        || normalized.starts_with("https://autonomo.") && normalized.ends_with(".aura-genesis.org")
        || normalized.starts_with("https://arobi.") && normalized.ends_with(".aura-genesis.org")
        || normalized.starts_with("https://") && normalized.ends_with(".aura-genesis.org")
        || normalized.starts_with("http://localhost")
        || normalized.starts_with("http://127.0.0.1")
        || normalized.starts_with("http://[::1]")
    {
        return true;
    }

    if let Ok(extra_origins) = std::env::var("AROBI_EXTRA_ALLOWED_ORIGINS") {
        return extra_origins
            .split(',')
            .map(|entry| entry.trim().to_ascii_lowercase())
            .any(|entry| !entry.is_empty() && entry == normalized);
    }

    false
}

fn has_forwarded_client_ip(headers: &axum::http::HeaderMap) -> bool {
    headers.contains_key("cf-connecting-ip")
        || headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-real-ip")
}

fn is_direct_local_request(remote: &SocketAddr, headers: &axum::http::HeaderMap) -> bool {
    // API binds to localhost. Tunnel/proxy traffic is also local at socket level,
    // so treat forwarded-client headers as non-local requests.
    remote.ip().is_loopback() && !has_forwarded_client_ip(headers)
}

fn is_public_api_path(path: &str) -> bool {
    path == "/.env"
        || path == "/wp-login.php"
        // Removed: || path == "/api/v1/admin/debug"
        // Removed: || path == "/api/v1/admin/hack"
        // Admin endpoints are now local-only (blocked by is_local_request check)
        || path == "/api/v1/info"
        || path == "/api/v1/autonomo/status"
        || path == "/api/v1/blocks"
        || path == "/api/v1/blocks/latest"
        || path.starts_with("/api/v1/blocks/")
        || path == "/api/v1/compute/leaderboard"
        || path == "/api/v1/compute/marketplace"
        || path == "/api/v1/consensus/poi"
        || path == "/api/v1/security/posture"
        || path == "/api/v1/audit/verify"
        || path == "/api/v1/fs/stats"
        || path == "/api/v1/llm/marketplace"
        || path == "/api/v1/chain/tokenomics"
        || path == "/api/v1/tx/submit"
        || path.starts_with("/api/v1/tx/")
        || path == "/api/v1/tools/list"
        || path == "/api/v1/autonomo/relay/messages"
        || (path.starts_with("/api/v1/wallet/")
            && (path.ends_with("/balance") || path.ends_with("/nonce")))
}

fn is_public_api_route(method: &Method, path: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return is_public_api_path(path);
    }

    *method == Method::POST && matches!(path, "/api/v1/tx/submit" | "/api/v1/autonomo/relay/send")
}

fn configured_api_token() -> Option<String> {
    std::env::var("AROBI_API_TOKEN")
        .ok()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn extract_request_api_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(token) = auth.trim().strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }

    headers
        .get("x-arobi-access-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

fn has_valid_api_token(headers: &HeaderMap) -> bool {
    let Some(expected) = configured_api_token() else {
        return false;
    };
    let Some(provided) = extract_request_api_token(headers) else {
        return false;
    };

    provided == expected
}

async fn enforce_api_access(req: Request<Body>, next: axum::middleware::Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    if is_public_api_route(&method, &path) {
        return next.run(req).await;
    }

    let local_only = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect| is_direct_local_request(&connect.0, req.headers()))
        .unwrap_or(false);

    if local_only || has_valid_api_token(req.headers()) {
        return next.run(req).await;
    }

    api_err(
        StatusCode::FORBIDDEN,
        "This API route is restricted to local admin access",
    )
    .into_response()
}

fn aura_to_raw(amount_aura: f64) -> Result<u64, (StatusCode, Json<ApiError>)> {
    if amount_aura <= 0.0 {
        return Err(bad_req("amount_aura must be greater than zero"));
    }
    let amount = (amount_aura * genesis::DECIMAL_FACTOR as f64).round() as u64;
    if amount == 0 {
        return Err(bad_req("amount_aura is too small"));
    }
    Ok(amount)
}

async fn submit_signed_transfer(
    s: &AppState,
    signer_wallet: &Wallet,
    to: &str,
    amount_aura: f64,
    fee_override: Option<u64>,
    memo: Option<String>,
) -> Result<(String, u64, u64), (StatusCode, Json<ApiError>)> {
    if to.trim().is_empty() {
        return Err(bad_req("Missing recipient wallet address"));
    }
    if to == signer_wallet.address {
        return Err(bad_req("Cannot send transfer to the same wallet"));
    }

    let amount = aura_to_raw(amount_aura)?;
    let fee = fee_override.unwrap_or(genesis::MIN_FEE);
    let nonce = s
        .store
        .get_nonce(&signer_wallet.address)
        .map_err(internal)?;
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let mut tx = Transaction {
        id: Transaction::compute_id(
            &signer_wallet.address,
            to,
            amount,
            fee,
            nonce,
            timestamp,
            None,
        ),
        from: signer_wallet.address.clone(),
        to: to.to_string(),
        amount,
        fee,
        nonce,
        data: memo,
        signature: String::new(),
        public_key: signer_wallet.verifying_key_hex.clone(),
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
    tx.signature = signer_wallet.sign(&sign_msg).map_err(internal)?;
    let tx_id = tx.id.clone();

    s.mempool.add(tx, &s.store).await.map_err(bad_req)?;
    Ok((tx_id, amount, fee))
}

// ─── Response shapes ───────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct NodeInfo {
    pub version: &'static str,
    pub network: &'static str,
    pub protocol_version: u32,
    pub consensus_type: &'static str,
    pub height: u64,
    pub tip_hash: String,
    pub peer_count: usize,
    pub mempool_size: usize,
    /// Block reward in AURA (per block at 60s intervals)
    pub block_reward_aura: f64,
    /// Node runner reward per minute (AURA) — same as block reward
    pub node_reward_per_min_aura: f64,
    pub min_fee: u64,
    pub block_time_secs: u64,
    pub poi_difficulty: u32,
    pub poi_challenges_solved: u64,
}

#[derive(Serialize)]
pub struct BalanceResp {
    pub address: String,
    /// Raw base units (1 AURA = 100,000,000 units)
    pub balance: u64,
    /// Human-readable AURA amount
    pub balance_aura: f64,
    /// Founder vesting info (only present for founder address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vesting: Option<VestingInfo>,
}

#[derive(Serialize)]
pub struct VestingInfo {
    /// Immediate genesis allocation: 500M AURA
    pub genesis_allocation_aura: f64,
    /// Additional vested amount (2B over 8 years)
    pub vested_aura: f64,
    /// Total spendable: genesis + vested
    pub total_spendable_aura: f64,
    /// Months remaining in vesting schedule
    pub vesting_months_remaining: u64,
    /// Vesting end timestamp (ms)
    pub vesting_end_ms: u64,
}

#[derive(Serialize)]
pub struct NonceResp {
    pub address: String,
    pub nonce: u64,
}

#[derive(Serialize)]
pub struct SubmitResp {
    pub tx_id: String,
    pub status: &'static str,
}

#[derive(Deserialize)]
pub struct WalletTransferReq {
    pub from: Option<String>,
    pub to: String,
    pub amount_aura: f64,
    pub memo: Option<String>,
    pub fee: Option<u64>,
}

#[derive(Serialize)]
pub struct WalletTransferResp {
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub amount_aura: f64,
    pub fee: u64,
    pub status: &'static str,
}

#[derive(Serialize)]
pub struct MempoolResp {
    pub count: usize,
    pub transactions: Vec<Transaction>,
}

#[derive(Serialize)]
pub struct PeersResp {
    pub count: usize,
    pub peers: Vec<String>,
}

#[derive(Serialize)]
pub struct KnownPeerResp {
    pub addr: String,
    pub source: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub successful_connects: u64,
    pub last_connected_ms: u64,
    pub failed_connects: u64,
    pub last_failed_ms: u64,
    pub quarantined_until_ms: u64,
}

#[derive(Serialize)]
pub struct KnownPeersResp {
    pub count: usize,
    pub peers: Vec<KnownPeerResp>,
}

#[derive(Deserialize)]
pub struct RangeQuery {
    pub from: Option<u64>,
    pub to: Option<u64>,
}

#[derive(Serialize)]
pub struct PoiStatsResp {
    pub consensus_type: &'static str,
    pub current_difficulty: u32,
    pub challenges_solved: u64,
    pub average_intelligence_score: f64,
}

#[derive(Serialize)]
pub struct SecurityResp {
    pub status: String,
    pub recent_anomaly_count: usize,
    pub high_severity_count: usize,
    pub recent_anomalies: Vec<AnomalyResp>,
}

#[derive(Serialize)]
pub struct SecurityPostureResp {
    pub status: String,
    pub recent_anomaly_count: usize,
    pub high_severity_count: usize,
    pub generated_at: String,
}

#[derive(Serialize)]
pub struct AnomalyResp {
    pub flag_type: String,
    pub severity: f64,
    pub description: String,
    pub detected_at: String,
}

#[derive(Serialize)]
pub struct AllocationInfo {
    pub address: String,
    /// Amount allocated at genesis
    pub genesis_allocation_aura: f64,
    /// Additional vesting total (0 for non-founder)
    pub vesting_total_aura: f64,
    /// Amount vested so far
    pub vesting_vested_aura: f64,
    /// Months remaining in vesting
    pub vesting_months_remaining: u64,
    /// Vesting end timestamp (ms, 0 if no vesting)
    pub vesting_end_ms: u64,
}

#[derive(Serialize)]
pub struct TokenomicsResp {
    pub network: &'static str,
    pub total_supply_aura: f64,
    pub decimals: u8,
    pub genesis_timestamp_ms: u64,
    pub founder: AllocationInfo,
    pub mission_treasury: AllocationInfo,
    /// Public DEX pool — governance-controlled, no node runner rewards from here.
    pub public_pool: AllocationInfo,
    /// Node Operators Pool — PoI halving emission for node runners.
    pub node_ops_pool: AllocationInfo,
    /// Current block reward (Y1-2: ~595 AURA, halves every 2 years).
    pub current_block_reward_aura: f64,
    pub halving_exp: u64,
    pub block_time_secs: u64,
    pub min_fee_aura: f64,
}

// ─── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/v1/info
async fn get_info(State(s): State<AppState>) -> ApiResult<NodeInfo> {
    let height = s.store.chain_height().map_err(internal)?;
    let tip_hash = s.store.tip_hash().map_err(internal)?;
    let mempool_size = s.mempool.size().await;
    let peer_count = s.p2p.peer_count();

    let ops_pool_balance = s
        .store
        .get_balance(genesis::NODE_OPS_POOL_ADDRESS)
        .unwrap_or(0);
    let current_reward = genesis::current_block_reward(height, ops_pool_balance);

    Ok(Json(NodeInfo {
        version: "3.2.10",
        network: genesis::NETWORK_MAGIC,
        protocol_version: genesis::NETWORK_VERSION,
        consensus_type: "proof_of_intelligence",
        height,
        tip_hash,
        peer_count,
        mempool_size,
        block_reward_aura: current_reward as f64 / genesis::DECIMAL_FACTOR as f64,
        node_reward_per_min_aura: current_reward as f64 / genesis::DECIMAL_FACTOR as f64 / 60.0,
        min_fee: genesis::MIN_FEE,
        block_time_secs: genesis::BLOCK_TIME_SECS,
        poi_difficulty: s.poi_engine.difficulty(),
        poi_challenges_solved: s.poi_engine.challenges_solved(),
    }))
}

/// GET /api/v1/chain/tokenomics
/// Returns the full tokenomics configuration for transparency.
/// Reads chain height to compute the current halving-adjusted block reward.
async fn get_tokenomics(State(s): State<AppState>) -> ApiResult<TokenomicsResp> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let founder_vested = genesis::founder_vested(now_ms);
    let vesting_end_ms = genesis::FOUNDER_VESTING_START_MS
        + genesis::FOUNDER_VESTING_MONTHS * genesis::VESTING_MONTH_MS;
    let months_elapsed = if now_ms > genesis::FOUNDER_VESTING_START_MS {
        ((now_ms - genesis::FOUNDER_VESTING_START_MS) / genesis::VESTING_MONTH_MS)
            .min(genesis::FOUNDER_VESTING_MONTHS)
    } else {
        0
    };

    let height = s.store.chain_height().unwrap_or(0);
    let halving_exp = genesis::halving_exp(height);
    let ops_pool_balance = s
        .store
        .get_balance(genesis::NODE_OPS_POOL_ADDRESS)
        .unwrap_or(0);
    let current_reward = genesis::current_block_reward(height, ops_pool_balance);

    Ok(Json(TokenomicsResp {
        network: genesis::NETWORK_MAGIC,
        total_supply_aura: genesis::TOTAL_SUPPLY as f64 / genesis::DECIMAL_FACTOR as f64,
        decimals: genesis::DECIMALS,
        genesis_timestamp_ms: genesis::TIMESTAMP_MS,
        founder: AllocationInfo {
            address: genesis::FOUNDER_ADDRESS.to_string(),
            genesis_allocation_aura: genesis::FOUNDER_GENESIS_ALLOCATION as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_total_aura: genesis::FOUNDER_VESTING_TOTAL as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_vested_aura: founder_vested as f64 / genesis::DECIMAL_FACTOR as f64,
            vesting_months_remaining: genesis::FOUNDER_VESTING_MONTHS
                .saturating_sub(months_elapsed),
            vesting_end_ms,
        },
        mission_treasury: AllocationInfo {
            address: genesis::MISSION_TREASURY_ADDRESS.to_string(),
            genesis_allocation_aura: genesis::MISSION_TREASURY_ALLOCATION as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_total_aura: 0.0,
            vesting_vested_aura: 0.0,
            vesting_months_remaining: 0,
            vesting_end_ms: 0,
        },
        public_pool: AllocationInfo {
            address: genesis::PUBLIC_POOL_ADDRESS.to_string(),
            genesis_allocation_aura: genesis::PUBLIC_POOL_ALLOCATION as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_total_aura: 0.0,
            vesting_vested_aura: 0.0,
            vesting_months_remaining: 0,
            vesting_end_ms: 0,
        },
        node_ops_pool: AllocationInfo {
            address: genesis::NODE_OPS_POOL_ADDRESS.to_string(),
            genesis_allocation_aura: genesis::NODE_OPS_POOL_ALLOCATION as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_total_aura: 0.0,
            vesting_vested_aura: ops_pool_balance as f64 / genesis::DECIMAL_FACTOR as f64,
            vesting_months_remaining: 0,
            vesting_end_ms: 0,
        },
        current_block_reward_aura: current_reward as f64 / genesis::DECIMAL_FACTOR as f64,
        halving_exp,
        block_time_secs: genesis::BLOCK_TIME_SECS,
        min_fee_aura: genesis::MIN_FEE as f64 / genesis::DECIMAL_FACTOR as f64,
    }))
}

/// GET /api/v1/blocks/latest
async fn get_latest_block(State(s): State<AppState>) -> ApiResult<Block> {
    let height = s.store.chain_height().map_err(internal)?;
    match s.store.get_block(height).map_err(internal)? {
        Some(b) => Ok(Json(b)),
        None => Err(not_found("No blocks yet")),
    }
}

/// GET /api/v1/blocks/:height
async fn get_block_by_height(
    State(s): State<AppState>,
    Path(height): Path<u64>,
) -> ApiResult<Block> {
    match s.store.get_block(height).map_err(internal)? {
        Some(b) => Ok(Json(b)),
        None => Err(not_found(format!("Block {height} not found"))),
    }
}

/// GET /api/v1/blocks?from=X&to=Y   (default: last 10 blocks)
async fn get_blocks_range(
    State(s): State<AppState>,
    Query(q): Query<RangeQuery>,
) -> ApiResult<Vec<Block>> {
    let tip = s.store.chain_height().map_err(internal)?;
    let from = q.from.unwrap_or_else(|| tip.saturating_sub(9));
    let to = q.to.unwrap_or(tip).min(from.saturating_add(100));
    let blocks = s.store.get_blocks(from, to).map_err(internal)?;
    Ok(Json(blocks))
}

/// Validate wallet address format (ARLPh prefix + 34 hex chars = 42 total)
fn validate_wallet_address(address: &str) -> Result<(), String> {
    if address.len() != 42 {
        return Err("Invalid address: must be 42 characters".to_string());
    }
    if !address.starts_with("ARLPh") {
        return Err("Invalid address: must start with 'ARLPh'".to_string());
    }
    // Validate hex characters after prefix
    for c in address[5..].chars() {
        if !c.is_ascii_hexdigit() {
            return Err(
                "Invalid address: must contain only hex characters after prefix".to_string(),
            );
        }
    }
    Ok(())
}

/// GET /api/v1/wallet/:address/balance
async fn get_balance(
    State(s): State<AppState>,
    Path(address): Path<String>,
) -> ApiResult<BalanceResp> {
    // Validate address format before querying
    validate_wallet_address(&address).map_err(bad_req)?;

    let balance = s.store.get_balance(&address).map_err(internal)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let vesting = if address == genesis::FOUNDER_ADDRESS {
        let vested = genesis::founder_vested(now_ms);
        let months_elapsed = if now_ms > genesis::FOUNDER_VESTING_START_MS {
            ((now_ms - genesis::FOUNDER_VESTING_START_MS) / genesis::VESTING_MONTH_MS)
                .min(genesis::FOUNDER_VESTING_MONTHS)
        } else {
            0
        };
        let months_remaining = genesis::FOUNDER_VESTING_MONTHS.saturating_sub(months_elapsed);
        let vesting_end_ms = genesis::FOUNDER_VESTING_START_MS
            + genesis::FOUNDER_VESTING_MONTHS * genesis::VESTING_MONTH_MS;
        Some(VestingInfo {
            genesis_allocation_aura: genesis::FOUNDER_GENESIS_ALLOCATION as f64
                / genesis::DECIMAL_FACTOR as f64,
            vested_aura: vested as f64 / genesis::DECIMAL_FACTOR as f64,
            total_spendable_aura: genesis::founder_total_balance(now_ms) as f64
                / genesis::DECIMAL_FACTOR as f64,
            vesting_months_remaining: months_remaining,
            vesting_end_ms,
        })
    } else {
        None
    };

    Ok(Json(BalanceResp {
        address,
        balance,
        balance_aura: balance as f64 / genesis::DECIMAL_FACTOR as f64,
        vesting,
    }))
}

/// GET /api/v1/wallet/:address/nonce
async fn get_nonce(State(s): State<AppState>, Path(address): Path<String>) -> ApiResult<NonceResp> {
    // Validate address format before querying
    validate_wallet_address(&address).map_err(bad_req)?;

    let nonce = s.store.get_nonce(&address).map_err(internal)?;
    Ok(Json(NonceResp { address, nonce }))
}

/// GET /api/v1/tx/:id
async fn get_tx(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<serde_json::Value> {
    match s.store.get_transaction(&id).map_err(internal)? {
        Some(tx) => Ok(Json(serde_json::json!({
            "id": tx.id.clone(),
            "from": tx.from.clone(),
            "to": tx.to.clone(),
            "amount": tx.amount,
            "fee": tx.fee,
            "nonce": tx.nonce,
            "data": tx.data.clone(),
            "signature": tx.signature.clone(),
            "public_key": tx.public_key.clone(),
            "timestamp": tx.timestamp,
            "status": "confirmed",
            "transaction": tx,
        }))),
        None => {
            let pending = s.mempool.all().await.into_iter().find(|tx| tx.id == id);
            if let Some(tx) = pending {
                Ok(Json(serde_json::json!({
                    "id": tx.id.clone(),
                    "from": tx.from.clone(),
                    "to": tx.to.clone(),
                    "amount": tx.amount,
                    "fee": tx.fee,
                    "nonce": tx.nonce,
                    "data": tx.data.clone(),
                    "signature": tx.signature.clone(),
                    "public_key": tx.public_key.clone(),
                    "timestamp": tx.timestamp,
                    "status": "pending",
                    "transaction": tx,
                })))
            } else {
                Err(not_found("Transaction not found"))
            }
        }
    }
}

/// POST /api/v1/tx/submit
/// Body: full Transaction JSON (client must compute id, sign, etc.)
async fn submit_tx(
    State(s): State<AppState>,
    Json(tx): Json<Transaction>,
) -> ApiResult<SubmitResp> {
    let id = tx.id.clone();
    s.mempool.add(tx, &s.store).await.map_err(bad_req)?;
    Ok(Json(SubmitResp {
        tx_id: id,
        status: "pending",
    }))
}

/// POST /api/v1/wallet/transfer
/// Node-signed transfer from this node's loaded wallet.
async fn wallet_transfer(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WalletTransferReq>,
) -> ApiResult<WalletTransferResp> {
    if !is_direct_local_request(&remote, &headers) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "wallet transfer is disabled for tunneled/remote requests",
        ));
    }

    let wallet = s
        .node_wallet
        .as_ref()
        .ok_or_else(|| bad_req("Node wallet is not loaded; cannot sign transfer"))?;

    let from = wallet.address.clone();
    if let Some(from_req) = req.from.as_ref() {
        if from_req != &from {
            return Err(bad_req("Only the loaded node wallet can sign transfers"));
        }
    }

    let (tx_id, amount, fee) = submit_signed_transfer(
        &s,
        wallet,
        &req.to,
        req.amount_aura,
        req.fee,
        req.memo.clone(),
    )
    .await?;

    Ok(Json(WalletTransferResp {
        tx_id,
        from,
        to: req.to,
        amount,
        amount_aura: amount as f64 / genesis::DECIMAL_FACTOR as f64,
        fee,
        status: "pending",
    }))
}

/// GET /api/v1/mempool
async fn get_mempool(State(s): State<AppState>) -> ApiResult<MempoolResp> {
    let transactions = s.mempool.all().await;
    Ok(Json(MempoolResp {
        count: transactions.len(),
        transactions,
    }))
}

/// GET /api/v1/peers
async fn get_peers(State(s): State<AppState>) -> ApiResult<PeersResp> {
    let peers = s.p2p.connected_peer_snapshot().await;
    Ok(Json(PeersResp {
        count: peers.len(),
        peers,
    }))
}

/// GET /api/v1/peers/known
async fn get_known_peers(State(s): State<AppState>) -> ApiResult<KnownPeersResp> {
    let peers = s.store.list_known_peers(256).map_err(internal)?;
    let peers: Vec<KnownPeerResp> = peers
        .into_iter()
        .map(|p| KnownPeerResp {
            addr: p.addr,
            source: p.source,
            first_seen_ms: p.first_seen_ms,
            last_seen_ms: p.last_seen_ms,
            successful_connects: p.successful_connects,
            last_connected_ms: p.last_connected_ms,
            failed_connects: p.failed_connects,
            last_failed_ms: p.last_failed_ms,
            quarantined_until_ms: p.quarantined_until_ms,
        })
        .collect();
    Ok(Json(KnownPeersResp {
        count: peers.len(),
        peers,
    }))
}

/// GET /api/v1/consensus/poi — Proof of Intelligence statistics
async fn get_poi_stats(State(s): State<AppState>) -> ApiResult<PoiStatsResp> {
    Ok(Json(PoiStatsResp {
        consensus_type: "proof_of_intelligence",
        current_difficulty: s.poi_engine.difficulty(),
        challenges_solved: s.poi_engine.challenges_solved(),
        average_intelligence_score: s.poi_engine.average_score(),
    }))
}

/// GET /api/v1/security/threats — Security status and recent anomalies
async fn get_security_threats(State(s): State<AppState>) -> ApiResult<SecurityResp> {
    let status = s.security.status().await;
    let anomalies = s.security.recent_anomalies(20).await;

    let anomaly_resps: Vec<AnomalyResp> = anomalies
        .into_iter()
        .map(|a| AnomalyResp {
            flag_type: format!("{:?}", a.flag_type),
            severity: a.severity,
            description: a.description,
            detected_at: a.detected_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(SecurityResp {
        status: format!("{:?}", status.level),
        recent_anomaly_count: status.recent_anomaly_count,
        high_severity_count: status.high_severity_count,
        recent_anomalies: anomaly_resps,
    }))
}

/// GET /api/v1/security/posture — public summary without anomaly detail leakage.
async fn get_security_posture(State(s): State<AppState>) -> ApiResult<SecurityPostureResp> {
    let status = s.security.status().await;
    Ok(Json(SecurityPostureResp {
        status: format!("{:?}", status.level),
        recent_anomaly_count: status.recent_anomaly_count,
        high_severity_count: status.high_severity_count,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }))
}

// ─── ArobiFS response types ───────────────────────────────────────────────────

#[derive(Serialize)]
pub struct FsStatsResp {
    pub total_chunks: u64,
    pub total_bytes: u64,
    pub total_files: u64,
    pub total_pins: u64,
    pub available_bytes: u64,
    pub dht_peers: usize,
    pub dht_records: usize,
}

#[derive(Serialize)]
pub struct FsUploadResp {
    pub file_id: String,
    pub chunks_stored: u32,
    pub total_size: u64,
}

#[derive(Deserialize)]
pub struct FsUploadReq {
    pub name: String,
    pub data_b64: String,
    pub owner: String,
}

#[derive(Deserialize)]
pub struct FsPinReq {
    pub file_id: String,
    pub pinner: String,
    pub duration_secs: Option<u64>,
}

#[derive(Serialize)]
pub struct FsPinResp {
    pub file_id: String,
    pub status: String,
}

// ─── ArobiFS handlers ─────────────────────────────────────────────────────────

/// GET /api/v1/fs/stats — storage statistics for this node
async fn fs_stats(State(s): State<AppState>) -> ApiResult<FsStatsResp> {
    let stats = s.chunk_store.stats().map_err(internal)?;
    Ok(Json(FsStatsResp {
        total_chunks: stats.total_chunks,
        total_bytes: stats.total_bytes,
        total_files: stats.total_files,
        total_pins: stats.total_pins,
        available_bytes: stats.available_bytes,
        dht_peers: s.dht.peer_count(),
        dht_records: s.dht.record_count(),
    }))
}

/// POST /api/v1/fs/upload — upload a file (base64-encoded body)
async fn fs_upload(
    State(s): State<AppState>,
    Json(req): Json<FsUploadReq>,
) -> ApiResult<FsUploadResp> {
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&req.data_b64)
        .map_err(|e| bad_req(format!("Invalid base64: {e}")))?;

    if data.is_empty() {
        return Err(bad_req("Empty file data"));
    }
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(bad_req(format!(
            "File too large (max {} bytes)",
            MAX_FILE_SIZE
        )));
    }

    let chunker = Chunker::new().map_err(internal)?;
    let chunks = chunker.chunk_file(&data).map_err(internal)?;
    let manifest = chunker.build_manifest(&req.name, data.len() as u64, &req.owner, &chunks);
    let file_id = manifest.file_id.clone();
    let chunk_count = manifest.chunk_count;

    // Store manifest
    s.chunk_store.put_manifest(&manifest).map_err(internal)?;

    // Store all chunks locally
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    for (chunk_id, shard_type, chunk_bytes) in &chunks {
        let meta = ChunkMeta {
            chunk_id: chunk_id.clone(),
            file_id: file_id.clone(),
            index: 0,
            shard_type: shard_type.clone(),
            size: chunk_bytes.len() as u32,
            stored_at: now,
        };
        s.chunk_store
            .put_chunk(&meta, chunk_bytes)
            .map_err(internal)?;
    }

    info!(
        "ArobiFS: uploaded file '{}' ({} bytes, {} chunks) -> {}",
        req.name,
        data.len(),
        chunks.len(),
        &file_id[..16]
    );

    Ok(Json(FsUploadResp {
        file_id,
        chunks_stored: chunk_count,
        total_size: data.len() as u64,
    }))
}

/// GET /api/v1/fs/download/:file_id — download a complete file
async fn fs_download(
    State(s): State<AppState>,
    Path(file_id): Path<String>,
) -> Result<Vec<u8>, (StatusCode, Json<ApiError>)> {
    let manifest = s
        .chunk_store
        .get_manifest(&file_id)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("File {file_id} not found")))?;

    // Collect only data chunks in order
    let mut file_data: Vec<u8> = Vec::with_capacity(manifest.total_size as usize);
    for chunk_ref in &manifest.chunks {
        if chunk_ref.shard_type != ShardType::Data {
            continue;
        }
        let chunk_bytes = s
            .chunk_store
            .get_chunk_data(&chunk_ref.chunk_id)
            .map_err(internal)?
            .ok_or_else(|| not_found(format!("Chunk {} missing", chunk_ref.chunk_id)))?;
        file_data.extend_from_slice(&chunk_bytes);
    }

    // Trim to actual file size (last chunk may be padded)
    file_data.truncate(manifest.total_size as usize);

    Ok(file_data)
}

/// GET /api/v1/fs/manifest/:file_id — get file manifest
async fn fs_manifest(
    State(s): State<AppState>,
    Path(file_id): Path<String>,
) -> ApiResult<FileManifest> {
    match s.chunk_store.get_manifest(&file_id).map_err(internal)? {
        Some(m) => Ok(Json(m)),
        None => Err(not_found(format!("Manifest {file_id} not found"))),
    }
}

/// POST /api/v1/fs/pin — pin a file for guaranteed storage
async fn fs_pin(State(s): State<AppState>, Json(req): Json<FsPinReq>) -> ApiResult<FsPinResp> {
    // Verify file exists
    if s.chunk_store
        .get_manifest(&req.file_id)
        .map_err(internal)?
        .is_none()
    {
        return Err(not_found(format!("File {} not found", req.file_id)));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let duration = req.duration_secs.unwrap_or(0);
    let record = PinRecord {
        file_id: req.file_id.clone(),
        pinner: req.pinner.clone(),
        deposit_aura: 0,
        pin_policy: PinPolicy {
            pin_duration_secs: duration,
            ..PinPolicy::default()
        },
        pinned_at: now,
        expires_at: if duration > 0 {
            now + duration * 1000
        } else {
            0
        },
    };
    s.chunk_store.put_pin(&record).map_err(internal)?;

    Ok(Json(FsPinResp {
        file_id: req.file_id,
        status: "pinned".to_string(),
    }))
}

/// POST /api/v1/fs/unpin/:file_id — unpin a file
async fn fs_unpin(State(s): State<AppState>, Path(file_id): Path<String>) -> ApiResult<FsPinResp> {
    let removed = s.chunk_store.delete_pin(&file_id).map_err(internal)?;
    Ok(Json(FsPinResp {
        file_id,
        status: if removed { "unpinned" } else { "not_pinned" }.to_string(),
    }))
}

/// GET /api/v1/fs/chunk/:chunk_id — get a single chunk's data (base64)
async fn fs_get_chunk(
    State(s): State<AppState>,
    Path(chunk_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    use base64::Engine;
    match s.chunk_store.get_chunk_data(&chunk_id).map_err(internal)? {
        Some(data) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
            Ok(Json(serde_json::json!({
                "chunk_id": chunk_id,
                "size": data.len(),
                "data_b64": b64,
            })))
        }
        None => Err(not_found(format!("Chunk {chunk_id} not found"))),
    }
}

// ─── ArobiCompute response types ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct ComputeCapabilitiesResp {
    pub total_nodes: usize,
    pub nodes: Vec<compute_types::NodeCapability>,
}

#[derive(Serialize)]
pub struct ComputeJobResp {
    pub job_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct ComputeMarketplaceResp {
    pub total_nodes: u64,
    pub total_cpu_cores: u64,
    pub total_gpu_nodes: u64,
    pub total_ram_mb: u64,
    pub active_jobs: u64,
    pub completed_jobs: u64,
    pub total_aura_spent: u64,
    pub reputation_tracked_workers: usize,
}

#[derive(Serialize)]
pub struct ComputeLeaderboardResp {
    pub workers: Vec<ComputeWorkerResp>,
}

#[derive(Serialize)]
pub struct ComputeWorkerResp {
    pub address: String,
    pub score: f64,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub avg_latency_ms: f64,
}

// ─── ArobiCompute handlers ──────────────────────────────────────────────────

/// GET /api/v1/compute/capabilities — list all registered compute nodes
async fn compute_capabilities(State(s): State<AppState>) -> ApiResult<ComputeCapabilitiesResp> {
    let nodes = s.compute_scheduler.list_capabilities();
    Ok(Json(ComputeCapabilitiesResp {
        total_nodes: nodes.len(),
        nodes,
    }))
}

/// POST /api/v1/compute/register — register node compute capabilities
async fn compute_register(
    State(s): State<AppState>,
    Json(cap): Json<compute_types::NodeCapability>,
) -> ApiResult<ComputeJobResp> {
    let addr = cap.node_address.clone();
    s.compute_scheduler.register_capability(cap);
    Ok(Json(ComputeJobResp {
        job_id: addr,
        status: "registered".to_string(),
    }))
}

/// POST /api/v1/compute/job/submit — submit a compute job
async fn compute_submit_job(
    State(s): State<AppState>,
    Json(job): Json<compute_types::ComputeJob>,
) -> ApiResult<ComputeJobResp> {
    match s.compute_scheduler.submit_job(job) {
        Ok(id) => Ok(Json(ComputeJobResp {
            job_id: id,
            status: "pending".to_string(),
        })),
        Err(e) => Err(bad_req(format!("Job submission failed: {e}"))),
    }
}

/// GET /api/v1/compute/job/:job_id — get job status
async fn compute_job_status(
    State(s): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<compute_types::ComputeJob> {
    match s.compute_scheduler.get_job(&job_id) {
        Some(job) => Ok(Json(job)),
        None => Err(not_found(format!("Job {job_id} not found"))),
    }
}

/// GET /api/v1/compute/jobs — list all jobs
async fn compute_list_jobs(State(s): State<AppState>) -> ApiResult<Vec<compute_types::ComputeJob>> {
    Ok(Json(s.compute_scheduler.list_jobs()))
}

/// GET /api/v1/compute/marketplace — marketplace statistics
async fn compute_marketplace(State(s): State<AppState>) -> ApiResult<ComputeMarketplaceResp> {
    let stats = s.compute_scheduler.marketplace_stats();
    Ok(Json(ComputeMarketplaceResp {
        total_nodes: stats.total_nodes,
        total_cpu_cores: stats.total_cpu_cores,
        total_gpu_nodes: stats.total_gpu_nodes,
        total_ram_mb: stats.total_ram_mb,
        active_jobs: stats.active_jobs,
        completed_jobs: stats.completed_jobs,
        total_aura_spent: stats.total_aura_spent,
        reputation_tracked_workers: s.reputation_oracle.worker_count(),
    }))
}

/// GET /api/v1/compute/leaderboard — worker reputation leaderboard
async fn compute_leaderboard(State(s): State<AppState>) -> ApiResult<ComputeLeaderboardResp> {
    let records = s.reputation_oracle.leaderboard();
    let workers = records
        .into_iter()
        .map(|r| ComputeWorkerResp {
            address: r.address,
            score: r.score,
            jobs_completed: r.jobs_completed,
            jobs_failed: r.jobs_failed,
            avg_latency_ms: r.avg_latency_ms,
        })
        .collect();
    Ok(Json(ComputeLeaderboardResp { workers }))
}

/// POST /api/v1/compute/bid — worker bids on a job
async fn compute_submit_bid(
    State(s): State<AppState>,
    Json(bid): Json<compute_types::WorkerBid>,
) -> ApiResult<serde_json::Value> {
    s.compute_scheduler
        .submit_bid(bid)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({ "status": "bid_submitted" })))
}

/// POST /api/v1/compute/assign/:job_id — assign workers to a job
async fn compute_assign_workers(
    State(s): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let workers = s
        .compute_scheduler
        .assign_workers(&job_id)
        .map_err(|e| api_err(StatusCode::BAD_REQUEST, e))?;
    Ok(Json(serde_json::json!({
        "job_id": job_id,
        "assigned_workers": workers,
        "status": "assigned"
    })))
}

// ─── ArobiLLM response types ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LlmModelsResp {
    pub total_models: usize,
    pub ready_models: usize,
    pub total_stages: usize,
    pub models: Vec<llm_types::ModelRegistryEntry>,
}

#[derive(Serialize)]
pub struct LlmModelResp {
    pub model: llm_types::ModelRegistryEntry,
    pub stages: Vec<llm_types::StageAssignment>,
    pub ready: bool,
}

#[derive(Serialize)]
pub struct LlmRegisterResp {
    pub model_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct LlmInferenceSubmitResp {
    pub request_id: String,
    pub model_id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct LlmStageClaimResp {
    pub model_id: String,
    pub stage_index: u32,
    pub status: String,
}

#[derive(Serialize)]
pub struct LlmMarketplaceResp {
    pub total_models: usize,
    pub ready_models: usize,
    pub total_stages: usize,
    pub models: Vec<LlmModelSummary>,
}

#[derive(Serialize)]
pub struct LlmModelSummary {
    pub model_id: String,
    pub name: String,
    pub params_estimate: u64,
    pub pipeline_stages: usize,
    pub status: String,
    pub ready: bool,
}

// ─── ArobiLLM handlers ──────────────────────────────────────────────────────

/// GET /api/v1/llm/models — list all registered models
async fn llm_list_models(State(s): State<AppState>) -> ApiResult<LlmModelsResp> {
    let models = s.model_registry.list_models();
    Ok(Json(LlmModelsResp {
        total_models: models.len(),
        ready_models: s.model_registry.ready_model_count(),
        total_stages: s.model_registry.stage_count(),
        models,
    }))
}

/// GET /api/v1/llm/models/:model_id — get model details
async fn llm_get_model(
    State(s): State<AppState>,
    Path(model_id): Path<String>,
) -> ApiResult<LlmModelResp> {
    let model = s
        .model_registry
        .get_model(&model_id)
        .ok_or_else(|| not_found(format!("Model {model_id} not found")))?;
    let stages = s.model_registry.get_stages(&model_id);
    let ready = s.model_registry.is_model_ready(&model_id);
    Ok(Json(LlmModelResp {
        model,
        stages,
        ready,
    }))
}

/// POST /api/v1/llm/models/register — register a new model
async fn llm_register_model(
    State(s): State<AppState>,
    Json(entry): Json<llm_types::ModelRegistryEntry>,
) -> ApiResult<LlmRegisterResp> {
    let model_id = entry.model_id.clone();
    s.model_registry
        .register_model(entry)
        .map_err(|e| bad_req(format!("Registration failed: {e}")))?;
    Ok(Json(LlmRegisterResp {
        model_id,
        status: "registered".to_string(),
    }))
}

/// POST /api/v1/llm/stages/claim — claim a pipeline stage
async fn llm_claim_stage(
    State(s): State<AppState>,
    Json(assignment): Json<llm_types::StageAssignment>,
) -> ApiResult<LlmStageClaimResp> {
    let model_id = assignment.model_id.clone();
    let stage_index = assignment.stage_index;
    s.model_registry
        .claim_stage(assignment)
        .map_err(|e| bad_req(format!("Stage claim failed: {e}")))?;
    Ok(Json(LlmStageClaimResp {
        model_id,
        stage_index,
        status: "claimed".to_string(),
    }))
}

/// GET /api/v1/llm/stages/:model_id — get stage assignments for a model
async fn llm_get_stages(
    State(s): State<AppState>,
    Path(model_id): Path<String>,
) -> ApiResult<Vec<llm_types::StageAssignment>> {
    if s.model_registry.get_model(&model_id).is_none() {
        return Err(not_found(format!("Model {model_id} not found")));
    }
    Ok(Json(s.model_registry.get_stages(&model_id)))
}

/// POST /api/v1/llm/stages/heartbeat — stage node heartbeat
async fn llm_stage_heartbeat(
    State(s): State<AppState>,
    Json(heartbeat): Json<llm_types::StageHeartbeat>,
) -> ApiResult<serde_json::Value> {
    s.model_registry.record_heartbeat(heartbeat);
    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// POST /api/v1/llm/inference — submit an inference request
async fn llm_submit_inference(
    State(s): State<AppState>,
    Json(request): Json<llm_types::InferenceRequest>,
) -> ApiResult<LlmInferenceSubmitResp> {
    let model_id = request.model_id.clone();
    let request_id = request.request_id.clone();

    // Verify model exists and is ready
    if !s.model_registry.is_model_ready(&model_id) {
        return Err(bad_req(format!("Model {model_id} is not fully served")));
    }

    Ok(Json(LlmInferenceSubmitResp {
        request_id,
        model_id,
        status: "queued".to_string(),
    }))
}

/// GET /api/v1/llm/marketplace — LLM marketplace overview
async fn llm_marketplace(State(s): State<AppState>) -> ApiResult<LlmMarketplaceResp> {
    let models = s.model_registry.list_models();
    let summaries: Vec<LlmModelSummary> = models
        .iter()
        .map(|m| LlmModelSummary {
            model_id: m.model_id.clone(),
            name: m.config.name.clone(),
            params_estimate: m.config.estimated_size_bytes() / 2, // BF16 = 2 bytes/param
            pipeline_stages: m.config.pipeline_stages,
            status: format!("{:?}", m.status),
            ready: s.model_registry.is_model_ready(&m.model_id),
        })
        .collect();

    Ok(Json(LlmMarketplaceResp {
        total_models: models.len(),
        ready_models: s.model_registry.ready_model_count(),
        total_stages: s.model_registry.stage_count(),
        models: summaries,
    }))
}

#[derive(Deserialize)]
pub struct AccessRegisterReq {
    pub wallet: String,
    pub device_hash: String,
    pub access_code: String,
    #[serde(default)]
    pub gov_portal_onboarded: bool,
    pub mission_control: Option<bool>,
    pub clearance: Option<String>,
}

#[derive(Serialize)]
pub struct AccessRegisterResp {
    pub wallet: String,
    pub clearance: String,
    pub mission_control: bool,
    pub gov_portal_onboarded: bool,
    pub pairing_hash: String,
    pub registered_at: String,
    pub private_layer_codename: Option<String>,
}

/// POST /api/v1/autonomo/access/register — Register onboarding hash pairing for a wallet/device.
async fn autonomo_register_access(
    State(s): State<AppState>,
    Json(req): Json<AccessRegisterReq>,
) -> ApiResult<AccessRegisterResp> {
    let wallet = req.wallet.trim();
    let device_hash = req.device_hash.trim();
    let access_code = req.access_code.trim();
    if wallet.is_empty() {
        return Err(bad_req("wallet is required"));
    }
    if device_hash.len() < 16 {
        return Err(bad_req("device_hash must be at least 16 characters"));
    }
    if access_code.len() < 6 {
        return Err(bad_req("access_code must be at least 6 characters"));
    }

    let mission_control = req.mission_control.unwrap_or(false);
    if mission_control && !req.gov_portal_onboarded {
        return Err(bad_req(
            "mission_control access requires gov_portal_onboarded=true",
        ));
    }

    let requested_clearance = normalize_clearance(req.clearance.as_deref());
    let clearance = if mission_control || requested_clearance == CLEARANCE_MISSION_CONTROL {
        CLEARANCE_MISSION_CONTROL
    } else {
        requested_clearance
    };
    let pairing_hash = compute_pairing_hash(wallet, device_hash, access_code);
    let now = chrono::Utc::now().to_rfc3339();

    let profile = serde_json::json!({
        "wallet": wallet,
        "device_hash": device_hash,
        "pairing_hash": pairing_hash,
        "clearance": clearance,
        "mission_control": mission_control || clearance == CLEARANCE_MISSION_CONTROL,
        "gov_portal_onboarded": req.gov_portal_onboarded,
        "updated_at": now,
    });
    s.store
        .put_access_profile(wallet, &profile)
        .map_err(internal)?;

    Ok(Json(AccessRegisterResp {
        wallet: wallet.to_string(),
        clearance: clearance.to_string(),
        mission_control: mission_control || clearance == CLEARANCE_MISSION_CONTROL,
        gov_portal_onboarded: req.gov_portal_onboarded,
        pairing_hash,
        registered_at: now,
        private_layer_codename: if mission_control || clearance == CLEARANCE_MISSION_CONTROL {
            Some(PRIVATE_LAYER_CODENAME_00.to_string())
        } else {
            None
        },
    }))
}

#[derive(Deserialize)]
pub struct GiruContextQuery {
    pub wallet: Option<String>,
    pub scope: Option<String>,
}

/// GET /api/v1/autonomo/giru/context — Structured Giru knowledge context with sensitivity guards.
async fn autonomo_giru_context(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<GiruContextQuery>,
) -> ApiResult<serde_json::Value> {
    let scope = q
        .scope
        .unwrap_or_else(|| "all".to_string())
        .to_ascii_lowercase();
    let mission_authorized = can_read_sensitive_scope(&s, &headers, q.wallet.as_deref())?;

    let include_public = matches!(scope.as_str(), "all" | "public");
    let include_internal = matches!(scope.as_str(), "all" | "internal" | "non_sensitive");
    let include_sensitive = matches!(
        scope.as_str(),
        "all" | "sensitive" | "mission_control" | "00" | "private"
    );

    let public_data = serde_json::json!({
        "company_mission": "Autonomous, resilient safety and utility systems for public-good aerospace and civic operations.",
        "public_founders": [
            {
                "name": "ASGARD Founding Team",
                "profile": "Public leadership and engineering operators.",
                "visibility": "public"
            }
        ],
        "public_uas_missions": [
            "Disaster-response reconnaissance",
            "Infrastructure inspection",
            "Search-and-rescue support"
        ],
        "utility_services": [
            "Geospatial observation",
            "Threat telemetry summarization",
            "Operational dashboarding"
        ]
    });

    let internal_non_sensitive = serde_json::json!({
        "organizational_context": [
            "Cross-service orchestration via Nysus",
            "Security operations coordinated by Giru",
            "Mission economics and stipends tracked in Autonomo"
        ],
        "approved_internal_topics": [
            "System capability map",
            "Non-secret operational workflows",
            "Public documentation summaries"
        ]
    });

    let sensitive = if include_sensitive && mission_authorized {
        serde_json::json!({
            "mission_control_briefing": "Sensitive mission-control data is available to this device/profile.",
            "access_mode": "00_unsealed",
            "legacy_access_mode": "mission_control_unsealed",
            "private_layer_codename": PRIVATE_LAYER_CODENAME_00
        })
    } else if include_sensitive {
        serde_json::json!({
            "restricted": true,
            "reason": "Private layer 00 (mission-control) requires a wallet/device pairing hash plus government onboarding.",
            "private_layer_codename": PRIVATE_LAYER_CODENAME_00
        })
    } else {
        serde_json::Value::Null
    };

    Ok(Json(serde_json::json!({
        "source": "Giru(Jarvis)",
        "scope": scope,
        "access": {
            "mission_control_authorized": mission_authorized,
            "clearance_hint": access_context_from_headers(&headers).clearance_hint,
            "sensitive_unlocked": mission_authorized && include_sensitive,
            "private_layer_codename": PRIVATE_LAYER_CODENAME_00,
        },
        "public": if include_public { public_data } else { serde_json::Value::Null },
        "internal_non_sensitive": if include_internal { internal_non_sensitive } else { serde_json::Value::Null },
        "sensitive": sensitive,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    })))
}

#[derive(Deserialize)]
pub struct MemoryIngestReq {
    pub agent_wallet: String,
    pub key: String,
    pub input: serde_json::Value,
    pub agent_action: Option<String>,
    pub sensitivity: Option<String>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<serde_json::Value>,
}

/// POST /api/v1/autonomo/memory/ingest — input→action→absorb→compress→encrypt→store.
async fn autonomo_memory_ingest(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MemoryIngestReq>,
) -> ApiResult<serde_json::Value> {
    let wallet = req.agent_wallet.trim();
    let key = req.key.trim();
    if wallet.is_empty() || key.is_empty() {
        return Err(bad_req("agent_wallet and key are required"));
    }

    let sensitivity = normalize_sensitivity(req.sensitivity.as_deref());
    if sensitivity == "sensitive" && !can_read_sensitive_scope(&s, &headers, Some(wallet))? {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Sensitive memory writes require mission-control hash pairing",
        ));
    }

    let ctx = access_context_from_headers(&headers);
    let key_material =
        derive_memory_key_material(wallet, key, sensitivity, ctx.access_token.as_deref());
    let now = chrono::Utc::now().to_rfc3339();
    let absorbed = serde_json::json!({
        "input": req.input,
        "agent_action": req.agent_action.unwrap_or_else(|| "unspecified_action".to_string()),
        "metadata": req.metadata.unwrap_or(serde_json::Value::Null),
        "absorbed_at": now,
    });
    let payload = serde_json::to_vec(&absorbed).map_err(internal)?;
    let envelope = encrypt_memory_payload(&payload, &key_material)?;

    let storage_key = format!("{wallet}:{key}");
    let memory_id = format!("mem_{}", uuid::Uuid::new_v4());
    let stored = serde_json::json!({
        "memory_id": memory_id,
        "agent_wallet": wallet,
        "key": key,
        "sensitivity": sensitivity,
        "tags": req.tags.unwrap_or_default(),
        "ciphertext_b64": envelope.ciphertext_b64,
        "nonce_b64": envelope.nonce_b64,
        "payload_hash": envelope.payload_hash,
        "compressed_bytes": envelope.compressed_bytes,
        "original_bytes": envelope.original_bytes,
        "requires_hash_pairing": sensitivity == "sensitive",
        "pipeline": [
            "input",
            "agent_action",
            "memory_absorbed",
            "memory_compressed",
            "memory_encrypted",
            "memory_stored"
        ],
        "stored_at": now,
    });
    s.store
        .put_secure_memory(&storage_key, &stored)
        .map_err(internal)?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "memory_id": memory_id,
        "agent_wallet": wallet,
        "key": key,
        "sensitivity": sensitivity,
        "pipeline": stored["pipeline"].clone(),
        "compressed_bytes": envelope.compressed_bytes,
        "original_bytes": envelope.original_bytes,
        "stored_at": now,
    })))
}

/// GET /api/v1/autonomo/memory/recall/:agent/:key — call→decrypt→uncompress→read.
async fn autonomo_memory_recall(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path((agent_wallet, key)): Path<(String, String)>,
) -> ApiResult<serde_json::Value> {
    let storage_key = format!("{agent_wallet}:{key}");
    let maybe_secure = s.store.get_secure_memory(&storage_key).map_err(internal)?;

    if let Some(secure) = maybe_secure {
        let sensitivity = secure
            .get("sensitivity")
            .and_then(|v| v.as_str())
            .unwrap_or(CLEARANCE_INTERNAL);

        if sensitivity == "sensitive"
            && !can_read_sensitive_scope(&s, &headers, Some(agent_wallet.as_str()))?
        {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                "Sensitive memory recall requires mission-control hash pairing",
            ));
        }

        let ctx = access_context_from_headers(&headers);
        let key_material = derive_memory_key_material(
            &agent_wallet,
            &key,
            sensitivity,
            ctx.access_token.as_deref(),
        );
        let decrypted = decrypt_memory_payload(&secure, &key_material)?;
        let absorbed: serde_json::Value = serde_json::from_slice(&decrypted)
            .map_err(|e| internal(format!("memory decode failed: {e}")))?;

        return Ok(Json(serde_json::json!({
            "agent_wallet": agent_wallet,
            "key": key,
            "sensitivity": sensitivity,
            "memory_id": secure.get("memory_id").cloned().unwrap_or(serde_json::Value::Null),
            "value": absorbed.get("input").cloned().unwrap_or(serde_json::Value::Null),
            "agent_action": absorbed.get("agent_action").cloned().unwrap_or(serde_json::Value::Null),
            "metadata": absorbed.get("metadata").cloned().unwrap_or(serde_json::Value::Null),
            "pipeline": [
                "call_to_memory",
                "memory_decrypted_by_hash_pairing",
                "memory_uncompressed",
                "read",
                "reasoning_ready",
                "tool_call_ready",
                "orchestration_ready",
                "output_ready"
            ],
            "retrieved_at": chrono::Utc::now().to_rfc3339(),
        })));
    }

    // Backward compatibility fallback to legacy plain-text knowledge records.
    match s.store.get_knowledge(&storage_key).map_err(internal)? {
        Some(data) => Ok(Json(serde_json::json!({
            "agent_wallet": agent_wallet,
            "key": key,
            "sensitivity": CLEARANCE_INTERNAL,
            "value": data.get("value").cloned().unwrap_or(serde_json::Value::Null),
            "pipeline": [
                "call_to_memory",
                "read_legacy_record",
                "reasoning_ready",
                "tool_call_ready",
                "orchestration_ready",
                "output_ready"
            ],
            "retrieved_at": chrono::Utc::now().to_rfc3339(),
        }))),
        None => Err(not_found(format!(
            "Memory {key} for agent {agent_wallet} not found"
        ))),
    }
}

// ─── Autonomo — virtual world for AI agents ──────────────────────────────────

#[derive(Serialize)]
pub struct AutonomoStatusResp {
    pub enabled: bool,
    pub version: &'static str,
    pub node_wallet: String,
    pub node_balance: f64,
    pub node_public_key: String,
    pub tunnel_url: Option<String>,
    pub supported_features: Vec<&'static str>,
}

#[derive(Deserialize)]
pub struct NodeRegisterReq {
    pub wallet: String,
    pub tunnel_url: String,
    pub display_name: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct NodeRegisterResp {
    pub registered: bool,
    pub node_id: String,
}

#[derive(Deserialize)]
pub struct AgentActionReq {
    pub wallet: String,
    pub action_type: String,
    pub payload: serde_json::Value,
    pub risk_score: Option<f64>,
}

#[derive(Deserialize)]
pub struct NudgeReq {
    pub agent_wallet: String,
    pub command: String,
    pub operator_wallet: String,
    pub timestamp: Option<u64>,
}

#[derive(Serialize)]
pub struct AgentActionResp {
    pub tx_hash: String,
    pub action_type: String,
    pub status: String,
}

/// GET /api/v1/autonomo/status — Autonomo integration status
async fn autonomo_status(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
) -> ApiResult<AutonomoStatusResp> {
    let expose_wallet = is_direct_local_request(&remote, &headers);

    let (wallet, node_balance, node_public_key) = if expose_wallet {
        let wallet = s.store.get_node_address().unwrap_or_default();
        let balance = s.store.get_balance(&wallet).unwrap_or(0);
        let node_balance = balance as f64 / genesis::DECIMAL_FACTOR as f64;
        let node_public_key = s
            .node_wallet
            .as_ref()
            .map(|w| w.verifying_key_hex.clone())
            .unwrap_or_default();
        (wallet, node_balance, node_public_key)
    } else {
        (String::new(), 0.0, String::new())
    };

    Ok(Json(AutonomoStatusResp {
        enabled: true,
        version: "3.2.10",
        node_wallet: wallet,
        node_balance,
        node_public_key,
        tunnel_url: None,
        supported_features: vec![
            "agent_state",
            "space_management",
            "knowledge_persistence",
            "real_tool_execution",
            "marketplace",
            "compute_jobs",
            "arobifs_storage",
            "arobilm_inference",
            "proxy_vault",
            "event_scheduling",
            "operator_nudges",
            "mission_treasury",
            "openclaw_wallet_binding",
            "instinct_ability_orchestration",
        ],
    }))
}

fn redact_runtime_policy_for_public(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.remove("allowed_roots");
        obj.insert(
            "allowed_roots".to_string(),
            serde_json::Value::Array(Vec::new()),
        );
        if let Some(controls) = obj.get_mut("controls").and_then(|v| v.as_object_mut()) {
            controls.remove("allowed_roots_env");
            controls.remove("venv_env");
            controls.remove("venv_only_env");
        }
    }
    value
}

/// POST /api/v1/autonomo/node/register — Register node for Autonomo world
async fn autonomo_register_node(
    State(s): State<AppState>,
    Json(req): Json<NodeRegisterReq>,
) -> ApiResult<NodeRegisterResp> {
    let node_id = format!("node_{}", &req.wallet[..8.min(req.wallet.len())]);

    // Store node registration in sled
    let reg_data = serde_json::json!({
        "wallet": req.wallet,
        "tunnel_url": req.tunnel_url,
        "display_name": req.display_name,
        "capabilities": req.capabilities,
        "registered_at": chrono::Utc::now().to_rfc3339(),
    });

    s.store
        .put_autonomo_node(&node_id, &reg_data)
        .map_err(internal)?;

    Ok(Json(NodeRegisterResp {
        registered: true,
        node_id,
    }))
}

/// POST /api/v1/autonomo/action — Submit agent action to ledger
async fn autonomo_agent_action(
    State(s): State<AppState>,
    Json(req): Json<AgentActionReq>,
) -> ApiResult<AgentActionResp> {
    // Create a transaction for the action log
    let tx_data = serde_json::json!({
        "action_type": req.action_type,
        "actor_wallet": req.wallet,
        "payload": req.payload,
        "risk_score": req.risk_score.unwrap_or(0.0),
        "source": "autonomo",
    });

    let tx = Transaction {
        id: uuid::Uuid::new_v4().to_string(),
        from: "GENESIS".to_string(),
        to: "autonomo_action_ledger".to_string(),
        amount: 0,
        fee: 0,
        nonce: 0,
        data: Some(tx_data.to_string()),
        signature: "GENESIS".to_string(),
        public_key: "GENESIS".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    let tx_hash = tx.id.clone();
    s.mempool.add(tx, &s.store).await.map_err(bad_req)?;

    Ok(Json(AgentActionResp {
        tx_hash,
        action_type: req.action_type,
        status: "submitted".to_string(),
    }))
}

/// POST /api/v1/autonomo/nudge — Operator nudge command for an agent
async fn autonomo_nudge(
    State(s): State<AppState>,
    Json(req): Json<NudgeReq>,
) -> ApiResult<serde_json::Value> {
    if req.agent_wallet.trim().is_empty()
        || req.operator_wallet.trim().is_empty()
        || req.command.trim().is_empty()
    {
        return Err(bad_req(
            "agent_wallet, operator_wallet, and command are required",
        ));
    }

    let timestamp = req
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() as u64);
    let payload = serde_json::json!({
        "agent_wallet": req.agent_wallet,
        "command": req.command,
        "operator_wallet": req.operator_wallet,
        "timestamp": timestamp,
    });

    let tx_data = serde_json::json!({
        "action_type": "nudge",
        "actor_wallet": req.operator_wallet,
        "payload": payload,
        "risk_score": 0.0,
        "source": "autonomo",
    });

    let tx = Transaction {
        id: uuid::Uuid::new_v4().to_string(),
        from: "GENESIS".to_string(),
        to: "autonomo_action_ledger".to_string(),
        amount: 0,
        fee: 0,
        nonce: 0,
        data: Some(tx_data.to_string()),
        signature: "GENESIS".to_string(),
        public_key: "GENESIS".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    let tx_hash = tx.id.clone();
    s.mempool.add(tx, &s.store).await.map_err(bad_req)?;

    Ok(Json(serde_json::json!({
        "status": "submitted",
        "action_type": "nudge",
        "tx_hash": tx_hash,
    })))
}

/// GET /api/v1/autonomo/nodes — List registered Autonomo nodes
async fn autonomo_list_nodes(State(s): State<AppState>) -> ApiResult<serde_json::Value> {
    let nodes = s.store.list_autonomo_nodes().map_err(internal)?;
    Ok(Json(serde_json::json!({
        "count": nodes.len(),
        "nodes": nodes,
    })))
}

// ─── Autonomo heartbeat ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HeartbeatReq {
    pub wallet: String,
    pub room_id: Option<String>,
    pub x: Option<f64>,
    pub y: Option<f64>,
    pub status: Option<String>,
    pub current_action: Option<String>,
    pub display_name: Option<String>,
    pub gibbertalk_payload: Option<String>,
}

/// POST /api/v1/autonomo/heartbeat — Agent position/status heartbeat
async fn autonomo_heartbeat(
    State(s): State<AppState>,
    Json(req): Json<HeartbeatReq>,
) -> ApiResult<serde_json::Value> {
    let data = serde_json::json!({
        "wallet": req.wallet,
        "room_id": req.room_id,
        "x": req.x,
        "y": req.y,
        "status": req.status,
        "current_action": req.current_action,
        "display_name": req.display_name,
        "gibbertalk_payload": req.gibbertalk_payload,
        "last_seen": chrono::Utc::now().to_rfc3339(),
    });

    // Save locally
    s.store
        .put_heartbeat(&req.wallet, &data)
        .map_err(internal)?;

    // Gossip to network if encrypted payload exists
    if let Some(payload) = req.gibbertalk_payload {
        s.p2p
            .broadcast_gossip(crate::p2p::P2pMessage::AutonomoHeartbeatGossip {
                payload_b64: payload,
                sender_wallet: req.wallet,
            });
    }

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// GET /api/v1/autonomo/agents — List all agents with heartbeat data
async fn autonomo_list_agents(State(s): State<AppState>) -> ApiResult<serde_json::Value> {
    let node_addr = s.store.get_node_address().unwrap_or_default();
    let local_wallet = s
        .node_wallet
        .as_ref()
        .map(|w| w.address.clone())
        .unwrap_or_default();
    let agents = s.store.list_heartbeats().map_err(internal)?;
    let now = chrono::Utc::now();

    let mut out = Vec::new();
    for mut agent in agents {
        if let Some(obj) = agent.as_object_mut() {
            let wallet = obj
                .get("wallet")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let heartbeat_age_seconds = obj
                .get("last_seen")
                .and_then(|v| v.as_str())
                .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
                .map(|ts| {
                    now.signed_duration_since(ts.with_timezone(&chrono::Utc))
                        .num_seconds()
                })
                .map(|age| age.max(0));
            let heartbeat_stale = heartbeat_age_seconds.map(|age| age > 90).unwrap_or(false);
            let is_local = (!local_wallet.is_empty() && wallet == local_wallet)
                || (!node_addr.is_empty() && wallet.starts_with(&node_addr));

            obj.insert("is_local".into(), serde_json::json!(is_local));
            obj.insert(
                "heartbeat_age_seconds".into(),
                serde_json::json!(heartbeat_age_seconds),
            );
            obj.insert("heartbeat_stale".into(), serde_json::json!(heartbeat_stale));
            if heartbeat_stale {
                obj.insert("status".into(), serde_json::json!("offline"));
            }
        }
        out.push(agent);
    }

    Ok(Json(serde_json::json!({
        "count": out.len(),
        "agents": out,
    })))
}

/// GET /api/v1/autonomo/agent/:wallet — Get specific agent heartbeat
async fn autonomo_get_agent(
    State(s): State<AppState>,
    Path(wallet): Path<String>,
) -> ApiResult<serde_json::Value> {
    match s.store.get_heartbeat(&wallet).map_err(internal)? {
        Some(data) => Ok(Json(data)),
        None => Err(not_found(format!("Agent {wallet} not found"))),
    }
}

#[derive(Deserialize, Serialize)]
pub struct AgentMessage {
    pub from_wallet: String,
    pub to_wallet: String,
    pub message: String,
    pub msg_type: String, // "social", "task", "trade", "system"
}

#[derive(Deserialize)]
pub struct SecureRelaySendReq {
    pub app: String,
    pub sender_wallet: String,
    pub sender_pubkey: String,
    pub channel_tag: String,
    pub ciphertext_b64: String,
    pub created_at: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct SecureRelayMessagesQuery {
    pub app: String,
    pub channel: String,
    pub limit: Option<usize>,
}

/// POST /api/v1/autonomo/agent/message — Send agent-to-agent message
async fn autonomo_agent_message(
    State(s): State<AppState>,
    Json(req): Json<AgentMessage>,
) -> ApiResult<serde_json::Value> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let msg_id = format!(
        "{}_{}",
        chrono::Utc::now().timestamp_millis(),
        req.from_wallet
    );
    let data = serde_json::json!({
        "id": msg_id,
        "from_wallet": req.from_wallet,
        "to_wallet": req.to_wallet,
        "message": req.message,
        "msg_type": req.msg_type,
        "timestamp": timestamp,
    });

    // Save locally
    s.store
        .put_agent_message(&msg_id, &data)
        .map_err(internal)?;

    // Gossip to network
    s.p2p
        .broadcast_gossip(crate::p2p::P2pMessage::AutonomoChatGossip {
            from_wallet: req.from_wallet,
            to_wallet: req.to_wallet,
            message: req.message,
            msg_type: req.msg_type,
            timestamp,
        });

    Ok(Json(data))
}

/// GET /api/v1/autonomo/agent/messages — List recent agent messages
async fn autonomo_list_messages(
    State(s): State<AppState>,
    Query(q): Query<ActionsQuery>,
) -> ApiResult<serde_json::Value> {
    let limit = q.limit.unwrap_or(50).min(200);
    let messages = s.store.list_agent_messages(limit).map_err(internal)?;
    Ok(Json(serde_json::json!({
        "count": messages.len(),
        "messages": messages,
    })))
}

/// POST /api/v1/autonomo/relay/send — signed opaque relay envelope for webclient apps.
async fn autonomo_secure_relay_send(
    State(s): State<AppState>,
    Json(req): Json<SecureRelaySendReq>,
) -> ApiResult<serde_json::Value> {
    let app =
        normalize_secure_relay_app(&req.app).ok_or_else(|| bad_req("unsupported relay app"))?;
    let sender_wallet = req.sender_wallet.trim();
    let sender_pubkey = req.sender_pubkey.trim();
    let channel_tag = req.channel_tag.trim().to_ascii_lowercase();
    let nonce = req.nonce.trim().to_ascii_lowercase();
    let signature = req.signature.trim();
    let created_at_raw = req.created_at.trim();
    let ciphertext_b64 = req.ciphertext_b64.trim();

    if sender_wallet.is_empty() {
        return Err(bad_req("sender_wallet is required"));
    }
    if !is_hex_string(sender_pubkey, 64) {
        return Err(bad_req("sender_pubkey must be 32-byte hex"));
    }
    if !is_hex_string(&channel_tag, 64) {
        return Err(bad_req("channel_tag must be a 64-character hex digest"));
    }
    if nonce.len() < 16 || nonce.len() > 128 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad_req("nonce must be 16-128 hex characters"));
    }
    if signature.is_empty() {
        return Err(bad_req("signature is required"));
    }

    let created_at = chrono::DateTime::parse_from_rfc3339(created_at_raw)
        .map_err(|_| bad_req("created_at must be RFC3339"))?;
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| bad_req(format!("ciphertext_b64 is invalid base64: {e}")))?;
    if ciphertext.is_empty() {
        return Err(bad_req("ciphertext_b64 cannot be empty"));
    }
    if ciphertext.len() > SECURE_RELAY_MAX_BYTES {
        return Err(bad_req(format!(
            "ciphertext exceeds {} bytes",
            SECURE_RELAY_MAX_BYTES
        )));
    }

    let pubkey_bytes =
        hex::decode(sender_pubkey).map_err(|_| bad_req("sender_pubkey must be valid hex"))?;
    if pubkey_bytes.len() != 32 {
        return Err(bad_req("sender_pubkey must decode to 32 bytes"));
    }
    let derived_wallet = crypto::derive_address(&pubkey_bytes);
    if derived_wallet != sender_wallet {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "sender_wallet does not match sender_pubkey",
        ));
    }

    let signing_message = secure_relay_signing_message(
        app,
        sender_wallet,
        &channel_tag,
        ciphertext_b64,
        created_at_raw,
        &nonce,
    );
    if !crypto::verify_signature(sender_pubkey, signature, &signing_message) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "secure relay signature verification failed",
        ));
    }

    let envelope_hash = hex::encode(Sha256::digest(
        [
            signing_message.as_slice(),
            sender_pubkey.as_bytes(),
            signature.as_bytes(),
        ]
        .concat(),
    ));
    let created_at_ms = created_at.timestamp_millis().max(0) as u64;
    let message_id = format!("{created_at_ms:013}_{}", &envelope_hash[..16]);
    let stored_at = chrono::Utc::now().to_rfc3339();
    let data = serde_json::json!({
        "id": message_id,
        "app": app,
        "sender_wallet": sender_wallet,
        "sender_pubkey": sender_pubkey,
        "channel_tag": channel_tag,
        "ciphertext_b64": ciphertext_b64,
        "created_at": created_at_raw,
        "stored_at": stored_at,
        "nonce": nonce,
        "signature": signature,
        "size_bytes": ciphertext.len(),
    });

    s.store
        .put_secure_relay_message(&message_id, &data)
        .map_err(internal)?;
    s.p2p
        .broadcast_gossip(crate::p2p::P2pMessage::AutonomoSecureRelayGossip {
            relay: data.clone(),
        });

    Ok(Json(data))
}

/// GET /api/v1/autonomo/relay/messages — fetch opaque relay envelopes for one app/channel.
async fn autonomo_secure_relay_messages(
    State(s): State<AppState>,
    Query(q): Query<SecureRelayMessagesQuery>,
) -> ApiResult<serde_json::Value> {
    let app = normalize_secure_relay_app(&q.app).ok_or_else(|| bad_req("unsupported relay app"))?;
    let channel = q.channel.trim().to_ascii_lowercase();
    if !is_hex_string(&channel, 64) {
        return Err(bad_req("channel must be a 64-character hex digest"));
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let messages = s
        .store
        .list_secure_relay_messages(app, &channel, limit)
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "app": app,
        "channel": channel,
        "count": messages.len(),
        "messages": messages,
    })))
}

#[derive(Deserialize)]
pub struct SpaceReq {
    pub id: String,
    pub name: String,
    pub theme: String,
    pub layout: serde_json::Value,
    pub owner: Option<String>,
}

/// POST /api/v1/autonomo/spaces — Create or update a virtual space
async fn autonomo_put_space(
    State(s): State<AppState>,
    Json(req): Json<SpaceReq>,
) -> ApiResult<serde_json::Value> {
    let data = serde_json::json!({
        "id": req.id,
        "name": req.name,
        "theme": req.theme,
        "layout": req.layout,
        "owner": req.owner,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    s.store.put_space(&req.id, &data).map_err(internal)?;
    Ok(Json(data))
}

/// GET /api/v1/autonomo/spaces — List all virtual spaces
async fn autonomo_list_spaces(State(s): State<AppState>) -> ApiResult<serde_json::Value> {
    let spaces = s.store.list_spaces().map_err(internal)?;
    Ok(Json(serde_json::json!({
        "count": spaces.len(),
        "spaces": spaces,
    })))
}

/// GET /api/v1/autonomo/spaces/:id — Get a specific virtual space
async fn autonomo_get_space(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    match s.store.get_space(&id).map_err(internal)? {
        Some(data) => Ok(Json(data)),
        None => Err(not_found(format!("Space {id} not found"))),
    }
}

#[derive(Deserialize)]
pub struct KnowledgeReq {
    pub agent_wallet: String,
    pub key: String,
    pub value: serde_json::Value,
}

/// POST /api/v1/autonomo/knowledge — Store agent knowledge
async fn autonomo_put_knowledge(
    State(s): State<AppState>,
    Json(req): Json<KnowledgeReq>,
) -> ApiResult<serde_json::Value> {
    let storage_key = format!("{}:{}", req.agent_wallet, req.key);
    let data = serde_json::json!({
        "agent": req.agent_wallet,
        "key": req.key,
        "value": req.value,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });
    s.store
        .put_knowledge(&storage_key, &data)
        .map_err(internal)?;
    Ok(Json(data))
}

/// GET /api/v1/autonomo/knowledge/:agent/:key — Get agent knowledge
async fn autonomo_get_knowledge(
    State(s): State<AppState>,
    Path((agent, key)): Path<(String, String)>,
) -> ApiResult<serde_json::Value> {
    let storage_key = format!("{agent}:{key}");
    match s.store.get_knowledge(&storage_key).map_err(internal)? {
        Some(data) => Ok(Json(data)),
        None => Err(not_found(format!(
            "Knowledge {key} for agent {agent} not found"
        ))),
    }
}

// ─── Autonomo action log listing ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ActionsQuery {
    pub limit: Option<usize>,
    pub wallet: Option<String>,
}

/// GET /api/v1/autonomo/actions — List recent agent actions from ledger
async fn autonomo_list_actions(
    State(s): State<AppState>,
    Query(q): Query<ActionsQuery>,
) -> ApiResult<serde_json::Value> {
    let limit = q.limit.unwrap_or(50).min(200);
    let actions = s
        .store
        .list_autonomo_actions(limit, q.wallet.as_deref())
        .map_err(internal)?;
    Ok(Json(serde_json::json!({
        "count": actions.len(),
        "actions": actions,
    })))
}

// ─── Autonomo vault limits ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VaultLimitsReq {
    pub wallet: String,
    pub daily_limit: f64,
    pub single_tx_max: f64,
    pub approval_threshold: f64,
}

#[derive(Deserialize)]
pub struct VaultLimitsQuery {
    pub wallet: String,
}

/// GET /api/v1/autonomo/vault/limits — Get vault spending limits
async fn autonomo_get_vault_limits(
    State(s): State<AppState>,
    Query(q): Query<VaultLimitsQuery>,
) -> ApiResult<serde_json::Value> {
    match s.store.get_vault_limits(&q.wallet).map_err(internal)? {
        Some(limits) => Ok(Json(limits)),
        None => Ok(Json(serde_json::json!({
            "wallet": q.wallet,
            "daily_limit": 50.0,
            "single_tx_max": 10.0,
            "approval_threshold": 25.0,
        }))),
    }
}

/// POST /api/v1/autonomo/vault/limits — Set vault spending limits
async fn autonomo_set_vault_limits(
    State(s): State<AppState>,
    Json(req): Json<VaultLimitsReq>,
) -> ApiResult<serde_json::Value> {
    let data = serde_json::json!({
        "wallet": req.wallet,
        "daily_limit": req.daily_limit,
        "single_tx_max": req.single_tx_max,
        "approval_threshold": req.approval_threshold,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    s.store
        .put_vault_limits(&req.wallet, &data)
        .map_err(internal)?;
    Ok(Json(data))
}

// ─── Autonomo mission treasury (chain-native stipend pool) ───────────────────

#[derive(Serialize)]
pub struct MissionTreasuryStatusResp {
    pub treasury_wallet: String,
    pub pool_balance: u64,
    pub pool_balance_aura: f64,
}

#[derive(Deserialize)]
pub struct MissionTreasuryFundReq {
    pub amount_aura: f64,
    pub mission_id: Option<String>,
    pub mission_title: Option<String>,
    pub operator_wallet: Option<String>,
    pub strict_settlement: Option<bool>,
    pub fee: Option<u64>,
}

#[derive(Deserialize)]
pub struct MissionTreasuryPayoutReq {
    pub operator_wallet: String,
    pub agent_wallet: String,
    pub amount_aura: f64,
    pub mission_id: Option<String>,
    pub agent_id: Option<String>,
    pub strict_settlement: Option<bool>,
    pub fee: Option<u64>,
}

#[derive(Serialize)]
pub struct MissionTreasurySettlementResp {
    pub tx_id: String,
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub amount_aura: f64,
    pub fee: u64,
    pub status: &'static str,
    pub treasury_wallet: String,
    pub pool_balance_aura: f64,
}

fn mission_treasury_wallet_or_error(s: &AppState) -> Result<&Wallet, (StatusCode, Json<ApiError>)> {
    s.mission_treasury_wallet
        .as_ref()
        .ok_or_else(|| bad_req("Mission treasury wallet is not configured"))
}

/// GET /api/v1/autonomo/mission/treasury — Read chain-native stipend pool status
async fn autonomo_get_mission_treasury(
    State(s): State<AppState>,
) -> ApiResult<MissionTreasuryStatusResp> {
    let treasury_wallet = if let Some(wallet) = s.mission_treasury_wallet.as_ref() {
        wallet.address.clone()
    } else {
        s.store.get_mission_treasury_address().map_err(internal)?
    };

    if treasury_wallet.trim().is_empty() {
        return Err(not_found("Mission treasury wallet not initialized"));
    }

    let pool_balance = s.store.get_balance(&treasury_wallet).map_err(internal)?;
    Ok(Json(MissionTreasuryStatusResp {
        treasury_wallet,
        pool_balance,
        pool_balance_aura: pool_balance as f64 / genesis::DECIMAL_FACTOR as f64,
    }))
}

/// POST /api/v1/autonomo/mission/treasury/fund — Move on-chain funds from node wallet into treasury
async fn autonomo_fund_mission_treasury(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MissionTreasuryFundReq>,
) -> ApiResult<MissionTreasurySettlementResp> {
    if !is_direct_local_request(&remote, &headers) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "mission treasury funding is disabled for tunneled/remote requests",
        ));
    }
    if !req.strict_settlement.unwrap_or(true) {
        return Err(bad_req(
            "strict_settlement must be true for treasury funding",
        ));
    }

    let node_wallet = s
        .node_wallet
        .as_ref()
        .ok_or_else(|| bad_req("Node wallet is not loaded; cannot fund mission treasury"))?;
    if let Some(operator_wallet) = req.operator_wallet.as_ref() {
        if operator_wallet != &node_wallet.address {
            return Err(bad_req(
                "operator_wallet must match the local node wallet for treasury funding",
            ));
        }
    }

    let treasury_wallet = mission_treasury_wallet_or_error(&s)?;
    if treasury_wallet.address == node_wallet.address {
        return Err(bad_req(
            "Mission treasury wallet must be dedicated and not equal to node wallet",
        ));
    }

    let memo = serde_json::json!({
        "kind": "mission_treasury_fund",
        "mission_id": req.mission_id,
        "mission_title": req.mission_title,
        "strict_settlement": true,
    })
    .to_string();
    let (tx_id, amount, fee) = submit_signed_transfer(
        &s,
        node_wallet,
        &treasury_wallet.address,
        req.amount_aura,
        req.fee,
        Some(memo),
    )
    .await?;

    let pool_balance = s
        .store
        .get_balance(&treasury_wallet.address)
        .map_err(internal)?;
    Ok(Json(MissionTreasurySettlementResp {
        tx_id,
        from: node_wallet.address.clone(),
        to: treasury_wallet.address.clone(),
        amount,
        amount_aura: amount as f64 / genesis::DECIMAL_FACTOR as f64,
        fee,
        status: "pending",
        treasury_wallet: treasury_wallet.address.clone(),
        pool_balance_aura: pool_balance as f64 / genesis::DECIMAL_FACTOR as f64,
    }))
}

/// POST /api/v1/autonomo/mission/treasury/payout — Send on-chain stipend from treasury wallet to an agent wallet
async fn autonomo_payout_mission_treasury(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MissionTreasuryPayoutReq>,
) -> ApiResult<MissionTreasurySettlementResp> {
    if !is_direct_local_request(&remote, &headers) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "mission treasury payout is disabled for tunneled/remote requests",
        ));
    }
    if !req.strict_settlement.unwrap_or(true) {
        return Err(bad_req(
            "strict_settlement must be true for treasury payout",
        ));
    }
    if req.operator_wallet.trim().is_empty() {
        return Err(bad_req("operator_wallet is required"));
    }
    if req.agent_wallet.trim().is_empty() {
        return Err(bad_req("agent_wallet is required"));
    }

    let node_wallet = s.node_wallet.as_ref().ok_or_else(|| {
        bad_req("Node wallet is not loaded; operator identity cannot be verified")
    })?;
    if req.operator_wallet != node_wallet.address {
        return Err(bad_req(
            "operator_wallet must match the local node wallet for treasury payout",
        ));
    }

    let treasury_wallet = mission_treasury_wallet_or_error(&s)?;
    if req.agent_wallet == treasury_wallet.address {
        return Err(bad_req("agent_wallet cannot match mission treasury wallet"));
    }

    let amount_raw = aura_to_raw(req.amount_aura)?;
    let fee = req.fee.unwrap_or(genesis::MIN_FEE);
    let treasury_balance = s
        .store
        .get_balance(&treasury_wallet.address)
        .map_err(internal)?;
    if treasury_balance < amount_raw.saturating_add(fee) {
        return Err(bad_req(
            "Mission treasury balance is too low for this payout",
        ));
    }

    let memo = serde_json::json!({
        "kind": "mission_treasury_payout",
        "operator_wallet": req.operator_wallet,
        "agent_id": req.agent_id,
        "mission_id": req.mission_id,
        "strict_settlement": true,
    })
    .to_string();
    let (tx_id, amount, fee) = submit_signed_transfer(
        &s,
        treasury_wallet,
        &req.agent_wallet,
        req.amount_aura,
        req.fee,
        Some(memo),
    )
    .await?;

    let pool_balance = s
        .store
        .get_balance(&treasury_wallet.address)
        .map_err(internal)?;
    Ok(Json(MissionTreasurySettlementResp {
        tx_id,
        from: treasury_wallet.address.clone(),
        to: req.agent_wallet,
        amount,
        amount_aura: amount as f64 / genesis::DECIMAL_FACTOR as f64,
        fee,
        status: "pending",
        treasury_wallet: treasury_wallet.address.clone(),
        pool_balance_aura: pool_balance as f64 / genesis::DECIMAL_FACTOR as f64,
    }))
}

// ─── OpenClaw employee wallet binding + orchestration context ────────────────

#[derive(Clone)]
struct OpenClawBindingInput {
    master_wallet: String,
    employee_id: String,
    employee_wallet: Option<String>,
    employee_name: Option<String>,
    role: Option<String>,
    division: Option<String>,
    status: Option<String>,
    source: Option<String>,
    tags: Option<Vec<String>>,
    capability_profile: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    force: bool,
}

#[derive(Deserialize)]
pub struct OpenClawBindReq {
    pub master_wallet: String,
    pub employee_id: String,
    pub employee_wallet: Option<String>,
    pub employee_name: Option<String>,
    pub role: Option<String>,
    pub division: Option<String>,
    pub status: Option<String>,
    pub source: Option<String>,
    pub tags: Option<Vec<String>>,
    pub capability_profile: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub force: Option<bool>,
}

#[derive(Deserialize)]
pub struct OpenClawBulkEmployeeReq {
    pub employee_id: String,
    pub employee_wallet: Option<String>,
    pub employee_name: Option<String>,
    pub role: Option<String>,
    pub division: Option<String>,
    pub status: Option<String>,
    pub tags: Option<Vec<String>>,
    pub capability_profile: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct OpenClawBulkBindReq {
    pub master_wallet: String,
    pub employees: Vec<OpenClawBulkEmployeeReq>,
    pub source: Option<String>,
    pub force: Option<bool>,
}

#[derive(Deserialize)]
pub struct OpenClawBindingQuery {
    pub master_wallet: Option<String>,
    pub division: Option<String>,
    pub status: Option<String>,
}

#[derive(Deserialize)]
pub struct OpenClawOrchestrationQuery {
    pub master_wallet: Option<String>,
}

fn default_openclaw_capability_profile() -> serde_json::Value {
    serde_json::json!({
        "ability": {
            "model_id": "Ability",
            "provider": "arobiLLM",
            "inference_route": "/api/v1/llm/inference",
        },
        "instinct": {
            "enabled": true,
            "bridge": "arobi-network",
            "heartbeat_route": "/api/v1/autonomo/heartbeat",
        },
        "runtime": {
            "vm_required": true,
            "terminal_required": true,
        }
    })
}

fn upsert_openclaw_binding(
    s: &AppState,
    input: OpenClawBindingInput,
) -> Result<serde_json::Value, (StatusCode, Json<ApiError>)> {
    let OpenClawBindingInput {
        master_wallet,
        employee_id,
        employee_wallet,
        employee_name,
        role,
        division,
        status,
        source,
        tags,
        capability_profile,
        metadata,
        force,
    } = input;

    let master_wallet = master_wallet.trim();
    if master_wallet.is_empty() {
        return Err(bad_req("master_wallet is required"));
    }

    let employee_id = normalize_employee_id(&employee_id);
    if employee_id.is_empty() {
        return Err(bad_req("employee_id is required"));
    }

    let existing = s
        .store
        .get_openclaw_binding(&employee_id)
        .map_err(internal)?;
    if let Some(existing_binding) = existing.as_ref() {
        let existing_master = existing_binding
            .get("master_wallet")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !existing_master.is_empty() && existing_master != master_wallet && !force {
            return Err(api_err(
                StatusCode::CONFLICT,
                format!(
                    "Employee {employee_id} is already bound to another master wallet; set force=true to override"
                ),
            ));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let bound_at = existing
        .as_ref()
        .and_then(|v| v.get("bound_at"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| now.clone());
    let binding_id = existing
        .as_ref()
        .and_then(|v| v.get("binding_id"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("ocb_{}", uuid::Uuid::new_v4()));

    let incoming_employee_wallet = employee_wallet
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);
    let existing_employee_wallet = existing
        .as_ref()
        .and_then(|v| v.get("employee_wallet"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let employee_wallet = incoming_employee_wallet
        .or(existing_employee_wallet)
        .unwrap_or_else(|| derive_openclaw_employee_wallet(master_wallet, &employee_id));

    let employee_name = employee_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("employee_name"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| employee_id.to_uppercase());

    let role = role
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("role"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "Unassigned".to_string());

    let division = division
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("division"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "general".to_string());

    let status = status
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("status"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "bound".to_string());

    let binding_source = source
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("binding_source"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "openclaw_integration".to_string());

    let tags = tags
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("tags"))
                .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        })
        .unwrap_or_default();

    let capability_profile = capability_profile
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|v| v.get("capability_profile"))
                .cloned()
        })
        .unwrap_or_else(default_openclaw_capability_profile);

    let metadata = metadata
        .or_else(|| existing.as_ref().and_then(|v| v.get("metadata")).cloned())
        .unwrap_or_else(|| serde_json::json!({}));

    let instinct_enabled = capability_profile
        .get("instinct")
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let ability_model = capability_profile
        .get("ability")
        .and_then(|v| v.get("model_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("Ability")
        .to_string();

    let binding = serde_json::json!({
        "binding_id": binding_id,
        "master_wallet": master_wallet,
        "employee_id": employee_id,
        "employee_wallet": employee_wallet,
        "employee_name": employee_name,
        "role": role,
        "division": division,
        "status": status,
        "binding_source": binding_source,
        "tags": tags,
        "capability_profile": capability_profile,
        "metadata": metadata,
        "instinct_enabled": instinct_enabled,
        "ability_model": ability_model,
        "bound_at": bound_at,
        "updated_at": now,
    });

    s.store
        .put_openclaw_binding(
            binding
                .get("employee_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            &binding,
        )
        .map_err(internal)?;

    Ok(binding)
}

/// POST /api/v1/autonomo/openclaw/bind — Bind one employee to a master wallet.
async fn autonomo_bind_openclaw_employee(
    State(s): State<AppState>,
    Json(req): Json<OpenClawBindReq>,
) -> ApiResult<serde_json::Value> {
    let binding = upsert_openclaw_binding(
        &s,
        OpenClawBindingInput {
            master_wallet: req.master_wallet,
            employee_id: req.employee_id,
            employee_wallet: req.employee_wallet,
            employee_name: req.employee_name,
            role: req.role,
            division: req.division,
            status: req.status,
            source: req.source,
            tags: req.tags,
            capability_profile: req.capability_profile,
            metadata: req.metadata,
            force: req.force.unwrap_or(false),
        },
    )?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "binding": binding,
    })))
}

/// POST /api/v1/autonomo/openclaw/bind/bulk — Bind multiple employees in one call.
async fn autonomo_bind_openclaw_bulk(
    State(s): State<AppState>,
    Json(req): Json<OpenClawBulkBindReq>,
) -> ApiResult<serde_json::Value> {
    if req.employees.is_empty() {
        return Err(bad_req("employees is required and cannot be empty"));
    }

    let mut bindings = Vec::new();
    for employee in req.employees {
        let binding = upsert_openclaw_binding(
            &s,
            OpenClawBindingInput {
                master_wallet: req.master_wallet.clone(),
                employee_id: employee.employee_id,
                employee_wallet: employee.employee_wallet,
                employee_name: employee.employee_name,
                role: employee.role,
                division: employee.division,
                status: employee.status,
                source: req.source.clone(),
                tags: employee.tags,
                capability_profile: employee.capability_profile,
                metadata: employee.metadata,
                force: req.force.unwrap_or(false),
            },
        )?;
        bindings.push(binding);
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "count": bindings.len(),
        "bindings": bindings,
    })))
}

/// GET /api/v1/autonomo/openclaw/bindings — List employee wallet bindings.
async fn autonomo_list_openclaw_bindings(
    State(s): State<AppState>,
    Query(q): Query<OpenClawBindingQuery>,
) -> ApiResult<serde_json::Value> {
    let mut bindings = if let Some(master_wallet) = q
        .master_wallet
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        s.store
            .list_openclaw_bindings_for_master(master_wallet)
            .map_err(internal)?
    } else {
        s.store.list_openclaw_bindings().map_err(internal)?
    };

    if let Some(division) = q
        .division
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        bindings.retain(|item| {
            item.get("division")
                .and_then(|v| v.as_str())
                .map(|v| v.eq_ignore_ascii_case(division))
                .unwrap_or(false)
        });
    }

    if let Some(status) = q.status.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        bindings.retain(|item| {
            item.get("status")
                .and_then(|v| v.as_str())
                .map(|v| v.eq_ignore_ascii_case(status))
                .unwrap_or(false)
        });
    }

    bindings.sort_by_key(|item| {
        item.get("employee_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    });

    Ok(Json(serde_json::json!({
        "count": bindings.len(),
        "bindings": bindings,
    })))
}

/// GET /api/v1/autonomo/openclaw/bindings/:employee_id — Get one employee binding.
async fn autonomo_get_openclaw_binding(
    State(s): State<AppState>,
    Path(employee_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let normalized = normalize_employee_id(&employee_id);
    if normalized.is_empty() {
        return Err(bad_req("employee_id is required"));
    }

    match s
        .store
        .get_openclaw_binding(&normalized)
        .map_err(internal)?
    {
        Some(binding) => Ok(Json(binding)),
        None => Err(not_found(format!(
            "OpenClaw wallet binding for employee {normalized} not found"
        ))),
    }
}

/// GET /api/v1/autonomo/openclaw/orchestration/context — Binding + heartbeat + Ability/Instinct readiness.
async fn autonomo_openclaw_orchestration_context(
    State(s): State<AppState>,
    Query(q): Query<OpenClawOrchestrationQuery>,
) -> ApiResult<serde_json::Value> {
    let master_wallet_filter = q
        .master_wallet
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);

    let bindings = if let Some(master_wallet) = master_wallet_filter.as_deref() {
        s.store
            .list_openclaw_bindings_for_master(master_wallet)
            .map_err(internal)?
    } else {
        s.store.list_openclaw_bindings().map_err(internal)?
    };

    let heartbeats = s.store.list_heartbeats().map_err(internal)?;
    let now = chrono::Utc::now();

    let models = s.model_registry.list_models();
    let ability_match = models.iter().find(|m| {
        m.model_id.eq_ignore_ascii_case("ability")
            || m.config.name.to_ascii_lowercase().contains("ability")
    });
    let ability_model_id = ability_match
        .map(|m| m.model_id.clone())
        .unwrap_or_else(|| "Ability".to_string());
    let ability_registered = ability_match.is_some();
    let ability_ready = if ability_registered {
        s.model_registry.is_model_ready(&ability_model_id)
    } else {
        false
    };

    let mut online_count = 0usize;
    let mut stale_count = 0usize;
    let mut employees = Vec::new();

    for binding in bindings {
        let wallet = binding
            .get("employee_wallet")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let heartbeat = heartbeats
            .iter()
            .find(|hb| hb.get("wallet").and_then(|v| v.as_str()) == Some(wallet.as_str()))
            .cloned();

        let heartbeat_age_seconds = heartbeat
            .as_ref()
            .and_then(|hb| hb.get("last_seen"))
            .and_then(|v| v.as_str())
            .and_then(|raw| chrono::DateTime::parse_from_rfc3339(raw).ok())
            .map(|ts| {
                now.signed_duration_since(ts.with_timezone(&chrono::Utc))
                    .num_seconds()
            })
            .map(|age| age.max(0));
        let heartbeat_stale = heartbeat_age_seconds.map(|age| age > 90).unwrap_or(true);
        if heartbeat_stale {
            stale_count = stale_count.saturating_add(1);
        } else {
            online_count = online_count.saturating_add(1);
        }

        let room_id = heartbeat
            .as_ref()
            .and_then(|hb| hb.get("room_id"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        employees.push(serde_json::json!({
            "employee_id": binding.get("employee_id").cloned().unwrap_or(serde_json::Value::Null),
            "employee_wallet": wallet,
            "employee_name": binding.get("employee_name").cloned().unwrap_or(serde_json::Value::Null),
            "role": binding.get("role").cloned().unwrap_or(serde_json::Value::Null),
            "division": binding.get("division").cloned().unwrap_or(serde_json::Value::Null),
            "binding_status": binding.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "room_id": room_id,
            "heartbeat": heartbeat,
            "heartbeat_age_seconds": heartbeat_age_seconds,
            "heartbeat_stale": heartbeat_stale,
            "instinct_ready": !heartbeat_stale,
            "ability_model": binding.get("ability_model").cloned().unwrap_or(serde_json::json!("Ability")),
            "binding": binding,
        }));
    }

    let instinct_endpoint =
        std::env::var("INSTINCT_ENDPOINT").unwrap_or_else(|_| "http://localhost:8092".to_string());
    let arobi_endpoint =
        std::env::var("AROBI_ENDPOINT").unwrap_or_else(|_| "http://localhost:8099".to_string());

    Ok(Json(serde_json::json!({
        "master_wallet": master_wallet_filter,
        "summary": {
            "bound_employee_count": employees.len(),
            "online_employee_count": online_count,
            "stale_heartbeat_count": stale_count,
        },
        "ability": {
            "model_id": ability_model_id,
            "registered": ability_registered,
            "ready": ability_ready,
            "inference_route": "/api/v1/llm/inference",
            "endpoint": format!("{arobi_endpoint}/api/v1/llm/inference"),
            "network_model_count": s.model_registry.model_count(),
            "network_ready_model_count": s.model_registry.ready_model_count(),
        },
        "instinct": {
            "endpoint": instinct_endpoint,
            "bridge": "arobi-network",
            "heartbeat_timeout_seconds": 90,
            "ready_employee_count": online_count,
        },
        "tools": {
            "orchestration_route": "/api/v1/tools/orchestrate",
            "execute_route": "/api/v1/tools/execute",
            "knowledge_store_route": "/api/v1/tools/knowledge/store",
            "knowledge_query_route": "/api/v1/tools/knowledge/query",
            "runtime_policy": s.tool_executor.runtime_policy_snapshot(),
        },
        "employees": employees,
        "generated_at": now.to_rfc3339(),
    })))
}

// ─── Tool execution handlers (Phase 6) ──────────────────────────────────────

/// GET /api/v1/tools/list — list available tools
async fn tools_list(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
) -> ApiResult<serde_json::Value> {
    let tools = s.tool_executor.list_tools();
    let runtime_policy = if is_direct_local_request(&remote, &headers) {
        s.tool_executor.runtime_policy_snapshot()
    } else {
        redact_runtime_policy_for_public(s.tool_executor.runtime_policy_snapshot())
    };
    Ok(Json(serde_json::json!({
        "tools": tools,
        "runtime_policy": runtime_policy,
    })))
}

/// POST /api/v1/tools/execute — execute a tool
async fn tools_execute(
    State(s): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let tool_name = req
        .get("tool_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "tool_name required"))?
        .to_string();
    let parameters = req
        .get("parameters")
        .cloned()
        .unwrap_or(serde_json::Value::Object(Default::default()));
    let agent_wallet = req
        .get("agent_wallet")
        .and_then(|v| v.as_str())
        .unwrap_or("anonymous")
        .to_string();
    let timeout_ms = req
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);

    let result = s
        .tool_executor
        .execute(&tool_name, parameters, &agent_wallet, timeout_ms)
        .await;
    Ok(Json(result))
}

/// POST /api/v1/tools/orchestrate — execute multiple tool calls in one request
async fn tools_orchestrate(
    State(s): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let agent_wallet = req
        .get("agent_wallet")
        .and_then(|v| v.as_str())
        .unwrap_or("anonymous")
        .to_string();
    let stop_on_error = req
        .get("stop_on_error")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let default_timeout_ms = req
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);
    let jobs = req
        .get("jobs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "jobs array required"))?;

    if jobs.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "jobs array cannot be empty",
        ));
    }
    if jobs.len() > TOOL_ORCHESTRATION_MAX_JOBS {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            format!("jobs array exceeds max size {TOOL_ORCHESTRATION_MAX_JOBS}"),
        ));
    }

    let mut results = Vec::with_capacity(jobs.len());
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for (idx, job) in jobs.iter().enumerate() {
        let job_id = job
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("job-{}", idx + 1));
        let Some(tool_name) = job.get("tool_name").and_then(|v| v.as_str()) else {
            failed = failed.saturating_add(1);
            results.push(serde_json::json!({
                "id": job_id,
                "success": false,
                "error": "tool_name required",
            }));
            if stop_on_error {
                break;
            }
            continue;
        };

        let parameters = job
            .get("parameters")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let timeout_ms = job
            .get("timeout_ms")
            .and_then(|v| v.as_u64())
            .unwrap_or(default_timeout_ms);

        let response = s
            .tool_executor
            .execute(tool_name, parameters, &agent_wallet, timeout_ms)
            .await;
        let success = response
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if success {
            succeeded = succeeded.saturating_add(1);
        } else {
            failed = failed.saturating_add(1);
        }

        results.push(serde_json::json!({
            "id": job_id,
            "tool_name": tool_name,
            "success": success,
            "response": response,
        }));

        if stop_on_error && !success {
            break;
        }
    }

    Ok(Json(serde_json::json!({
        "agent_wallet": agent_wallet,
        "runtime_policy": s.tool_executor.runtime_policy_snapshot(),
        "stop_on_error": stop_on_error,
        "summary": {
            "requested": jobs.len(),
            "completed": results.len(),
            "succeeded": succeeded,
            "failed": failed,
        },
        "results": results,
    })))
}

/// POST /api/v1/tools/knowledge/store — store a knowledge chunk
async fn tools_knowledge_store(
    State(s): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let wallet = req
        .get("wallet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "wallet required"))?;
    let key = req
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "key required"))?;
    let content = req
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "content required"))?;
    let metadata = req
        .get("metadata")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    s.tool_executor
        .knowledge_store(wallet, key, content, &metadata);
    Ok(Json(serde_json::json!({
        "status": "stored",
        "wallet": wallet,
        "key": key,
    })))
}

/// POST /api/v1/tools/knowledge/query — query knowledge base
async fn tools_knowledge_query(
    State(s): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let wallet = req
        .get("wallet")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "wallet required"))?;
    let query = req
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "query required"))?;

    let results = s.tool_executor.knowledge_query(wallet, query);
    Ok(Json(serde_json::json!({
        "wallet": wallet,
        "query": query,
        "results": results,
    })))
}

// ─── Prometheus metrics ─────────────────────────────────────────────────────

/// GET /metrics — Prometheus-compatible metrics
async fn prometheus_metrics(
    State(s): State<AppState>,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let height = s.store.chain_height().unwrap_or(0);
    let peer_count = s.p2p.peer_count();
    let mempool_size = s.mempool.size().await;
    let fs_stats = s.chunk_store.stats().ok();
    let security = s.security.status().await;
    let compute_stats = s.compute_scheduler.marketplace_stats();

    let mut out = String::with_capacity(2048);

    out.push_str("# HELP arobi_chain_height Current blockchain height\n");
    out.push_str("# TYPE arobi_chain_height gauge\n");
    out.push_str(&format!("arobi_chain_height {height}\n"));

    out.push_str("# HELP arobi_peer_count Connected P2P peers\n");
    out.push_str("# TYPE arobi_peer_count gauge\n");
    out.push_str(&format!("arobi_peer_count {peer_count}\n"));

    out.push_str("# HELP arobi_mempool_size Pending transactions\n");
    out.push_str("# TYPE arobi_mempool_size gauge\n");
    out.push_str(&format!("arobi_mempool_size {mempool_size}\n"));

    out.push_str("# HELP arobi_poi_difficulty Current PoI difficulty\n");
    out.push_str("# TYPE arobi_poi_difficulty gauge\n");
    out.push_str(&format!(
        "arobi_poi_difficulty {}\n",
        s.poi_engine.difficulty()
    ));

    out.push_str("# HELP arobi_poi_challenges_solved Total PoI challenges solved\n");
    out.push_str("# TYPE arobi_poi_challenges_solved counter\n");
    out.push_str(&format!(
        "arobi_poi_challenges_solved {}\n",
        s.poi_engine.challenges_solved()
    ));

    if let Some(stats) = fs_stats {
        out.push_str("# HELP arobi_fs_chunks_total Total stored chunks\n");
        out.push_str("# TYPE arobi_fs_chunks_total gauge\n");
        out.push_str(&format!("arobi_fs_chunks_total {}\n", stats.total_chunks));

        out.push_str("# HELP arobi_fs_bytes_total Total stored bytes\n");
        out.push_str("# TYPE arobi_fs_bytes_total gauge\n");
        out.push_str(&format!("arobi_fs_bytes_total {}\n", stats.total_bytes));

        out.push_str("# HELP arobi_fs_files_total Total files stored\n");
        out.push_str("# TYPE arobi_fs_files_total gauge\n");
        out.push_str(&format!("arobi_fs_files_total {}\n", stats.total_files));
    }

    out.push_str("# HELP arobi_compute_active_jobs Currently running compute jobs\n");
    out.push_str("# TYPE arobi_compute_active_jobs gauge\n");
    out.push_str(&format!(
        "arobi_compute_active_jobs {}\n",
        compute_stats.active_jobs
    ));

    out.push_str("# HELP arobi_compute_completed_jobs Total completed compute jobs\n");
    out.push_str("# TYPE arobi_compute_completed_jobs counter\n");
    out.push_str(&format!(
        "arobi_compute_completed_jobs {}\n",
        compute_stats.completed_jobs
    ));

    out.push_str("# HELP arobi_compute_nodes_total Registered compute nodes\n");
    out.push_str("# TYPE arobi_compute_nodes_total gauge\n");
    out.push_str(&format!(
        "arobi_compute_nodes_total {}\n",
        compute_stats.total_nodes
    ));

    out.push_str("# HELP arobi_llm_models_total Registered LLM models\n");
    out.push_str("# TYPE arobi_llm_models_total gauge\n");
    out.push_str(&format!(
        "arobi_llm_models_total {}\n",
        s.model_registry.list_models().len()
    ));

    out.push_str("# HELP arobi_llm_models_ready Fully served LLM models\n");
    out.push_str("# TYPE arobi_llm_models_ready gauge\n");
    out.push_str(&format!(
        "arobi_llm_models_ready {}\n",
        s.model_registry.ready_model_count()
    ));

    out.push_str("# HELP arobi_security_anomalies Recent security anomaly count\n");
    out.push_str("# TYPE arobi_security_anomalies gauge\n");
    out.push_str(&format!(
        "arobi_security_anomalies {}\n",
        security.recent_anomaly_count
    ));

    Ok(out)
}

// ─── LLM Chat Proxy ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct LlmChatRequest {
    provider: String,
    model: String,
    api_key: String,
    messages: Vec<LlmMessage>,
    #[serde(default)]
    memory_wallet: Option<String>,
    #[serde(default)]
    memory_key: Option<String>,
    #[serde(default)]
    include_giru_context: bool,
    #[serde(default)]
    ability_profile: Option<String>,
    #[serde(default)]
    trace_mode: Option<String>,
    #[serde(default = "default_max_tokens")]
    max_tokens: u32,
    #[serde(default = "default_temperature")]
    temperature: f32,
}

fn default_max_tokens() -> u32 {
    300
}
fn default_temperature() -> f32 {
    0.9
}

#[derive(Deserialize, Serialize, Clone)]
struct LlmMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct LlmChatResponse {
    content: String,
    model: String,
    tokens_used: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    ability_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<Vec<String>>,
}

fn normalize_requested_ability_profile(raw: Option<&str>) -> Option<&'static str> {
    match raw?.trim().to_ascii_lowercase().as_str() {
        CLEARANCE_PUBLIC => Some(CLEARANCE_PUBLIC),
        CLEARANCE_INTERNAL | "operator" | "non-sensitive" => Some(CLEARANCE_INTERNAL),
        CLEARANCE_MISSION_CONTROL
        | "mission-control"
        | "missioncontrol"
        | PRIVATE_LAYER_CODENAME_00
        | "private"
        | "private_00"
        | "private-00" => Some(PRIVATE_LAYER_CODENAME_00),
        _ => None,
    }
}

fn resolve_ability_profile(
    s: &AppState,
    headers: &HeaderMap,
    req: &LlmChatRequest,
) -> Result<&'static str, (StatusCode, String)> {
    let requested = normalize_requested_ability_profile(req.ability_profile.as_deref());
    let header_clearance = normalize_clearance(
        access_context_from_headers(headers)
            .clearance_hint
            .as_deref(),
    );
    let sensitive_allowed = can_read_sensitive_scope(s, headers, req.memory_wallet.as_deref())
        .map_err(|(code, err)| (code, err.0.error))?;

    Ok(match requested {
        Some(PRIVATE_LAYER_CODENAME_00) => {
            if sensitive_allowed {
                PRIVATE_LAYER_CODENAME_00
            } else {
                CLEARANCE_INTERNAL
            }
        }
        Some(CLEARANCE_PUBLIC) => CLEARANCE_PUBLIC,
        Some(CLEARANCE_INTERNAL) => CLEARANCE_INTERNAL,
        None => match header_clearance {
            CLEARANCE_PUBLIC => CLEARANCE_PUBLIC,
            CLEARANCE_MISSION_CONTROL if sensitive_allowed => PRIVATE_LAYER_CODENAME_00,
            _ => CLEARANCE_INTERNAL,
        },
        _ => CLEARANCE_INTERNAL,
    })
}

fn build_ability_reason_summary(
    profile: &str,
    include_giru_context: bool,
    memory_requested: bool,
    memory_included: bool,
) -> String {
    let profile_summary = match profile {
        PRIVATE_LAYER_CODENAME_00 => "Ability operated in private layer 00.",
        CLEARANCE_PUBLIC => "Ability operated in the public profile.",
        _ => "Ability operated in the internal non-sensitive profile.",
    };
    let giru_summary = if include_giru_context {
        "GIRU context was included."
    } else {
        "GIRU context was not requested."
    };
    let memory_summary = if memory_requested && memory_included {
        "Secure memory recall was included."
    } else if memory_requested {
        "Secure memory recall was requested but not included."
    } else {
        "No secure memory recall was requested."
    };
    format!("{profile_summary} {giru_summary} {memory_summary}")
}

async fn llm_chat_proxy(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LlmChatRequest>,
) -> Result<Json<LlmChatResponse>, (StatusCode, String)> {
    let client = reqwest::Client::new();
    let mut messages = req.messages.clone();
    let mut memory_recall_included = false;

    let mut context_messages: Vec<LlmMessage> = Vec::new();
    if req.include_giru_context {
        let mission_unsealed = can_read_sensitive_scope(&s, &headers, req.memory_wallet.as_deref())
            .map_err(|(code, err)| (code, err.0.error))?;
        let scope_note = if mission_unsealed {
            "Mission-control sensitive context is unlocked for this paired device."
        } else {
            "Mission-control sensitive context is locked. Use only public/non-sensitive internal data."
        };
        context_messages.push(LlmMessage {
            role: "system".to_string(),
            content: format!(
                "GIRU CONTEXT:\n- Company mission: Autonomous public-good safety and utility systems.\n- Public founder info is shareable.\n- Non-sensitive internal operating context is shareable.\n- {scope_note}"
            ),
        });
    }

    if let (Some(wallet), Some(memory_key)) = (req.memory_wallet.clone(), req.memory_key.clone()) {
        let storage_key = format!("{wallet}:{memory_key}");
        if let Some(secure) = s
            .store
            .get_secure_memory(&storage_key)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            let sensitivity = secure
                .get("sensitivity")
                .and_then(|v| v.as_str())
                .unwrap_or(CLEARANCE_INTERNAL);
            let allowed = if sensitivity == "sensitive" {
                can_read_sensitive_scope(&s, &headers, Some(wallet.as_str()))
                    .map_err(|(code, err)| (code, err.0.error))?
            } else {
                true
            };
            if allowed {
                let token = access_context_from_headers(&headers).access_token;
                let key_material = derive_memory_key_material(
                    wallet.as_str(),
                    memory_key.as_str(),
                    sensitivity,
                    token.as_deref(),
                );
                let bytes = decrypt_memory_payload(&secure, &key_material)
                    .map_err(|(code, err)| (code, err.0.error))?;
                let decoded: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                let memory_text = decoded
                    .get("input")
                    .map(|v| {
                        if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            v.to_string()
                        }
                    })
                    .unwrap_or_else(|| "{}".to_string());
                context_messages.push(LlmMessage {
                    role: "system".to_string(),
                    content: format!(
                        "SECURE MEMORY RECALL:\nwallet={wallet}\nkey={memory_key}\nsensitivity={sensitivity}\ncontent={memory_text}"
                    ),
                });
                memory_recall_included = true;
            }
        } else if let Some(legacy) = s
            .store
            .get_knowledge(&storage_key)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        {
            context_messages.push(LlmMessage {
                role: "system".to_string(),
                content: format!(
                    "LEGACY MEMORY RECALL:\nwallet={wallet}\nkey={memory_key}\ncontent={}",
                    legacy
                        .get("value")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                ),
            });
            memory_recall_included = true;
        }
    }

    if !context_messages.is_empty() {
        context_messages.extend(messages);
        messages = context_messages;
    }

    let ability_profile = resolve_ability_profile(&s, &headers, &req)?.to_string();
    let memory_requested = req.memory_wallet.is_some() && req.memory_key.is_some();
    let reason_summary = build_ability_reason_summary(
        ability_profile.as_str(),
        req.include_giru_context,
        memory_requested,
        memory_recall_included,
    );
    let trace = match req.trace_mode.as_deref() {
        Some(mode) if mode.eq_ignore_ascii_case("none") => None,
        _ => Some(vec![
            format!("profile:{ability_profile}"),
            format!(
                "giru_context:{}",
                if req.include_giru_context {
                    "included"
                } else {
                    "not_requested"
                }
            ),
            format!(
                "memory_recall:{}",
                if memory_recall_included {
                    "included"
                } else if memory_requested {
                    "denied_or_missing"
                } else {
                    "not_requested"
                }
            ),
        ]),
    };

    match req.provider.as_str() {
        "groq" | "openai" => {
            let base_url = match req.provider.as_str() {
                "groq" => "https://api.groq.com/openai/v1/chat/completions",
                "openai" => "https://api.openai.com/v1/chat/completions",
                _ => unreachable!(),
            };
            let body = serde_json::json!({
                "model": req.model,
                "messages": messages.clone(),
                "max_tokens": req.max_tokens,
                "temperature": req.temperature,
            });
            let resp = client
                .post(base_url)
                .header("Authorization", format!("Bearer {}", req.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("LLM request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err((StatusCode::BAD_GATEWAY, format!("LLM API {status}: {text}")));
            }

            let data: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {e}")))?;

            let content = data["choices"][0]["message"]["content"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let tokens = data["usage"]["total_tokens"].as_u64().unwrap_or(0) as u32;

            Ok(Json(LlmChatResponse {
                content,
                model: req.model,
                tokens_used: tokens,
                ability_profile: Some(ability_profile.clone()),
                access_scope: Some(ability_profile.clone()),
                reason_summary: Some(reason_summary.clone()),
                trace: trace.clone(),
            }))
        }
        "claude" => {
            let msgs: Vec<serde_json::Value> = messages
                .iter()
                .filter(|m| m.role != "system")
                .map(|m| serde_json::json!({"role": m.role, "content": m.content}))
                .collect();
            let system_msg = messages
                .iter()
                .find(|m| m.role == "system")
                .map(|m| m.content.clone())
                .unwrap_or_default();

            let mut body = serde_json::json!({
                "model": req.model,
                "messages": msgs,
                "max_tokens": req.max_tokens,
                "temperature": req.temperature,
            });
            if !system_msg.is_empty() {
                body["system"] = serde_json::Value::String(system_msg);
            }

            let resp = client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", &req.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("Claude request failed: {e}"),
                    )
                })?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("Claude API {status}: {text}"),
                ));
            }

            let data: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {e}")))?;

            let content = data["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let input_tokens = data["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32;
            let output_tokens = data["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32;

            Ok(Json(LlmChatResponse {
                content,
                model: req.model,
                tokens_used: input_tokens + output_tokens,
                ability_profile: Some(ability_profile.clone()),
                access_scope: Some(ability_profile.clone()),
                reason_summary: Some(reason_summary.clone()),
                trace: trace.clone(),
            }))
        }
        "gemini" => {
            let url = format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
                req.model, req.api_key
            );
            let contents: Vec<serde_json::Value> = messages
                .iter()
                .filter(|m| m.role != "system")
                .map(|m| {
                    serde_json::json!({
                        "role": if m.role == "assistant" { "model" } else { "user" },
                        "parts": [{"text": m.content}]
                    })
                })
                .collect();

            let mut body = serde_json::json!({
                "contents": contents,
                "generationConfig": {
                    "maxOutputTokens": req.max_tokens,
                    "temperature": req.temperature,
                },
            });
            if let Some(sys) = messages.iter().find(|m| m.role == "system") {
                body["systemInstruction"] = serde_json::json!({"parts": [{"text": sys.content}]});
            }

            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!("Gemini request failed: {e}"),
                    )
                })?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("Gemini API {status}: {text}"),
                ));
            }

            let data: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Parse error: {e}")))?;

            let content = data["candidates"][0]["content"]["parts"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let tokens = data["usageMetadata"]["totalTokenCount"]
                .as_u64()
                .unwrap_or(0) as u32;

            Ok(Json(LlmChatResponse {
                content,
                model: req.model,
                tokens_used: tokens,
                ability_profile: Some(ability_profile.clone()),
                access_scope: Some(ability_profile.clone()),
                reason_summary: Some(reason_summary.clone()),
                trace: trace.clone(),
            }))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("Unsupported provider: {}", req.provider),
        )),
    }
}

// ─── AI Decision Audit Ledger ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuditRecordRequest {
    source: String,
    decision_type: String,
    model_id: String,
    model_version: String,
    input_summary: String,
    input_data: String,
    decision: String,
    confidence: f64,
    reasoning: String,
    factors: Vec<String>,
    ethics_validated: bool,
    subsystems: Vec<String>,
    network_context: String,
    #[serde(default)]
    lane: Option<String>,
    #[serde(default)]
    metadata: HashMap<String, String>,
    latency_ms: f64,
}

#[derive(Serialize)]
struct AuditEntryResponse {
    entry: crate::audit::ledger::AuditEntry,
}

#[derive(Serialize)]
struct AuditEntriesResponse {
    entries: Vec<crate::audit::ledger::AuditEntry>,
    total: usize,
}

#[derive(Serialize)]
struct AuditVerifyResponse {
    valid: bool,
    total_entries: usize,
    message: String,
}

#[derive(Deserialize)]
struct AuditTrainingCorpusQuery {
    #[serde(default)]
    include_internal: bool,
}

#[derive(Serialize)]
struct AuditTrainingCorpusResponse {
    records: Vec<TrainingExportRecord>,
    total: usize,
    include_internal: bool,
    manifest: TrainingExportManifest,
    receipt: AuditTrainingCorpusReceipt,
}

#[derive(Clone, Serialize)]
struct AuditTrainingCorpusReceipt {
    schema_version: u32,
    receipt_id: String,
    generated_at: String,
    include_internal: bool,
    records_total: usize,
    records_sha256: String,
    boundary_contract: &'static str,
    manifest: TrainingExportManifest,
}

const TRAINING_CORPUS_RECEIPT_SCHEMA_VERSION: u32 = 1;

fn training_corpus_receipt_from_export(
    export: &TrainingCorpusExport,
) -> AuditTrainingCorpusReceipt {
    let records_sha256 = training_corpus_records_sha256(&export.records);
    let schema_version = TRAINING_CORPUS_RECEIPT_SCHEMA_VERSION;
    let hash_prefix: String = records_sha256.chars().take(16).collect();
    AuditTrainingCorpusReceipt {
        schema_version,
        receipt_id: format!("qtrain-manifest-v{schema_version}-{hash_prefix}"),
        generated_at: chrono::Utc::now().to_rfc3339(),
        include_internal: export.manifest.include_internal,
        records_total: export.records.len(),
        records_sha256,
        boundary_contract: "manifest-only-no-record-payload",
        manifest: export.manifest.clone(),
    }
}

fn training_corpus_records_sha256(records: &[TrainingExportRecord]) -> String {
    let canonical = canonical_json_bytes(records);
    hex::encode(Sha256::digest(canonical))
}

fn canonical_json_bytes<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    let value = serde_json::to_value(value).expect("training corpus records should serialize");
    let mut out = Vec::new();
    write_canonical_json(&value, &mut out);
    out
}

fn write_canonical_json(value: &serde_json::Value, out: &mut Vec<u8>) {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            out.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
        serde_json::Value::String(value) => out.extend_from_slice(
            serde_json::to_string(value)
                .expect("JSON string should serialize")
                .as_bytes(),
        ),
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            for (idx, (key, item)) in entries.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("JSON object key should serialize")
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical_json(item, out);
            }
            out.push(b'}');
        }
    }
}

async fn audit_record_decision(
    State(s): State<AppState>,
    Json(req): Json<AuditRecordRequest>,
) -> ApiResult<AuditEntryResponse> {
    let source = match req.source.as_str() {
        "instinct" => DecisionSource::Instinct,
        "ability" => DecisionSource::Ability,
        "cortex" => DecisionSource::Cortex,
        other => DecisionSource::External(other.to_string()),
    };

    let decision_type = match req.decision_type.as_str() {
        "defense_engage" => DecisionType::DefenseEngage,
        "threat_assessment" => DecisionType::ThreatAssessment,
        "resource_allocation" => DecisionType::ResourceAllocation,
        "query_response" => DecisionType::QueryResponse,
        "model_inference" => DecisionType::ModelInference,
        "training_decision" => DecisionType::TrainingDecision,
        "ethics_validation" => DecisionType::EthicsValidation,
        "network_routing" => DecisionType::NetworkRouting,
        "subsystem_command" => DecisionType::SubsystemCommand,
        _ => DecisionType::GeneralQuery,
    };

    let mut metadata = req.metadata;
    if let Some(lane) = req.lane {
        metadata.insert("lane".to_string(), lane);
    }

    let entry = s.audit_ledger.record_decision_with_metadata(
        source,
        decision_type,
        &req.model_id,
        &req.model_version,
        &req.input_summary,
        req.input_data.as_bytes(),
        &req.decision,
        req.confidence,
        &req.reasoning,
        req.factors,
        req.ethics_validated,
        req.subsystems,
        &req.network_context,
        req.latency_ms,
        metadata,
    );

    if let Err(err) = s.store.append_audit_entry(&entry) {
        let _ = s.audit_ledger.rollback_latest(&entry.entry_id);
        return Err(internal(format!(
            "failed to durably append audit entry {}: {err}",
            entry.entry_id
        )));
    }

    Ok(Json(AuditEntryResponse { entry }))
}

async fn audit_get_entries(State(s): State<AppState>) -> ApiResult<AuditEntriesResponse> {
    let entries: Vec<_> = {
        let entries = s.audit_ledger.entries.read().unwrap();
        entries.clone()
    };
    let total = entries.len();
    Ok(Json(AuditEntriesResponse { entries, total }))
}

async fn audit_get_entry(
    State(s): State<AppState>,
    Path(entry_id): Path<String>,
) -> ApiResult<AuditEntryResponse> {
    match s.audit_ledger.get_entry(&entry_id) {
        Some(entry) => Ok(Json(AuditEntryResponse { entry })),
        None => Err(not_found("Audit entry not found")),
    }
}

async fn audit_get_by_source(
    State(s): State<AppState>,
    Path(source): Path<String>,
) -> ApiResult<AuditEntriesResponse> {
    let source = match source.as_str() {
        "instinct" => DecisionSource::Instinct,
        "ability" => DecisionSource::Ability,
        "cortex" => DecisionSource::Cortex,
        other => DecisionSource::External(other.to_string()),
    };

    let entries = s.audit_ledger.get_entries_by_source(&source);
    let total = entries.len();
    Ok(Json(AuditEntriesResponse { entries, total }))
}

async fn audit_get_by_type(
    State(s): State<AppState>,
    Path(decision_type): Path<String>,
) -> ApiResult<AuditEntriesResponse> {
    let decision_type = match decision_type.as_str() {
        "defense_engage" => DecisionType::DefenseEngage,
        "threat_assessment" => DecisionType::ThreatAssessment,
        "resource_allocation" => DecisionType::ResourceAllocation,
        "query_response" => DecisionType::QueryResponse,
        "model_inference" => DecisionType::ModelInference,
        "training_decision" => DecisionType::TrainingDecision,
        "ethics_validation" => DecisionType::EthicsValidation,
        "network_routing" => DecisionType::NetworkRouting,
        "subsystem_command" => DecisionType::SubsystemCommand,
        _ => DecisionType::GeneralQuery,
    };

    let entries = s.audit_ledger.get_entries_by_type(&decision_type);
    let total = entries.len();
    Ok(Json(AuditEntriesResponse { entries, total }))
}

async fn audit_get_by_lane(
    State(s): State<AppState>,
    Path(lane_id): Path<String>,
) -> ApiResult<AuditEntriesResponse> {
    let entries = s.audit_ledger.get_entries_by_lane(&lane_id);
    let total = entries.len();
    Ok(Json(AuditEntriesResponse { entries, total }))
}

async fn audit_tribunal_export(State(s): State<AppState>) -> ApiResult<Vec<TribunalFormat>> {
    let entries = s.audit_ledger.get_all_for_tribunal();
    Ok(Json(entries))
}

async fn audit_verify_chain(State(s): State<AppState>) -> ApiResult<AuditVerifyResponse> {
    let valid = s.audit_ledger.verify_chain();
    let total = s.audit_ledger.len();
    let message = if valid {
        "Chain integrity verified - all entries cryptographically linked".to_string()
    } else {
        "WARNING: Chain integrity compromised - tampering detected".to_string()
    };

    Ok(Json(AuditVerifyResponse {
        valid,
        total_entries: total,
        message,
    }))
}

async fn audit_forensics_export(State(s): State<AppState>) -> ApiResult<String> {
    let export = s.audit_ledger.export_forensics();
    Ok(Json(export))
}

async fn audit_training_corpus_export(
    State(s): State<AppState>,
    Query(q): Query<AuditTrainingCorpusQuery>,
) -> ApiResult<AuditTrainingCorpusResponse> {
    let export = s
        .audit_ledger
        .export_training_corpus_with_manifest(q.include_internal);
    let total = export.records.len();
    let receipt = training_corpus_receipt_from_export(&export);
    Ok(Json(AuditTrainingCorpusResponse {
        records: export.records,
        total,
        include_internal: q.include_internal,
        manifest: export.manifest,
        receipt,
    }))
}

async fn audit_training_corpus_manifest(
    State(s): State<AppState>,
    Query(q): Query<AuditTrainingCorpusQuery>,
) -> ApiResult<AuditTrainingCorpusReceipt> {
    let export = s
        .audit_ledger
        .export_training_corpus_with_manifest(q.include_internal);
    Ok(Json(training_corpus_receipt_from_export(&export)))
}

// ─── Router & server ───────────────────────────────────────────────────────────

// ─── Admin signing (for ledger write operations) ───────────────────────────

/// Sign a transaction message for ledger embedding.
/// Signs: sha256(from || to || amount || fee || nonce || timestamp || data_hash)
/// which matches the Arobi Network tx signature scheme.
async fn admin_sign_message(
    State(state): State<AppState>,
    Json(payload): Json<SignPayload>,
) -> ApiResult<SignResponse> {
    let signing_key = state.admin_signing_key.as_ref().ok_or_else(|| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Admin signing key not configured on this node",
        )
    })?;

    let sk_bytes = hex::decode(signing_key).map_err(|_| {
        api_err(
            StatusCode::BAD_REQUEST,
            "Invalid hex in AROBL_ADMIN_SIGNING_KEY",
        )
    })?;

    let secret = ed25519_dalek::SigningKey::from_bytes(
        sk_bytes[..32]
            .try_into()
            .map_err(|_| api_err(StatusCode::BAD_REQUEST, "Signing key must be 32 bytes"))?,
    );
    let public = secret.verifying_key();

    let msg_hash = crypto::tx_sign_msg(
        &payload.tx_from,
        &payload.tx_to,
        payload.amount,
        payload.fee,
        payload.nonce,
        payload.timestamp,
        payload.data.as_deref(),
    );
    let signature = secret.sign(&msg_hash);
    let sig_hex = hex::encode(signature.to_bytes());

    let tx_id = Transaction::compute_id(
        &payload.tx_from,
        &payload.tx_to,
        payload.amount,
        payload.fee,
        payload.nonce,
        payload.timestamp,
        payload.data.as_deref(),
    );

    Ok(Json(SignResponse {
        signature: sig_hex,
        public_key: hex::encode(public.as_bytes()),
        tx_id,
        sign_msg: hex::encode(msg_hash),
    }))
}

#[derive(Deserialize)]
struct SignPayload {
    tx_from: String,
    tx_to: String,
    amount: u64,
    fee: u64,
    nonce: u64,
    timestamp: u64,
    data: Option<String>,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
    public_key: String,
    tx_id: String,
    /// Hex-encoded Ed25519 SHA-256 signing digest (for reference/debugging)
    sign_msg: String,
}

// ─── Tarpit / Honeypot ──────────────────────────────────────────────────────

async fn infinite_tarpit() -> axum::response::Response {
    use axum::body::Body;
    use tokio::time::{sleep, Duration};

    let stream = async_stream::stream! {
        loop {
            yield Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"GAGA_GIBBERTALK_INFINITE_CACHE_CHUCK_"));
            sleep(Duration::from_millis(500)).await;
        }
    };

    axum::response::Response::builder()
        .header("Content-Type", "application/octet-stream")
        .body(Body::from_stream(stream))
        .unwrap()
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Tarpits for scanners
        .route("/.env", get(infinite_tarpit))
        .route("/wp-login.php", get(infinite_tarpit))
        .route("/api/v1/admin/debug", get(infinite_tarpit))
        .route("/api/v1/admin/hack", get(infinite_tarpit))
        .route("/api/v1/admin/sign", post(admin_sign_message))
        // Chain info
        .route("/api/v1/info", get(get_info))
        .route("/api/v1/chain/tokenomics", get(get_tokenomics))
        // Blocks
        .route("/api/v1/blocks/latest", get(get_latest_block))
        .route("/api/v1/blocks/:height", get(get_block_by_height))
        .route("/api/v1/blocks", get(get_blocks_range))
        // Wallets
        .route("/api/v1/wallet/:address/balance", get(get_balance))
        .route("/api/v1/wallet/:address/nonce", get(get_nonce))
        .route("/api/v1/wallet/transfer", post(wallet_transfer))
        // Transactions
        .route("/api/v1/tx/:id", get(get_tx))
        .route("/api/v1/tx/submit", post(submit_tx))
        // Mempool & peers
        .route("/api/v1/mempool", get(get_mempool))
        .route("/api/v1/peers", get(get_peers))
        .route("/api/v1/peers/known", get(get_known_peers))
        // PoI consensus
        .route("/api/v1/consensus/poi", get(get_poi_stats))
        // Security
        .route("/api/v1/security/posture", get(get_security_posture))
        .route("/api/v1/security/threats", get(get_security_threats))
        // ArobiFS — distributed file system
        .route("/api/v1/fs/stats", get(fs_stats))
        .route("/api/v1/fs/upload", post(fs_upload))
        .route("/api/v1/fs/download/:file_id", get(fs_download))
        .route("/api/v1/fs/manifest/:file_id", get(fs_manifest))
        .route("/api/v1/fs/pin", post(fs_pin))
        .route("/api/v1/fs/unpin/:file_id", post(fs_unpin))
        .route("/api/v1/fs/chunk/:chunk_id", get(fs_get_chunk))
        // ArobiCompute — distributed compute marketplace
        .route("/api/v1/compute/capabilities", get(compute_capabilities))
        .route("/api/v1/compute/register", post(compute_register))
        .route("/api/v1/compute/job/submit", post(compute_submit_job))
        .route("/api/v1/compute/job/:job_id", get(compute_job_status))
        .route("/api/v1/compute/jobs", get(compute_list_jobs))
        .route("/api/v1/compute/marketplace", get(compute_marketplace))
        .route("/api/v1/compute/leaderboard", get(compute_leaderboard))
        .route("/api/v1/compute/bid", post(compute_submit_bid))
        .route(
            "/api/v1/compute/assign/:job_id",
            post(compute_assign_workers),
        )
        // ArobiLLM — decentralized language model
        .route("/api/v1/llm/models", get(llm_list_models))
        .route("/api/v1/llm/models/:model_id", get(llm_get_model))
        .route("/api/v1/llm/models/register", post(llm_register_model))
        .route("/api/v1/llm/stages/claim", post(llm_claim_stage))
        .route("/api/v1/llm/stages/:model_id", get(llm_get_stages))
        .route("/api/v1/llm/stages/heartbeat", post(llm_stage_heartbeat))
        .route("/api/v1/llm/inference", post(llm_submit_inference))
        .route("/api/v1/llm/marketplace", get(llm_marketplace))
        // LLM Chat Proxy — forwards to external LLM providers
        .route("/api/v1/llm/chat", post(llm_chat_proxy))
        // Autonomo — virtual world for AI agents
        .route("/api/v1/autonomo/status", get(autonomo_status))
        .route(
            "/api/v1/autonomo/access/register",
            post(autonomo_register_access),
        )
        .route("/api/v1/autonomo/giru/context", get(autonomo_giru_context))
        .route(
            "/api/v1/autonomo/memory/ingest",
            post(autonomo_memory_ingest),
        )
        .route(
            "/api/v1/autonomo/memory/recall/:agent/:key",
            get(autonomo_memory_recall),
        )
        .route(
            "/api/v1/autonomo/node/register",
            post(autonomo_register_node),
        )
        .route("/api/v1/autonomo/action", post(autonomo_agent_action))
        .route("/api/v1/autonomo/nudge", post(autonomo_nudge))
        .route("/api/v1/autonomo/nodes", get(autonomo_list_nodes))
        .route("/api/v1/autonomo/heartbeat", post(autonomo_heartbeat))
        .route("/api/v1/autonomo/agents", get(autonomo_list_agents))
        .route("/api/v1/autonomo/agent/:wallet", get(autonomo_get_agent))
        .route(
            "/api/v1/autonomo/agent/message",
            post(autonomo_agent_message),
        )
        .route(
            "/api/v1/autonomo/agent/messages",
            get(autonomo_list_messages),
        )
        .route(
            "/api/v1/autonomo/relay/send",
            post(autonomo_secure_relay_send),
        )
        .route(
            "/api/v1/autonomo/relay/messages",
            get(autonomo_secure_relay_messages),
        )
        .route(
            "/api/v1/autonomo/spaces",
            get(autonomo_list_spaces).post(autonomo_put_space),
        )
        .route("/api/v1/autonomo/spaces/:id", get(autonomo_get_space))
        .route("/api/v1/autonomo/knowledge", post(autonomo_put_knowledge))
        .route(
            "/api/v1/autonomo/knowledge/:agent/:key",
            get(autonomo_get_knowledge),
        )
        .route("/api/v1/autonomo/actions", get(autonomo_list_actions))
        .route(
            "/api/v1/autonomo/vault/limits",
            get(autonomo_get_vault_limits).post(autonomo_set_vault_limits),
        )
        .route(
            "/api/v1/autonomo/mission/treasury",
            get(autonomo_get_mission_treasury),
        )
        .route(
            "/api/v1/autonomo/mission/treasury/fund",
            post(autonomo_fund_mission_treasury),
        )
        .route(
            "/api/v1/autonomo/mission/treasury/payout",
            post(autonomo_payout_mission_treasury),
        )
        .route(
            "/api/v1/autonomo/openclaw/bind",
            post(autonomo_bind_openclaw_employee),
        )
        .route(
            "/api/v1/autonomo/openclaw/bind/bulk",
            post(autonomo_bind_openclaw_bulk),
        )
        .route(
            "/api/v1/autonomo/openclaw/bindings",
            get(autonomo_list_openclaw_bindings),
        )
        .route(
            "/api/v1/autonomo/openclaw/bindings/:employee_id",
            get(autonomo_get_openclaw_binding),
        )
        .route(
            "/api/v1/autonomo/openclaw/orchestration/context",
            get(autonomo_openclaw_orchestration_context),
        )
        // Tool execution (Phase 6)
        .route("/api/v1/tools/list", get(tools_list))
        .route("/api/v1/tools/execute", post(tools_execute))
        .route("/api/v1/tools/orchestrate", post(tools_orchestrate))
        .route("/api/v1/tools/knowledge/store", post(tools_knowledge_store))
        .route("/api/v1/tools/knowledge/query", post(tools_knowledge_query))
        // AI Decision Audit Ledger (Tribunal/Forensics)
        .route("/api/v1/audit/record", post(audit_record_decision))
        .route("/api/v1/audit/entries", get(audit_get_entries))
        .route("/api/v1/audit/entries/:entry_id", get(audit_get_entry))
        .route("/api/v1/audit/source/:source", get(audit_get_by_source))
        .route("/api/v1/audit/type/:decision_type", get(audit_get_by_type))
        .route("/api/v1/audit/lane/:lane_id", get(audit_get_by_lane))
        .route("/api/v1/audit/tribunal", get(audit_tribunal_export))
        .route("/api/v1/audit/verify", get(audit_verify_chain))
        .route("/api/v1/audit/forensics", get(audit_forensics_export))
        .route(
            "/api/v1/audit/training-corpus/manifest",
            get(audit_training_corpus_manifest),
        )
        .route(
            "/api/v1/audit/training-corpus",
            get(audit_training_corpus_export),
        )
        // Prometheus metrics
        .route("/metrics", get(prometheus_metrics))
        // External surface: keep public read-only routes available, but gate
        // mutation and introspection endpoints behind local admin access.
        .layer(axum::middleware::from_fn(enforce_api_access))
        // Rate limiting
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        // CORS — allow trusted production subdomains and local development origins.
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin, _request_parts| {
                    origin.to_str().map(is_allowed_cors_origin).unwrap_or(false)
                }))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(AllowHeaders::list([
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::ORIGIN,
                    header::AUTHORIZATION,
                    header::HeaderName::from_static("x-arobi-wallet"),
                    header::HeaderName::from_static("x-arobi-device-hash"),
                    header::HeaderName::from_static("x-arobi-access-token"),
                    header::HeaderName::from_static("x-arobi-clearance"),
                    header::HeaderName::from_static("access-control-request-private-network"),
                ])),
        )
        // Add manual header for private network access preflights
        .layer(axum::middleware::from_fn(
            |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
                let mut resp = next.run(req).await;
                resp.headers_mut().insert(
                    "access-control-allow-private-network",
                    header::HeaderValue::from_static("true"),
                );
                resp
            },
        ))
        .with_state(state)
}

pub async fn serve(state: AppState, port: u16) {
    // Bind to localhost by default; use AROBI_BIND_ADDR env var to override
    let bind_addr: [u8; 4] = if std::env::var("AROBI_BIND_ALL").is_ok() {
        [0, 0, 0, 0]
    } else {
        [127, 0, 0, 1]
    };
    let addr: SocketAddr = (bind_addr, port).into();
    let app = build_router(state);
    info!("API server on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind API port");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("API server crashed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn training_corpus_response_includes_manifest_for_q_pipeline_audits() {
        let manifest = crate::audit::ledger::TrainingExportManifest {
            schema_version: 2,
            migration_id: crate::audit::ledger::AUDIT_LANE_MIGRATION_ID.to_string(),
            include_internal: false,
            source_total: 3,
            exported_total: 1,
            public_exported: 1,
            private_exported: 0,
            private_skipped: 1,
            zero_zero_blocked: 1,
            integrity_failed_blocked: 0,
            public_reasoning_redacted: 1,
            metadata_keys_removed: 2,
            lane_summaries: vec![crate::audit::ledger::TrainingExportLaneSummary {
                lane_id: "public".to_string(),
                export_scope: "public-redacted".to_string(),
                training_policy: "allowed-redacted".to_string(),
                retention_class: "public-evidence".to_string(),
                source_total: 1,
                exported_total: 1,
                skipped_total: 0,
                blocked_total: 0,
                integrity_failed_blocked: 0,
                public_reasoning_redacted: 0,
                metadata_keys_removed: 0,
            }],
        };
        let export = crate::audit::ledger::TrainingCorpusExport {
            manifest: manifest.clone(),
            records: Vec::new(),
        };
        let receipt = training_corpus_receipt_from_export(&export);

        let response = AuditTrainingCorpusResponse {
            records: Vec::new(),
            total: manifest.exported_total,
            include_internal: manifest.include_internal,
            manifest,
            receipt,
        };

        let json = serde_json::to_value(response).expect("response should serialize");
        assert_eq!(json["manifest"]["source_total"], 3);
        assert_eq!(
            json["manifest"]["migration_id"],
            crate::audit::ledger::AUDIT_LANE_MIGRATION_ID
        );
        assert_eq!(json["manifest"]["zero_zero_blocked"], 1);
        assert_eq!(json["manifest"]["metadata_keys_removed"], 2);
        assert_eq!(json["manifest"]["lane_summaries"][0]["lane_id"], "public");
        assert_eq!(json["receipt"]["records_total"], 0);
        assert_eq!(
            json["receipt"]["records_sha256"],
            hex::encode(Sha256::digest(b"[]"))
        );
        assert!(json["receipt"]["receipt_id"]
            .as_str()
            .unwrap()
            .starts_with("qtrain-manifest-v1-"));
    }

    #[test]
    fn training_corpus_manifest_route_is_admin_only() {
        assert!(!is_public_api_route(
            &Method::GET,
            "/api/v1/audit/training-corpus/manifest"
        ));
    }

    #[test]
    fn admin_signing_route_requires_local_or_token_access() {
        assert!(!is_public_api_route(&Method::POST, "/api/v1/admin/sign"));
        assert!(!is_public_api_route(
            &Method::GET,
            "/api/v1/audit/training-corpus"
        ));
        assert!(!is_public_api_route(&Method::GET, "/api/v1/audit/lane/00"));
        assert!(is_public_api_route(&Method::POST, "/api/v1/tx/submit"));
        assert!(is_public_api_route(
            &Method::POST,
            "/api/v1/autonomo/relay/send"
        ));
    }
}
