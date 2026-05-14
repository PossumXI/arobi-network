use std::path::PathBuf;

/// Runtime node configuration (from CLI args)
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub p2p_port: u16,
    pub api_port: u16,
    pub seed_nodes: Vec<String>,
    pub advertised_addrs: Vec<String>,
    pub redial_interval_secs: u64,
    pub mine: bool,
}

/// Arobi Network tokenomics & consensus parameters.
/// ALL NODES MUST AGREE ON THESE — CHANGING THEM FORKS THE CHAIN.
/// Genesis: 2026-03-22 00:00:00 UTC
pub mod genesis {
    // ── Network identity ─────────────────────────────────────────────────
    pub const NETWORK_MAGIC: &str = "AROBI1";
    pub const NETWORK_VERSION: u32 = 1;
    /// Genesis timestamp: 2026-03-22 00:00:00 UTC
    pub const TIMESTAMP_MS: u64 = 1_742_611_200_000;

    // ── Token info ─────────────────────────────────────────────────────────
    /// AURA uses 8 decimal places (1 AURA = 100_000_000 base units)
    #[allow(dead_code)]
    pub const DECIMALS: u8 = 8;
    pub const DECIMAL_FACTOR: u64 = 100_000_000;

    // ── Total supply: 24,000,000,000 AURA (24 billion) ───────────────────
    pub const TOTAL_SUPPLY: u64 = 24_000_000_000 * DECIMAL_FACTOR;

    // ── Genesis allocations (minted at block 0) ─────────────────────────────
    /// Founder: 500,000,000 AURA — immediate, no vesting restriction
    pub const FOUNDER_GENESIS_ALLOCATION: u64 = 500_000_000 * DECIMAL_FACTOR;
    /// Mission Treasury: 4,000,000,000 AURA — governance controlled
    pub const MISSION_TREASURY_ALLOCATION: u64 = 4_000_000_000 * DECIMAL_FACTOR;

    /// Public Pool (DEX): 15,000,000,000 AURA (15B) — DEX liquidity and trading.
    /// Governance-controlled only. Bridge contracts access via governance approval.
    /// No node runner rewards come from this pool.
    pub const PUBLIC_POOL_ALLOCATION: u64 = 15_000_000_000 * DECIMAL_FACTOR;

    /// Node Operators Pool: 2,500,000,000 AURA (2.5B) — pays node runners via PoI-ranked halving.
    /// 50% halving every 2 years. Pool exhausted after 20 years max (Year 10 halving).
    /// Top PoI performers earn more. Pool-empty = no more block rewards.
    pub const NODE_OPS_POOL_ALLOCATION: u64 = 2_500_000_000 * DECIMAL_FACTOR;

    // ── Founder 8-year vesting ─────────────────────────────────────────────
    /// Additional 2,000,000,000 AURA vests linearly to founder over 8 years.
    /// Monthly unlock: VESTING_TOTAL / 96 months (8 years x 12 months).
    /// The vested amount accrues automatically — founder can spend up to vested total.
    pub const FOUNDER_VESTING_TOTAL: u64 = 2_000_000_000 * DECIMAL_FACTOR;
    /// Vesting period in months (8 years)
    pub const FOUNDER_VESTING_MONTHS: u64 = 96;
    /// Vesting start timestamp (same as genesis)
    pub const FOUNDER_VESTING_START_MS: u64 = TIMESTAMP_MS;
    /// 1 month in milliseconds (30 days)
    pub const VESTING_MONTH_MS: u64 = 30 * 24 * 60 * 60 * 1000;

    // ── Wallet addresses ──────────────────────────────────────────────────
    /// Founder wallet — receives genesis allocation + vesting.
    /// Format: ARLPh prefix + 37 hex chars = 42 total.
    pub const FOUNDER_ADDRESS: &str = "ARLPhd4b4f0782999f272dbd3e943835412dc13448";

    /// Mission Treasury wallet — governance controlled.
    /// Format: ARLPh prefix + 37 hex chars = 42 total.
    pub const MISSION_TREASURY_ADDRESS: &str = "ARLPhd79954b2219b64cad9742dea7014e2e6156d2";

    /// Public Pool (DEX) address — governance-only fund for DEX liquidity/bridge.
    /// NO private key. Governance multisig controls bridge withdrawals.
    /// Format: PUBLICP00L + 32 zeros = 42 total. (no Ed25519 key exists)
    pub const PUBLIC_POOL_ADDRESS: &str = "PUBLICP00L00000000000000000000000000000000000";

    /// Node Operators Pool address — consensus-only fund for PoI-ranked node rewards.
    /// NO private key. Only consensus can emit from this pool.
    /// Format: NODEOP00L + 32 zeros = 42 total. (no Ed25519 key exists)
    pub const NODE_OPS_POOL_ADDRESS: &str = "NODEOP00L000000000000000000000000000000000000";

    // ── Node Operators Pool — 20-year halving emission schedule ──────────────────
    /// 1 year in blocks (60s blocks): 525,960 blocks/year
    /// Total pool: 2.5B AURA. Halving every 2 years (1,051,920 blocks).
    /// Y1-2:  595 AURA/block | Y3-4:  297 AURA/block | Y5-6:  148 AURA/block
    /// Y7-8:   74 AURA/block | Y9-10:   37 AURA/block | Y11-12: 18 AURA/block
    /// Y13-14:   9 AURA/block | Y15-16:   5 AURA/block | Y17-18:  2 AURA/block
    /// Y19-20:  1 AURA/block | Pool exhausted after ~20 years
    #[allow(dead_code)]
    pub const BLOCKS_PER_YEAR: u64 = 525_960;
    pub const HALVING_PERIOD_BLOCKS: u64 = 1_051_920; // 2 years
    pub const MAX_HALVING_EXPONENT: u64 = 10; // 10 halvings = 20 years

    // ── Block reward (from NODE_OPS_POOL) ─────────────────────────────────
    /// Per-block reward starts at ~595 AURA/block and halves every 2 years.
    /// Calibrated so 2.5B AURA lasts exactly 20 years at PoI consensus.
    pub const BLOCK_REWARD_BASE: u64 = 59_514_700_000; // raw = ~595 AURA/block at Y1-2
    /// Minimum reward before pool exhaustion check
    #[allow(dead_code)]
    pub const NODE_REWARD_MIN: u64 = 1; // 0.00000001 AURA (1 raw unit)
    /// Target block time in seconds
    pub const BLOCK_TIME_SECS: u64 = 60;
    /// Maximum transactions per block
    pub const MAX_TXS_PER_BLOCK: usize = 500;
    /// Minimum transaction fee (0.00001 AURA)
    pub const MIN_FEE: u64 = 1_000;

    // ── Default seed nodes ─────────────────────────────────────────────────
    pub const DEFAULT_SEEDS: &[&str] = &[];

    // ── Block Reward Distribution (basis points = 1/10000) ───────────────
    /// Validator who produces the block: 30%
    #[allow(dead_code)]
    pub const REWARD_VALIDATOR_BPS: u64 = 3000;
    /// Storage providers (ArobiFS): 25%
    #[allow(dead_code)]
    pub const REWARD_STORAGE_BPS: u64 = 2500;
    /// Compute providers (ArobiCompute): 25%
    #[allow(dead_code)]
    pub const REWARD_COMPUTE_BPS: u64 = 2500;
    /// LLM operators (ArobiLLM): 20%
    #[allow(dead_code)]
    pub const REWARD_LLM_BPS: u64 = 2000;

    // ── ArobiFS ─────────────────────────────────────────────────────────
    #[allow(dead_code)]
    pub const CHUNK_SIZE: usize = 256 * 1024;
    #[allow(dead_code)]
    pub const MIN_REPLICAS: u8 = 3;

    // ── ArobiCompute ─────────────────────────────────────────────────────
    #[allow(dead_code)]
    pub const WASM_MAX_MEMORY_PAGES: u32 = 4096;
    #[allow(dead_code)]
    pub const JOB_MAX_DURATION_MS: u64 = 600_000;
    #[allow(dead_code)]
    pub const DEFAULT_JOB_REDUNDANCY: u8 = 3;

    // ── ArobiLLM ─────────────────────────────────────────────────────────
    #[allow(dead_code)]
    pub const MODEL_REGISTRATION_FEE: u64 = 10 * DECIMAL_FACTOR;
    #[allow(dead_code)]
    pub const DEFAULT_TOKEN_COST: u64 = 1_000;
    #[allow(dead_code)]
    pub const MAX_PIPELINE_STAGES: u32 = 16;

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Compute how much founder has vested at a given timestamp.
    /// Linear vesting over FOUNDER_VESTING_MONTHS months.
    #[allow(dead_code)]
    pub fn founder_vested(timestamp_ms: u64) -> u64 {
        if timestamp_ms < FOUNDER_VESTING_START_MS {
            return 0;
        }
        let elapsed = timestamp_ms - FOUNDER_VESTING_START_MS;
        let months_elapsed = elapsed / VESTING_MONTH_MS;
        let months_vested = months_elapsed.min(FOUNDER_VESTING_MONTHS);
        FOUNDER_VESTING_TOTAL / FOUNDER_VESTING_MONTHS * months_vested
    }

    /// Total founder balance (genesis immediate + vested).
    #[allow(dead_code)]
    pub fn founder_total_balance(timestamp_ms: u64) -> u64 {
        FOUNDER_GENESIS_ALLOCATION + founder_vested(timestamp_ms)
    }

    /// Current PoI halving exponent (0..10).
    /// Halving happens every HALVING_PERIOD_BLOCKS blocks.
    pub fn halving_exp(chain_height: u64) -> u64 {
        let exp = chain_height / HALVING_PERIOD_BLOCKS;
        exp.min(MAX_HALVING_EXPONENT)
    }

    /// Current block reward from Node Operators Pool, accounting for halving.
    /// Returns raw units. Pool-emptied = 0 reward.
    pub fn current_block_reward(chain_height: u64, pool_balance_raw: u64) -> u64 {
        let exp = halving_exp(chain_height);
        // reward = BASE / 2^exp
        let halving_divisor: u64 = 1 << exp.min(60); // shift safe for exp <= 10
        let reward = BLOCK_REWARD_BASE / halving_divisor;
        // Never pay more than what remains in pool
        reward.min(pool_balance_raw)
    }
}
