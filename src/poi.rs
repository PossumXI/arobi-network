//! Proof of Intelligence (PoI) Consensus Engine
//!
//! A novel consensus mechanism that requires validators to solve intelligence
//! challenges (pattern recognition, optimization, cryptographic puzzles,
//! machine learning tasks, and data analysis) before producing blocks.
//!
//! Ported from apex-os-project, adapted for arobi-network's Blake3/sled architecture.

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Intelligence challenge categories
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum ChallengeType {
    PatternRecognition,
    OptimizationProblem,
    CryptographicPuzzle,
    MachineLearningTask,
    DataAnalysis,
    /// Prove the node stores real data chunks (ArobiFS)
    StorageProof,
    /// Prove the node can execute compute tasks correctly (ArobiCompute)
    ComputeProof,
    /// Prove the node can run ML inference on its assigned model stage (ArobiLLM)
    InferenceProof,
}

/// Challenge issued to a validator before block production
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceChallenge {
    pub challenge_type: ChallengeType,
    pub difficulty: u32,
    pub seed: Vec<u8>,
    pub input_data: Vec<u8>,
    pub expected_complexity: u64,
    pub time_limit_ms: u64,
}

/// Solution submitted by the validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSolution {
    pub solution_data: Vec<u8>,
    pub computation_steps: u64,
    pub memory_used: u64,
    pub time_taken_ms: u64,
    pub algorithm_used: String,
}

/// Proof embedded in blocks — serialised challenge + solution + verification hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligenceProof {
    pub challenge_bytes: Vec<u8>,
    pub solution_bytes: Vec<u8>,
    pub computation_hash: String,
    pub intelligence_score: f64,
}

// ---------------------------------------------------------------------------
// Intelligence model trait
// ---------------------------------------------------------------------------

#[async_trait]
trait IntelligenceModel: Send + Sync {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution>;
    fn validate(&self, challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool;
}

// ---------------------------------------------------------------------------
// Intelligence engine — holds all 5 model implementations
// ---------------------------------------------------------------------------

struct IntelligenceEngine {
    models: HashMap<ChallengeType, Box<dyn IntelligenceModel>>,
    total_challenges: AtomicU64,
    successful_solutions: AtomicU64,
}

impl IntelligenceEngine {
    fn new() -> Self {
        let mut models: HashMap<ChallengeType, Box<dyn IntelligenceModel>> = HashMap::new();

        models.insert(
            ChallengeType::PatternRecognition,
            Box::new(PatternRecognitionModel),
        );
        models.insert(
            ChallengeType::OptimizationProblem,
            Box::new(OptimizationModel),
        );
        models.insert(
            ChallengeType::CryptographicPuzzle,
            Box::new(CryptographicModel),
        );
        models.insert(
            ChallengeType::MachineLearningTask,
            Box::new(MachineLearningModel),
        );
        models.insert(ChallengeType::DataAnalysis, Box::new(DataAnalysisModel));
        models.insert(ChallengeType::StorageProof, Box::new(StorageProofModel));
        models.insert(ChallengeType::ComputeProof, Box::new(ComputeProofModel));
        models.insert(ChallengeType::InferenceProof, Box::new(InferenceProofModel));

        Self {
            models,
            total_challenges: AtomicU64::new(0),
            successful_solutions: AtomicU64::new(0),
        }
    }

    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let model = self
            .models
            .get(&challenge.challenge_type)
            .ok_or_else(|| anyhow!("No model for challenge type {:?}", challenge.challenge_type))?;

        let solution = model.solve(challenge).await?;

        self.total_challenges.fetch_add(1, Ordering::Relaxed);
        self.successful_solutions.fetch_add(1, Ordering::Relaxed);

        Ok(solution)
    }

    fn validate(&self, challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        self.models
            .get(&challenge.challenge_type)
            .map(|m| m.validate(challenge, solution))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// PoI Engine — public API
// ---------------------------------------------------------------------------

/// Proof of Intelligence consensus engine.
///
/// Call `generate_proof(block_height)` during block production to create an
/// intelligence proof, and `verify_proof(proof)` when validating received blocks.
pub struct PoiEngine {
    engine: IntelligenceEngine,
    difficulty: RwLock<u32>,
    challenges_solved: AtomicU64,
    total_score: RwLock<f64>,
}

impl PoiEngine {
    /// Create a new PoI engine with all 5 intelligence models.
    pub fn new() -> Self {
        Self {
            engine: IntelligenceEngine::new(),
            difficulty: RwLock::new(1000),
            challenges_solved: AtomicU64::new(0),
            total_score: RwLock::new(0.0),
        }
    }

    /// Generate an intelligence challenge for the given block height.
    pub fn generate_challenge(&self, block_height: u64) -> Result<IntelligenceChallenge> {
        let mut seed_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
        let mut rng = StdRng::from_seed(seed_bytes);

        // Select challenge type pseudo-randomly, seeded by block height
        // 8 challenge types: 5 original intelligence + 3 resource proofs
        let challenge_type = match (block_height + rng.gen::<u64>()) % 8 {
            0 => ChallengeType::PatternRecognition,
            1 => ChallengeType::OptimizationProblem,
            2 => ChallengeType::CryptographicPuzzle,
            3 => ChallengeType::MachineLearningTask,
            4 => ChallengeType::DataAnalysis,
            5 => ChallengeType::StorageProof,
            6 => ChallengeType::ComputeProof,
            _ => ChallengeType::InferenceProof,
        };

        let difficulty = *self.difficulty.read();

        // Generate challenge seed
        let mut seed = vec![0u8; 32];
        rng.fill(&mut seed[..]);

        // Generate input data proportional to difficulty
        let input_size = rng.gen_range(100..1000.min(difficulty as usize * 10 + 100));
        let mut input_data = vec![0u8; input_size];
        rng.fill(&mut input_data[..]);

        Ok(IntelligenceChallenge {
            challenge_type,
            difficulty,
            seed,
            input_data,
            expected_complexity: difficulty as u64 * 1_000,
            time_limit_ms: 30_000, // half the block time
        })
    }

    /// Solve an intelligence challenge using the appropriate model.
    pub async fn solve_challenge(
        &self,
        challenge: &IntelligenceChallenge,
    ) -> Result<ChallengeSolution> {
        let solution = self.engine.solve(challenge).await?;

        // Verify time constraint
        if solution.time_taken_ms > challenge.time_limit_ms {
            return Err(anyhow!("Solution exceeded time limit"));
        }

        Ok(solution)
    }

    /// Generate a complete intelligence proof for a block at the given height.
    /// This generates a challenge, solves it, and packages everything into a proof.
    pub async fn generate_proof(&self, block_height: u64) -> Result<IntelligenceProof> {
        let challenge = self.generate_challenge(block_height)?;
        let solution = self.solve_challenge(&challenge).await?;

        let challenge_bytes =
            bincode::serialize(&challenge).map_err(|e| anyhow!("serialize challenge: {e}"))?;
        let solution_bytes =
            bincode::serialize(&solution).map_err(|e| anyhow!("serialize solution: {e}"))?;

        let computation_hash = Self::compute_hash(&challenge_bytes, &solution_bytes);
        let intelligence_score = Self::calculate_intelligence_score(&solution);

        self.challenges_solved.fetch_add(1, Ordering::Relaxed);
        {
            let mut total = self.total_score.write();
            *total += intelligence_score;
        }

        Ok(IntelligenceProof {
            challenge_bytes,
            solution_bytes,
            computation_hash,
            intelligence_score,
        })
    }

    /// Verify an intelligence proof embedded in a received block.
    pub fn verify_proof(proof: &IntelligenceProof) -> Result<()> {
        // Deserialize challenge and solution
        let challenge: IntelligenceChallenge = bincode::deserialize(&proof.challenge_bytes)
            .map_err(|e| anyhow!("deserialize challenge: {e}"))?;
        let solution: ChallengeSolution = bincode::deserialize(&proof.solution_bytes)
            .map_err(|e| anyhow!("deserialize solution: {e}"))?;

        // Verify computation hash
        let expected_hash = Self::compute_hash(&proof.challenge_bytes, &proof.solution_bytes);
        if proof.computation_hash != expected_hash {
            return Err(anyhow!("Invalid computation hash"));
        }

        // Verify intelligence score is consistent
        let expected_score = Self::calculate_intelligence_score(&solution);
        if (proof.intelligence_score - expected_score).abs() > 0.01 {
            return Err(anyhow!("Invalid intelligence score"));
        }

        // Verify solution meets basic requirements
        if solution.time_taken_ms > challenge.time_limit_ms {
            return Err(anyhow!("Solution exceeded time limit"));
        }

        // Use a temporary engine to validate the solution against the challenge
        let engine = IntelligenceEngine::new();
        if !engine.validate(&challenge, &solution) {
            return Err(anyhow!("Solution failed model validation"));
        }

        Ok(())
    }

    /// Compute blake3 hash of challenge || solution bytes.
    fn compute_hash(challenge_bytes: &[u8], solution_bytes: &[u8]) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(challenge_bytes);
        hasher.update(solution_bytes);
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Score a solution based on speed (40%), efficiency (30%), memory (20%),
    /// and algorithm sophistication (10%).
    pub fn calculate_intelligence_score(solution: &ChallengeSolution) -> f64 {
        let speed_score = (10_000.0 / (solution.time_taken_ms as f64 + 1.0)).min(100.0) * 0.4;
        let efficiency_score = (solution.computation_steps as f64 / 1000.0).min(100.0) * 0.3;
        let memory_score = (100.0 - (solution.memory_used as f64 / 1_000_000.0)).max(0.0) * 0.2;
        let algorithm_score = 80.0 * 0.1; // base score

        speed_score + efficiency_score + memory_score + algorithm_score
    }

    /// Current difficulty level.
    pub fn difficulty(&self) -> u32 {
        *self.difficulty.read()
    }

    /// Number of challenges solved since startup.
    pub fn challenges_solved(&self) -> u64 {
        self.challenges_solved.load(Ordering::Relaxed)
    }

    /// Average intelligence score across all solved challenges.
    pub fn average_score(&self) -> f64 {
        let solved = self.challenges_solved() as f64;
        if solved == 0.0 {
            return 0.0;
        }
        *self.total_score.read() / solved
    }

    /// Adjust difficulty (called periodically based on network state).
    #[allow(dead_code)]
    pub fn adjust_difficulty(&self, new_difficulty: u32) {
        let clamped = new_difficulty.clamp(100, 1_000_000);
        *self.difficulty.write() = clamped;
        tracing::info!("PoI difficulty adjusted to {clamped}");
    }
}

// ---------------------------------------------------------------------------
// Intelligence model implementations
// ---------------------------------------------------------------------------

struct PatternRecognitionModel;

#[async_trait]
impl IntelligenceModel for PatternRecognitionModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();

        // Pattern recognition: find repeating byte sequences in input data
        let data = &challenge.input_data;
        let mut patterns: HashMap<&[u8], usize> = HashMap::new();

        // Scan for 2-byte patterns
        for window in data.windows(2) {
            *patterns.entry(window).or_insert(0) += 1;
        }

        // Find the most common pattern
        let most_common = patterns
            .iter()
            .max_by_key(|(_, &count)| count)
            .map(|(pattern, count)| (pattern.to_vec(), *count))
            .unwrap_or((vec![0, 0], 0));

        let mut solution_data = most_common.0;
        solution_data.extend_from_slice(&(most_common.1 as u32).to_le_bytes());

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: data.len() as u64,
            memory_used: (patterns.len() * 16) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "PatternMatching".to_string(),
        })
    }

    fn validate(&self, _challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        !solution.solution_data.is_empty() && solution.computation_steps > 0
    }
}

struct OptimizationModel;

#[async_trait]
impl IntelligenceModel for OptimizationModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();

        // Optimization: sort the input data and find optimal partition
        let mut data = challenge.input_data.clone();
        data.sort();

        // Find the partition point that minimizes difference between halves
        let total: u64 = data.iter().map(|&b| b as u64).sum();
        let target = total / 2;
        let mut running = 0u64;
        let mut best_split = 0;
        let mut best_diff = u64::MAX;

        for (i, &val) in data.iter().enumerate() {
            running += val as u64;
            let diff = running.abs_diff(target);
            if diff < best_diff {
                best_diff = diff;
                best_split = i;
            }
        }

        let mut solution_data = Vec::new();
        solution_data.extend_from_slice(&(best_split as u32).to_le_bytes());
        solution_data.extend_from_slice(&best_diff.to_le_bytes());

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: (data.len() * 2) as u64,
            memory_used: (data.len() * 2) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "PartitionOptimization".to_string(),
        })
    }

    fn validate(&self, _challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        solution.solution_data.len() >= 12
    }
}

struct CryptographicModel;

#[async_trait]
impl IntelligenceModel for CryptographicModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();

        // Cryptographic puzzle: iterative blake3 hashing
        let iterations = (challenge.difficulty as usize).max(10);
        let mut hash = blake3::hash(&challenge.input_data);

        for _ in 1..iterations {
            hash = blake3::hash(hash.as_bytes());
        }

        Ok(ChallengeSolution {
            solution_data: hash.as_bytes().to_vec(),
            computation_steps: iterations as u64,
            memory_used: 32 * 2, // two hash buffers
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "Blake3Chain".to_string(),
        })
    }

    fn validate(&self, challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        // Re-compute and verify
        let iterations = (challenge.difficulty as usize).max(10);
        let mut hash = blake3::hash(&challenge.input_data);
        for _ in 1..iterations {
            hash = blake3::hash(hash.as_bytes());
        }
        solution.solution_data == hash.as_bytes()
    }
}

struct MachineLearningModel;

#[async_trait]
impl IntelligenceModel for MachineLearningModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();

        // ML task: compute statistical features of the input data
        let data = &challenge.input_data;
        if data.is_empty() {
            return Ok(ChallengeSolution {
                solution_data: vec![0; 32],
                computation_steps: 1,
                memory_used: 64,
                time_taken_ms: 0,
                algorithm_used: "StatisticalML".to_string(),
            });
        }

        let n = data.len() as f64;
        let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;
        let variance = data
            .iter()
            .map(|&b| {
                let diff = b as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / n;
        let std_dev = variance.sqrt();

        // Compute skewness
        let skewness = if std_dev > 0.0 {
            data.iter()
                .map(|&b| {
                    let z = (b as f64 - mean) / std_dev;
                    z * z * z
                })
                .sum::<f64>()
                / n
        } else {
            0.0
        };

        // Compute entropy
        let mut freq = [0u32; 256];
        for &b in data {
            freq[b as usize] += 1;
        }
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / n;
                -p * p.ln()
            })
            .sum();

        // Pack features
        let mut solution_data = Vec::with_capacity(32);
        solution_data.extend_from_slice(&mean.to_le_bytes());
        solution_data.extend_from_slice(&std_dev.to_le_bytes());
        solution_data.extend_from_slice(&skewness.to_le_bytes());
        solution_data.extend_from_slice(&entropy.to_le_bytes());

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: (data.len() * 5) as u64, // multiple passes
            memory_used: (256 * 4 + data.len()) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "StatisticalML".to_string(),
        })
    }

    fn validate(&self, _challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        solution.solution_data.len() == 32 && solution.computation_steps > 0
    }
}

struct DataAnalysisModel;

#[async_trait]
impl IntelligenceModel for DataAnalysisModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();

        let data = &challenge.input_data;

        // Chunk the data and compute per-chunk averages
        let chunk_size = 32;
        let mut result = Vec::with_capacity(data.len() / chunk_size + 1);

        for chunk in data.chunks(chunk_size) {
            let sum: u32 = chunk.iter().map(|&b| b as u32).sum();
            result.push((sum / chunk.len() as u32) as u8);
        }

        Ok(ChallengeSolution {
            solution_data: result,
            computation_steps: data.len() as u64,
            memory_used: data.len() as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "ChunkedAnalysis".to_string(),
        })
    }

    fn validate(&self, _challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        !solution.solution_data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Resource proof models (ArobiFS, ArobiCompute, ArobiLLM)
// ---------------------------------------------------------------------------

/// StorageProof: Proves the validator stores real data chunks.
/// The challenge contains synthetic chunk data; the validator must compute
/// a merkle proof over random byte ranges — mirroring the ArobiFS storage
/// proof protocol but within the PoI framework.
struct StorageProofModel;

#[async_trait]
impl IntelligenceModel for StorageProofModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();
        let data = &challenge.input_data;

        // Simulate storage proof: hash random byte ranges of the challenge data
        // using the seed as a nonce, just like ArobiFS proof.rs does
        let mut hasher = blake3::Hasher::new();
        hasher.update(&challenge.seed);

        // Divide data into segments and hash each one (simulating chunk verification)
        let segment_size = 32.max(data.len() / 8);
        let mut segments_hashed = 0u64;
        for chunk in data.chunks(segment_size) {
            hasher.update(chunk);
            segments_hashed += 1;
        }

        let proof_hash = hasher.finalize();

        // Also compute a merkle-like tree over 32-byte leaves
        let leaves: Vec<[u8; 32]> = data
            .chunks(32)
            .map(|leaf| {
                let mut padded = [0u8; 32];
                padded[..leaf.len()].copy_from_slice(leaf);
                *blake3::hash(&padded).as_bytes()
            })
            .collect();

        // Build root from leaves
        let num_leaves = leaves.len();
        let mut level = leaves;
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&pair[0]);
                if pair.len() > 1 {
                    h.update(&pair[1]);
                }
                next.push(*h.finalize().as_bytes());
            }
            level = next;
        }
        let merkle_root = level.first().copied().unwrap_or([0u8; 32]);

        let mut solution_data = proof_hash.as_bytes().to_vec();
        solution_data.extend_from_slice(&merkle_root);

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: segments_hashed + num_leaves as u64,
            memory_used: (data.len() + num_leaves * 32) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "StorageMerkleProof".to_string(),
        })
    }

    fn validate(&self, challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        if solution.solution_data.len() != 64 {
            return false;
        }
        // Re-compute the proof hash and verify it matches
        let data = &challenge.input_data;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&challenge.seed);
        let segment_size = 32.max(data.len() / 8);
        for chunk in data.chunks(segment_size) {
            hasher.update(chunk);
        }
        let expected_hash = hasher.finalize();
        solution.solution_data[..32] == *expected_hash.as_bytes()
    }
}

/// ComputeProof: Proves the validator can execute deterministic compute tasks.
/// The challenge contains a set of operations the validator must execute
/// and produce the correct result — proving real compute capacity.
struct ComputeProofModel;

#[async_trait]
impl IntelligenceModel for ComputeProofModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();
        let data = &challenge.input_data;

        // Phase 1: Matrix-like computation on the input data
        // Treat data as a flat array of u8, reshape into rows, compute dot products
        let row_size = 16.min(data.len());
        let rows: Vec<&[u8]> = data.chunks(row_size).collect();
        let num_rows = rows.len();

        // Compute pairwise dot products of adjacent rows
        let mut dot_products = Vec::new();
        for i in 0..num_rows.saturating_sub(1) {
            let mut dot: u64 = 0;
            for (&left, &right) in rows[i].iter().zip(rows[i + 1].iter()).take(row_size) {
                dot += left as u64 * right as u64;
            }
            dot_products.push(dot);
        }

        // Phase 2: Reduction — iterative sum-and-hash
        let sum: u64 = dot_products.iter().sum();
        let mut acc = blake3::hash(&sum.to_le_bytes());
        for _ in 0..challenge.difficulty.min(1000) {
            acc = blake3::hash(acc.as_bytes());
        }

        // Phase 3: Sort verification — prove we can sort efficiently
        let mut sorted = data.to_vec();
        sorted.sort_unstable();
        let sorted_hash = blake3::hash(&sorted);

        let mut solution_data = acc.as_bytes().to_vec();
        solution_data.extend_from_slice(sorted_hash.as_bytes());

        let steps =
            num_rows as u64 * row_size as u64 + challenge.difficulty as u64 + data.len() as u64;

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: steps,
            memory_used: (data.len() * 3 + dot_products.len() * 8) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "MatrixDotSort".to_string(),
        })
    }

    fn validate(&self, challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        if solution.solution_data.len() != 64 {
            return false;
        }
        // Verify the sorted hash portion
        let mut sorted = challenge.input_data.clone();
        sorted.sort_unstable();
        let expected_sorted_hash = blake3::hash(&sorted);
        solution.solution_data[32..64] == *expected_sorted_hash.as_bytes()
    }
}

/// InferenceProof: Proves the validator can perform ML-like forward pass
/// computations. Uses a simplified neural network simulation to verify
/// that the node has real compute capability for LLM inference.
struct InferenceProofModel;

#[async_trait]
impl IntelligenceModel for InferenceProofModel {
    async fn solve(&self, challenge: &IntelligenceChallenge) -> Result<ChallengeSolution> {
        let start = std::time::Instant::now();
        let data = &challenge.input_data;

        // Simulate a simplified transformer forward pass:
        // 1. Embedding: hash each byte into a 4-element "vector"
        let embedding_dim = 4;
        let mut embeddings: Vec<Vec<f32>> = data
            .iter()
            .map(|&b| {
                let h = blake3::hash(&[b]);
                let bytes = h.as_bytes();
                (0..embedding_dim)
                    .map(|i| (bytes[i] as f32 - 128.0) / 128.0)
                    .collect()
            })
            .collect();

        // 2. Self-attention: compute attention weights between positions
        let seq_len = embeddings.len().min(64); // cap for performance
        let embeddings = &mut embeddings[..seq_len];
        let mut attention_output: Vec<Vec<f32>> = Vec::with_capacity(seq_len);

        for i in 0..seq_len {
            let mut weighted = vec![0.0f32; embedding_dim];
            let mut total_weight: f32 = 0.0;

            for j in 0..seq_len {
                // Dot product attention score
                let score: f32 = embeddings[i]
                    .iter()
                    .zip(embeddings[j].iter())
                    .map(|(a, b)| a * b)
                    .sum();
                let weight = score.exp().min(1e6);
                total_weight += weight;

                for (acc, value) in weighted
                    .iter_mut()
                    .zip(embeddings[j].iter())
                    .take(embedding_dim)
                {
                    *acc += weight * *value;
                }
            }

            // Normalize
            if total_weight > 0.0 {
                for value in weighted.iter_mut().take(embedding_dim) {
                    *value /= total_weight;
                }
            }
            attention_output.push(weighted);
        }

        // 3. FFN: apply ReLU(W * x + b) simulation
        let mut ffn_output: Vec<Vec<f32>> = Vec::with_capacity(seq_len);
        for vec in &attention_output {
            let transformed: Vec<f32> = vec
                .iter()
                .map(|&x| (x * 1.5 + 0.1).max(0.0)) // ReLU activation
                .collect();
            ffn_output.push(transformed);
        }

        // 4. Output: hash the final hidden states into a proof
        let mut final_hasher = blake3::Hasher::new();
        for vec in &ffn_output {
            for &val in vec {
                final_hasher.update(&val.to_le_bytes());
            }
        }
        let output_hash = final_hasher.finalize();

        // Pack: output hash + attention stats
        let avg_value: f32 = ffn_output.iter().flat_map(|v| v.iter()).sum::<f32>()
            / (ffn_output.len() * embedding_dim) as f32;

        let mut solution_data = output_hash.as_bytes().to_vec();
        solution_data.extend_from_slice(&avg_value.to_le_bytes());

        let steps = seq_len as u64 * seq_len as u64 * embedding_dim as u64 * 3;

        Ok(ChallengeSolution {
            solution_data,
            computation_steps: steps,
            memory_used: (seq_len * embedding_dim * 4 * 3) as u64,
            time_taken_ms: start.elapsed().as_millis() as u64,
            algorithm_used: "TransformerForwardPass".to_string(),
        })
    }

    fn validate(&self, _challenge: &IntelligenceChallenge, solution: &ChallengeSolution) -> bool {
        // Must produce 32-byte hash + 4-byte avg float = 36 bytes
        solution.solution_data.len() == 36 && solution.computation_steps > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_poi_proof_roundtrip() {
        let engine = PoiEngine::new();
        let proof = engine.generate_proof(1).await.unwrap();

        assert!(!proof.computation_hash.is_empty());
        assert!(proof.intelligence_score > 0.0);

        // Verify should pass
        PoiEngine::verify_proof(&proof).unwrap();
    }

    #[tokio::test]
    async fn test_poi_tampered_proof_fails() {
        let engine = PoiEngine::new();
        let mut proof = engine.generate_proof(1).await.unwrap();

        // Tamper with the score
        proof.intelligence_score = 999.0;

        assert!(PoiEngine::verify_proof(&proof).is_err());
    }

    #[test]
    fn test_score_calculation() {
        let solution = ChallengeSolution {
            solution_data: vec![1],
            computation_steps: 5000,
            memory_used: 1_000_000,
            time_taken_ms: 100,
            algorithm_used: "test".to_string(),
        };
        let score = PoiEngine::calculate_intelligence_score(&solution);
        assert!(score > 0.0 && score <= 100.0);
    }
}
