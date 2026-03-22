//! Dataset loader for training data stored in ArobiFS.
//!
//! Reads sharded text datasets, tokenizes on-the-fly, and produces
//! batches of (input_ids, target_ids) for language model training.

use candle_core::{Device, Result as CandleResult, Tensor};
use rand::seq::SliceRandom;
use tracing::info;

use super::tokenizer::ArobiTokenizer;

/// A training dataset shard loaded into memory.
pub struct DatasetShard {
    /// Tokenized sequences (each is a Vec of token IDs)
    sequences: Vec<Vec<u32>>,
    /// Context length for each training sample
    context_length: usize,
    /// Shard identifier
    pub shard_id: String,
    /// Total number of tokens in this shard
    pub total_tokens: u64,
}

impl DatasetShard {
    /// Create a dataset shard from raw text, tokenizing with the provided tokenizer.
    pub fn from_text(
        text: &str,
        tokenizer: &ArobiTokenizer,
        context_length: usize,
        shard_id: &str,
    ) -> Result<Self, String> {
        let token_ids = tokenizer.encode(text, false)?;
        let total_tokens = token_ids.len() as u64;

        // Split into fixed-length sequences
        let sequences: Vec<Vec<u32>> = token_ids
            .chunks(context_length + 1) // +1 for the target shift
            .filter(|chunk| chunk.len() > 1) // Need at least 2 tokens
            .map(|chunk| chunk.to_vec())
            .collect();

        info!(
            "Dataset shard '{}': {} tokens, {} sequences (ctx={})",
            shard_id,
            total_tokens,
            sequences.len(),
            context_length
        );

        Ok(Self {
            sequences,
            context_length,
            shard_id: shard_id.to_string(),
            total_tokens,
        })
    }

    /// Number of sequences in this shard.
    pub fn len(&self) -> usize {
        self.sequences.len()
    }

    /// Whether the shard has no data.
    pub fn is_empty(&self) -> bool {
        self.sequences.is_empty()
    }
}

/// Batch of training data ready for the model.
pub struct TrainingBatch {
    /// Input token IDs: [batch_size, seq_len]
    pub input_ids: Tensor,
    /// Target token IDs (shifted by 1): [batch_size, seq_len]
    pub target_ids: Tensor,
    /// Number of tokens in this batch
    pub num_tokens: usize,
}

/// DataLoader that produces shuffled batches from dataset shards.
pub struct DataLoader {
    shards: Vec<DatasetShard>,
    batch_size: usize,
    device: Device,
    /// Flat index of all (shard_idx, sequence_idx) pairs
    indices: Vec<(usize, usize)>,
    /// Current position in the shuffled indices
    cursor: usize,
}

impl DataLoader {
    pub fn new(shards: Vec<DatasetShard>, batch_size: usize, device: Device) -> Self {
        let mut indices = Vec::new();
        for (shard_idx, shard) in shards.iter().enumerate() {
            for seq_idx in 0..shard.len() {
                indices.push((shard_idx, seq_idx));
            }
        }

        let mut loader = Self {
            shards,
            batch_size,
            device,
            indices,
            cursor: 0,
        };
        loader.shuffle();
        loader
    }

    /// Shuffle the iteration order (call at the start of each epoch).
    pub fn shuffle(&mut self) {
        let mut rng = rand::thread_rng();
        self.indices.shuffle(&mut rng);
        self.cursor = 0;
    }

    /// Get the next training batch. Returns None when the epoch is exhausted.
    pub fn next_batch(&mut self) -> CandleResult<Option<TrainingBatch>> {
        if self.cursor >= self.indices.len() {
            return Ok(None);
        }

        let end = (self.cursor + self.batch_size).min(self.indices.len());
        let batch_indices = &self.indices[self.cursor..end];
        self.cursor = end;

        // Find the maximum sequence length in this batch
        let max_len = batch_indices
            .iter()
            .map(|&(s, i)| self.shards[s].sequences[i].len() - 1) // -1 for target shift
            .max()
            .unwrap_or(1);

        let mut input_data = Vec::new();
        let mut target_data = Vec::new();
        let actual_batch_size = batch_indices.len();

        for &(shard_idx, seq_idx) in batch_indices {
            let seq = &self.shards[shard_idx].sequences[seq_idx];
            let seq_len = seq.len() - 1; // -1 for target shift

            // Input: all tokens except the last
            let mut input_row: Vec<u32> = seq[..seq_len].to_vec();
            // Target: all tokens except the first (shifted by 1)
            let mut target_row: Vec<u32> = seq[1..=seq_len].to_vec();

            // Pad to max_len if needed (pad with 0)
            input_row.resize(max_len, 0);
            target_row.resize(max_len, 0);

            input_data.extend_from_slice(&input_row);
            target_data.extend_from_slice(&target_row);
        }

        let input_ids = Tensor::from_vec(input_data, (actual_batch_size, max_len), &self.device)?;
        let target_ids = Tensor::from_vec(target_data, (actual_batch_size, max_len), &self.device)?;

        Ok(Some(TrainingBatch {
            input_ids,
            target_ids,
            num_tokens: actual_batch_size * max_len,
        }))
    }

    /// Total number of sequences across all shards.
    pub fn total_sequences(&self) -> usize {
        self.indices.len()
    }

    /// Total number of tokens across all shards.
    pub fn total_tokens(&self) -> u64 {
        self.shards.iter().map(|s| s.total_tokens).sum()
    }

    /// Number of batches per epoch.
    pub fn batches_per_epoch(&self) -> usize {
        (self.indices.len() + self.batch_size - 1) / self.batch_size
    }

    /// Reset cursor for a new epoch (also shuffles).
    pub fn reset(&mut self) {
        self.shuffle();
    }
}
