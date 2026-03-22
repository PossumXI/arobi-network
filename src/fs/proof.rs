//! Cryptographic storage proofs — challenge/response protocol.
//!
//! A verifier picks random byte ranges within a chunk and a nonce.
//! The prover must compute `blake3(nonce || bytes_at_ranges)` and return it.
//! This proves the prover actually holds the chunk data without transferring
//! the entire chunk.

use anyhow::{bail, Result};
use rand::Rng;

use super::types::*;

/// Generates storage challenges for peers.
pub struct StorageChallenger;

impl StorageChallenger {
    /// Generate a storage challenge for a specific chunk.
    ///
    /// `chunk_size` is the actual size of the chunk in bytes.
    /// `num_ranges` is how many random byte ranges to include (more = harder to fake).
    pub fn generate(
        chunk_id: &ChunkId,
        chunk_size: u32,
        num_ranges: usize,
        deadline_ms: u64,
    ) -> StorageChallenge {
        let mut rng = rand::thread_rng();

        // Generate random nonce (32 bytes)
        let mut nonce = vec![0u8; 32];
        rng.fill(&mut nonce[..]);

        // Generate random byte ranges within the chunk
        let mut byte_ranges = Vec::with_capacity(num_ranges);
        for _ in 0..num_ranges {
            let range_size = rng.gen_range(32..=256).min(chunk_size as usize);
            let max_start = (chunk_size as usize).saturating_sub(range_size);
            let start = if max_start > 0 {
                rng.gen_range(0..max_start) as u64
            } else {
                0
            };
            let end = start + range_size as u64;
            byte_ranges.push((start, end));
        }

        // Challenge ID = blake3(chunk_id || nonce || timestamp)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let id_input = format!("{}|{}|{}", chunk_id, hex::encode(&nonce), now);
        let challenge_id = blake3::hash(id_input.as_bytes()).to_hex().to_string();

        StorageChallenge {
            challenge_id,
            chunk_id: chunk_id.clone(),
            byte_ranges,
            nonce,
            deadline_ms,
        }
    }
}

/// Verifies storage proofs and generates proofs from local data.
pub struct StorageVerifier;

impl StorageVerifier {
    /// Generate a proof by reading local chunk data.
    ///
    /// `chunk_data` is the full chunk bytes.
    /// `challenge` is the challenge to respond to.
    /// `prover_address` is our AROBI address.
    pub fn generate_proof(
        chunk_data: &[u8],
        challenge: &StorageChallenge,
        prover_address: &str,
    ) -> Result<StorageProof> {
        let proof_hash =
            Self::compute_proof_hash(&challenge.nonce, chunk_data, &challenge.byte_ranges)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(StorageProof {
            challenge_id: challenge.challenge_id.clone(),
            chunk_id: challenge.chunk_id.clone(),
            proof_hash,
            prover: prover_address.to_string(),
            timestamp: now,
        })
    }

    /// Verify a proof against known chunk data.
    ///
    /// Returns `true` if the proof hash matches the expected hash.
    pub fn verify_proof(
        chunk_data: &[u8],
        challenge: &StorageChallenge,
        proof: &StorageProof,
    ) -> Result<bool> {
        // Check challenge_id matches
        if proof.challenge_id != challenge.challenge_id {
            bail!("Challenge ID mismatch");
        }

        // Check deadline
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if now > challenge.deadline_ms {
            return Ok(false); // Proof submitted after deadline
        }

        // Recompute expected proof hash
        let expected =
            Self::compute_proof_hash(&challenge.nonce, chunk_data, &challenge.byte_ranges)?;

        Ok(proof.proof_hash == expected)
    }

    /// Compute proof hash: blake3(nonce || bytes_at_range_0 || bytes_at_range_1 || ...)
    fn compute_proof_hash(
        nonce: &[u8],
        chunk_data: &[u8],
        ranges: &[(u64, u64)],
    ) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(nonce);

        for &(start, end) in ranges {
            let start = start as usize;
            let end = (end as usize).min(chunk_data.len());
            if start >= chunk_data.len() {
                continue;
            }
            hasher.update(&chunk_data[start..end]);
        }

        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_generation() {
        let challenge =
            StorageChallenger::generate(&"test_chunk_id".to_string(), 1024, 3, u64::MAX);
        assert_eq!(challenge.chunk_id, "test_chunk_id");
        assert_eq!(challenge.byte_ranges.len(), 3);
        assert_eq!(challenge.nonce.len(), 32);
        assert!(!challenge.challenge_id.is_empty());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let chunk_data = vec![42u8; 1024];
        let challenge = StorageChallenger::generate(
            &"test_chunk".to_string(),
            1024,
            3,
            u64::MAX, // no deadline for test
        );

        let proof =
            StorageVerifier::generate_proof(&chunk_data, &challenge, "ARtestaddress").unwrap();

        let valid = StorageVerifier::verify_proof(&chunk_data, &challenge, &proof).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_proof_fails_with_wrong_data() {
        let real_data = vec![42u8; 1024];
        let fake_data = vec![99u8; 1024];

        let challenge = StorageChallenger::generate(&"test_chunk".to_string(), 1024, 3, u64::MAX);

        // Generate proof with real data
        let proof =
            StorageVerifier::generate_proof(&real_data, &challenge, "ARtestaddress").unwrap();

        // Verify against fake data — should fail
        let valid = StorageVerifier::verify_proof(&fake_data, &challenge, &proof).unwrap();

        assert!(!valid);
    }

    #[test]
    fn test_deterministic_proof_hash() {
        let data = vec![7u8; 512];
        let challenge = StorageChallenge {
            challenge_id: "test".to_string(),
            chunk_id: "chunk1".to_string(),
            byte_ranges: vec![(0, 100), (200, 300)],
            nonce: vec![1, 2, 3, 4],
            deadline_ms: u64::MAX,
        };

        let proof1 = StorageVerifier::generate_proof(&data, &challenge, "addr1").unwrap();
        let proof2 = StorageVerifier::generate_proof(&data, &challenge, "addr2").unwrap();

        // Same data + same challenge = same proof hash (prover identity doesn't affect hash)
        assert_eq!(proof1.proof_hash, proof2.proof_hash);
    }
}
