//! File chunker with Reed-Solomon erasure coding.
//!
//! Splits files into fixed-size chunks (256 KiB), computes blake3 content
//! addresses, and generates parity shards for fault tolerance.

use anyhow::{bail, Context, Result};
use reed_solomon_erasure::galois_8::ReedSolomon;

use super::types::*;

/// File chunker — splits raw bytes into content-addressed chunks with erasure coding.
pub struct Chunker {
    rs: ReedSolomon,
}

impl Chunker {
    pub fn new() -> Result<Self> {
        let rs = ReedSolomon::new(RS_DATA_SHARDS, RS_PARITY_SHARDS)
            .map_err(|e| anyhow::anyhow!("Reed-Solomon init failed: {e}"))?;
        Ok(Self { rs })
    }

    /// Split raw file bytes into data chunks + parity chunks.
    ///
    /// Returns a list of `(ChunkId, ShardType, Vec<u8>)` tuples.
    /// The ChunkId is the blake3 hash of the chunk bytes.
    pub fn chunk_file(&self, data: &[u8]) -> Result<Vec<(ChunkId, ShardType, Vec<u8>)>> {
        if data.is_empty() {
            bail!("Cannot chunk empty data");
        }
        if data.len() as u64 > MAX_FILE_SIZE {
            bail!(
                "File too large: {} bytes (max {})",
                data.len(),
                MAX_FILE_SIZE
            );
        }

        // Split into CHUNK_SIZE data chunks
        let data_chunks: Vec<Vec<u8>> = data.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();

        let mut result = Vec::new();

        // Process in groups of RS_DATA_SHARDS for erasure coding
        for (group_idx, group) in data_chunks.chunks(RS_DATA_SHARDS).enumerate() {
            let parity = self.encode_group(group)?;

            // Add data shards
            for (i, chunk_bytes) in group.iter().enumerate() {
                let chunk_id = blake3::hash(chunk_bytes).to_hex().to_string();
                let global_index = group_idx * RS_DATA_SHARDS + i;
                result.push((chunk_id, ShardType::Data, chunk_bytes.clone()));
                let _ = global_index; // used for ordering in manifest
            }

            // Add parity shards
            for (i, parity_bytes) in parity.into_iter().enumerate() {
                let chunk_id = blake3::hash(&parity_bytes).to_hex().to_string();
                result.push((
                    chunk_id,
                    ShardType::Parity {
                        parity_index: i as u32,
                    },
                    parity_bytes,
                ));
            }
        }

        Ok(result)
    }

    /// Reconstruct original data from a set of shards (data + parity).
    ///
    /// `shards` is a Vec of `RS_TOTAL_SHARDS` entries per group.
    /// Each entry is `Option<Vec<u8>>` — `None` means that shard is missing.
    /// At least `RS_DATA_SHARDS` of `RS_TOTAL_SHARDS` must be present per group.
    pub fn reconstruct_group(&self, shards: &mut [Option<Vec<u8>>]) -> Result<Vec<u8>> {
        if shards.len() != RS_TOTAL_SHARDS {
            bail!("Expected {} shards, got {}", RS_TOTAL_SHARDS, shards.len());
        }

        let present = shards.iter().filter(|s| s.is_some()).count();
        if present < RS_DATA_SHARDS {
            bail!(
                "Need at least {} shards to reconstruct, only {} present",
                RS_DATA_SHARDS,
                present
            );
        }

        // Determine shard size from any present shard
        let shard_size = shards
            .iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .context("No shards present")?;

        // Track which shards were present, then build reconstruct input
        let present_mask: Vec<bool> = shards.iter().map(|s| s.is_some()).collect();
        let mut reconstruct_shards: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if present_mask[i] {
                    s.clone()
                } else {
                    // Reed-Solomon needs None for missing shards
                    None
                }
            })
            .collect();

        // Ensure missing shards are None (already handled above) but present
        // shards must have correct size
        for shard in reconstruct_shards.iter_mut() {
            if let Some(ref mut v) = shard {
                v.resize(shard_size, 0);
            }
        }

        // Reconstruct missing shards
        self.rs
            .reconstruct(&mut reconstruct_shards)
            .map_err(|e| anyhow::anyhow!("Reed-Solomon reconstruction failed: {e}"))?;

        // Extract data shards (first RS_DATA_SHARDS)
        let mut data = Vec::new();
        for shard in reconstruct_shards.iter().take(RS_DATA_SHARDS) {
            if let Some(bytes) = shard {
                data.extend_from_slice(bytes);
            } else {
                bail!("Reconstruction produced None for a data shard");
            }
        }

        Ok(data)
    }

    /// Build a FileManifest from chunking results.
    pub fn build_manifest(
        &self,
        name: &str,
        total_size: u64,
        owner: &str,
        chunks: &[(ChunkId, ShardType, Vec<u8>)],
    ) -> FileManifest {
        let mut chunk_refs: Vec<ChunkRef> = Vec::new();
        let mut data_count: u32 = 0;
        let mut parity_count: u32 = 0;

        for (idx, (chunk_id, shard_type, bytes)) in chunks.iter().enumerate() {
            match shard_type {
                ShardType::Data => data_count += 1,
                ShardType::Parity { .. } => parity_count += 1,
            }
            chunk_refs.push(ChunkRef {
                chunk_id: chunk_id.clone(),
                index: idx as u32,
                shard_type: shard_type.clone(),
                size: bytes.len() as u32,
            });
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Compute file_id from deterministic manifest content (without file_id itself)
        let id_input = format!(
            "{}|{}|{}|{}|{}",
            name, total_size, owner, data_count, now_ms
        );
        let file_id = blake3::hash(id_input.as_bytes()).to_hex().to_string();

        FileManifest {
            file_id,
            name: name.to_string(),
            total_size,
            chunk_count: data_count,
            parity_count,
            chunks: chunk_refs,
            owner: owner.to_string(),
            encryption: EncryptionMeta::None,
            created_at: now_ms,
            pin_policy: PinPolicy::default(),
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    /// Encode a group of up to RS_DATA_SHARDS chunks into parity shards.
    fn encode_group(&self, group: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        // All shards in a group must be the same size — pad last chunk if needed
        let max_size = group.iter().map(|c| c.len()).max().unwrap_or(0);

        let mut padded: Vec<Vec<u8>> = group
            .iter()
            .map(|c| {
                let mut v = c.clone();
                v.resize(max_size, 0);
                v
            })
            .collect();

        // If group has fewer than RS_DATA_SHARDS chunks, pad with zero-filled shards
        while padded.len() < RS_DATA_SHARDS {
            padded.push(vec![0u8; max_size]);
        }

        // Create parity shards (initially empty, same size as data shards)
        let mut parity: Vec<Vec<u8>> = (0..RS_PARITY_SHARDS).map(|_| vec![0u8; max_size]).collect();

        // Build the full shard array: data + parity
        let mut all_shards: Vec<&mut [u8]> = Vec::new();
        for shard in padded.iter_mut() {
            all_shards.push(shard.as_mut_slice());
        }
        for shard in parity.iter_mut() {
            all_shards.push(shard.as_mut_slice());
        }

        self.rs
            .encode(&mut all_shards)
            .map_err(|e| anyhow::anyhow!("Reed-Solomon encode failed: {e}"))?;

        Ok(parity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_small_file() {
        let chunker = Chunker::new().unwrap();
        let data = vec![42u8; 1024]; // 1 KiB
        let chunks = chunker.chunk_file(&data).unwrap();
        // 1 data chunk + 2 parity chunks
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].1, ShardType::Data);
        assert_eq!(chunks[1].1, ShardType::Parity { parity_index: 0 });
        assert_eq!(chunks[2].1, ShardType::Parity { parity_index: 1 });
    }

    #[test]
    fn test_chunk_ids_are_content_addressed() {
        let chunker = Chunker::new().unwrap();
        let data = vec![99u8; 1024];
        let chunks1 = chunker.chunk_file(&data).unwrap();
        let chunks2 = chunker.chunk_file(&data).unwrap();
        assert_eq!(chunks1[0].0, chunks2[0].0); // same content = same ID
    }

    #[test]
    fn test_reconstruct_with_missing_shard() {
        let chunker = Chunker::new().unwrap();
        // Create data that fits in exactly 4 chunks of CHUNK_SIZE
        let data = vec![7u8; CHUNK_SIZE * 4];
        let chunks = chunker.chunk_file(&data).unwrap();

        // We should have 4 data + 2 parity = 6 shards
        assert_eq!(chunks.len(), 6);

        // Simulate losing 2 shards (shard 1 and shard 3)
        let mut shards: Vec<Option<Vec<u8>>> = chunks
            .iter()
            .map(|(_, _, bytes)| Some(bytes.clone()))
            .collect();
        shards[1] = None; // lose data shard 1
        shards[3] = None; // lose data shard 3

        let reconstructed = chunker.reconstruct_group(&mut shards).unwrap();
        assert_eq!(&reconstructed[..data.len()], &data[..]);
    }

    #[test]
    fn test_reject_empty_data() {
        let chunker = Chunker::new().unwrap();
        assert!(chunker.chunk_file(&[]).is_err());
    }
}
