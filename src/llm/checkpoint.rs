//! Model checkpoint save/load — versioned with block height.
//!
//! Checkpoints are stored in ArobiFS for distributed availability.
//! Each checkpoint includes model weights, optimizer state, and training metadata.

use candle_core::{Device, Result as CandleResult};
use candle_nn::VarMap;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

/// Metadata for a model checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMeta {
    /// Model ID this checkpoint belongs to
    pub model_id: String,
    /// Training round when this checkpoint was created
    pub round_id: u64,
    /// Block height at checkpoint time
    pub block_height: u64,
    /// Training step count
    pub step: usize,
    /// Total tokens trained on so far
    pub total_tokens: u64,
    /// Best validation loss achieved
    pub best_loss: f64,
    /// Current learning rate
    pub learning_rate: f64,
    /// ArobiFS file ID for the weight file
    pub weight_file_id: Option<String>,
    /// blake3 hash of the weight data
    pub weight_hash: String,
    /// Size of the checkpoint in bytes
    pub size_bytes: u64,
    /// Timestamp
    pub created_at: u64,
}

/// Save model weights to a safetensors file on disk.
pub fn save_checkpoint(var_map: &VarMap, path: &Path, meta: &CheckpointMeta) -> CandleResult<u64> {
    // Collect all tensors from the VarMap into a HashMap
    let data = var_map.data().lock().unwrap();
    let tensors: std::collections::HashMap<String, candle_core::Tensor> = data
        .iter()
        .map(|(name, var)| (name.clone(), var.as_tensor().clone()))
        .collect();

    // Save as safetensors
    candle_core::safetensors::save(&tensors, path)?;

    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    // Save metadata alongside
    let meta_path = path.with_extension("meta.json");
    let meta_json = serde_json::to_string_pretty(meta)
        .map_err(|e| candle_core::Error::Msg(format!("JSON serialize failed: {e}")))?;
    std::fs::write(&meta_path, meta_json)
        .map_err(|e| candle_core::Error::Msg(format!("Write meta failed: {e}")))?;

    info!(
        "Checkpoint saved: step={}, loss={:.4}, size={:.1}MB -> {}",
        meta.step,
        meta.best_loss,
        size as f64 / 1_048_576.0,
        path.display()
    );

    Ok(size)
}

/// Load model weights from a safetensors checkpoint file.
pub fn load_checkpoint(
    var_map: &VarMap,
    path: &Path,
    device: &Device,
) -> CandleResult<CheckpointMeta> {
    // Load tensors from safetensors
    let tensors = candle_core::safetensors::load(path, device)?;

    // Apply loaded tensors to VarMap
    let data = var_map.data().lock().unwrap();
    for (name, var) in data.iter() {
        if let Some(tensor) = tensors.get(name.as_str()) {
            var.set(tensor)?;
        }
    }

    // Load metadata
    let meta_path = path.with_extension("meta.json");
    let meta = if meta_path.exists() {
        let json = std::fs::read_to_string(&meta_path)
            .map_err(|e| candle_core::Error::Msg(format!("Read meta failed: {e}")))?;
        serde_json::from_str(&json)
            .map_err(|e| candle_core::Error::Msg(format!("Parse meta failed: {e}")))?
    } else {
        // Create default metadata if no meta file exists
        CheckpointMeta {
            model_id: String::new(),
            round_id: 0,
            block_height: 0,
            step: 0,
            total_tokens: 0,
            best_loss: f64::MAX,
            learning_rate: 0.0,
            weight_file_id: None,
            weight_hash: String::new(),
            size_bytes: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            created_at: 0,
        }
    };

    info!(
        "Checkpoint loaded: step={}, loss={:.4} <- {}",
        meta.step,
        meta.best_loss,
        path.display()
    );

    Ok(meta)
}

/// Compute blake3 hash of a checkpoint file for integrity verification.
pub fn hash_checkpoint(path: &Path) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read checkpoint: {e}"))?;
    Ok(blake3::hash(&data).to_hex().to_string())
}

/// Save model weights to ArobiFS for distributed availability.
/// Returns the ArobiFS file_id of the stored checkpoint.
pub fn save_to_arobifs(
    var_map: &VarMap,
    meta: &CheckpointMeta,
    chunk_store: &crate::fs::local_store::ChunkStore,
    owner: &str,
) -> Result<String, String> {
    // Save to a temp file first
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!(
        "arobi_ckpt_{}_{}.safetensors",
        meta.model_id, meta.round_id
    ));

    save_checkpoint(var_map, &temp_path, meta)
        .map_err(|e| format!("Failed to save checkpoint: {e}"))?;

    // Read the file and chunk it
    let data =
        std::fs::read(&temp_path).map_err(|e| format!("Failed to read temp checkpoint: {e}"))?;

    let chunker =
        crate::fs::chunker::Chunker::new().map_err(|e| format!("Chunker init failed: {e}"))?;
    let chunks = chunker
        .chunk_file(&data)
        .map_err(|e| format!("Chunking failed: {e}"))?;

    let manifest = chunker.build_manifest(
        &format!("{}_checkpoint_{}", meta.model_id, meta.round_id),
        data.len() as u64,
        owner,
        &chunks,
    );

    // Store chunks and manifest
    for (chunk_id, shard_type, chunk_data) in &chunks {
        let chunk_meta = crate::fs::types::ChunkMeta {
            chunk_id: chunk_id.clone(),
            file_id: manifest.file_id.clone(),
            index: 0,
            shard_type: shard_type.clone(),
            size: chunk_data.len() as u32,
            stored_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        chunk_store
            .put_chunk(&chunk_meta, chunk_data)
            .map_err(|e| format!("Failed to store chunk: {e}"))?;
    }
    chunk_store
        .put_manifest(&manifest)
        .map_err(|e| format!("Failed to store manifest: {e}"))?;

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_path);

    info!(
        "Checkpoint saved to ArobiFS: file_id={}, {} chunks, {:.1}MB",
        &manifest.file_id[..16.min(manifest.file_id.len())],
        chunks.len(),
        data.len() as f64 / 1_048_576.0
    );

    Ok(manifest.file_id)
}

/// Load model weights from ArobiFS.
pub fn load_from_arobifs(
    var_map: &VarMap,
    file_id: &str,
    chunk_store: &crate::fs::local_store::ChunkStore,
    device: &Device,
) -> Result<CheckpointMeta, String> {
    let data = chunk_store
        .reassemble_file(file_id)
        .map_err(|e| format!("Failed to reassemble file from ArobiFS: {e}"))?;

    // Write to temp file for safetensors loading
    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join(format!("arobi_ckpt_load_{file_id}.safetensors"));
    std::fs::write(&temp_path, &data).map_err(|e| format!("Failed to write temp file: {e}"))?;

    let meta = load_checkpoint(var_map, &temp_path, device)
        .map_err(|e| format!("Failed to load checkpoint: {e}"))?;

    // Clean up
    let _ = std::fs::remove_file(&temp_path);

    info!(
        "Checkpoint loaded from ArobiFS: file_id={}, step={}, loss={:.4}",
        &file_id[..16.min(file_id.len())],
        meta.step,
        meta.best_loss
    );

    Ok(meta)
}
