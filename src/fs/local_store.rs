//! Local chunk store — filesystem blobs + sled index.
//!
//! Chunk bytes are stored as flat files at `~/.arobi/chunks/{chunk_id_hex}`.
//! sled holds the metadata index for fast lookup without reading file contents.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::types::*;

/// Local chunk store backed by filesystem + sled index.
pub struct ChunkStore {
    /// Directory where chunk blobs are stored.
    chunks_dir: PathBuf,
    /// sled database (shared with the main blockchain store).
    db: sled::Db,
}

impl ChunkStore {
    /// Open or create the chunk store.
    pub fn open(data_dir: &Path, db: sled::Db) -> Result<Self> {
        let chunks_dir = data_dir.join("chunks");
        std::fs::create_dir_all(&chunks_dir).context("Failed to create chunks directory")?;

        let store = Self { chunks_dir, db };

        let count = store.chunk_count()?;
        if count > 0 {
            info!("ChunkStore loaded: {count} chunks on disk");
        } else {
            info!("ChunkStore initialized (empty)");
        }

        Ok(store)
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Store a chunk (bytes on disk, metadata in sled).
    pub fn put_chunk(&self, meta: &ChunkMeta, data: &[u8]) -> Result<()> {
        // Verify content address
        let computed_id = blake3::hash(data).to_hex().to_string();
        if computed_id != meta.chunk_id {
            bail!(
                "Chunk ID mismatch: expected {}, computed {}",
                meta.chunk_id,
                computed_id
            );
        }

        // Check storage limits
        let count = self.chunk_count()?;
        if count >= MAX_LOCAL_CHUNKS {
            bail!("Local chunk storage full ({count} chunks)");
        }

        // Write blob to filesystem
        let blob_path = self.blob_path(&meta.chunk_id);
        std::fs::write(&blob_path, data)
            .with_context(|| format!("Failed to write chunk blob: {}", blob_path.display()))?;

        // Write metadata to sled index
        let meta_json = serde_json::to_vec(meta)?;
        self.index()?.insert(meta.chunk_id.as_bytes(), meta_json)?;

        Ok(())
    }

    /// Store a file manifest in sled.
    pub fn put_manifest(&self, manifest: &FileManifest) -> Result<()> {
        let json = serde_json::to_vec(manifest)?;
        self.manifests()?
            .insert(manifest.file_id.as_bytes(), json)?;
        Ok(())
    }

    /// Store a pin record in sled.
    pub fn put_pin(&self, record: &PinRecord) -> Result<()> {
        let json = serde_json::to_vec(record)?;
        self.pins()?.insert(record.file_id.as_bytes(), json)?;
        Ok(())
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Read chunk data bytes from disk.
    pub fn get_chunk_data(&self, chunk_id: &str) -> Result<Option<Vec<u8>>> {
        let blob_path = self.blob_path(chunk_id);
        if blob_path.exists() {
            let data = std::fs::read(&blob_path)?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Read chunk metadata from sled.
    pub fn get_chunk_meta(&self, chunk_id: &str) -> Result<Option<ChunkMeta>> {
        match self.index()?.get(chunk_id.as_bytes())? {
            Some(bytes) => {
                let meta: ChunkMeta = serde_json::from_slice(&bytes)?;
                Ok(Some(meta))
            }
            None => Ok(None),
        }
    }

    /// Check if we have a chunk locally.
    pub fn has_chunk(&self, chunk_id: &str) -> Result<bool> {
        Ok(self.index()?.contains_key(chunk_id.as_bytes())?)
    }

    /// Get a file manifest.
    pub fn get_manifest(&self, file_id: &str) -> Result<Option<FileManifest>> {
        match self.manifests()?.get(file_id.as_bytes())? {
            Some(bytes) => {
                let manifest: FileManifest = serde_json::from_slice(&bytes)?;
                Ok(Some(manifest))
            }
            None => Ok(None),
        }
    }

    /// Get a pin record.
    pub fn get_pin(&self, file_id: &str) -> Result<Option<PinRecord>> {
        match self.pins()?.get(file_id.as_bytes())? {
            Some(bytes) => {
                let record: PinRecord = serde_json::from_slice(&bytes)?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Read specific byte ranges from a chunk (for storage proofs).
    pub fn read_chunk_ranges(
        &self,
        chunk_id: &str,
        ranges: &[(u64, u64)],
    ) -> Result<Option<Vec<u8>>> {
        let data = match self.get_chunk_data(chunk_id)? {
            Some(d) => d,
            None => return Ok(None),
        };

        let mut result = Vec::new();
        for &(start, end) in ranges {
            let start = start as usize;
            let end = (end as usize).min(data.len());
            if start >= data.len() {
                continue;
            }
            result.extend_from_slice(&data[start..end]);
        }

        Ok(Some(result))
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    /// Remove a chunk from disk and sled.
    pub fn delete_chunk(&self, chunk_id: &str) -> Result<bool> {
        let removed = self.index()?.remove(chunk_id.as_bytes())?.is_some();
        let blob_path = self.blob_path(chunk_id);
        if blob_path.exists() {
            if let Err(e) = std::fs::remove_file(&blob_path) {
                warn!("Failed to delete chunk blob {chunk_id}: {e}");
            }
        }
        Ok(removed)
    }

    /// Remove a pin record.
    pub fn delete_pin(&self, file_id: &str) -> Result<bool> {
        Ok(self.pins()?.remove(file_id.as_bytes())?.is_some())
    }

    // ── Enumeration ───────────────────────────────────────────────────────────

    /// Count of locally stored chunks.
    pub fn chunk_count(&self) -> Result<u64> {
        Ok(self.index()?.len() as u64)
    }

    /// Count of stored manifests.
    pub fn manifest_count(&self) -> Result<u64> {
        Ok(self.manifests()?.len() as u64)
    }

    /// Count of active pins.
    pub fn pin_count(&self) -> Result<u64> {
        Ok(self.pins()?.len() as u64)
    }

    /// Total bytes used on disk for chunk storage.
    pub fn total_bytes(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for entry in self.index()?.iter() {
            let (_, val) = entry?;
            let meta: ChunkMeta = serde_json::from_slice(&val)?;
            total += meta.size as u64;
        }
        Ok(total)
    }

    /// List all chunk IDs stored locally.
    pub fn list_chunk_ids(&self) -> Result<Vec<ChunkId>> {
        let mut ids = Vec::new();
        for entry in self.index()?.iter() {
            let (key, _) = entry?;
            let id = String::from_utf8(key.to_vec())?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// List all file manifests.
    pub fn list_manifests(&self) -> Result<Vec<FileManifest>> {
        let mut manifests = Vec::new();
        for entry in self.manifests()?.iter() {
            let (_, val) = entry?;
            let manifest: FileManifest = serde_json::from_slice(&val)?;
            manifests.push(manifest);
        }
        Ok(manifests)
    }

    /// Get storage statistics.
    pub fn stats(&self) -> Result<StorageStats> {
        let total_chunks = self.chunk_count()?;
        let total_bytes = self.total_bytes()?;
        let total_files = self.manifest_count()?;
        let total_pins = self.pin_count()?;

        // Estimate available space from chunks dir filesystem
        let available_bytes = fs_available_bytes(&self.chunks_dir);

        // Proof stats from sled
        let proofs_tree = self.storage_proofs()?;
        let storage_proofs_passed = proofs_tree.len() as u64;

        Ok(StorageStats {
            total_chunks,
            total_bytes,
            total_files,
            total_pins,
            available_bytes,
            storage_proofs_passed,
            storage_proofs_failed: 0,
        })
    }

    // ── sled tree accessors ───────────────────────────────────────────────────

    fn index(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_chunks")?)
    }

    fn manifests(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_manifests")?)
    }

    fn pins(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_pins")?)
    }

    fn storage_proofs(&self) -> Result<sled::Tree> {
        Ok(self.db.open_tree("fs_storage_proofs")?)
    }

    /// Store a storage proof result.
    pub fn put_storage_proof(&self, proof: &StorageProof) -> Result<()> {
        let json = serde_json::to_vec(proof)?;
        self.storage_proofs()?
            .insert(proof.challenge_id.as_bytes(), json)?;
        Ok(())
    }

    // ── File Reassembly ─────────────────────────────────────────────────────

    /// Reassemble a complete file from its ArobiFS manifest.
    /// Loads all data chunks in order and concatenates them.
    pub fn reassemble_file(&self, file_id: &str) -> Result<Vec<u8>> {
        let manifest = self
            .get_manifest(file_id)?
            .ok_or_else(|| anyhow::anyhow!("Manifest not found: {file_id}"))?;

        // Collect data chunks in order (skip parity)
        let mut data_refs: Vec<&ChunkRef> = manifest
            .chunks
            .iter()
            .filter(|c| matches!(c.shard_type, ShardType::Data))
            .collect();
        data_refs.sort_by_key(|c| c.index);

        let mut file_data = Vec::with_capacity(manifest.total_size as usize);
        for chunk_ref in &data_refs {
            let chunk_bytes = self.get_chunk_data(&chunk_ref.chunk_id)?.ok_or_else(|| {
                anyhow::anyhow!("Missing chunk {} for file {file_id}", chunk_ref.chunk_id)
            })?;
            file_data.extend_from_slice(&chunk_bytes);
        }

        // Trim to exact file size (last chunk may be padded)
        file_data.truncate(manifest.total_size as usize);
        Ok(file_data)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn blob_path(&self, chunk_id: &str) -> PathBuf {
        self.chunks_dir.join(chunk_id)
    }
}

/// Get available filesystem space (best effort).
fn fs_available_bytes(path: &Path) -> u64 {
    #[cfg(target_os = "windows")]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        let wide_path: Vec<u16> = OsStr::new(path.to_str().unwrap_or("C:\\"))
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut free_bytes: u64 = 0;
        unsafe {
            // GetDiskFreeSpaceExW
            extern "system" {
                fn GetDiskFreeSpaceExW(
                    dir: *const u16,
                    free_caller: *mut u64,
                    total: *mut u64,
                    total_free: *mut u64,
                ) -> i32;
            }
            GetDiskFreeSpaceExW(
                wide_path.as_ptr(),
                &mut free_bytes,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
        }
        free_bytes
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
        // Conservative fallback: report 100 GiB
        100 * 1024 * 1024 * 1024
    }
}
