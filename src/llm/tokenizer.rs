//! Tokenizer wrapper for BPE tokenization.
//!
//! Wraps the HuggingFace `tokenizers` crate. The tokenizer model file
//! is loaded from ArobiFS (or a local path for development).

use std::path::Path;
use std::str::FromStr;

/// Wrapper around a HuggingFace BPE tokenizer.
pub struct ArobiTokenizer {
    inner: tokenizers::Tokenizer,
    bos_id: u32,
    eos_id: u32,
    pad_id: u32,
}

impl ArobiTokenizer {
    /// Load a tokenizer from a JSON file (HuggingFace format).
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let inner = tokenizers::Tokenizer::from_file(path)
            .map_err(|e| format!("Failed to load tokenizer: {e}"))?;

        // Extract special token IDs (defaults if not found)
        let bos_id = inner.token_to_id("<s>").unwrap_or(1);
        let eos_id = inner.token_to_id("</s>").unwrap_or(2);
        let pad_id = inner.token_to_id("<pad>").unwrap_or(0);

        Ok(Self {
            inner,
            bos_id,
            eos_id,
            pad_id,
        })
    }

    /// Load a tokenizer from raw JSON bytes (e.g., fetched from ArobiFS).
    pub fn from_bytes(json_bytes: &[u8]) -> Result<Self, String> {
        let json_str = std::str::from_utf8(json_bytes)
            .map_err(|e| format!("Invalid UTF-8 in tokenizer data: {e}"))?;
        let inner = tokenizers::Tokenizer::from_str(json_str)
            .map_err(|e| format!("Failed to parse tokenizer JSON: {}", e))?;

        let bos_id = inner.token_to_id("<s>").unwrap_or(1);
        let eos_id = inner.token_to_id("</s>").unwrap_or(2);
        let pad_id = inner.token_to_id("<pad>").unwrap_or(0);

        Ok(Self {
            inner,
            bos_id,
            eos_id,
            pad_id,
        })
    }

    /// Encode text to token IDs.
    pub fn encode(&self, text: &str, add_bos: bool) -> Result<Vec<u32>, String> {
        let encoding = self
            .inner
            .encode(text, false)
            .map_err(|e| format!("Tokenization failed: {e}"))?;

        let mut ids: Vec<u32> = encoding.get_ids().to_vec();
        if add_bos {
            ids.insert(0, self.bos_id);
        }
        Ok(ids)
    }

    /// Decode token IDs back to text.
    pub fn decode(&self, ids: &[u32], skip_special: bool) -> Result<String, String> {
        self.inner
            .decode(ids, skip_special)
            .map_err(|e| format!("Detokenization failed: {e}"))
    }

    /// Decode a single token ID to its string representation.
    pub fn decode_token(&self, id: u32) -> String {
        self.inner.decode(&[id], true).unwrap_or_default()
    }

    /// Check if a token ID is the end-of-sequence token.
    pub fn is_eos(&self, id: u32) -> bool {
        id == self.eos_id
    }

    /// Get the BOS token ID.
    pub fn bos_id(&self) -> u32 {
        self.bos_id
    }

    /// Get the EOS token ID.
    pub fn eos_id(&self) -> u32 {
        self.eos_id
    }

    /// Get the PAD token ID.
    pub fn pad_id(&self) -> u32 {
        self.pad_id
    }

    /// Vocabulary size.
    pub fn vocab_size(&self) -> usize {
        self.inner.get_vocab_size(true)
    }
}
