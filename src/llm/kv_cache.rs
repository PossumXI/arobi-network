//! KV Cache management for autoregressive generation.
//!
//! Each pipeline stage maintains its own KV cache. During generation,
//! the cache grows as new tokens are produced. The cache can be serialized
//! for transfer between nodes during pipeline execution.

use candle_core::{Result, Tensor};

/// Per-layer KV cache entry.
#[derive(Clone)]
pub struct LayerCache {
    pub k: Tensor,
    pub v: Tensor,
}

/// KV cache for a set of transformer layers (one pipeline stage).
pub struct KvCache {
    /// One cache entry per layer in this stage
    layers: Vec<Option<LayerCache>>,
    /// Number of layers this cache covers
    num_layers: usize,
    /// Current sequence length in the cache
    seq_len: usize,
    /// Maximum allowed sequence length
    max_seq_len: usize,
}

impl KvCache {
    /// Create an empty KV cache for `num_layers` layers.
    pub fn new(num_layers: usize, max_seq_len: usize) -> Self {
        let layers = (0..num_layers).map(|_| None).collect();
        Self {
            layers,
            num_layers,
            seq_len: 0,
            max_seq_len,
        }
    }

    /// Get the cache for a specific layer (if populated).
    pub fn get(&self, layer_idx: usize) -> Option<(&Tensor, &Tensor)> {
        self.layers
            .get(layer_idx)
            .and_then(|c| c.as_ref())
            .map(|c| (&c.k, &c.v))
    }

    /// Update the cache for a specific layer with new K and V tensors.
    /// The new tensors should already include the concatenated history.
    pub fn set(&mut self, layer_idx: usize, k: Tensor, v: Tensor) -> Result<()> {
        if layer_idx >= self.num_layers {
            return Err(candle_core::Error::Msg(format!(
                "Layer index {layer_idx} out of range (cache has {} layers)",
                self.num_layers
            )));
        }
        self.seq_len = k.dim(2)?;
        self.layers[layer_idx] = Some(LayerCache { k, v });
        Ok(())
    }

    /// Update from a vec of (k, v) pairs produced by a forward pass.
    pub fn update_from_vec(&mut self, caches: Vec<(Tensor, Tensor)>) -> Result<()> {
        for (i, (k, v)) in caches.into_iter().enumerate() {
            self.set(i, k, v)?;
        }
        Ok(())
    }

    /// Convert to a vec of (k, v) pairs for use in forward pass.
    pub fn to_vec(&self) -> Vec<(Tensor, Tensor)> {
        self.layers
            .iter()
            .filter_map(|c| c.as_ref().map(|c| (c.k.clone(), c.v.clone())))
            .collect()
    }

    /// Current cached sequence length.
    pub fn seq_len(&self) -> usize {
        self.seq_len
    }

    /// Whether the cache has reached maximum capacity.
    pub fn is_full(&self) -> bool {
        self.seq_len >= self.max_seq_len
    }

    /// Number of layers in this cache.
    pub fn num_layers(&self) -> usize {
        self.num_layers
    }

    /// Reset the cache (clear all cached KV pairs).
    pub fn clear(&mut self) {
        for layer in &mut self.layers {
            *layer = None;
        }
        self.seq_len = 0;
    }

    /// Whether the cache is empty (no tokens cached yet).
    pub fn is_empty(&self) -> bool {
        self.seq_len == 0
    }
}
