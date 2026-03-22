//! Custom "Arobi Transformer" architecture implemented with Candle.
//!
//! A decoder-only transformer with:
//! - RMSNorm (pre-norm)
//! - Grouped Query Attention (GQA) with Rotary Position Embeddings (RoPE)
//! - SwiGLU FFN
//! - 24 layers, 2048 hidden dim, 16 query heads, 4 KV heads, 32K vocab
//!
//! Designed to split cleanly into 4 pipeline stages of 6 layers each.

use candle_core::{DType, Device, IndexOp, Module, Result, Tensor, D};
use candle_nn::{embedding, linear_no_bias, Embedding, Linear, VarBuilder};
use std::sync::Arc;

use super::types::ModelConfig;

// ─── RMS Normalization ───────────────────────────────────────────────────────

pub struct RmsNorm {
    weight: Tensor,
    eps: f64,
}

impl RmsNorm {
    pub fn new(dim: usize, eps: f64, vb: VarBuilder<'_>) -> Result<Self> {
        let weight = vb.get(dim, "weight")?;
        Ok(Self { weight, eps })
    }

    pub fn forward(&self, x: &Tensor) -> Result<Tensor> {
        let dtype = x.dtype();
        let x = x.to_dtype(DType::F32)?;
        let variance = (&x * &x)?.mean_keepdim(D::Minus1)?;
        let x_normed = x.broadcast_div(&(variance + self.eps)?.sqrt()?)?;
        let out = x_normed.to_dtype(dtype)?.broadcast_mul(&self.weight)?;
        Ok(out)
    }
}

// ─── Rotary Position Embeddings ──────────────────────────────────────────────

pub struct RotaryEmbedding {
    cos_cached: Tensor,
    sin_cached: Tensor,
}

impl RotaryEmbedding {
    pub fn new(head_dim: usize, max_seq_len: usize, theta: f64, device: &Device) -> Result<Self> {
        let half_dim = head_dim / 2;
        let inv_freq: Vec<f32> = (0..half_dim)
            .map(|i| 1.0 / (theta as f32).powf(2.0 * i as f32 / head_dim as f32))
            .collect();
        let inv_freq = Tensor::from_vec(inv_freq, (1, half_dim), device)?;

        let positions: Vec<f32> = (0..max_seq_len).map(|p| p as f32).collect();
        let positions = Tensor::from_vec(positions, (max_seq_len, 1), device)?;

        let freqs = positions.matmul(&inv_freq)?;
        let cos_cached = freqs.cos()?;
        let sin_cached = freqs.sin()?;

        Ok(Self {
            cos_cached,
            sin_cached,
        })
    }

    pub fn apply(&self, q: &Tensor, k: &Tensor, offset: usize) -> Result<(Tensor, Tensor)> {
        let seq_len = q.dim(2)?;
        let cos = self.cos_cached.i(offset..offset + seq_len)?;
        let sin = self.sin_cached.i(offset..offset + seq_len)?;

        let q_rot = Self::rotate_half(q, &cos, &sin)?;
        let k_rot = Self::rotate_half(k, &cos, &sin)?;
        Ok((q_rot, k_rot))
    }

    fn rotate_half(x: &Tensor, cos: &Tensor, sin: &Tensor) -> Result<Tensor> {
        let half_dim = x.dim(D::Minus1)? / 2;
        let x1 = x.narrow(D::Minus1, 0, half_dim)?;
        let x2 = x.narrow(D::Minus1, half_dim, half_dim)?;

        let cos = cos.unsqueeze(0)?.unsqueeze(0)?;
        let sin = sin.unsqueeze(0)?.unsqueeze(0)?;

        let rotated = Tensor::cat(
            &[
                &(x1.broadcast_mul(&cos)? - x2.broadcast_mul(&sin)?)?,
                &(x2.broadcast_mul(&cos)? + x1.broadcast_mul(&sin)?)?,
            ],
            D::Minus1,
        )?;
        Ok(rotated)
    }
}

// ─── Grouped Query Attention ─────────────────────────────────────────────────

pub struct Attention {
    q_proj: Linear,
    k_proj: Linear,
    v_proj: Linear,
    o_proj: Linear,
    num_heads: usize,
    num_kv_heads: usize,
    head_dim: usize,
    kv_group_size: usize,
}

impl Attention {
    pub fn new(config: &ModelConfig, vb: VarBuilder<'_>) -> Result<Self> {
        let head_dim = config.hidden_dim / config.num_heads;
        let kv_dim = config.num_kv_heads * head_dim;
        let q_proj = linear_no_bias(config.hidden_dim, config.hidden_dim, vb.pp("q_proj"))?;
        let k_proj = linear_no_bias(config.hidden_dim, kv_dim, vb.pp("k_proj"))?;
        let v_proj = linear_no_bias(config.hidden_dim, kv_dim, vb.pp("v_proj"))?;
        let o_proj = linear_no_bias(config.hidden_dim, config.hidden_dim, vb.pp("o_proj"))?;
        Ok(Self {
            q_proj,
            k_proj,
            v_proj,
            o_proj,
            num_heads: config.num_heads,
            num_kv_heads: config.num_kv_heads,
            head_dim,
            kv_group_size: config.num_heads / config.num_kv_heads,
        })
    }

    pub fn forward(
        &self,
        x: &Tensor,
        rope: &RotaryEmbedding,
        kv_cache: Option<(&Tensor, &Tensor)>,
        offset: usize,
    ) -> Result<(Tensor, Tensor, Tensor)> {
        let (batch, seq_len, _) = x.dims3()?;

        let q = self.q_proj.forward(x)?;
        let k = self.k_proj.forward(x)?;
        let v = self.v_proj.forward(x)?;

        // Reshape Q: [batch, seq, num_heads * head_dim] -> [batch, num_heads, seq, head_dim]
        let q = q
            .reshape((batch, seq_len, self.num_heads, self.head_dim))?
            .transpose(1, 2)?;
        // Reshape K,V: [batch, seq, num_kv_heads * head_dim] -> [batch, num_kv_heads, seq, head_dim]
        let k = k
            .reshape((batch, seq_len, self.num_kv_heads, self.head_dim))?
            .transpose(1, 2)?;
        let v = v
            .reshape((batch, seq_len, self.num_kv_heads, self.head_dim))?
            .transpose(1, 2)?;

        // Apply rotary embeddings
        let (q, k) = rope.apply(&q, &k, offset)?;

        // Concatenate with KV cache if present
        let (k, v) = if let Some((k_cache, v_cache)) = kv_cache {
            let k = Tensor::cat(&[k_cache, &k], 2)?;
            let v = Tensor::cat(&[v_cache, &v], 2)?;
            (k, v)
        } else {
            (k, v)
        };

        // Expand KV heads to match query heads (GQA)
        let k = Self::repeat_kv(&k, self.kv_group_size)?;
        let v = Self::repeat_kv(&v, self.kv_group_size)?;

        // Scaled dot-product attention
        let scale = (self.head_dim as f64).sqrt();
        let attn = (q.matmul(&k.transpose(2, 3)?)? / scale)?;

        // Causal mask
        let total_len = k.dim(2)?;
        let mask = Self::causal_mask(seq_len, total_len, x.device())?;
        let attn = attn.broadcast_add(&mask)?;

        let attn = candle_nn::ops::softmax_last_dim(&attn)?;
        let out = attn.matmul(&v)?;

        // Reshape back: [batch, heads, seq, head_dim] -> [batch, seq, hidden]
        let out = out
            .transpose(1, 2)?
            .reshape((batch, seq_len, self.num_heads * self.head_dim))?;
        let out = self.o_proj.forward(&out)?;

        // Return the un-expanded KV for cache (save memory)
        let k_for_cache = k.narrow(1, 0, self.num_kv_heads)?;
        let v_for_cache = v.narrow(1, 0, self.num_kv_heads)?;

        Ok((out, k_for_cache, v_for_cache))
    }

    /// Repeat KV heads to match query head count for GQA.
    fn repeat_kv(x: &Tensor, n_rep: usize) -> Result<Tensor> {
        if n_rep == 1 {
            return Ok(x.clone());
        }
        let (batch, num_kv_heads, seq_len, head_dim) = x.dims4()?;
        let x = x
            .unsqueeze(2)?
            .expand((batch, num_kv_heads, n_rep, seq_len, head_dim))?
            .reshape((batch, num_kv_heads * n_rep, seq_len, head_dim))?;
        Ok(x)
    }

    fn causal_mask(q_len: usize, kv_len: usize, device: &Device) -> Result<Tensor> {
        let offset = kv_len - q_len;
        let mask: Vec<f32> = (0..q_len)
            .flat_map(|i| {
                (0..kv_len).map(move |j| {
                    if j <= i + offset {
                        0.0_f32
                    } else {
                        f32::NEG_INFINITY
                    }
                })
            })
            .collect();
        Tensor::from_vec(mask, (1, 1, q_len, kv_len), device)
    }
}

// ─── SwiGLU Feed-Forward Network ─────────────────────────────────────────────

pub struct FeedForward {
    gate_proj: Linear,
    up_proj: Linear,
    down_proj: Linear,
}

impl FeedForward {
    pub fn new(config: &ModelConfig, vb: VarBuilder<'_>) -> Result<Self> {
        let gate_proj = linear_no_bias(
            config.hidden_dim,
            config.intermediate_dim,
            vb.pp("gate_proj"),
        )?;
        let up_proj = linear_no_bias(config.hidden_dim, config.intermediate_dim, vb.pp("up_proj"))?;
        let down_proj = linear_no_bias(
            config.intermediate_dim,
            config.hidden_dim,
            vb.pp("down_proj"),
        )?;
        Ok(Self {
            gate_proj,
            up_proj,
            down_proj,
        })
    }

    pub fn forward(&self, x: &Tensor) -> Result<Tensor> {
        let gate = self.gate_proj.forward(x)?;
        let gate = candle_nn::Activation::Silu.forward(&gate)?;
        let up = self.up_proj.forward(x)?;
        let out = (gate * up)?;
        self.down_proj.forward(&out)
    }
}

// ─── Transformer Block ──────────────────────────────────────────────────────

pub struct TransformerBlock {
    attention: Attention,
    ffn: FeedForward,
    input_norm: RmsNorm,
    post_attn_norm: RmsNorm,
}

impl TransformerBlock {
    pub fn new(config: &ModelConfig, vb: VarBuilder<'_>) -> Result<Self> {
        let attention = Attention::new(config, vb.pp("self_attn"))?;
        let ffn = FeedForward::new(config, vb.pp("mlp"))?;
        let input_norm = RmsNorm::new(
            config.hidden_dim,
            config.rms_norm_eps,
            vb.pp("input_layernorm"),
        )?;
        let post_attn_norm = RmsNorm::new(
            config.hidden_dim,
            config.rms_norm_eps,
            vb.pp("post_attention_layernorm"),
        )?;
        Ok(Self {
            attention,
            ffn,
            input_norm,
            post_attn_norm,
        })
    }

    pub fn forward(
        &self,
        x: &Tensor,
        rope: &RotaryEmbedding,
        kv_cache: Option<(&Tensor, &Tensor)>,
        offset: usize,
    ) -> Result<(Tensor, Tensor, Tensor)> {
        // Pre-norm + attention + residual
        let residual = x;
        let x = self.input_norm.forward(x)?;
        let (attn_out, k_cache, v_cache) = self.attention.forward(&x, rope, kv_cache, offset)?;
        let x = (residual + attn_out)?;

        // Pre-norm + FFN + residual
        let residual = &x;
        let x = self.post_attn_norm.forward(&x)?;
        let x = self.ffn.forward(&x)?;
        let x = (residual + x)?;

        Ok((x, k_cache, v_cache))
    }
}

// ─── Full Arobi Transformer ─────────────────────────────────────────────────

/// The complete Arobi Transformer model.
/// For pipeline parallelism, load only a subset of layers via `from_stage()`.
pub struct ArobiTransformer {
    token_embedding: Embedding,
    layers: Vec<TransformerBlock>,
    final_norm: RmsNorm,
    lm_head: Linear,
    rope: Arc<RotaryEmbedding>,
    config: ModelConfig,
}

impl ArobiTransformer {
    /// Load the full model (all layers).
    pub fn new(config: &ModelConfig, vb: VarBuilder<'_>) -> Result<Self> {
        Self::load_layers(config, vb, 0, config.num_layers)
    }

    /// Load a specific range of layers for pipeline stage execution.
    /// `layer_start` is inclusive, `layer_end` is exclusive.
    pub fn from_stage(
        config: &ModelConfig,
        vb: VarBuilder<'_>,
        layer_start: usize,
        layer_end: usize,
    ) -> Result<Self> {
        Self::load_layers(config, vb, layer_start, layer_end)
    }

    fn load_layers(
        config: &ModelConfig,
        vb: VarBuilder<'_>,
        layer_start: usize,
        layer_end: usize,
    ) -> Result<Self> {
        let device = vb.device();
        let head_dim = config.hidden_dim / config.num_heads;

        let token_embedding = embedding(
            config.vocab_size,
            config.hidden_dim,
            vb.pp("model.embed_tokens"),
        )?;

        let mut layers = Vec::with_capacity(layer_end - layer_start);
        for i in layer_start..layer_end {
            let block = TransformerBlock::new(config, vb.pp(format!("model.layers.{i}")))?;
            layers.push(block);
        }

        let final_norm = RmsNorm::new(config.hidden_dim, config.rms_norm_eps, vb.pp("model.norm"))?;

        let lm_head = linear_no_bias(config.hidden_dim, config.vocab_size, vb.pp("lm_head"))?;

        let rope = Arc::new(RotaryEmbedding::new(
            head_dim,
            config.max_seq_len,
            config.rope_theta,
            device,
        )?);

        Ok(Self {
            token_embedding,
            layers,
            final_norm,
            lm_head,
            rope,
            config: config.clone(),
        })
    }

    /// Full forward pass: tokens in, logits out.
    /// `kv_caches` should have one entry per layer, or be empty for first pass.
    pub fn forward(
        &self,
        token_ids: &Tensor,
        kv_caches: &mut Vec<(Tensor, Tensor)>,
        offset: usize,
    ) -> Result<Tensor> {
        let mut x = self.token_embedding.forward(token_ids)?;
        let use_cache = !kv_caches.is_empty();

        for (i, layer) in self.layers.iter().enumerate() {
            let cache = if use_cache {
                Some((kv_caches[i].0.as_ref(), kv_caches[i].1.as_ref()))
            } else {
                None
            };
            let (out, k, v) = layer.forward(&x, &self.rope, cache, offset)?;
            x = out;
            if use_cache {
                kv_caches[i] = (k, v);
            } else {
                kv_caches.push((k, v));
            }
        }

        let x = self.final_norm.forward(&x)?;
        let logits = self.lm_head.forward(&x)?;
        Ok(logits)
    }

    /// Forward pass for a pipeline stage: hidden state in, hidden state out.
    /// Only runs the layers loaded in this instance.
    pub fn forward_stage(
        &self,
        hidden: &Tensor,
        kv_caches: &mut Vec<(Tensor, Tensor)>,
        offset: usize,
    ) -> Result<Tensor> {
        let mut x = hidden.clone();
        let use_cache = !kv_caches.is_empty();

        for (i, layer) in self.layers.iter().enumerate() {
            let cache = if use_cache {
                Some((kv_caches[i].0.as_ref(), kv_caches[i].1.as_ref()))
            } else {
                None
            };
            let (out, k, v) = layer.forward(&x, &self.rope, cache, offset)?;
            x = out;
            if use_cache {
                kv_caches[i] = (k, v);
            } else {
                kv_caches.push((k, v));
            }
        }

        Ok(x)
    }

    /// Apply final norm + LM head to get logits from the last stage's hidden state.
    pub fn head(&self, hidden: &Tensor) -> Result<Tensor> {
        let x = self.final_norm.forward(hidden)?;
        self.lm_head.forward(&x)
    }

    pub fn config(&self) -> &ModelConfig {
        &self.config
    }

    pub fn num_layers(&self) -> usize {
        self.layers.len()
    }
}
