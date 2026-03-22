//! Tensor I/O — serialize and deserialize hidden state tensors for P2P transfer.
//!
//! Hidden states are compressed with zstd before sending over the network,
//! and decompressed on receipt. This reduces bandwidth for pipeline parallelism.

use candle_core::{DType, Device, Result, Tensor};
use safetensors::tensor::View;

/// Serialized tensor payload with shape metadata.
pub struct SerializedTensor {
    /// zstd-compressed raw tensor bytes
    pub data: Vec<u8>,
    /// Tensor shape dimensions
    pub shape: Vec<usize>,
    /// Data type of the tensor
    pub dtype: TensorDType,
    /// Uncompressed size in bytes (for allocation hint)
    pub uncompressed_size: usize,
}

/// Supported tensor data types for serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TensorDType {
    F32,
    F16,
    BF16,
}

impl TensorDType {
    pub fn bytes_per_element(&self) -> usize {
        match self {
            TensorDType::F32 => 4,
            TensorDType::F16 | TensorDType::BF16 => 2,
        }
    }

    pub fn to_candle_dtype(&self) -> DType {
        match self {
            TensorDType::F32 => DType::F32,
            TensorDType::F16 => DType::F16,
            TensorDType::BF16 => DType::BF16,
        }
    }

    pub fn from_candle_dtype(dtype: DType) -> std::result::Result<Self, String> {
        match dtype {
            DType::F32 => Ok(TensorDType::F32),
            DType::F16 => Ok(TensorDType::F16),
            DType::BF16 => Ok(TensorDType::BF16),
            other => Err(format!("Unsupported dtype for serialization: {:?}", other)),
        }
    }
}

/// Serialize a Candle tensor to a compressed byte payload.
pub fn serialize_tensor(tensor: &Tensor) -> Result<SerializedTensor> {
    let shape = tensor.dims().to_vec();
    let dtype = TensorDType::from_candle_dtype(tensor.dtype()).map_err(candle_core::Error::Msg)?;

    // Flatten to contiguous bytes on CPU
    let tensor_cpu = tensor.to_device(&Device::Cpu)?;
    let raw_bytes = tensor_cpu.data();
    let raw_data = raw_bytes.as_ref();
    let uncompressed_size = raw_data.len();

    // Compress with zstd (level 3 = good balance of speed vs ratio)
    let compressed = zstd::encode_all(raw_data, 3)
        .map_err(|e| candle_core::Error::Msg(format!("zstd compress failed: {e}")))?;

    Ok(SerializedTensor {
        data: compressed,
        shape,
        dtype,
        uncompressed_size,
    })
}

/// Deserialize a compressed byte payload back to a Candle tensor.
pub fn deserialize_tensor(payload: &SerializedTensor, device: &Device) -> Result<Tensor> {
    // Decompress
    let raw_data = zstd::decode_all(payload.data.as_slice())
        .map_err(|e| candle_core::Error::Msg(format!("zstd decompress failed: {e}")))?;

    if raw_data.len() != payload.uncompressed_size {
        return Err(candle_core::Error::Msg(format!(
            "Decompressed size mismatch: expected {}, got {}",
            payload.uncompressed_size,
            raw_data.len()
        )));
    }

    let candle_dtype = payload.dtype.to_candle_dtype();

    // Create tensor from raw bytes
    let tensor = match candle_dtype {
        DType::F32 => {
            let floats: Vec<f32> = raw_data
                .chunks_exact(4)
                .map(|b| f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .collect();
            Tensor::from_vec(floats, payload.shape.as_slice(), device)?
        }
        DType::F16 => {
            let halfs: Vec<half::f16> = raw_data
                .chunks_exact(2)
                .map(|b| half::f16::from_le_bytes([b[0], b[1]]))
                .collect();
            Tensor::from_vec(halfs, payload.shape.as_slice(), device)?
        }
        DType::BF16 => {
            let bhalfs: Vec<half::bf16> = raw_data
                .chunks_exact(2)
                .map(|b| half::bf16::from_le_bytes([b[0], b[1]]))
                .collect();
            Tensor::from_vec(bhalfs, payload.shape.as_slice(), device)?
        }
        _ => {
            return Err(candle_core::Error::Msg(
                "Unsupported dtype for deserialization".to_string(),
            ));
        }
    };

    Ok(tensor)
}

/// Calculate the compression ratio achieved.
pub fn compression_ratio(serialized: &SerializedTensor) -> f64 {
    if serialized.data.is_empty() {
        return 0.0;
    }
    serialized.uncompressed_size as f64 / serialized.data.len() as f64
}
