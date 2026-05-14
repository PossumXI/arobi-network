use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// An Arobi Network wallet backed by an Ed25519 key pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Public AROBI address (prefix "ARLPh" + 37 hex chars of sha256(sha256(pubkey)))
    pub address: String,
    /// Hex-encoded Ed25519 signing key (32 bytes) — KEEP PRIVATE
    signing_key_hex: String,
    /// Hex-encoded Ed25519 verifying (public) key (32 bytes)
    pub verifying_key_hex: String,
}

impl Wallet {
    /// Generate a brand-new wallet using OS entropy.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let address = derive_address(verifying_key.as_bytes());
        Self {
            address,
            signing_key_hex: hex::encode(signing_key.to_bytes()),
            verifying_key_hex: hex::encode(verifying_key.to_bytes()),
        }
    }

    /// Load wallet from a JSON keystore file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path).context("Failed to read wallet file")?;
        let wallet = serde_json::from_str(&data).context("Failed to parse wallet file")?;
        let _ = harden_wallet_file_permissions(path);
        Ok(wallet)
    }

    /// Save wallet to a JSON keystore file.
    /// On Unix the file is chmod 600 so only the owner can read it.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data).context("Failed to write wallet file")?;
        harden_wallet_file_permissions(path)?;
        Ok(())
    }

    /// Sign arbitrary bytes. Returns a hex-encoded 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Result<String> {
        let bytes = hex::decode(&self.signing_key_hex)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
        let signing_key = SigningKey::from_bytes(&arr);
        let sig: Signature = signing_key.sign(message);
        Ok(hex::encode(sig.to_bytes()))
    }
}

fn harden_wallet_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(windows)]
    {
        let path_arg = path.display().to_string();
        let status = std::process::Command::new("icacls")
            .args([
                &path_arg,
                "/inheritance:r",
                "/grant:r",
                "*S-1-3-4:(F)",
                "*S-1-5-18:(F)",
                "*S-1-5-32-544:(F)",
            ])
            .status()
            .context("Failed to harden wallet file permissions")?;
        if !status.success() {
            anyhow::bail!("Failed to harden wallet file permissions");
        }
    }

    Ok(())
}

/// Derive an AROBI address from a raw Ed25519 public key (32 bytes).
/// Format: "ARLPh" + first 37 hex chars of sha256(sha256(pubkey)) = 42 total.
pub fn derive_address(pubkey: &[u8]) -> String {
    let h1 = Sha256::digest(pubkey);
    let h2 = Sha256::digest(h1);
    let hex_str = hex::encode(h2);
    format!("ARLPh{}", &hex_str[..37])
}

/// Build the canonical signing message for a transaction.
/// All fields are concatenated and SHA-256 hashed.
pub fn tx_sign_msg(
    from: &str,
    to: &str,
    amount: u64,
    fee: u64,
    nonce: u64,
    timestamp: u64,
    data: Option<&str>,
) -> Vec<u8> {
    let data_hash = data
        .map(|payload| hex::encode(Sha256::digest(payload.as_bytes())))
        .unwrap_or_default();
    let s = format!("{from}{to}{amount}{fee}{nonce}{timestamp}{data_hash}");
    Sha256::digest(s.as_bytes()).to_vec()
}

/// Verify an Ed25519 signature against an arbitrary signing message.
pub fn verify_signature(pubkey_hex: &str, sig_hex: &str, message: &[u8]) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(arr) = key_bytes.try_into() as Result<[u8; 32], _> else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_arr) = sig_bytes.try_into() as Result<[u8; 64], _> else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).is_ok()
}

/// Verify an Ed25519 signature against the transaction signing message.
pub fn verify_tx_sig(pubkey_hex: &str, sig_hex: &str, message: &[u8]) -> bool {
    verify_signature(pubkey_hex, sig_hex, message)
}
