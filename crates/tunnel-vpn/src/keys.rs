//! WireGuard key generation and management.
//!
//! This module handles WireGuard X25519 keypair generation, storage, and serialization.

use crate::error::{VpnError, VpnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// A WireGuard keypair (private + public key).
#[derive(Clone)]
pub struct WgKeyPair {
    /// The private key (kept secret).
    private_key: StaticSecret,
    /// The public key (shared with peers).
    public_key: PublicKey,
}

impl WgKeyPair {
    /// Generate a new random WireGuard keypair.
    pub fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Create a keypair from an existing private key.
    pub fn from_private_key(private_key: StaticSecret) -> Self {
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    /// Create a keypair from raw private key bytes.
    pub fn from_private_key_bytes(bytes: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(bytes);
        Self::from_private_key(private_key)
    }

    /// Get the private key.
    pub fn private_key(&self) -> &StaticSecret {
        &self.private_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the public key as bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Get the private key as bytes.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// Encode the public key as base64.
    pub fn public_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key_bytes())
    }

    /// Encode the private key as base64.
    pub fn private_key_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.private_key_bytes())
    }

    /// Load a keypair from a file (private key stored as base64).
    pub async fn load_from_file(path: &Path) -> VpnResult<Self> {
        let contents = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| VpnError::Key(format!("Failed to read key file: {}", e)))?;

        Self::from_base64_private_key(contents.trim())
    }

    /// Load a keypair from a file synchronously (private key stored as base64).
    pub fn load_from_file_sync(path: &Path) -> VpnResult<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| VpnError::Key(format!("Failed to read key file: {}", e)))?;

        Self::from_base64_private_key(contents.trim())
    }

    /// Save the private key to a file (as base64).
    pub async fn save_to_file(&self, path: &Path) -> VpnResult<()> {
        let base64_key = self.private_key_base64();
        tokio::fs::write(path, base64_key)
            .await
            .map_err(|e| VpnError::Key(format!("Failed to write key file: {}", e)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(path, perms)
                .await
                .map_err(|e| VpnError::Key(format!("Failed to set key file permissions: {}", e)))?;
        }

        Ok(())
    }

    /// Create a keypair from a base64-encoded private key.
    pub fn from_base64_private_key(base64: &str) -> VpnResult<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| VpnError::Key(format!("Invalid base64: {}", e)))?;

        if bytes.len() != 32 {
            return Err(VpnError::Key(format!(
                "Invalid key length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::from_private_key_bytes(key_bytes))
    }

    /// Parse a public key from base64.
    pub fn parse_public_key_base64(base64: &str) -> VpnResult<PublicKey> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| VpnError::Key(format!("Invalid base64: {}", e)))?;

        if bytes.len() != 32 {
            return Err(VpnError::Key(format!(
                "Invalid key length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(PublicKey::from(key_bytes))
    }

    /// Parse a public key from raw bytes.
    pub fn parse_public_key_bytes(bytes: [u8; 32]) -> PublicKey {
        PublicKey::from(bytes)
    }
}

impl fmt::Debug for WgKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only show public key in debug output for security
        f.debug_struct("WgKeyPair")
            .field("public_key", &self.public_key_base64())
            .finish()
    }
}

/// Serializable representation of a WireGuard public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WgPublicKey(#[serde(with = "base64_bytes")] pub [u8; 32]);

impl WgPublicKey {
    /// Create from a PublicKey.
    pub fn from_public_key(key: &PublicKey) -> Self {
        Self(key.to_bytes())
    }

    /// Convert to a PublicKey.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from(self.0)
    }

    /// Encode as base64.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

impl From<PublicKey> for WgPublicKey {
    fn from(key: PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<&PublicKey> for WgPublicKey {
    fn from(key: &PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

/// Serde module for base64 encoding of byte arrays.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&base64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_str = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&base64_str)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "Expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = WgKeyPair::generate();
        assert_eq!(keypair.public_key_bytes().len(), 32);
        assert_eq!(keypair.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_keypair_roundtrip() {
        let keypair = WgKeyPair::generate();
        let base64 = keypair.private_key_base64();
        let restored = WgKeyPair::from_base64_private_key(&base64).unwrap();
        assert_eq!(keypair.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = WgKeyPair::generate();
        let wg_pub = WgPublicKey::from_public_key(keypair.public_key());
        let json = serde_json::to_string(&wg_pub).unwrap();
        let restored: WgPublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(wg_pub, restored);
    }
}
