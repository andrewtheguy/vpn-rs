//! Manual signaling payloads and helpers.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};

pub const MANUAL_SIGNAL_VERSION: u16 = 1;

const PREFIX: &str = "TRS";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualOffer {
    pub version: u16,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub candidates: Vec<String>,
    pub quic_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualAnswer {
    pub version: u16,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub candidates: Vec<String>,
}

pub fn encode_offer(offer: &ManualOffer) -> Result<String> {
    encode_payload(offer)
}

pub fn decode_offer(payload: &str) -> Result<ManualOffer> {
    decode_payload(payload)
}

pub fn encode_answer(answer: &ManualAnswer) -> Result<String> {
    encode_payload(answer)
}

pub fn decode_answer(payload: &str) -> Result<ManualAnswer> {
    decode_payload(payload)
}

fn encode_payload<T: Serialize>(payload: &T) -> Result<String> {
    let json = serde_json::to_vec(payload).context("Failed to serialize manual payload")?;
    let checksum = crc32(&json);
    let encoded = URL_SAFE_NO_PAD.encode(&json);
    Ok(format!("{}{}:{:08x}:{}", PREFIX, MANUAL_SIGNAL_VERSION, checksum, encoded))
}

fn decode_payload<T: for<'de> Deserialize<'de>>(payload: &str) -> Result<T> {
    let trimmed = payload.trim();
    let mut parts = trimmed.splitn(3, ':');
    let header = parts
        .next()
        .ok_or_else(|| anyhow!("Invalid manual payload header"))?;
    let checksum_hex = parts
        .next()
        .ok_or_else(|| anyhow!("Invalid manual payload checksum"))?;
    let body = parts
        .next()
        .ok_or_else(|| anyhow!("Invalid manual payload body"))?;

    if !header.starts_with(PREFIX) {
        return Err(anyhow!("Manual payload missing prefix"));
    }

    let version = header
        .strip_prefix(PREFIX)
        .ok_or_else(|| anyhow!("Manual payload missing version"))?;
    if version != MANUAL_SIGNAL_VERSION.to_string() {
        return Err(anyhow!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            version
        ));
    }

    let expected_crc = u32::from_str_radix(checksum_hex, 16)
        .context("Invalid manual payload checksum")?;
    let decoded = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .context("Manual payload base64 decode failed")?;

    let actual_crc = crc32(&decoded);
    if actual_crc != expected_crc {
        return Err(anyhow!(
            "Manual payload checksum mismatch (expected {:08x}, got {:08x})",
            expected_crc,
            actual_crc
        ));
    }

    let parsed: T = serde_json::from_slice(&decoded).context("Manual payload JSON parse failed")?;
    Ok(parsed)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize()
}
