//! Nostr-based signaling for custom mode ICE/QUIC connections.
//!
//! Uses Nostr events (kind 24242) to exchange ICE offers/answers between peers,
//! eliminating the need for manual copy-paste signaling.

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};

use super::signaling::{ManualAnswer, ManualOffer, ManualRequest};

/// Custom event kind for tunnel-rs signaling (ephemeral range)
fn tunnel_signaling_kind() -> Kind {
    Kind::from_u16(24242)
}

const SIGNALING_TYPE_REQUEST: &str = "tunnel-request";
const SIGNALING_TYPE_OFFER: &str = "tunnel-offer";
const SIGNALING_TYPE_ANSWER: &str = "tunnel-answer";

/// Default timeout for waiting for signaling messages (seconds)
const DEFAULT_SIGNALING_TIMEOUT_SECS: u64 = 120;

/// Nostr signaling client for ICE exchange
pub struct NostrSignaling {
    client: Client,
    keys: Keys,
    peer_pubkey: PublicKey,
    transfer_id: String,
    relay_urls: Vec<String>,
}

impl NostrSignaling {
    /// Create a new Nostr signaling client with user-provided keys.
    ///
    /// # Arguments
    /// * `nsec` - Private key in nsec (bech32) or hex format
    /// * `peer_pubkey_str` - Peer's public key in npub (bech32) or hex format
    /// * `relays` - Optional custom relay URLs (defaults to public relays)
    pub async fn new(
        nsec: &str,
        peer_pubkey_str: &str,
        relays: Option<Vec<String>>,
    ) -> Result<Self> {
        // Parse keys (supports nsec/hex formats)
        let keys = Keys::parse(nsec)
            .context("Failed to parse private key (expected nsec or hex format)")?;

        let peer_pubkey = if peer_pubkey_str.starts_with("npub") {
            PublicKey::from_bech32(peer_pubkey_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse npub: {}", e))
        } else {
            PublicKey::from_hex(peer_pubkey_str)
                .map_err(|e| anyhow::anyhow!("Failed to parse hex pubkey: {}", e))
        }
        .context("Failed to parse peer public key (expected npub or hex format)")?;

        // Derive transfer ID from both pubkeys (deterministic)
        let transfer_id = derive_transfer_id(&keys.public_key(), &peer_pubkey);

        let relay_urls = relays.unwrap_or_else(crate::config::default_nostr_relays);

        let client = Client::new(keys.clone());

        // Add and connect to relays
        for relay_url in &relay_urls {
            if let Err(e) = client.add_relay(relay_url).await {
                eprintln!("Warning: Failed to add relay {}: {}", relay_url, e);
            }
        }

        client.connect().await;

        // Wait for relay connections
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(Self {
            client,
            keys,
            peer_pubkey,
            transfer_id,
            relay_urls,
        })
    }

    /// Get the transfer ID
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// Get our public key in npub format
    pub fn public_key_bech32(&self) -> String {
        self.keys
            .public_key()
            .to_bech32()
            .unwrap_or_else(|_| self.keys.public_key().to_hex())
    }

    /// Get the relay URLs we're connected to
    pub fn relay_urls(&self) -> &[String] {
        &self.relay_urls
    }

    /// Subscribe to incoming signaling events for our pubkey
    pub async fn subscribe(&self) -> Result<()> {
        let filter = Filter::new()
            .kind(tunnel_signaling_kind())
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::T),
                self.transfer_id.clone(),
            )
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::P),
                self.keys.public_key().to_hex(),
            );

        self.client
            .subscribe(filter, None)
            .await
            .context("Failed to subscribe to signaling events")?;

        Ok(())
    }

    /// Publish an ICE offer to the peer
    pub async fn publish_offer(&self, offer: &ManualOffer) -> Result<()> {
        let json = serde_json::to_string(offer)?;
        let content = URL_SAFE_NO_PAD.encode(json.as_bytes());

        let event = self.create_signaling_event(SIGNALING_TYPE_OFFER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish ICE offer")?;

        println!("Published ICE offer to Nostr relays");
        Ok(())
    }

    /// Publish an ICE answer to the peer
    pub async fn publish_answer(&self, answer: &ManualAnswer) -> Result<()> {
        let json = serde_json::to_string(answer)?;
        let content = URL_SAFE_NO_PAD.encode(json.as_bytes());

        let event = self.create_signaling_event(SIGNALING_TYPE_ANSWER, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish ICE answer")?;

        println!("Published ICE answer to Nostr relays");
        Ok(())
    }

    /// Publish an ICE request to the peer (receiver -> sender to initiate session)
    pub async fn publish_request(&self, request: &ManualRequest) -> Result<()> {
        let json = serde_json::to_string(request)?;
        let content = URL_SAFE_NO_PAD.encode(json.as_bytes());

        let event = self.create_signaling_event(SIGNALING_TYPE_REQUEST, &content)?;

        self.client
            .send_event(&event)
            .await
            .context("Failed to publish ICE request")?;

        println!("Published ICE request to Nostr relays");
        Ok(())
    }

    /// Wait for a fresh request from the peer (uses default timeout).
    /// Rejects requests older than `max_age_secs` seconds.
    pub async fn wait_for_fresh_request(&self, max_age_secs: u64) -> Result<ManualRequest> {
        println!(
            "Waiting for {} from peer (timeout: {}s, max age: {}s)...",
            SIGNALING_TYPE_REQUEST, DEFAULT_SIGNALING_TIMEOUT_SECS, max_age_secs
        );

        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(DEFAULT_SIGNALING_TIMEOUT_SECS);
        let mut notifications = self.client.notifications();

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(1), notifications.recv()).await {
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                    if let Some(request) =
                        self.try_parse_event::<ManualRequest>(&event, SIGNALING_TYPE_REQUEST)
                    {
                        // Check if request is fresh
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        let age = now.saturating_sub(request.timestamp);
                        if age <= max_age_secs {
                            println!("Received fresh {} from peer (age: {}s)", SIGNALING_TYPE_REQUEST, age);
                            return Ok(request);
                        } else {
                            println!(
                                "Ignoring stale request (age: {}s > max {}s)",
                                age, max_age_secs
                            );
                        }
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(recv_err)) => {
                    match recv_err {
                        RecvError::Closed => {
                            return Err(anyhow::anyhow!(
                                "Notification channel closed while waiting for request"
                            ));
                        }
                        RecvError::Lagged(skipped) => {
                            eprintln!(
                                "Warning: Notification receiver lagged, skipped {} messages",
                                skipped
                            );
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!(
            "Timeout waiting for fresh request from peer"
        ))
    }

    /// Wait for an offer from the peer with custom timeout, returns None on timeout.
    /// Use this variant for re-publish loops where timeout is expected and not an error.
    pub async fn try_wait_for_offer_timeout(&self, timeout_secs: u64) -> Option<ManualOffer> {
        self.wait_for_message_optional(SIGNALING_TYPE_OFFER, timeout_secs)
            .await
    }

    /// Wait for an answer from the peer with custom timeout, returns None on timeout.
    /// Use this variant for re-publish loops where timeout is expected and not an error.
    pub async fn try_wait_for_answer_timeout(&self, timeout_secs: u64) -> Option<ManualAnswer> {
        self.wait_for_message_optional(SIGNALING_TYPE_ANSWER, timeout_secs)
            .await
    }

    /// Wait for a specific message type with timeout, returns None on timeout or channel closed.
    ///
    /// If the notification receiver lags behind, this will drain buffered messages
    /// and check each one for the expected type before continuing to wait.
    async fn wait_for_message_optional<T: for<'de> serde::Deserialize<'de>>(
        &self,
        expected_type: &str,
        timeout_secs: u64,
    ) -> Option<T> {
        self.wait_for_message_inner(expected_type, timeout_secs)
            .await
    }

    /// Internal helper that waits for a message, returning None on timeout or channel closed.
    async fn wait_for_message_inner<T: for<'de> serde::Deserialize<'de>>(
        &self,
        expected_type: &str,
        timeout_secs: u64,
    ) -> Option<T> {
        let mut notifications = self.client.notifications();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(1), notifications.recv()).await {
                Ok(Ok(RelayPoolNotification::Event { event, .. })) => {
                    if let Some(payload) = self.try_parse_event::<T>(&event, expected_type) {
                        println!("Received {} from peer", expected_type);
                        return Some(payload);
                    }
                }
                Ok(Ok(_)) => continue,
                Ok(Err(recv_err)) => {
                    match recv_err {
                        RecvError::Closed => {
                            eprintln!(
                                "Error: Notification channel closed while waiting for {}",
                                expected_type
                            );
                            return None;
                        }
                        RecvError::Lagged(skipped) => {
                            eprintln!(
                                "Warning: Notification receiver lagged, skipped {} messages; draining buffer...",
                                skipped
                            );
                            // Drain buffered messages and check each one
                            if let Some(payload) =
                                self.drain_and_find::<T>(&mut notifications, expected_type)
                            {
                                return Some(payload);
                            }
                        }
                    }
                }
                Err(_) => continue, // tokio::time::timeout elapsed, try again
            }
        }

        None
    }

    /// Drain buffered messages from the notification channel and return the first matching payload.
    fn drain_and_find<T: for<'de> serde::Deserialize<'de>>(
        &self,
        notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
        expected_type: &str,
    ) -> Option<T> {
        loop {
            match notifications.try_recv() {
                Ok(RelayPoolNotification::Event { event, .. }) => {
                    if let Some(payload) = self.try_parse_event::<T>(&event, expected_type) {
                        println!(
                            "Received {} from peer (found in drained messages)",
                            expected_type
                        );
                        return Some(payload);
                    }
                }
                Ok(_) => continue,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Closed) => {
                    eprintln!(
                        "Error: Notification channel closed while draining for {}",
                        expected_type
                    );
                    return None;
                }
                Err(TryRecvError::Lagged(more_skipped)) => {
                    eprintln!(
                        "Warning: Additional {} messages skipped while draining",
                        more_skipped
                    );
                    continue;
                }
            }
        }
    }

    /// Try to parse an event as the expected message type.
    /// Returns Some(payload) if the event matches our criteria and can be parsed.
    fn try_parse_event<T: for<'de> serde::Deserialize<'de>>(
        &self,
        event: &Event,
        expected_type: &str,
    ) -> Option<T> {
        // Verify this is from our peer
        if event.pubkey != self.peer_pubkey {
            return None;
        }

        // Check transfer ID
        let is_our_transfer = event.tags.iter().any(|t| {
            t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T))
                && t.content() == Some(&self.transfer_id)
        });
        if !is_our_transfer {
            return None;
        }

        // Check event type
        let event_type = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::custom("type"))
            .and_then(|t| t.content());

        if event_type != Some(expected_type) {
            return None;
        }

        // Decode content
        let decoded = URL_SAFE_NO_PAD.decode(event.content.as_bytes()).ok()?;
        serde_json::from_slice(&decoded).ok()
    }

    fn create_signaling_event(&self, event_type: &str, content: &str) -> Result<Event> {
        let tags = vec![
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T)),
                vec![self.transfer_id.clone()],
            ),
            Tag::custom(
                TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::P)),
                vec![self.peer_pubkey.to_hex()],
            ),
            Tag::custom(TagKind::custom("type"), vec![event_type.to_string()]),
        ];

        EventBuilder::new(tunnel_signaling_kind(), content)
            .tags(tags)
            .sign_with_keys(&self.keys)
            .context("Failed to sign signaling event")
    }

    /// Disconnect from all relays
    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }
}

/// Derive a deterministic transfer ID from two public keys.
/// This ensures both peers calculate the same ID without prior coordination.
fn derive_transfer_id(pk1: &PublicKey, pk2: &PublicKey) -> String {
    let mut keys = [pk1.to_hex(), pk2.to_hex()];
    keys.sort(); // Deterministic ordering

    let mut hasher = Sha256::new();
    hasher.update(keys[0].as_bytes());
    hasher.update(keys[1].as_bytes());
    let result = hasher.finalize();

    hex::encode(&result[..16]) // 16 bytes = 32 hex chars
}

/// Generate a new Nostr keypair
pub fn generate_keypair() -> Keys {
    Keys::generate()
}
