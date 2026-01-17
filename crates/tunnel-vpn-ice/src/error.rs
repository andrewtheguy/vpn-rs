//! Error types for VPN ICE mode.

use std::io;
use thiserror::Error;

/// Error type for VPN ICE operations.
#[derive(Debug, Error)]
pub enum VpnIceError {
    /// I/O error (TUN device, network, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// ICE/STUN connectivity error.
    #[error("ICE connectivity error: {0}")]
    Ice(String),

    /// QUIC transport error.
    #[error("QUIC error: {0}")]
    Quic(String),

    /// Nostr signaling error.
    #[error("Nostr signaling error: {0}")]
    Signaling(String),

    /// VPN handshake error.
    #[error("VPN handshake error: {0}")]
    Handshake(String),

    /// TUN device error.
    #[error("TUN device error: {0}")]
    Tun(String),

    /// Connection rejected by peer.
    #[error("Connection rejected: {0}")]
    Rejected(String),

    /// Authentication error.
    #[error("Authentication error: {0}")]
    Auth(String),

    /// Timeout error.
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Lock acquisition error (single instance).
    #[error("Lock error: {0}")]
    Lock(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for VPN ICE operations.
pub type VpnIceResult<T> = Result<T, VpnIceError>;

impl From<anyhow::Error> for VpnIceError {
    fn from(err: anyhow::Error) -> Self {
        VpnIceError::Internal(err.to_string())
    }
}

impl From<tunnel_vpn::error::VpnError> for VpnIceError {
    fn from(err: tunnel_vpn::error::VpnError) -> Self {
        VpnIceError::Internal(err.to_string())
    }
}
