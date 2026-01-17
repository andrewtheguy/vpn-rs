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
        VpnIceError::Internal(format!("{:#}", err))
    }
}

impl From<tunnel_vpn::error::VpnError> for VpnIceError {
    fn from(err: tunnel_vpn::error::VpnError) -> Self {
        use tunnel_vpn::error::VpnError;

        match err {
            VpnError::TunDevice(message) => VpnIceError::Tun(message),
            VpnError::Tunnel(message) => VpnIceError::Internal(message),
            VpnError::Key(message) => VpnIceError::Internal(message),
            VpnError::Network(io_err) => VpnIceError::Io(io_err),
            VpnError::Config(message) => VpnIceError::Config(message),
            VpnError::Signaling(message) => VpnIceError::Signaling(message),
            VpnError::AuthenticationFailed(message) => VpnIceError::Auth(message),
            VpnError::IpAssignment(message) => VpnIceError::Internal(message),
            VpnError::PeerNotFound(message) => VpnIceError::Signaling(message),
            VpnError::ConnectionLost(message) => VpnIceError::Internal(message),
            VpnError::MaxReconnectAttemptsExceeded(value) => {
                VpnIceError::Internal(value.to_string())
            }
            VpnError::Nat64(message) => VpnIceError::Internal(message),
            VpnError::Nat64PortExhausted => {
                VpnIceError::Internal("NAT64 port pool exhausted".to_string())
            }
            VpnError::Nat64UnsupportedProtocol(proto) => {
                VpnIceError::Internal(format!("NAT64 unsupported protocol: {}", proto))
            }
            other => VpnIceError::Internal(other.to_string()),
        }
    }
}
