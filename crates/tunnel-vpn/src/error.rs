//! Error types for the VPN module.

use std::num::NonZeroU32;
use thiserror::Error;

/// VPN-specific errors.
#[derive(Debug, Error)]
pub enum VpnError {
    /// TUN device creation failed.
    #[error("TUN device error: {0}")]
    TunDevice(String),

    /// WireGuard tunnel error.
    #[error("WireGuard tunnel error: {0}")]
    WireGuard(String),

    /// Key generation or parsing error.
    #[error("Key error: {0}")]
    Key(String),

    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Signaling/iroh error.
    #[error("Signaling error: {0}")]
    Signaling(String),

    /// IP address assignment error.
    #[error("IP assignment error: {0}")]
    IpAssignment(String),

    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Connection lost during VPN session (recoverable via reconnect).
    #[error("Connection lost: {0}")]
    ConnectionLost(String),

    /// Maximum reconnection attempts exceeded.
    #[error("Max reconnection attempts ({0}) exceeded")]
    MaxReconnectAttemptsExceeded(NonZeroU32),
}

impl VpnError {
    /// Returns true if this error is potentially recoverable via reconnection.
    ///
    /// Recoverable errors include connection loss, network issues, and signaling
    /// failures. Non-recoverable errors include configuration problems, permission
    /// issues, and authentication failures.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VpnError::ConnectionLost(_) | VpnError::Network(_) | VpnError::Signaling(_)
        )
    }
}

/// Result type alias for VPN operations.
pub type VpnResult<T> = Result<T, VpnError>;
