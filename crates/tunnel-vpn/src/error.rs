//! Error types for the VPN module.

use std::num::NonZeroU32;
use thiserror::Error;

/// VPN-specific errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VpnError {
    /// TUN device creation failed.
    #[error("TUN device error: {0}")]
    TunDevice(String),

    /// Tunnel/protocol error.
    #[error("Tunnel error: {0}")]
    Tunnel(String),

    /// Key generation or parsing error.
    #[error("Key error: {0}")]
    Key(String),

    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Signaling/iroh error (transient, e.g., connection failed).
    #[error("Signaling error: {0}")]
    Signaling(String),

    /// Authentication failed (permanent, e.g., invalid token, server rejected).
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

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

    /// NAT64 translation error.
    #[error("NAT64 error: {0}")]
    Nat64(String),

    /// NAT64 port pool exhausted.
    #[error("NAT64 port pool exhausted")]
    Nat64PortExhausted,

    /// NAT64 unsupported protocol.
    #[error("NAT64 unsupported protocol: {0}")]
    Nat64UnsupportedProtocol(u8),
}

impl VpnError {
    /// Returns true if this error is potentially recoverable via reconnection.
    ///
    /// **Recoverable (transient):**
    /// - `ConnectionLost` - VPN session ended (server restart, network blip)
    /// - `Network` - I/O errors (connection reset, timeout)
    /// - `Signaling` - iroh connection issues (peer unreachable, relay failure)
    ///
    /// **Non-recoverable (permanent):**
    /// - `AuthenticationFailed` - invalid token, server rejected credentials
    /// - `Config` - invalid configuration (won't change without user action)
    /// - `TunDevice` - permission denied, device creation failed
    /// - `Tunnel` - protocol errors
    /// - `Key` - invalid key format
    /// - `IpAssignment` - IP pool exhausted (unlikely to recover quickly)
    /// - `PeerNotFound` - unknown peer
    /// - `MaxReconnectAttemptsExceeded` - retry limit hit
    /// - `Nat64` - NAT64 translation error (malformed packet)
    /// - `Nat64PortExhausted` - NAT64 port pool exhausted
    /// - `Nat64UnsupportedProtocol` - unsupported protocol for NAT64 translation
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VpnError::ConnectionLost(_) | VpnError::Network(_) | VpnError::Signaling(_)
        )
    }
}

/// Result type alias for VPN operations.
pub type VpnResult<T> = Result<T, VpnError>;
