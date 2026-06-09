//! QUIC transport configuration shared by endpoint setup and per-connection
//! transport upgrades.
//!
//! The server applies [`TransportTuning`] to its endpoint and dictates the
//! resolved values to clients in the handshake response. Clients connect with
//! the default baseline and, on mismatch, reconnect with a per-connection
//! transport config built here.

use crate::vpn_core::file_config::{CongestionController, TransportTuning};
use anyhow::{Context, Result};
use iroh::endpoint::{ControllerFactory, QuicTransportConfig};
use log::info;
use noq_proto::congestion::{Bbr3Config, CubicConfig, NewRenoConfig};
use std::sync::Arc;
use std::time::Duration;

/// QUIC keep-alive interval for tunnel connections.
///
/// Active connections send pings at this interval to prevent idle timeout.
/// This value matches iroh's relay ping interval (15s), which is designed to be
/// well under half common QUIC idle timeout defaults (30s is typical in many
/// implementations and protocol discussions). This codebase uses a more generous
/// [`QUIC_IDLE_TIMEOUT`] of 300s for long-running tunnels, but 15s keep-alive
/// remains appropriate for NAT traversal and prompt dead-connection detection.
///
/// For long-running tunnels, 15s is a good balance between:
/// - Keeping NAT mappings alive (most NAT timeouts are 30-120s)
/// - Not wasting bandwidth with excessive pings
/// - Detecting dead connections reasonably quickly
///
/// Reference: iroh uses 1s for endpoint default, 15s for relay pings.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout for tunnel connections.
///
/// Connections without activity (no data or keep-alive pings) for this duration
/// are considered dead and closed. With QUIC_KEEP_ALIVE_INTERVAL enabled,
/// this timeout only triggers for truly unresponsive connections.
///
/// 5 minutes is generous for tunnels where the underlying TCP/UDP connection
/// may have long idle periods between bursts of activity.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
///
/// quinn defaults to the protocol minimum of 1200, which keeps early packets
/// small and slows the throughput ramp-up of every new connection. 1300 is
/// safe on virtually all internet paths (well below 1492 PPPoE / 1500
/// Ethernet minus IP+UDP overhead) and shortens the ramp-up. MTU discovery
/// stays enabled with its default upper bound (1452); we do not raise
/// `min_mtu`, so black-hole detection can still drop back to 1200.
pub const QUIC_INITIAL_MTU: u16 = 1300;

/// Lower bound for the QUIC datagram send/receive buffers.
///
/// The data plane carries IP packets as unreliable datagrams. Unlike streams,
/// datagrams are not flow-controlled by a window; these buffers are the only
/// backpressure point (replacing the old bounded mpsc + stream window). At
/// ~1.4 KB per datagram, 4 MiB holds ~2900 queued datagrams — a few ms of
/// buffering at multi-Gbps, large enough that bursty TUN reads don't stall on
/// `send_datagram_wait`, small enough to bound memory and surface backpressure.
const DATAGRAM_BUFFER_MIN: usize = 4 * 1024 * 1024;

/// Upper bound for the QUIC datagram send/receive buffers, so a large
/// configured window does not translate into an unbounded datagram queue.
const DATAGRAM_BUFFER_MAX: usize = 8 * 1024 * 1024;

/// Create a congestion controller factory based on the selected algorithm.
fn create_congestion_controller_factory(
    controller: CongestionController,
) -> Arc<dyn ControllerFactory + Send + Sync> {
    match controller {
        CongestionController::Cubic => Arc::new(CubicConfig::default()),
        CongestionController::Bbr => {
            // noq-proto 1.0 removed the original BBR implementation; Bbr3 is
            // its replacement but is marked experimental upstream.
            info!("BBR congestion control is backed by the experimental Bbr3 implementation");
            Arc::new(Bbr3Config::default())
        }
        CongestionController::NewReno => Arc::new(NewRenoConfig::default()),
    }
}

/// Build a QUIC transport config with keep-alive, idle timeout, and tuning.
///
/// Shared by endpoint creation and per-connection transport upgrades so both
/// paths apply identical settings.
pub fn build_quic_transport_config(tuning: &TransportTuning) -> Result<QuicTransportConfig> {
    // Configure transport with keep-alive and idle timeout.
    // See QUIC_KEEP_ALIVE_INTERVAL and QUIC_IDLE_TIMEOUT constants for rationale.
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);

    // Set congestion controller
    let factory = create_congestion_controller_factory(tuning.congestion_controller);
    transport_config = transport_config.congestion_controller_factory(factory);
    info!(
        "Using {:?} congestion controller",
        tuning.congestion_controller
    );

    // Set receive window (flow control) for connection + streams, and send
    // window (defaults to receive window if not specified)
    let (receive_window, send_window) = tuning.effective_windows();
    transport_config = transport_config.receive_window(receive_window.into());
    transport_config = transport_config.stream_receive_window(receive_window.into());
    transport_config = transport_config.send_window(send_window.into());

    let recv_source = if tuning.receive_window.is_none() {
        "default"
    } else {
        "config"
    };
    let send_source = if tuning.send_window.is_none() {
        if tuning.receive_window.is_none() {
            "default"
        } else {
            "derived"
        }
    } else {
        "config"
    };
    info!(
        "Transport windows: stream/receive={}KB ({}), send={}KB ({})",
        receive_window / 1024,
        recv_source,
        send_window / 1024,
        send_source
    );

    // Start with a larger initial path MTU so early packets are full-size and
    // the throughput ramp-up is shorter (see QUIC_INITIAL_MTU). MTU discovery
    // and min_mtu keep their defaults.
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    info!(
        "Transport MTU: initial={} (discovery enabled)",
        QUIC_INITIAL_MTU
    );

    // Enable unreliable QUIC datagrams (required for the data plane and for
    // `Connection::max_datagram_size()` to return `Some`). Size the buffers off
    // the configured receive window so config stays coherent, clamped to a sane
    // range (see DATAGRAM_BUFFER_MIN/MAX).
    let datagram_buffer = (receive_window as usize)
        .clamp(DATAGRAM_BUFFER_MIN, DATAGRAM_BUFFER_MAX);
    transport_config = transport_config.datagram_receive_buffer_size(Some(datagram_buffer));
    transport_config = transport_config.datagram_send_buffer_size(datagram_buffer);
    info!(
        "Transport datagrams enabled: send/receive buffer={}KB",
        datagram_buffer / 1024
    );

    Ok(transport_config.build())
}
