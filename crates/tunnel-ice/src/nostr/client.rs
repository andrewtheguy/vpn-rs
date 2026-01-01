//! Nostr mode client implementations.
//!
//! This module provides the client-side logic for nostr tunnels:
//! - TCP client with local listener
//! - UDP client with local socket

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

/// Configuration for the nostr client.
pub struct NostrClientConfig {
    /// Local listen address (e.g., "127.0.0.1:2222").
    pub listen: String,
    /// Source URL to request from server (e.g., "tcp://host:port" or "udp://host:port").
    pub source: String,
    /// STUN servers for ICE candidate gathering.
    pub stun_servers: Vec<String>,
    /// Nostr secret key (nsec) for signing messages. **Sensitive field - redacted in Debug output.**
    pub nsec: String,
    /// Nostr public key (npub) of the peer to communicate with.
    pub peer_npub: String,
    /// Nostr relay URLs for signaling.
    pub relays: Vec<String>,
    /// Interval in seconds between republishing signaling messages.
    pub republish_interval_secs: u64,
    /// Maximum wait time in seconds for signaling responses.
    pub max_wait_secs: u64,
}

impl std::fmt::Debug for NostrClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrClientConfig")
            .field("listen", &self.listen)
            .field("source", &self.source)
            .field("stun_servers", &self.stun_servers)
            .field("nsec", &"[REDACTED]")
            .field("peer_npub", &self.peer_npub)
            .field("relays", &self.relays)
            .field("republish_interval_secs", &self.republish_interval_secs)
            .field("max_wait_secs", &self.max_wait_secs)
            .finish()
    }
}

use crate::signaling::{
    ManualAnswer, ManualOffer, ManualRequest, NostrSignaling, OfferWaitError, MANUAL_SIGNAL_VERSION,
};
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    current_timestamp, forward_stream_to_udp_client, forward_udp_to_stream, generate_session_id,
    handle_tcp_client_connection, open_bi_with_retry, resolve_listen_addr, QUIC_CONNECTION_TIMEOUT,
};

// ============================================================================
// Validation and Setup Helpers
// ============================================================================

/// Validates a source URL has the expected scheme and required host/port.
fn validate_source_url(source: &str, expected_scheme: &str) -> Result<url::Url> {
    let source_url = url::Url::parse(source).with_context(|| {
        format!(
            "Invalid source URL '{}'. Expected format: {}://host:port",
            source, expected_scheme
        )
    })?;

    if source_url.scheme() != expected_scheme {
        anyhow::bail!(
            "Source URL must use {}:// scheme (got '{}://')",
            expected_scheme,
            source_url.scheme()
        );
    }
    if source_url.host_str().is_none() {
        anyhow::bail!("Source URL '{}' missing host", source);
    }
    if source_url.port().is_none() {
        anyhow::bail!("Source URL '{}' missing port", source);
    }

    Ok(source_url)
}

/// Converts a relay list to Option, returning None if empty.
fn relays_to_option(relays: Vec<String>) -> Option<Vec<String>> {
    if relays.is_empty() {
        None
    } else {
        Some(relays)
    }
}

/// Creates and initializes a NostrSignaling client with subscription.
async fn init_signaling(
    nsec: &str,
    peer_npub: &str,
    relays: Option<Vec<String>>,
    source: &str,
) -> Result<NostrSignaling> {
    let signaling = NostrSignaling::new(nsec, peer_npub, relays).await?;

    log::info!("Your pubkey: {}", signaling.public_key_bech32());
    log::info!("Transfer ID: {}", signaling.transfer_id());
    log::info!("Relays: {:?}", signaling.relay_urls());
    log::info!("Requesting source: {}", source);

    signaling.subscribe().await?;

    Ok(signaling)
}

// ============================================================================
// Nostr Signaling Helpers
// ============================================================================

/// Publish request and wait for offer with periodic re-publishing.
async fn publish_request_and_wait_for_offer(
    signaling: &NostrSignaling,
    request: &ManualRequest,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<ManualOffer> {
    let start_time = std::time::Instant::now();
    let session_id = &request.session_id;

    // Exponential backoff: start at base interval, double each time, cap at 60s
    let mut current_interval = republish_interval_secs;
    const MAX_INTERVAL: u64 = 60;

    signaling.publish_request(request).await?;
    log::info!(
        "Waiting for offer (re-publishing with backoff, starting {}s, max {}s)...",
        republish_interval_secs,
        max_wait_secs
    );

    loop {
        // Wait for offer, also checking for rejections inline
        match signaling
            .try_wait_for_offer_or_rejection(session_id, current_interval)
            .await
        {
            Ok(Some(offer)) => return Ok(offer),
            Err(OfferWaitError::Rejected(reject)) => {
                anyhow::bail!("Session rejected by server: {}", reject.reason);
            }
            Err(OfferWaitError::ChannelClosed) => {
                anyhow::bail!("Nostr signaling channel closed while waiting for offer");
            }
            Ok(None) => {
                // Timeout - continue to re-publish
            }
        }

        // Check overall timeout
        if start_time.elapsed().as_secs() >= max_wait_secs {
            anyhow::bail!("Timeout waiting for offer from peer ({}s)", max_wait_secs);
        }

        // Exponential backoff
        let next_interval = (current_interval * 2).min(MAX_INTERVAL);

        // Re-publish request with backoff
        log::info!("Re-publishing request (next wait: {}s)...", next_interval);
        signaling.publish_request(request).await?;

        current_interval = next_interval;
    }
}

// ============================================================================
// Public API
// ============================================================================

pub async fn run_nostr_tcp_client(config: NostrClientConfig) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    // Validate source URL
    let _source_url = validate_source_url(&config.source, "tcp")?;

    let listen_addr: SocketAddr = resolve_listen_addr(&config.listen)
        .await
        .context("Invalid listen address format. Use format like localhost:2222, 127.0.0.1:2222 or [::]:2222")?;

    log::info!("Nostr TCP Tunnel - Client Mode");
    log::info!("===============================");

    // Create and initialize signaling
    let relay_list = relays_to_option(config.relays);
    let signaling = init_signaling(&config.nsec, &config.peer_npub, relay_list, &config.source).await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    log::info!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&config.stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Create and publish request to initiate session
    let request = ManualRequest {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates.clone(),
        session_id: session_id.clone(),
        timestamp: current_timestamp(),
        source: Some(config.source),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        config.republish_interval_secs,
        config.max_wait_secs,
    )
    .await?;

    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    // Create and publish answer (echo session_id)
    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: Some(session_id),
        quic_fingerprint: None, // Nostr mode: fingerprint is in the offer, not answer
    };

    // Publish answer once - server already has our ICE credentials from the request,
    // so we can proceed to ICE immediately after publishing (no blocking sleep)
    signaling.publish_answer(&answer).await?;
    log::info!("Published answer, starting ICE immediately");

    // Disconnect from Nostr in background after brief delay to ensure answer propagates
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        signaling.disconnect().await;
        log::debug!("Nostr signaling disconnected");
    });

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    log::info!(
        "Connecting to server via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to server")?;
    log::info!("Connected to server over QUIC.");

    let conn = Arc::new(conn);
    let tunnel_established = Arc::new(AtomicBool::new(false));

    let listener = TcpListener::bind(listen_addr)
        .await
        .context("Failed to bind TCP listener")?;
    log::info!(
        "Listening on TCP {} - configure your client to connect here",
        listen_addr
    );

    let mut connection_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (tcp_stream, peer_addr) = match accept_result {
                    Ok(result) => result,
                    Err(e) => {
                        log::warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                log::info!("New local connection from {}", peer_addr);
                let conn_clone = conn.clone();
                let established = tunnel_established.clone();

                connection_tasks.spawn(async move {
                    match handle_tcp_client_connection(conn_clone, tcp_stream, peer_addr, established)
                        .await
                    {
                        Ok(()) => {}
                        Err(e) => {
                            // Connection closed errors are expected when tunnel shuts down
                            let err_str = e.to_string();
                            if !err_str.contains("closed") && !err_str.contains("reset") {
                                log::warn!("TCP tunnel error for {}: {}", peer_addr, e);
                            }
                        }
                    }
                });
            }
            error = conn.closed() => {
                log::info!("QUIC connection closed: {}", error);
                break;
            }
            result = ice_disconnect_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *ice_disconnect_rx.borrow() {
                            log::warn!("ICE disconnected; shutting down client.");
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; shutting down client.");
                        break;
                    }
                }
            }
        }

        // Clean up completed tasks and log any panics
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(e) = result {
                log::error!("Connection task panicked: {}", e);
            }
        }
    }

    // Abort remaining connection tasks
    let remaining = connection_tasks.len();
    if remaining > 0 {
        log::debug!("Aborting {} remaining connection tasks", remaining);
    }
    connection_tasks.shutdown().await;

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    log::info!("TCP client stopped.");
    Ok(())
}

pub async fn run_nostr_udp_client(config: NostrClientConfig) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    // Validate source URL
    let _source_url = validate_source_url(&config.source, "udp")?;

    let listen_addr: SocketAddr = resolve_listen_addr(&config.listen)
        .await
        .context("Invalid listen address format. Use format like localhost:51820, 127.0.0.1:51820 or [::]:51820")?;

    log::info!("Nostr UDP Tunnel - Client Mode");
    log::info!("===============================");

    // Create and initialize signaling
    let relay_list = relays_to_option(config.relays);
    let signaling = init_signaling(&config.nsec, &config.peer_npub, relay_list, &config.source).await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    log::info!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&config.stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();

    // Create and publish request to initiate session
    let request = ManualRequest {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates.clone(),
        session_id: session_id.clone(),
        timestamp: current_timestamp(),
        source: Some(config.source),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        config.republish_interval_secs,
        config.max_wait_secs,
    )
    .await?;

    if offer.version != MANUAL_SIGNAL_VERSION {
        anyhow::bail!(
            "Manual signaling version mismatch (expected {}, got {})",
            MANUAL_SIGNAL_VERSION,
            offer.version
        );
    }

    // Create and publish answer (echo session_id)
    let answer = ManualAnswer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        session_id: Some(session_id),
        quic_fingerprint: None, // Nostr mode: fingerprint is in the offer, not answer
    };

    // Publish answer once - server already has our ICE credentials from the request,
    // so we can proceed to ICE immediately after publishing (no blocking sleep)
    signaling.publish_answer(&answer).await?;
    log::info!("Published answer, starting ICE immediately");

    // Disconnect from Nostr in background after brief delay to ensure answer propagates
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        signaling.disconnect().await;
        log::debug!("Nostr signaling disconnected");
    });

    let remote_creds = str0m::IceCreds {
        ufrag: offer.ice_ufrag,
        pass: offer.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlled, remote_creds, offer.candidates)
        .await?;

    // Spawn the ICE keeper to handle STUN packets in the background
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_client_endpoint(ice_conn.socket, &offer.quic_fingerprint)?;
    log::info!(
        "Connecting to server via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to server")?;
    log::info!("Connected to server over QUIC.");

    let (send_stream, recv_stream) = open_bi_with_retry(&conn).await?;

    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );
    log::info!(
        "Listening on UDP {} - configure your client to connect here",
        listen_addr
    );

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let udp_clone = udp_socket.clone();
    let client_clone = client_addr.clone();

    // Use select! for UDP: forward_udp_to_stream has no exit mechanism when peer closes,
    // so we need select! to ensure prompt shutdown. UDP is inherently unreliable, so
    // losing buffered data on shutdown is acceptable.
    tokio::select! {
        result = forward_udp_to_stream(udp_clone, send_stream, client_clone) => {
            if let Err(e) = result {
                log::warn!("UDP to stream error: {}", e);
            }
        }
        result = forward_stream_to_udp_client(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
        result = ice_disconnect_rx.changed() => {
            match result {
                Ok(()) => {
                    if *ice_disconnect_rx.borrow() {
                        log::warn!("ICE disconnected; shutting down client.");
                    }
                }
                Err(_) => {
                    log::warn!("ICE disconnect watcher closed; shutting down client.");
                }
            }
        }
    }

    conn.close(0u32.into(), b"done");
    log::info!("Connection closed.");

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("ICE keeper task failed: {}", e),
    }

    Ok(())
}
