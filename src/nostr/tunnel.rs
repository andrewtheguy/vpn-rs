//! Nostr mode tunnel implementations (ICE + QUIC with Nostr signaling).
//!
//! This module provides tunnel implementations using custom ICE (str0m) + QUIC (quinn)
//! with Nostr relay-based automated signaling.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::signaling::{
    ManualAnswer, ManualOffer, ManualReject, ManualRequest, NostrSignaling, OfferWaitError,
    SignalingError, MANUAL_SIGNAL_VERSION,
};
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    current_timestamp, extract_addr_from_source, forward_stream_to_udp_receiver,
    forward_stream_to_udp_sender, forward_udp_to_stream, generate_session_id,
    handle_tcp_receiver_connection, handle_tcp_sender_stream, is_source_allowed,
    open_bi_with_retry, resolve_all_target_addrs, resolve_target_addr, short_session_id,
    validate_allowed_networks, MAX_REQUEST_AGE_SECS, QUIC_CONNECTION_TIMEOUT,
};

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
                anyhow::bail!("Session rejected by sender: {}", reject.reason);
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
// Nostr Sender Loop (shared session management for TCP/UDP)
// ============================================================================

/// Session handler function type for nostr mode.
type SessionHandler = fn(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    allowed_tcp: Arc<Vec<String>>,
    allowed_udp: Arc<Vec<String>>,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// Generic nostr sender loop that handles session management.
async fn run_nostr_sender_loop(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    signaling: Arc<NostrSignaling>,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
    max_sessions: usize,
    session_handler: SessionHandler,
) -> Result<()> {
    // Wrap allowed networks in Arc to avoid per-session Vec cloning
    let allowed_tcp = Arc::new(allowed_tcp);
    let allowed_udp = Arc::new(allowed_udp);

    // Session limit enforcement via semaphore (None = unlimited)
    let session_semaphore: Option<Arc<tokio::sync::Semaphore>> = if max_sessions > 0 {
        Some(Arc::new(tokio::sync::Semaphore::new(max_sessions)))
    } else {
        None
    };

    let mut session_tasks: JoinSet<Result<()>> = JoinSet::new();

    // Track recently-processed session IDs with timestamps to avoid duplicate processing.
    // Nostr relays may deliver the same request multiple times.
    // Uses TTL-based eviction: entries older than MAX_REQUEST_AGE_SECS are eligible for removal.
    let mut processed_sessions: HashMap<String, Instant> = HashMap::new();
    const MAX_PROCESSED_SESSIONS: usize = 1000; // Limit memory usage
    let session_ttl = Duration::from_secs(MAX_REQUEST_AGE_SECS * 2); // 2x request age for safety margin

    let limit_str = if max_sessions == 0 {
        "unlimited".to_string()
    } else {
        max_sessions.to_string()
    };
    log::info!(
        "Waiting for tunnel requests (max sessions: {})...",
        limit_str
    );

    loop {
        // Clean up completed tasks without blocking
        while let Some(result) = session_tasks.try_join_next() {
            if let Err(e) = result {
                log::warn!("Session task panicked: {:?}", e);
            }
        }

        // Wait for fresh request from receiver (no timeout for multi-session mode)
        let request = match signaling
            .wait_for_fresh_request_forever(MAX_REQUEST_AGE_SECS)
            .await
        {
            Ok(req) => req,
            Err(e) => {
                // Check for fatal error: notification channel closed (client disconnected)
                if e.downcast_ref::<SignalingError>()
                    .map(|se| se.is_channel_closed())
                    .unwrap_or(false)
                {
                    return Err(e.context("Nostr signaling channel closed"));
                }
                // Transient error: log and retry
                log::warn!("Error waiting for request: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        if request.version != MANUAL_SIGNAL_VERSION {
            log::warn!(
                "Ignoring request with version mismatch (expected {}, got {})",
                MANUAL_SIGNAL_VERSION,
                request.version
            );
            continue;
        }

        let session_id = request.session_id.clone();
        let now = Instant::now();

        // Skip duplicate requests (Nostr relays may deliver the same event multiple times)
        if processed_sessions.contains_key(&session_id) {
            log::debug!(
                "Ignoring duplicate request for session {}",
                short_session_id(&session_id)
            );
            continue;
        }

        // Evict expired entries when approaching capacity (TTL-based eviction)
        if processed_sessions.len() >= MAX_PROCESSED_SESSIONS {
            let before_count = processed_sessions.len();
            processed_sessions.retain(|_, timestamp| now.duration_since(*timestamp) < session_ttl);
            let evicted = before_count - processed_sessions.len();
            if evicted > 0 {
                log::debug!(
                    "Evicted {} expired session entries (TTL: {:?})",
                    evicted,
                    session_ttl
                );
            }

            // If still at capacity after TTL eviction, remove oldest 25% of entries
            if processed_sessions.len() >= MAX_PROCESSED_SESSIONS {
                let to_remove = MAX_PROCESSED_SESSIONS / 4;
                let mut entries: Vec<_> = processed_sessions
                    .iter()
                    .map(|(k, ts)| (k.clone(), *ts))
                    .collect();
                entries.sort_by_key(|(_, ts)| *ts);
                let keys_to_remove: Vec<_> = entries
                    .into_iter()
                    .take(to_remove)
                    .map(|(k, _)| k)
                    .collect();
                for session in keys_to_remove {
                    processed_sessions.remove(&session);
                }
                log::debug!(
                    "Evicted {} oldest session entries (capacity limit)",
                    to_remove
                );
            }
        }
        processed_sessions.insert(session_id.clone(), now);
        let protocol = request
            .source
            .as_ref()
            .and_then(|s| s.split("://").next())
            .unwrap_or("unknown");
        log::info!(
            "Received {} request for session {}",
            protocol.to_uppercase(),
            short_session_id(&session_id)
        );

        // Acquire session permit (if limited) - held for task lifetime
        let permit = if let Some(ref sem) = session_semaphore {
            match sem.clone().try_acquire_owned() {
                Ok(permit) => Some(permit),
                Err(_) => {
                    // At capacity - reject the request
                    let reject = ManualReject::new(
                        session_id.clone(),
                        format!(
                            "Sender at capacity ({}/{} sessions)",
                            max_sessions, max_sessions
                        ),
                    );
                    if let Err(e) = signaling.publish_reject(&reject).await {
                        log::warn!(
                            "[{}] Failed to publish reject: {}",
                            short_session_id(&session_id),
                            e
                        );
                    }
                    log::info!(
                        "[{}] Rejected: at capacity",
                        short_session_id(&session_id)
                    );
                    continue;
                }
            }
        } else {
            None
        };

        // Spawn session handler
        let signaling_clone = signaling.clone();
        let stun_servers_clone = stun_servers.clone();
        let allowed_tcp_clone = allowed_tcp.clone();
        let allowed_udp_clone = allowed_udp.clone();

        session_tasks.spawn(async move {
            let result = session_handler(
                signaling_clone,
                request,
                allowed_tcp_clone,
                allowed_udp_clone,
                stun_servers_clone,
                republish_interval_secs,
                max_wait_secs,
            )
            .await;

            // Drop permit when session ends (if we had one)
            drop(permit);

            result
        });
    }
}

// ============================================================================
// Session Handlers
// ============================================================================

fn handle_nostr_session(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    allowed_tcp: Arc<Vec<String>>,
    allowed_udp: Arc<Vec<String>>,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(handle_nostr_session_impl(
        signaling,
        request,
        allowed_tcp,
        allowed_udp,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
    ))
}

/// Handle a nostr session by routing to TCP or UDP based on source protocol.
async fn handle_nostr_session_impl(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    allowed_tcp: Arc<Vec<String>>,
    allowed_udp: Arc<Vec<String>>,
    stun_servers: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    let session_id = request.session_id.clone();
    let short_id = short_session_id(&session_id).to_string();

    // source is required - receiver must specify which source to connect to
    let requested_source = request.source.as_ref().ok_or_else(|| {
        anyhow::anyhow!("[{}] Request missing required 'source' field", short_id)
    })?;

    // Parse protocol from source (tcp:// or udp://)
    let protocol = requested_source.split("://").next().unwrap_or("");

    match protocol {
        "tcp" => {
            // Validate against TCP allowed networks
            if !is_source_allowed(requested_source, &allowed_tcp).await {
                let reject = ManualReject::new(
                    session_id.clone(),
                    format!("TCP source '{}' not in allowed networks", requested_source),
                );
                if let Err(e) = signaling.publish_reject(&reject).await {
                    log::warn!("[{}] Failed to publish reject: {}", short_id, e);
                }
                anyhow::bail!("[{}] Rejected: TCP source not allowed", short_id);
            }
            handle_nostr_tcp_session_impl(
                signaling,
                request,
                stun_servers,
                republish_interval_secs,
                max_wait_secs,
            )
            .await
        }
        "udp" => {
            // Validate against UDP allowed networks
            if !is_source_allowed(requested_source, &allowed_udp).await {
                let reject = ManualReject::new(
                    session_id.clone(),
                    format!("UDP source '{}' not in allowed networks", requested_source),
                );
                if let Err(e) = signaling.publish_reject(&reject).await {
                    log::warn!("[{}] Failed to publish reject: {}", short_id, e);
                }
                anyhow::bail!("[{}] Rejected: UDP source not allowed", short_id);
            }
            handle_nostr_udp_session_impl(
                signaling,
                request,
                stun_servers,
                republish_interval_secs,
                max_wait_secs,
            )
            .await
        }
        _ => {
            let reject = ManualReject::new(
                session_id.clone(),
                format!(
                    "Unknown protocol in source '{}'. Use tcp:// or udp://",
                    requested_source
                ),
            );
            if let Err(e) = signaling.publish_reject(&reject).await {
                log::warn!("[{}] Failed to publish reject: {}", short_id, e);
            }
            anyhow::bail!("[{}] Unknown protocol: {}", short_id, protocol)
        }
    }
}

/// Handle a single nostr TCP session from request to connection closure.
async fn handle_nostr_tcp_session_impl(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    stun_servers: Vec<String>,
    _republish_interval_secs: u64,
    _max_wait_secs: u64,
) -> Result<()> {
    let session_id = request.session_id.clone();
    let short_id = short_session_id(&session_id).to_string();
    log::info!("[{}] Starting TCP session...", short_id);

    // Source is required - already validated by handle_nostr_session_impl
    let requested_source = request
        .source
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("[{}] Missing source", short_id))?;

    // Extract host:port from source URL (strip protocol prefix)
    let target_hostport = extract_addr_from_source(requested_source)
        .ok_or_else(|| anyhow::anyhow!("[{}] Invalid source format '{}'", short_id, requested_source))?;

    log::info!("[{}] Forwarding to: {}", short_id, requested_source);
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&target_hostport)
            .await
            .with_context(|| format!("Invalid source '{}'", requested_source))?,
    );

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();
    log::info!(
        "[{}] Gathered {} ICE candidates",
        short_id,
        local_candidates.len()
    );

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: Some(session_id.clone()),
        source: None, // Source is communicated via SourceRequest in nostr mode
    };

    // Publish offer once - we already have receiver's ICE credentials from the REQUEST,
    // so we can start ICE immediately without waiting for the answer.
    // The answer is only a confirmation that receiver got the offer.
    signaling.publish_offer(&offer).await?;
    log::info!("[{}] Published offer, starting ICE immediately", short_id);

    // Use receiver's ICE credentials from the REQUEST (not from answer)
    let remote_creds = str0m::IceCreds {
        ufrag: request.ice_ufrag,
        pass: request.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, request.candidates)
        .await?;
    log::info!("[{}] ICE connection established", short_id);

    // Spawn the ICE keeper
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    log::info!(
        "[{}] QUIC connected, forwarding to {:?}",
        short_id,
        target_addrs.as_slice()
    );

    loop {
        tokio::select! {
            accept_result = conn.accept_bi() => {
                let (send_stream, recv_stream) = match accept_result {
                    Ok(streams) => streams,
                    Err(e) => {
                        log::info!("[{}] Session ended: {}", short_id, e);
                        break;
                    }
                };

                let target = Arc::clone(&target_addrs);
                let sid = short_id.to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_sender_stream(send_stream, recv_stream, target).await {
                        log::warn!("[{}] TCP connection error: {}", sid, e);
                    }
                });
            }
            result = ice_disconnect_rx.changed() => {
                match result {
                    Ok(()) => {
                        if *ice_disconnect_rx.borrow() {
                            log::warn!("[{}] ICE disconnected; ending session.", short_id);
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("[{}] ICE disconnect watcher closed; ending session.", short_id);
                        break;
                    }
                }
            }
        }
    }

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("[{}] ICE keeper task failed: {}", short_id, e),
    }

    Ok(())
}

/// Handle a single nostr UDP session from request to connection closure.
async fn handle_nostr_udp_session_impl(
    signaling: Arc<NostrSignaling>,
    request: ManualRequest,
    stun_servers: Vec<String>,
    _republish_interval_secs: u64,
    _max_wait_secs: u64,
) -> Result<()> {
    let session_id = request.session_id.clone();
    let short_id = short_session_id(&session_id).to_string();
    log::info!("[{}] Starting UDP session...", short_id);

    // Source is required - already validated by handle_nostr_session_impl
    let requested_source = request
        .source
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("[{}] Missing source", short_id))?;

    // Extract host:port from source URL (strip protocol prefix)
    let target_hostport = extract_addr_from_source(requested_source)
        .ok_or_else(|| anyhow::anyhow!("[{}] Invalid source format '{}'", short_id, requested_source))?;

    log::info!("[{}] Forwarding to: {}", short_id, requested_source);
    let target_addr = resolve_target_addr(&target_hostport)
        .await
        .with_context(|| format!("Invalid source '{}'", requested_source))?;

    // Gather ICE candidates
    let ice = IceEndpoint::gather(&stun_servers).await?;
    let local_creds = ice.local_credentials();
    let local_candidates = ice.local_candidates();
    log::debug!(
        "[{}] Gathered {} ICE candidates",
        short_id,
        local_candidates.len()
    );

    let quic_identity = quic::generate_server_identity()?;

    let offer = ManualOffer {
        version: MANUAL_SIGNAL_VERSION,
        ice_ufrag: local_creds.ufrag.clone(),
        ice_pwd: local_creds.pass.clone(),
        candidates: local_candidates,
        quic_fingerprint: quic_identity.fingerprint.clone(),
        session_id: Some(session_id.clone()),
        source: None, // Source is communicated via SourceRequest in nostr mode
    };

    // Publish offer once - we already have receiver's ICE credentials from the REQUEST,
    // so we can start ICE immediately without waiting for the answer.
    // The answer is only a confirmation that receiver got the offer.
    signaling.publish_offer(&offer).await?;
    log::info!("[{}] Published offer, starting ICE immediately", short_id);

    // Use receiver's ICE credentials from the REQUEST (not from answer)
    let remote_creds = str0m::IceCreds {
        ufrag: request.ice_ufrag,
        pass: request.ice_pwd,
    };

    let ice_conn = ice
        .connect(IceRole::Controlling, remote_creds, request.candidates)
        .await?;
    log::info!("[{}] ICE connection established", short_id);

    // Spawn the ICE keeper
    let mut ice_disconnect_rx = ice_conn.disconnect_rx.clone();
    let ice_keeper_handle = tokio::spawn(ice_conn.ice_keeper.run());

    let endpoint = quic::make_server_endpoint(ice_conn.socket, quic_identity.server_config)?;

    let connecting = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, endpoint.accept())
        .await
        .context("Timeout waiting for QUIC connection")?
        .context("No incoming QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC handshake")?
        .context("Failed to accept QUIC connection")?;
    log::info!("[{}] QUIC connected", short_id);

    let (send_stream, recv_stream) = conn
        .accept_bi()
        .await
        .context("Failed to accept stream from receiver")?;

    log::info!("[{}] Forwarding UDP traffic to {}", short_id, target_addr);

    // Bind to the same address family as the target
    let bind_addr: SocketAddr = if target_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let udp_socket = Arc::new(
        UdpSocket::bind(bind_addr)
            .await
            .context("Failed to bind UDP socket")?,
    );

    let disconnect_short_id = short_id.clone();
    let disconnect_conn = conn.clone();
    let disconnect_task = tokio::spawn(async move {
        match ice_disconnect_rx.changed().await {
            Ok(()) => {
                if *ice_disconnect_rx.borrow() {
                    log::warn!(
                        "[{}] ICE disconnected; closing QUIC connection.",
                        disconnect_short_id
                    );
                    disconnect_conn.close(0u32.into(), b"ice disconnected");
                }
            }
            Err(_) => {
                log::warn!(
                    "[{}] ICE disconnect watcher closed; closing QUIC connection.",
                    disconnect_short_id
                );
                disconnect_conn.close(0u32.into(), b"ice watcher closed");
            }
        }
    });

    let forward_result = tokio::select! {
        result = forward_stream_to_udp_sender(recv_stream, send_stream, udp_socket, target_addr) => {
            result
        }
        error = conn.closed() => {
            log::info!("[{}] QUIC connection closed: {}", short_id, error);
            Ok(())
        }
    };

    conn.close(0u32.into(), b"done");
    log::info!("[{}] UDP session closed", short_id);

    if !disconnect_task.is_finished() {
        disconnect_task.abort();
    }
    match disconnect_task.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("[{}] ICE disconnect task failed: {}", short_id, e),
    }

    // Clean up the ICE keeper task
    ice_keeper_handle.abort();
    match ice_keeper_handle.await {
        Ok(()) => {}
        Err(e) if e.is_cancelled() => {}
        Err(e) => log::warn!("[{}] ICE keeper task failed: {}", short_id, e),
    }

    forward_result
}

// ============================================================================
// Public API
// ============================================================================

/// Unified nostr sender that handles both TCP and UDP requests.
pub async fn run_nostr_sender(
    allowed_tcp: Vec<String>,
    allowed_udp: Vec<String>,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
    max_sessions: usize,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    // Validate CIDR networks upfront (fail fast on misconfiguration)
    validate_allowed_networks(&allowed_tcp, "--allowed-tcp")?;
    validate_allowed_networks(&allowed_udp, "--allowed-udp")?;

    log::info!("Nostr Tunnel - Sender Mode (Multi-Session)");
    log::info!("==========================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() {
        None
    } else {
        Some(relays)
    };
    let signaling = Arc::new(NostrSignaling::new(&nsec, &peer_npub, relay_list).await?);

    log::info!("Your pubkey: {}", signaling.public_key_bech32());
    log::info!("Transfer ID: {}", signaling.transfer_id());
    log::info!("Relays: {:?}", signaling.relay_urls());
    if !allowed_tcp.is_empty() {
        log::info!("Allowed TCP networks: {:?}", allowed_tcp);
    }
    if !allowed_udp.is_empty() {
        log::info!("Allowed UDP networks: {:?}", allowed_udp);
    }

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Run the session management loop
    run_nostr_sender_loop(
        allowed_tcp,
        allowed_udp,
        signaling,
        stun_servers,
        republish_interval_secs,
        max_wait_secs,
        max_sessions,
        handle_nostr_session,
    )
    .await
}

pub async fn run_nostr_tcp_receiver(
    listen: String,
    source: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    // Validate source URL locally before publishing request
    let source_url = url::Url::parse(&source).with_context(|| {
        format!(
            "Invalid source URL '{}'. Expected format: tcp://host:port",
            source
        )
    })?;
    if source_url.scheme() != "tcp" {
        anyhow::bail!(
            "Source URL must use tcp:// scheme for TCP receiver (got '{}://'). Use run_nostr_udp_receiver for udp://",
            source_url.scheme()
        );
    }
    if source_url.host_str().is_none() {
        anyhow::bail!("Source URL '{}' missing host", source);
    }
    if source_url.port().is_none() {
        anyhow::bail!("Source URL '{}' missing port", source);
    }

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:2222 or [::]:2222")?;

    log::info!("Nostr TCP Tunnel - Receiver Mode");
    log::info!("================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() {
        None
    } else {
        Some(relays)
    };
    let signaling = NostrSignaling::new(&nsec, &peer_npub, relay_list).await?;

    log::info!("Your pubkey: {}", signaling.public_key_bech32());
    log::info!("Transfer ID: {}", signaling.transfer_id());
    log::info!("Relays: {:?}", signaling.relay_urls());
    log::info!("Requesting source: {}", source);

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    log::info!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&stun_servers).await?;
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
        source: Some(source),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        republish_interval_secs,
        max_wait_secs,
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

    // Publish answer once - sender already has our ICE credentials from the request,
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
        "Connecting to sender via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to sender")?;
    log::info!("Connected to sender over QUIC.");

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
                    match handle_tcp_receiver_connection(conn_clone, tcp_stream, peer_addr, established)
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
                            log::warn!("ICE disconnected; shutting down receiver.");
                            break;
                        }
                    }
                    Err(_) => {
                        log::warn!("ICE disconnect watcher closed; shutting down receiver.");
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

    log::info!("TCP receiver stopped.");
    Ok(())
}

pub async fn run_nostr_udp_receiver(
    listen: String,
    source: String,
    stun_servers: Vec<String>,
    nsec: String,
    peer_npub: String,
    relays: Vec<String>,
    republish_interval_secs: u64,
    max_wait_secs: u64,
) -> Result<()> {
    // Ensure crypto provider is installed before nostr-sdk uses rustls
    quic::ensure_crypto_provider();

    // Validate source URL locally before publishing request
    let source_url = url::Url::parse(&source).with_context(|| {
        format!(
            "Invalid source URL '{}'. Expected format: udp://host:port",
            source
        )
    })?;
    if source_url.scheme() != "udp" {
        anyhow::bail!(
            "Source URL must use udp:// scheme for UDP receiver (got '{}://'). Use run_nostr_tcp_receiver for tcp://",
            source_url.scheme()
        );
    }
    if source_url.host_str().is_none() {
        anyhow::bail!("Source URL '{}' missing host", source);
    }
    if source_url.port().is_none() {
        anyhow::bail!("Source URL '{}' missing port", source);
    }

    let listen_addr: SocketAddr = listen
        .parse()
        .context("Invalid listen address format. Use format like 127.0.0.1:51820 or [::]:51820")?;

    log::info!("Nostr UDP Tunnel - Receiver Mode");
    log::info!("================================");

    // Create Nostr signaling client
    let relay_list = if relays.is_empty() {
        None
    } else {
        Some(relays)
    };
    let signaling = NostrSignaling::new(&nsec, &peer_npub, relay_list).await?;

    log::info!("Your pubkey: {}", signaling.public_key_bech32());
    log::info!("Transfer ID: {}", signaling.transfer_id());
    log::info!("Relays: {:?}", signaling.relay_urls());
    log::info!("Requesting source: {}", source);

    // Subscribe to incoming events
    signaling.subscribe().await?;

    // Generate session ID to filter stale events
    let session_id = generate_session_id();
    log::info!("Session ID: {}", session_id);

    // Gather ICE candidates first (before sending request)
    let ice = IceEndpoint::gather(&stun_servers).await?;
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
        source: Some(source),
    };

    // Publish request and wait for offer (re-publish periodically)
    let offer = publish_request_and_wait_for_offer(
        &signaling,
        &request,
        republish_interval_secs,
        max_wait_secs,
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

    // Publish answer once - sender already has our ICE credentials from the request,
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
        "Connecting to sender via QUIC (timeout: {:?})...",
        QUIC_CONNECTION_TIMEOUT
    );
    let connecting = endpoint
        .connect(ice_conn.remote_addr, "manual")
        .context("Failed to start QUIC connection")?;
    let conn = tokio::time::timeout(QUIC_CONNECTION_TIMEOUT, connecting)
        .await
        .context("Timeout during QUIC connection")?
        .context("Failed to connect to sender")?;
    log::info!("Connected to sender over QUIC.");

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
        result = forward_stream_to_udp_receiver(recv_stream, udp_socket, client_addr) => {
            if let Err(e) = result {
                log::warn!("Stream to UDP error: {}", e);
            }
        }
        result = ice_disconnect_rx.changed() => {
            match result {
                Ok(()) => {
                    if *ice_disconnect_rx.borrow() {
                        log::warn!("ICE disconnected; shutting down receiver.");
                    }
                }
                Err(_) => {
                    log::warn!("ICE disconnect watcher closed; shutting down receiver.");
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
