//! Nostr mode server implementation.
//!
//! This module provides the server-side logic for nostr tunnels:
//! - Multi-session management with concurrency limits
//! - TCP and UDP session handlers
//! - Session request validation and routing

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

use crate::signaling::{
    ManualOffer, ManualReject, ManualRequest, NostrSignaling, SignalingError,
    MANUAL_SIGNAL_VERSION,
};
use crate::transport::ice::{IceEndpoint, IceRole};
use crate::transport::quic;
use crate::tunnel_common::{
    bind_udp_for_targets, check_source_allowed, extract_addr_from_source,
    forward_stream_to_udp_server, handle_tcp_server_stream, resolve_all_target_addrs,
    short_session_id, validate_allowed_networks, MAX_REQUEST_AGE_SECS, QUIC_CONNECTION_TIMEOUT,
};

// ============================================================================
// Nostr Server Loop (shared session management for TCP/UDP)
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

/// Generic nostr server loop that handles session management.
async fn run_nostr_server_loop(
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

        // Wait for fresh request from client (no timeout for multi-session mode)
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
                            "Server at capacity ({}/{} sessions)",
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

    // source is required - client must specify which source to connect to
    let requested_source = request.source.as_ref().ok_or_else(|| {
        anyhow::anyhow!("[{}] Request missing required 'source' field", short_id)
    })?;

    // Parse protocol from source (tcp:// or udp://)
    let protocol = requested_source.split("://").next().unwrap_or("");

    match protocol {
        "tcp" => {
            // Validate against TCP allowed networks
            let check_result = check_source_allowed(requested_source, &allowed_tcp).await;
            if !check_result.allowed {
                let reason = check_result.rejection_reason(requested_source, &allowed_tcp);
                let reject = ManualReject::new(session_id.clone(), reason.clone());
                if let Err(e) = signaling.publish_reject(&reject).await {
                    log::warn!("[{}] Failed to publish reject: {}", short_id, e);
                }
                anyhow::bail!("[{}] Rejected: {}", short_id, reason);
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
            let check_result = check_source_allowed(requested_source, &allowed_udp).await;
            if !check_result.allowed {
                let reason = check_result.rejection_reason(requested_source, &allowed_udp);
                let reject = ManualReject::new(session_id.clone(), reason.clone());
                if let Err(e) = signaling.publish_reject(&reject).await {
                    log::warn!("[{}] Failed to publish reject: {}", short_id, e);
                }
                anyhow::bail!("[{}] Rejected: {}", short_id, reason);
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
    if target_addrs.is_empty() {
        anyhow::bail!("[{}] No target addresses resolved for '{}'", short_id, requested_source);
    }

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

    // Publish offer once - we already have client's ICE credentials from the REQUEST,
    // so we can start ICE immediately without waiting for the answer.
    // The answer is only a confirmation that receiver got the offer.
    signaling.publish_offer(&offer).await?;
    log::info!("[{}] Published offer, starting ICE immediately", short_id);

    // Use client's ICE credentials from the REQUEST (not from answer)
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
                    if let Err(e) = handle_tcp_server_stream(send_stream, recv_stream, target).await {
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
    let target_addrs = Arc::new(
        resolve_all_target_addrs(&target_hostport)
            .await
            .with_context(|| format!("Invalid source '{}'", requested_source))?,
    );
    if target_addrs.is_empty() {
        anyhow::bail!("[{}] No target addresses resolved for '{}'", short_id, requested_source);
    }

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

    // Publish offer once - we already have client's ICE credentials from the REQUEST,
    // so we can start ICE immediately without waiting for the answer.
    // The answer is only a confirmation that receiver got the offer.
    signaling.publish_offer(&offer).await?;
    log::info!("[{}] Published offer, starting ICE immediately", short_id);

    // Use client's ICE credentials from the REQUEST (not from answer)
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
        .context("Failed to accept stream from client")?;

    let primary_addr = target_addrs.first().copied().unwrap();
    log::info!(
        "[{}] Forwarding UDP traffic to {} ({} address(es) resolved)",
        short_id,
        primary_addr,
        target_addrs.len()
    );

    // Bind to appropriate address family based on all resolved targets
    let udp_socket = Arc::new(
        bind_udp_for_targets(&target_addrs)
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
        result = forward_stream_to_udp_server(recv_stream, send_stream, udp_socket, Arc::clone(&target_addrs)) => {
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

/// Unified nostr server that handles both TCP and UDP requests.
pub async fn run_nostr_server(
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

    log::info!("Nostr Tunnel - Server Mode (Multi-Session)");
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
    run_nostr_server_loop(
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
