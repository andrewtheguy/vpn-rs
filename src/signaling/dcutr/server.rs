//! DCUtR-style signaling server implementation.
//!
//! Handles client registration, RTT measurement, and coordinated hole punching.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

use super::framing::{read_message, write_message};
use super::protocol::*;

/// Buffer time added to RTT for timing coordination (milliseconds)
/// Increased from 200ms to 500ms to account for clock skew, network jitter, and processing delays
const TIMING_BUFFER_MS: u64 = 500;

/// Maximum RTT samples to keep per client
const MAX_RTT_SAMPLES: usize = 10;

/// Client state stored by the server
#[derive(Debug)]
#[allow(dead_code)]
struct ClientState {
    client_id: String,
    /// ICE username fragment
    ice_ufrag: String,
    /// ICE password
    ice_pwd: String,
    /// SDP candidate strings
    candidates: Vec<String>,
    /// QUIC fingerprint (for server role)
    quic_fingerprint: Option<String>,
    rtt_samples_us: Vec<u64>, // RTT in microseconds
    tx: mpsc::Sender<ServerMessage>,
    connected_at: Instant,
}

impl ClientState {
    /// Get average RTT in milliseconds
    fn avg_rtt_ms(&self) -> u64 {
        if self.rtt_samples_us.is_empty() {
            return 100; // Default 100ms if no samples
        }
        let sum: u64 = self.rtt_samples_us.iter().sum();
        (sum / self.rtt_samples_us.len() as u64) / 1000 // Convert us to ms
    }
}

/// Message sent from server to client handler
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ServerMessage {
    SyncConnect(SyncConnectParams),
    Shutdown,
}

/// Shared server state
struct SignalingServerState {
    clients: HashMap<String, ClientState>,
}

impl SignalingServerState {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }
}

/// DCUtR signaling server
pub struct SignalingServer {
    state: Arc<RwLock<SignalingServerState>>,
}

impl SignalingServer {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SignalingServerState::new())),
        }
    }

    /// Run the signaling server on the given address
    pub async fn run(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Signaling server listening on {}", bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("Client connected from {}", peer_addr);
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, peer_addr, state).await {
                            debug!("Client {} disconnected: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

impl Default for SignalingServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a single client connection
async fn handle_client<S>(
    stream: S,
    peer_addr: SocketAddr,
    state: Arc<RwLock<SignalingServerState>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Channel for server-initiated messages
    let (tx, mut rx) = mpsc::channel::<ServerMessage>(32);

    let mut client_id: Option<String> = None;
    let mut loop_error: Option<anyhow::Error> = None;

    loop {
        tokio::select! {
            // Handle incoming messages from client
            msg_result = read_message::<_, JsonRpcRequest>(&mut reader) => {
                match msg_result {
                    Ok(request) => {
                        let response = handle_request(
                            &request,
                            peer_addr,
                            &mut client_id,
                            tx.clone(),
                            state.clone(),
                        ).await;

                        // Send response if request had an id
                        if let Some(id) = request.id {
                            let resp = match response {
                                Ok(result) => JsonRpcResponse::success(id, result),
                                Err(error) => JsonRpcResponse::error(id, error),
                            };
                            if let Err(e) = write_message(&mut writer, &resp).await {
                                loop_error = Some(anyhow!("Write error: {}", e));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Connection closed or parse error
                        loop_error = Some(anyhow!("Read error: {}", e));
                        break;
                    }
                }
            }

            // Handle server-initiated messages
            Some(server_msg) = rx.recv() => {
                match server_msg {
                    ServerMessage::SyncConnect(params) => {
                        let notification = JsonRpcNotification::new("sync_connect", params);
                        if let Err(e) = write_message(&mut writer, &notification).await {
                            loop_error = Some(anyhow!("Write error: {}", e));
                            break;
                        }
                    }
                    ServerMessage::Shutdown => {
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: always remove client from state on any exit
    if let Some(id) = &client_id {
        let mut state = state.write().await;
        state.clients.remove(id);
        info!("Client {} unregistered", id);
    }

    // Return error if one occurred, otherwise Ok
    match loop_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Handle a JSON-RPC request and return result or error
async fn handle_request(
    request: &JsonRpcRequest,
    peer_addr: SocketAddr,
    client_id: &mut Option<String>,
    tx: mpsc::Sender<ServerMessage>,
    state: Arc<RwLock<SignalingServerState>>,
) -> Result<serde_json::Value, JsonRpcError> {
    match request.method.as_str() {
        "register" => handle_register(request, peer_addr, client_id, tx, state).await,
        "ping" => handle_ping(request, client_id, state).await,
        "connect_request" => handle_connect_request(request, client_id, state).await,
        "connect_result" => handle_connect_result(request, client_id).await,
        _ => Err(JsonRpcError::method_not_found(&request.method)),
    }
}

/// Handle "register" method
async fn handle_register(
    request: &JsonRpcRequest,
    _peer_addr: SocketAddr,
    client_id: &mut Option<String>,
    tx: mpsc::Sender<ServerMessage>,
    state: Arc<RwLock<SignalingServerState>>,
) -> Result<serde_json::Value, JsonRpcError> {
    let params: RegisterParams = serde_json::from_value(
        request
            .params
            .clone()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?,
    )
    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

    let mut state = state.write().await;

    // Check if already registered - allow re-registration (overwrite)
    let is_reregister = state.clients.contains_key(&params.client_id);
    if is_reregister {
        info!("Client re-registering (overwriting): {}", params.client_id);
    }

    // Register client (overwrites existing registration if any)
    let client_state = ClientState {
        client_id: params.client_id.clone(),
        ice_ufrag: params.ice_ufrag,
        ice_pwd: params.ice_pwd,
        candidates: params.candidates,
        quic_fingerprint: params.quic_fingerprint,
        rtt_samples_us: Vec::new(),
        tx,
        connected_at: Instant::now(),
    };

    state.clients.insert(params.client_id.clone(), client_state);
    *client_id = Some(params.client_id.clone());

    if !is_reregister {
        info!("Client registered: {}", params.client_id);
    }

    Ok(serde_json::to_value(RegisterResult { success: true }).unwrap())
}

/// Handle "ping" method for RTT measurement
async fn handle_ping(
    request: &JsonRpcRequest,
    client_id: &Option<String>,
    state: Arc<RwLock<SignalingServerState>>,
) -> Result<serde_json::Value, JsonRpcError> {
    let params: PingParams = serde_json::from_value(
        request
            .params
            .clone()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?,
    )
    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

    let server_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Store client-measured RTT if provided (from previous ping response)
    if let Some(id) = client_id {
        if let Some(measured_rtt_us) = params.measured_rtt_us {
            let mut state = state.write().await;
            if let Some(client) = state.clients.get_mut(id) {
                // Keep only last N samples
                if client.rtt_samples_us.len() >= MAX_RTT_SAMPLES {
                    client.rtt_samples_us.remove(0);
                }
                client.rtt_samples_us.push(measured_rtt_us);

                debug!(
                    "Client {} RTT sample: {}us (avg: {}ms)",
                    id,
                    measured_rtt_us,
                    client.avg_rtt_ms()
                );
            }
        }
    }

    Ok(serde_json::to_value(PingResult {
        seq: params.seq,
        client_ts: params.timestamp,
        server_ts,
    })
    .unwrap())
}

/// Handle "connect_request" method
async fn handle_connect_request(
    request: &JsonRpcRequest,
    client_id: &Option<String>,
    state: Arc<RwLock<SignalingServerState>>,
) -> Result<serde_json::Value, JsonRpcError> {
    let requester_id = client_id
        .as_ref()
        .ok_or_else(|| JsonRpcError::invalid_request("Not registered"))?;

    let params: ConnectRequestParams = serde_json::from_value(
        request
            .params
            .clone()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?,
    )
    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

    let state = state.read().await;

    // Find target client
    let target = state
        .clients
        .get(&params.target_id)
        .ok_or_else(|| JsonRpcError::peer_not_found(&params.target_id))?;

    // Get requester state
    let requester = state.clients.get(requester_id).unwrap();

    // Get RTT values
    let rtt_requester = requester.avg_rtt_ms();
    let rtt_target = target.avg_rtt_ms();

    // Calculate synchronized start time
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let max_rtt = rtt_requester.max(rtt_target);
    let start_at_ms = now_ms + max_rtt / 2 + TIMING_BUFFER_MS;

    info!(
        "Coordinating hole punch: {} <-> {} (RTT: {}ms / {}ms, start at +{}ms)",
        requester_id,
        params.target_id,
        rtt_requester,
        rtt_target,
        start_at_ms - now_ms
    );

    // Prepare sync_connect messages with full ICE credentials
    // Requester gets target's info (and acts as QUIC client)
    let sync_to_requester = SyncConnectParams {
        peer_ice_ufrag: target.ice_ufrag.clone(),
        peer_ice_pwd: target.ice_pwd.clone(),
        peer_candidates: target.candidates.clone(),
        peer_quic_fingerprint: target.quic_fingerprint.clone(),
        start_at_ms,
        is_server: false, // Requester is the QUIC client
    };

    // Target gets requester's info from the connect_request params (and acts as QUIC server)
    let sync_to_target = SyncConnectParams {
        peer_ice_ufrag: params.ice_ufrag,
        peer_ice_pwd: params.ice_pwd,
        peer_candidates: params.candidates,
        peer_quic_fingerprint: params.quic_fingerprint,
        start_at_ms,
        is_server: true, // Target is the QUIC server
    };

    // Get channels before dropping lock
    let target_tx = target.tx.clone();
    let requester_tx = requester.tx.clone();

    // Drop the lock before sending
    drop(state);

    // Send notifications (best effort)
    let _ = target_tx
        .send(ServerMessage::SyncConnect(sync_to_target))
        .await;
    let _ = requester_tx
        .send(ServerMessage::SyncConnect(sync_to_requester))
        .await;

    Ok(serde_json::to_value(ConnectRequestResult {
        accepted: true,
        message: Some(format!("Hole punch scheduled at {}", start_at_ms)),
    })
    .unwrap())
}

/// Handle "connect_result" notification
async fn handle_connect_result(
    request: &JsonRpcRequest,
    client_id: &Option<String>,
) -> Result<serde_json::Value, JsonRpcError> {
    let params: ConnectResultParams = serde_json::from_value(
        request
            .params
            .clone()
            .ok_or_else(|| JsonRpcError::invalid_params("Missing params"))?,
    )
    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

    if let Some(id) = client_id {
        info!(
            "Client {} reported connect result: success={}, method={:?}",
            id, params.success, params.method
        );
    }

    // This is typically a notification, but respond if id is present
    Ok(serde_json::json!({"received": true}))
}

/// Run the signaling server (convenience function)
pub async fn run_signaling_server(bind_addr: SocketAddr) -> Result<()> {
    let server = SignalingServer::new();
    server.run(bind_addr).await
}
