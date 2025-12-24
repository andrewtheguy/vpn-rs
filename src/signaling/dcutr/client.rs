//! DCUtR signaling client implementation.
//!
//! Connects to a DCUtR signaling server for coordinated NAT hole punching.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::framing::{read_message, write_message};
use super::protocol::*;

/// Number of RTT measurement rounds
const RTT_ROUNDS: u32 = 5;

/// DCUtR signaling client
pub struct DCUtRSignaling<S> {
    stream: S,
    client_id: Option<String>,
    rtt_ms: u64,
    next_id: u64,
}

impl DCUtRSignaling<TcpStream> {
    /// Connect to a DCUtR signaling server via TCP
    pub async fn connect(server_addr: &str) -> Result<Self> {
        info!("Connecting to DCUtR signaling server at {}", server_addr);
        let stream = TcpStream::connect(server_addr)
            .await
            .context("Failed to connect to signaling server")?;
        Ok(Self::new(stream))
    }
}

impl<S> DCUtRSignaling<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new signaling client with an existing stream
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            client_id: None,
            rtt_ms: 100, // Default RTT
            next_id: 1,
        }
    }

    /// Get the next request ID
    fn next_request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Get current time in milliseconds since Unix epoch
    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Register with the signaling server
    ///
    /// # Arguments
    /// * `client_id` - Unique identifier for this client
    /// * `ice_ufrag` - ICE username fragment
    /// * `ice_pwd` - ICE password
    /// * `candidates` - SDP candidate strings
    /// * `quic_fingerprint` - Optional QUIC TLS fingerprint (required if this client will be QUIC server)
    pub async fn register(
        &mut self,
        client_id: &str,
        ice_ufrag: &str,
        ice_pwd: &str,
        candidates: Vec<String>,
        quic_fingerprint: Option<String>,
    ) -> Result<()> {
        info!("Registering with signaling server as '{}'", client_id);

        let request = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: "register".to_string(),
            params: Some(serde_json::to_value(RegisterParams {
                client_id: client_id.to_string(),
                ice_ufrag: ice_ufrag.to_string(),
                ice_pwd: ice_pwd.to_string(),
                candidates,
                quic_fingerprint,
            })?),
            id: Some(self.next_request_id()),
        };

        write_message(&mut self.stream, &request).await?;
        let response: JsonRpcResponse = read_message(&mut self.stream).await?;

        if let Some(error) = response.error {
            return Err(anyhow!("Registration failed: {}", error.message));
        }

        self.client_id = Some(client_id.to_string());
        info!("Successfully registered as '{}'", client_id);
        Ok(())
    }

    /// Measure RTT to the server using ping/pong
    pub async fn measure_rtt(&mut self) -> Result<u64> {
        info!("Measuring RTT to signaling server ({} rounds)", RTT_ROUNDS);

        let mut rtt_samples = Vec::with_capacity(RTT_ROUNDS as usize);

        for seq in 0..RTT_ROUNDS {
            let send_time = Self::current_time_ms();

            let request = JsonRpcRequest {
                jsonrpc: JSONRPC_VERSION.to_string(),
                method: "ping".to_string(),
                params: Some(serde_json::to_value(PingParams {
                    seq,
                    timestamp: send_time,
                })?),
                id: Some(self.next_request_id()),
            };

            write_message(&mut self.stream, &request).await?;
            let response: JsonRpcResponse = read_message(&mut self.stream).await?;

            if let Some(error) = response.error {
                return Err(anyhow!("Ping failed: {}", error.message));
            }

            let recv_time = Self::current_time_ms();
            let rtt = recv_time.saturating_sub(send_time);
            rtt_samples.push(rtt);
            debug!("RTT sample {}: {}ms", seq, rtt);
        }

        // Calculate average RTT
        let avg_rtt = if rtt_samples.is_empty() {
            100 // Default
        } else {
            rtt_samples.iter().sum::<u64>() / rtt_samples.len() as u64
        };

        self.rtt_ms = avg_rtt;
        info!("Average RTT: {}ms", avg_rtt);
        Ok(avg_rtt)
    }

    /// Get the measured RTT in milliseconds
    pub fn rtt_ms(&self) -> u64 {
        self.rtt_ms
    }

    /// Send a connect request to initiate hole punching with a peer
    ///
    /// # Arguments
    /// * `target_id` - ID of the peer to connect to
    /// * `ice_ufrag` - Our ICE username fragment
    /// * `ice_pwd` - Our ICE password
    /// * `candidates` - Our SDP candidate strings
    /// * `quic_fingerprint` - Optional QUIC TLS fingerprint (if we're the QUIC client, we don't need this)
    pub async fn connect_request(
        &mut self,
        target_id: &str,
        ice_ufrag: &str,
        ice_pwd: &str,
        candidates: Vec<String>,
        quic_fingerprint: Option<String>,
    ) -> Result<()> {
        info!(
            "Requesting connection to peer '{}' with {} candidates",
            target_id,
            candidates.len()
        );

        let request = JsonRpcRequest {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: "connect_request".to_string(),
            params: Some(serde_json::to_value(ConnectRequestParams {
                target_id: target_id.to_string(),
                ice_ufrag: ice_ufrag.to_string(),
                ice_pwd: ice_pwd.to_string(),
                candidates,
                quic_fingerprint,
            })?),
            id: Some(self.next_request_id()),
        };

        write_message(&mut self.stream, &request).await?;
        let response: JsonRpcResponse = read_message(&mut self.stream).await?;

        if let Some(error) = response.error {
            return Err(anyhow!("Connect request failed: {}", error.message));
        }

        if let Some(result) = response.result {
            let connect_result: ConnectRequestResult = serde_json::from_value(result)?;
            if connect_result.accepted {
                info!(
                    "Connect request accepted: {}",
                    connect_result.message.unwrap_or_default()
                );
            } else {
                return Err(anyhow!(
                    "Connect request rejected: {}",
                    connect_result.message.unwrap_or_default()
                ));
            }
        }

        Ok(())
    }

    /// Wait for a sync_connect notification from the server
    pub async fn wait_for_sync_connect(&mut self) -> Result<SyncConnectParams> {
        info!("Waiting for sync_connect notification...");

        loop {
            // Read any message - could be notification or response
            let msg: serde_json::Value = read_message(&mut self.stream).await?;

            // Check if it's a notification (has method, no id)
            if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                if method == "sync_connect" {
                    if let Some(params) = msg.get("params") {
                        let sync_params: SyncConnectParams = serde_json::from_value(params.clone())?;
                        info!(
                            "Received sync_connect: {} peer candidates, start at {}, is_server={}",
                            sync_params.peer_candidates.len(),
                            sync_params.start_at_ms,
                            sync_params.is_server
                        );
                        return Ok(sync_params);
                    }
                }
                debug!("Received notification: {}", method);
            } else {
                // It's a response to something we sent
                debug!("Received response while waiting for sync_connect");
            }
        }
    }

    /// Report the result of a hole punch attempt
    pub async fn report_result(&mut self, success: bool, method: Option<String>) -> Result<()> {
        info!(
            "Reporting connect result: success={}, method={:?}",
            success, method
        );

        // This is a notification (no id), so we don't expect a response
        let notification = JsonRpcNotification::new(
            "connect_result",
            ConnectResultParams { success, method },
        );

        write_message(&mut self.stream, &notification).await?;
        Ok(())
    }
}
