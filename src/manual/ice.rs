//! Manual ICE gathering and connectivity using str0m.

use anyhow::{anyhow, Context, Result};
use get_if_addrs::get_if_addrs;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::ice::{IceAgent, IceAgentEvent, IceCreds, StunMessage, StunPacket};
use str0m::IceConnectionState;
use str0m::net::{Protocol, Transmit};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::interval;

use super::mux::{DemuxSocket, IceConnection, IceKeeper};

#[derive(Debug, Clone, Copy)]
pub enum IceRole {
    Controlling,
    Controlled,
}

/// ICE candidate type for connection info display
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CandidateType::Host => write!(f, "Direct (Host)"),
            CandidateType::ServerReflexive => write!(f, "NAT Traversal (Server Reflexive)"),
        }
    }
}

pub struct IceEndpoint {
    sockets: Vec<IceSocket>,
    ice: IceAgent,
    local_candidates: Vec<String>,
    /// Maps local socket addresses to their candidate types
    candidate_types: HashMap<SocketAddr, CandidateType>,
}

struct IceSocket {
    std_socket: std::net::UdpSocket,
    udp: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl IceEndpoint {
    pub async fn gather(stun_servers: &[String]) -> Result<Self> {
        let provider = str0m::crypto::from_feature_flags();
        let sha1 = provider.sha1_hmac_provider;
        provider.install_process_default();

        let mut ice = IceAgent::new(IceCreds::new(), sha1);
        // Use more conservative timing (similar to webrtc crate defaults)
        // Aggressive timing causes issues when one side connects faster than the other
        ice.set_timing_advance(Duration::from_millis(50));
        ice.set_initial_stun_rto(Duration::from_millis(250));
        ice.set_max_stun_rto(Duration::from_millis(3000));
        ice.set_max_stun_retransmits(7);
        ice.set_local_preference(|c: &str0m::Candidate, same_kind| {
            use str0m::CandidateKind;
            let ip = c.addr();
            let counter_start: u32 = {
                let x = match c.kind() {
                    CandidateKind::Host => 65_535,
                    CandidateKind::PeerReflexive => 49_151,
                    CandidateKind::ServerReflexive => 32_767,
                    CandidateKind::Relayed => 16_383,
                };
                // Prefer IPv4 over IPv6 (flip the default ordering).
                x - if ip.is_ipv4() { 0 } else { 1 }
            };
            counter_start.saturating_sub(same_kind as u32 * 2)
        });

        let mut local_candidates = Vec::new();
        let mut sockets = Vec::new();
        let mut candidate_types = HashMap::new();

        // Step 1: Get non-loopback interface IPs for host candidates
        let interface_ips = list_interface_ips()?;
        if interface_ips.is_empty() {
            let fallback_ip = detect_local_ip(stun_servers)
                .await
                .ok_or_else(|| anyhow!("Failed to determine local IP for ICE"))?;
            sockets.push(bind_socket(fallback_ip)?);
        } else {
            for ip in interface_ips {
                if let Ok(socket) = bind_socket(ip) {
                    sockets.push(socket);
                }
            }
        }

        // Step 2: Add host candidates from interface-bound sockets
        for sock in &sockets {
            if let Ok(candidate) = str0m::Candidate::host(sock.local_addr, "udp") {
                if let Some(added) = ice.add_local_candidate(candidate) {
                    local_candidates.push(added.to_sdp_string());
                    candidate_types.insert(sock.local_addr, CandidateType::Host);
                }
            }
        }

        // Step 3: Gather server-reflexive (STUN) candidates using WILDCARD sockets
        // This is the key difference from our previous approach - webrtc-ice binds to
        // 0.0.0.0:0 or [::]:0 for STUN, letting the OS choose the right interface
        let mut got_ipv4_stun = false;
        let mut got_ipv6_stun = false;

        for stun in stun_servers {
            for server in resolve_stun_addrs(stun) {
                // Skip if we already have STUN for this address family
                let is_ipv4 = server.is_ipv4();
                if is_ipv4 && got_ipv4_stun {
                    continue;
                }
                if !is_ipv4 && got_ipv6_stun {
                    continue;
                }

                // Create a wildcard socket matching the STUN server's address family
                let bind_addr: SocketAddr = if is_ipv4 {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };

                let stun_socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Failed to bind STUN socket for {}: {}", server, e);
                        continue;
                    }
                };
                stun_socket.set_nonblocking(true).ok();

                // Create tokio socket - DON'T clone, use the original
                // We'll drop this after STUN query and create a fresh one for ICE
                let tokio_socket = match UdpSocket::from_std(stun_socket) {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        eprintln!("Failed to create tokio socket for STUN: {}", e);
                        continue;
                    }
                };

                let client = stunclient::StunClient::new(server);
                match client.query_external_address_async(&tokio_socket).await {
                    Ok(external) => {
                        // Get the local address that was used for the STUN query
                        let local_addr = match tokio_socket.local_addr() {
                            Ok(addr) => addr,
                            Err(_) => continue,
                        };

                        // Create srflx candidate - the base is our local addr, mapped is external
                        if let Ok(candidate) =
                            str0m::Candidate::server_reflexive(external, local_addr, "udp")
                        {
                            if let Some(added) = ice.add_local_candidate(candidate) {
                                local_candidates.push(added.to_sdp_string());
                                candidate_types.insert(local_addr, CandidateType::ServerReflexive);
                                println!("STUN: {} -> external {}", local_addr, external);
                            }
                        }

                        // Get the std socket back from tokio - this is safe because we have the only Arc
                        let std_socket = match Arc::try_unwrap(tokio_socket) {
                            Ok(ts) => ts.into_std().ok(),
                            Err(_) => None,
                        };

                        // Add this socket to our sockets list for ICE connectivity checks
                        if let Some(std_sock) = std_socket {
                            if let Ok(ice_socket) = bind_socket_from_std(std_sock) {
                                sockets.push(ice_socket);
                            }
                        }

                        if is_ipv4 {
                            got_ipv4_stun = true;
                        } else {
                            got_ipv6_stun = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("STUN query failed for {} ({}): {}", stun, server, e);
                    }
                }
            }
        }

        if local_candidates.is_empty() {
            return Err(anyhow!("No ICE candidates gathered (STUN failed?)"));
        }

        Ok(Self {
            sockets,
            ice,
            local_candidates,
            candidate_types,
        })
    }

    pub fn local_credentials(&self) -> IceCreds {
        self.ice.local_credentials().clone()
    }

    pub fn local_candidates(&self) -> Vec<String> {
        self.local_candidates.clone()
    }

    pub async fn connect(
        mut self,
        role: IceRole,
        remote_creds: IceCreds,
        remote_candidates: Vec<String>,
    ) -> Result<IceConnection> {
        self.ice.set_controlling(matches!(role, IceRole::Controlling));
        self.ice.set_remote_credentials(remote_creds);

        for candidate in remote_candidates {
            let parsed = str0m::Candidate::from_sdp_string(&candidate)
                .with_context(|| format!("Invalid ICE candidate: {}", candidate))?;
            self.ice.add_remote_candidate(parsed);
        }

        let mut nominated_source: Option<SocketAddr> = None;
        let mut nominated_dest: Option<SocketAddr> = None;
        let mut buf = vec![0u8; 2000];
        let mut tick = interval(Duration::from_millis(50)); // Slower tick to match conservative timing

        self.ice.handle_timeout(Instant::now());

        // Use channels to signal receive tasks to stop and confirm they stopped
        let (stop_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let (done_tx, mut done_rx) = mpsc::channel::<()>(self.sockets.len());

        let (tx, mut rx) = mpsc::unbounded_channel();
        let num_tasks = self.sockets.len();
        for sock in &self.sockets {
            let udp = sock.udp.clone();
            let local_addr = sock.local_addr;
            let tx = tx.clone();
            let mut stop_rx = stop_tx.subscribe();
            let done = done_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2000];
                loop {
                    tokio::select! {
                        biased;
                        _ = stop_rx.recv() => {
                            break;
                        }
                        result = udp.recv_from(&mut buf) => {
                            match result {
                                Ok((len, source)) => {
                                    let data = buf[..len].to_vec();
                                    if tx.send((local_addr, source, data)).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
                // Drop the udp socket before signaling done
                drop(udp);
                let _ = done.send(()).await;
            });
        }
        drop(done_tx); // Drop our copy so done_rx completes when all tasks finish

        loop {
            let socket_map = socket_map(&self.sockets);
            drain_transmit(&mut self.ice, &socket_map).await?;
            drain_events(&mut self.ice, &mut nominated_source, &mut nominated_dest);

            if self.ice.state().is_connected() {
                if let (Some(source), Some(destination)) = (nominated_source, nominated_dest) {
                    // Find and take ownership of the nominated socket
                    let nominated_idx = self
                        .sockets
                        .iter()
                        .position(|s| s.local_addr == source);

                    if let Some(idx) = nominated_idx {
                        // Signal all receive tasks to stop
                        let _ = stop_tx.send(());

                        // Wait for all tasks to confirm they stopped and dropped their sockets
                        for _ in 0..num_tasks {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(500),
                                done_rx.recv()
                            ).await;
                        }

                        // Take ownership of the nominated socket by removing it
                        let sock = self.sockets.remove(idx);

                        // Drop other sockets and their tokio wrappers
                        for s in self.sockets.drain(..) {
                            drop(s.udp);
                            drop(s.std_socket);
                        }

                        // Drop the cloned tokio socket for the nominated one too
                        // (tasks already dropped their clones, this is our last reference)
                        drop(sock.udp);

                        // Now create a fresh tokio socket from the std socket
                        // This is safe because all tokio sockets for this fd are dropped
                        let nominated_tokio = UdpSocket::from_std(sock.std_socket)
                            .context("Failed to create tokio socket from nominated socket")?;

                        // Create the demultiplexing socket
                        let (demux_socket, stun_rx) = DemuxSocket::new(nominated_tokio)
                            .context("Failed to create demux socket")?;

                        // Create the ICE keeper to handle STUN in the background
                        let ice_keeper = IceKeeper::new(
                            self.ice,
                            demux_socket.clone(),
                            stun_rx,
                            source,
                        );

                        // Print connection info
                        let conn_type = self
                            .candidate_types
                            .get(&source)
                            .copied()
                            .unwrap_or(CandidateType::Host);
                        println!("ICE connection established!");
                        println!("   Connection: {}", conn_type);
                        println!("   Local: {} -> Remote: {}", source, destination);

                        return Ok(IceConnection {
                            socket: demux_socket,
                            ice_keeper,
                            remote_addr: destination,
                        });
                    }
                }
            }

            tokio::select! {
                biased;
                _ = tick.tick() => {
                    self.ice.handle_timeout(Instant::now());
                }
                result = rx.recv() => {
                    let (destination, source, data) = match result {
                        Some(v) => v,
                        None => break,
                    };
                    buf.clear();
                    buf.extend_from_slice(&data);
                    if let Ok(message) = StunMessage::parse(&buf) {
                        let packet = StunPacket {
                            proto: Protocol::Udp,
                            source,
                            destination,
                            message,
                        };
                        self.ice.handle_packet(Instant::now(), packet);
                    }
                }
            }
        }

        Err(anyhow!("ICE failed to connect"))
    }
}

async fn detect_local_ip(stun_servers: &[String]) -> Option<IpAddr> {
    for server in stun_servers {
        for addr in resolve_stun_addrs(server) {
            if let Ok(ip) = local_ip_for_target(addr).await {
                return Some(ip);
            }
        }
    }
    None
}

async fn local_ip_for_target(target: SocketAddr) -> Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .context("Failed to bind UDP socket for local IP lookup")?;
    socket.connect(target).context("Failed to connect UDP socket")?;
    Ok(socket.local_addr()?.ip())
}

fn resolve_stun_addrs(stun: &str) -> Vec<SocketAddr> {
    match stun.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    }
}

async fn drain_transmit(
    ice: &mut IceAgent,
    sockets: &HashMap<SocketAddr, Arc<UdpSocket>>,
) -> Result<()> {
    while let Some(Transmit {
        destination,
        contents,
        source,
        ..
    }) = ice.poll_transmit()
    {
        let udp = match sockets.get(&source) {
            Some(sock) => sock,
            None => {
                eprintln!("ICE warning: no socket for source {}", source);
                continue;
            }
        };
        if let Err(err) = udp.send_to(&contents, destination).await {
            if is_no_route_error(&err) {
                continue;
            }
            return Err(err).context("Failed to send ICE packet");
        }
    }
    Ok(())
}

fn drain_events(
    ice: &mut IceAgent,
    nominated_source: &mut Option<SocketAddr>,
    nominated_dest: &mut Option<SocketAddr>,
) {
    while let Some(event) = ice.poll_event() {
        match event {
            IceAgentEvent::IceConnectionStateChange(state) => {
                println!("ICE state: {:?}", state);
                if state == IceConnectionState::Disconnected {
                    println!("ICE disconnected");
                }
            }
            IceAgentEvent::NominatedSend {
                source,
                destination,
                ..
            } => {
                *nominated_source = Some(source);
                *nominated_dest = Some(destination);
            }
            _ => {}
        }
    }
}

fn list_interface_ips() -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    for iface in get_if_addrs().context("Failed to list network interfaces")? {
        let ip = iface.ip();
        // Filter out loopback and multicast - they can't do NAT traversal
        if ip.is_loopback() || ip.is_multicast() {
            continue;
        }
        ips.push(ip);
    }
    Ok(ips)
}

fn bind_socket(ip: IpAddr) -> Result<IceSocket> {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip, 0))
        .with_context(|| format!("Failed to bind UDP socket on {}", ip))?;
    bind_socket_from_std(socket)
}

fn bind_socket_from_std(socket: std::net::UdpSocket) -> Result<IceSocket> {
    socket
        .set_nonblocking(true)
        .context("Failed to set ICE socket nonblocking")?;
    let local_addr = socket.local_addr().context("ICE socket local addr")?;
    // Clone for tokio socket - the original will be used for DemuxSocket later
    let tokio_clone = socket.try_clone().context("Failed to clone ICE socket")?;
    let udp = UdpSocket::from_std(tokio_clone)
        .context("Failed to create tokio UDP socket for ICE")?;
    Ok(IceSocket {
        std_socket: socket,
        udp: Arc::new(udp),
        local_addr,
    })
}

fn socket_map(sockets: &[IceSocket]) -> HashMap<SocketAddr, Arc<UdpSocket>> {
    sockets
        .iter()
        .map(|s| (s.local_addr, s.udp.clone()))
        .collect()
}

fn is_no_route_error(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        Some(65) => true, // macOS: No route to host
        Some(51) => true, // ENETUNREACH
        Some(113) => true, // Linux: No route to host
        _ => matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable),
    }
}
