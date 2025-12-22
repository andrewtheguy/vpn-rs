//! Manual ICE gathering and connectivity using str0m.

use anyhow::{anyhow, Context, Result};
use get_if_addrs::get_if_addrs;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
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

pub struct IceEndpoint {
    sockets: Vec<IceSocket>,
    ice: IceAgent,
    local_candidates: Vec<String>,
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

        for sock in &sockets {
            if let Ok(candidate) = str0m::Candidate::host(sock.local_addr, "udp") {
                if let Some(added) = ice.add_local_candidate(candidate) {
                    local_candidates.push(added.to_sdp_string());
                }
            }
        }

        for sock in &sockets {
            for stun in stun_servers {
                for server in resolve_stun_addrs(stun) {
                    if sock.local_addr.is_ipv4() != server.is_ipv4() {
                        continue;
                    }
                    let client = stunclient::StunClient::new(server);
                    match client.query_external_address_async(&sock.udp).await {
                        Ok(external) => {
                            if let Ok(candidate) =
                                str0m::Candidate::server_reflexive(external, sock.local_addr, "udp")
                            {
                                if let Some(added) = ice.add_local_candidate(candidate) {
                                    local_candidates.push(added.to_sdp_string());
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("STUN query failed for {} on {}: {}", stun, sock.local_addr, e);
                        }
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

        // Use a stop flag to signal receive tasks to stop
        let stop_flag = Arc::new(AtomicBool::new(false));

        let (tx, mut rx) = mpsc::unbounded_channel();
        for sock in &self.sockets {
            let udp = sock.udp.clone();
            let local_addr = sock.local_addr;
            let tx = tx.clone();
            let stop = stop_flag.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2000];
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    // Use a short timeout so we can check the stop flag
                    let result = tokio::time::timeout(
                        Duration::from_millis(100),
                        udp.recv_from(&mut buf),
                    ).await;

                    match result {
                        Ok(Ok((len, source))) => {
                            let data = buf[..len].to_vec();
                            if tx.send((local_addr, source, data)).is_err() {
                                break;
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => continue, // Timeout, check stop flag
                    }
                }
            });
        }

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
                        // Signal receive tasks to stop
                        stop_flag.store(true, Ordering::Relaxed);

                        // Give tasks time to stop (they check every 100ms)
                        tokio::time::sleep(Duration::from_millis(150)).await;

                        // Take ownership of the nominated socket by removing it
                        let sock = self.sockets.remove(idx);

                        // Drop other sockets to release them
                        drop(self.sockets);

                        // Use the original tokio socket directly (via try_clone on std)
                        // We need a fresh tokio socket since the Arc'd one is shared
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
        if ip.is_multicast() {
            continue;
        }
        ips.push(ip);
    }
    Ok(ips)
}

fn bind_socket(ip: IpAddr) -> Result<IceSocket> {
    let socket = std::net::UdpSocket::bind(SocketAddr::new(ip, 0))
        .with_context(|| format!("Failed to bind UDP socket on {}", ip))?;
    socket
        .set_nonblocking(true)
        .context("Failed to set ICE socket nonblocking")?;
    let udp = UdpSocket::from_std(socket.try_clone().context("Failed to clone ICE socket")?)
        .context("Failed to create tokio UDP socket for ICE")?;
    let local_addr = socket.local_addr().context("ICE socket local addr")?;
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
