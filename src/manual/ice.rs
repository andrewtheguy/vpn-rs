//! Manual ICE gathering and connectivity using str0m.

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use str0m::ice::{IceAgent, IceAgentEvent, IceCreds, StunMessage, StunPacket};
use str0m::IceConnectionState;
use str0m::net::{Protocol, Transmit};

use tokio::net::UdpSocket;
use tokio::time::sleep_until;

#[derive(Debug, Clone, Copy)]
pub enum IceRole {
    Controlling,
    Controlled,
}

pub struct IceEndpoint {
    socket: std::net::UdpSocket,
    udp: UdpSocket,
    ice: IceAgent,
    local_candidates: Vec<String>,
}

impl IceEndpoint {
    pub async fn gather(stun_servers: &[String]) -> Result<Self> {
        let provider = str0m::crypto::from_feature_flags();
        let sha1 = provider.sha1_hmac_provider;
        provider.install_process_default();

        let mut ice = IceAgent::new(IceCreds::new(), sha1);

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket for ICE")?;
        socket
            .set_nonblocking(true)
            .context("Failed to set ICE socket nonblocking")?;

        let udp = UdpSocket::from_std(socket.try_clone().context("Failed to clone ICE socket")?)
            .context("Failed to create tokio UDP socket for ICE")?;

        let local_port = socket.local_addr().context("ICE socket local addr")?.port();
        let mut local_candidates = Vec::new();

        if let Some(local_ip) = detect_local_ip(stun_servers).await {
            let host_addr = SocketAddr::new(local_ip, local_port);
            if let Ok(candidate) = str0m::Candidate::host(host_addr, "udp") {
                if let Some(added) = ice.add_local_candidate(candidate) {
                    local_candidates.push(added.to_sdp_string());
                }
            }
        }

        let base_addr = socket.local_addr().context("ICE socket local addr")?;
        for stun in stun_servers {
            if let Some(server) = resolve_stun_addr(stun) {
                let client = stunclient::StunClient::new(server);
                match client.query_external_address_async(&udp).await {
                    Ok(external) => {
                        if let Ok(candidate) =
                            str0m::Candidate::server_reflexive(external, base_addr, "udp")
                        {
                            if let Some(added) = ice.add_local_candidate(candidate) {
                                local_candidates.push(added.to_sdp_string());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("STUN query failed for {}: {}", stun, e);
                    }
                }
            }
        }

        if local_candidates.is_empty() {
            return Err(anyhow!("No ICE candidates gathered (STUN failed?)"));
        }

        Ok(Self {
            socket,
            udp,
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
    ) -> Result<(std::net::UdpSocket, SocketAddr)> {
        self.ice.set_controlling(matches!(role, IceRole::Controlling));
        self.ice.set_remote_credentials(remote_creds);

        for candidate in remote_candidates {
            let parsed = str0m::Candidate::from_sdp_string(&candidate)
                .with_context(|| format!("Invalid ICE candidate: {}", candidate))?;
            self.ice.add_remote_candidate(parsed);
        }

        let mut nominated: Option<SocketAddr> = None;

        self.ice.handle_timeout(Instant::now());
        let mut next_deadline = self.ice.poll_timeout();

        let mut buf = vec![0u8; 2000];

        loop {
            drain_transmit(&mut self.ice, &self.udp).await?;
            drain_events(&mut self.ice, &mut nominated);

            if self.ice.state().is_connected() {
                if let Some(destination) = nominated {
                    return Ok((self.socket, destination));
                }
            }

            let deadline = next_deadline.unwrap_or_else(|| Instant::now() + Duration::from_millis(50));
            let sleep = sleep_until(tokio::time::Instant::from_std(deadline));

            tokio::select! {
                result = self.udp.recv_from(&mut buf) => {
                    let (len, source) = result.context("ICE recv failed")?;
                    if let Ok(message) = StunMessage::parse(&buf[..len]) {
                        let destination = self.udp.local_addr().context("ICE local addr")?;
                        let packet = StunPacket {
                            proto: Protocol::Udp,
                            source,
                            destination,
                            message,
                        };
                        self.ice.handle_packet(Instant::now(), packet);
                    }
                }
                _ = sleep => {
                    self.ice.handle_timeout(Instant::now());
                    next_deadline = self.ice.poll_timeout();
                }
            }
        }
    }
}

async fn detect_local_ip(stun_servers: &[String]) -> Option<IpAddr> {
    for server in stun_servers {
        if let Some(addr) = resolve_stun_addr(server) {
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

fn resolve_stun_addr(stun: &str) -> Option<SocketAddr> {
    match stun.to_socket_addrs() {
        Ok(mut iter) => iter.find(|addr| addr.is_ipv4()),
        Err(_) => None,
    }
}

async fn drain_transmit(ice: &mut IceAgent, udp: &UdpSocket) -> Result<()> {
    while let Some(Transmit { destination, contents, .. }) = ice.poll_transmit() {
        udp.send_to(&contents, destination)
            .await
            .context("Failed to send ICE packet")?;
    }
    Ok(())
}

fn drain_events(ice: &mut IceAgent, nominated: &mut Option<SocketAddr>) {
    while let Some(event) = ice.poll_event() {
        match event {
            IceAgentEvent::IceConnectionStateChange(state) => {
                println!("ICE state: {:?}", state);
                if state == IceConnectionState::Disconnected {
                    println!("ICE disconnected");
                }
            }
            IceAgentEvent::NominatedSend { destination, .. } => {
                *nominated = Some(destination);
            }
            _ => {}
        }
    }
}
