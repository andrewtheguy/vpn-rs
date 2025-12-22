//! STUN/QUIC demultiplexing socket for ICE+QUIC coexistence.
//!
//! This module provides a socket wrapper that demultiplexes incoming packets:
//! - STUN packets (first byte 0x00-0x03) are routed to the ICE agent
//! - QUIC packets (first byte has bit 6 set) are routed to quinn

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use str0m::ice::{IceAgent, IceAgentEvent, StunMessage, StunPacket};
use str0m::net::Protocol;
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Classify packet by first byte
fn is_stun_packet(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    // STUN: first 2 bits are 00, so first byte is 0x00-0x03
    data[0] <= 0x03
}

/// Received packet with source address
#[derive(Debug)]
pub struct ReceivedPacket {
    pub source: SocketAddr,
    pub data: Vec<u8>,
}

/// A demultiplexing socket that routes STUN to ICE and QUIC to quinn.
#[derive(Debug)]
pub struct DemuxSocket {
    io: UdpSocket,
    inner: quinn::udp::UdpSocketState,
    stun_tx: mpsc::UnboundedSender<ReceivedPacket>,
    local_addr: SocketAddr,
}

impl DemuxSocket {
    /// Create a new demultiplexing socket.
    ///
    /// Returns the socket and a receiver for STUN packets.
    pub fn new(
        io: UdpSocket,
    ) -> io::Result<(Arc<Self>, mpsc::UnboundedReceiver<ReceivedPacket>)> {
        let local_addr = io.local_addr()?;
        let inner = quinn::udp::UdpSocketState::new((&io).into())?;
        let (stun_tx, stun_rx) = mpsc::unbounded_channel();

        let socket = Arc::new(Self {
            io,
            inner,
            stun_tx,
            local_addr,
        });

        Ok((socket, stun_rx))
    }

    /// Get the underlying tokio UdpSocket for sending.
    pub fn io(&self) -> &UdpSocket {
        &self.io
    }

    /// Route a STUN packet to the ICE channel.
    fn route_stun(&self, source: SocketAddr, data: Vec<u8>) {
        let packet = ReceivedPacket { source, data };
        // Ignore send errors (receiver may be dropped)
        let _ = self.stun_tx.send(packet);
    }
}

impl AsyncUdpSocket for DemuxSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(DemuxPoller {
            socket: self,
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_io(Interest::WRITABLE, || {
            self.inner.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.io.poll_recv_ready(cx))?;

            match self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                Ok(count) => {
                    // Process received packets: route STUN to ICE, keep QUIC
                    let mut quic_count = 0;

                    for i in 0..count {
                        let len = meta[i].len;
                        let data = &bufs[i][..len];

                        if is_stun_packet(data) {
                            // Route STUN to ICE handler
                            self.route_stun(meta[i].addr, data.to_vec());
                            // Don't include in results for quinn
                        } else {
                            // Keep QUIC packet in results
                            if quic_count != i {
                                // Shift meta entry down
                                meta[quic_count] = meta[i];
                                // Copy data to correct buffer position
                                // Need to copy to temp first to avoid borrow issues
                                let temp: Vec<u8> = bufs[i][..len].to_vec();
                                bufs[quic_count][..len].copy_from_slice(&temp);
                            }
                            quic_count += 1;
                        }
                    }

                    if quic_count > 0 {
                        return Poll::Ready(Ok(quic_count));
                    }
                    // All packets were STUN, continue polling for QUIC packets
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Socket indicated ready but recv returned WouldBlock.
                    // This cleared the readiness flag. We need to loop back
                    // to poll_recv_ready to properly register the waker.
                    continue;
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.gro_segments()
    }
}

/// UdpPoller implementation for DemuxSocket
struct DemuxPoller {
    socket: Arc<DemuxSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl std::fmt::Debug for DemuxPoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DemuxPoller").finish_non_exhaustive()
    }
}

impl UdpPoller for DemuxPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            let socket = self.socket.clone();
            self.fut = Some(Box::pin(async move { socket.io.writable().await }));
        }

        let result = Pin::new(self.fut.as_mut().unwrap()).poll(cx);
        if result.is_ready() {
            self.fut = None;
        }
        result
    }
}

/// Keeps ICE alive after QUIC starts, handling STUN packets.
pub struct IceKeeper {
    ice: IceAgent,
    socket: Arc<DemuxSocket>,
    stun_rx: mpsc::UnboundedReceiver<ReceivedPacket>,
    local_addr: SocketAddr,
}

impl IceKeeper {
    /// Create a new ICE keeper.
    pub fn new(
        ice: IceAgent,
        socket: Arc<DemuxSocket>,
        stun_rx: mpsc::UnboundedReceiver<ReceivedPacket>,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            ice,
            socket,
            stun_rx,
            local_addr,
        }
    }

    /// Run the ICE keeper, handling STUN packets and sending keepalives.
    ///
    /// This should be spawned as a background task.
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            tokio::select! {
                biased;

                _ = interval.tick() => {
                    self.ice.handle_timeout(Instant::now());
                    self.drain_transmit().await;
                    self.drain_events();
                }

                result = self.stun_rx.recv() => {
                    match result {
                        Some(packet) => {
                            self.handle_stun_packet(packet);
                            self.drain_transmit().await;
                            self.drain_events();
                        }
                        None => {
                            // Channel closed, stop running
                            break;
                        }
                    }
                }
            }
        }
    }

    fn handle_stun_packet(&mut self, packet: ReceivedPacket) {
        if let Ok(message) = StunMessage::parse(&packet.data) {
            let stun_packet = StunPacket {
                proto: Protocol::Udp,
                source: packet.source,
                destination: self.local_addr,
                message,
            };
            self.ice.handle_packet(Instant::now(), stun_packet);
        }
    }

    async fn drain_transmit(&mut self) {
        while let Some(transmit) = self.ice.poll_transmit() {
            let _ = self
                .socket
                .io()
                .send_to(&transmit.contents, transmit.destination)
                .await;
        }
    }

    fn drain_events(&mut self) {
        while let Some(event) = self.ice.poll_event() {
            if let IceAgentEvent::IceConnectionStateChange(state) = event {
                // ICE state may change even after initial connection
                // (e.g., if keepalives fail)
                if state.is_disconnected() {
                    // Log or handle ICE disconnection if needed
                }
            }
        }
    }
}

/// Result of ICE connection with demultiplexing support.
pub struct IceConnection {
    /// The demultiplexing socket for use with quinn.
    pub socket: Arc<DemuxSocket>,
    /// The ICE keeper to run in the background.
    pub ice_keeper: IceKeeper,
    /// The remote peer address (nominated by ICE).
    pub remote_addr: SocketAddr,
}
