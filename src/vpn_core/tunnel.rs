//! Shared stream-transport packet pipeline (`run_tunnel`).
//!
//! This is the standalone equivalent of the vpn-iroh dummy TCP tunnel: a single
//! direct connection carries framed IP packets between the TUN device and a
//! byte-stream transport, with end-to-end backpressure. Unlike the production
//! UDP path (`client.rs` / `server.rs`, which hands off to an external tunnel
//! over a loopback UDP socket), this pipeline owns the network connection
//! itself, so there is no datagram drop point — the whole reason the dummy TCP
//! benchmark runs smooth with no inner-TCP retransmits.
//!
//! [`run_tunnel`] takes no `self`: it only shovels framed IP packets between the
//! TUN device and the transport, plus heartbeats. It is generic over the write
//! half (`W: ChunkedWrite`) and read half (`R: AsyncRead`), so the same hot path
//! can serve any stream transport.

use crate::vpn_core::buffer::uninitialized_vec;
use crate::vpn_core::chunked_write::ChunkedWrite;
use crate::vpn_core::device::TunDevice;
use crate::vpn_core::error::{VpnError, VpnResult};
use crate::vpn_core::frame_reader::{FrameError, FrameEvent, FrameReader};
use crate::vpn_core::offload::{
    materialize_offload_into, CoalescedOutput, TcpGroTable, VirtioNetHdr,
};
use crate::vpn_core::signaling::{
    append_ip_packet_v2, parse_ip_packet_v2, HEARTBEAT_PING_BYTE, HEARTBEAT_PONG_BYTE,
};
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;

/// Heartbeat ping interval (how often each end sends a ping).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Heartbeat timeout (max time to wait for a pong before declaring the link dead).
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// Channel buffer size for outbound frames queued to the writer task.
const OUTBOUND_CHANNEL_SIZE: usize = 256;

/// Channel buffer size for inbound packets queued to the TUN writer task.
const INBOUND_TUN_CHANNEL_SIZE: usize = 512;

/// Maximum number of frames/writes drained from a channel per batch.
const WRITE_BATCH_SIZE: usize = 256;

/// Maximum accepted inbound IP frame length (guards `FrameReader` allocation).
const MAX_IP_PACKET_SIZE: usize = 65536 + 64;

/// Reserve granularity for the outbound framing arena.
const FRAME_ARENA_CHUNK: usize = 64 * 1024;

/// A decoded inbound packet queued for the dedicated TUN writer task.
struct InboundTunWrite {
    packet: Bytes,
    offload: Option<VirtioNetHdr>,
}

/// Run the VPN packet processing loop over a stream transport.
///
/// `peer_gso_enabled` is the *peer's* advertised GSO capability (the dummy
/// client's for the server, the server's for the client). Returns
/// [`VpnError::ConnectionLost`] once any of the internal tasks ends.
pub async fn run_tunnel<W, R>(
    tun_device: TunDevice,
    data_send: W,
    data_recv: R,
    peer_gso_enabled: bool,
) -> VpnResult<()>
where
    W: ChunkedWrite + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let (mut tun_reader, mut tun_writer) = tun_device.split()?;
    let local_gso_enabled = tun_reader.offload_status().enabled;
    debug_assert_eq!(local_gso_enabled, tun_writer.offload_status().enabled);
    let negotiated_gso = local_gso_enabled && peer_gso_enabled;
    let buffer_size = tun_reader.buffer_size();

    // Outbound channel decouples packet production from stream writes. The
    // writer task owns the write half and performs the actual I/O, so the TUN
    // reader and heartbeat tasks never touch the socket directly.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(OUTBOUND_CHANNEL_SIZE);
    let outbound_tx_heartbeat = outbound_tx.clone();
    // Lets the inbound task reply to heartbeat pings with pongs, keeping the
    // loop symmetric (both ends ping).
    let outbound_tx_pong = outbound_tx.clone();

    // Dedicated writer task: drains a batch and writes it with one vectored
    // call per batch rather than one syscall per frame.
    let mut writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let mut data_send = data_send;
        let mut batch = Vec::with_capacity(WRITE_BATCH_SIZE);
        loop {
            let count = outbound_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
            if count == 0 {
                log::trace!("Writer task exiting");
                break;
            }
            if let Err(e) = data_send.write_all_chunks(batch.as_mut_slice()).await {
                log::warn!("Failed to write to stream: {}", e);
                return Some(format!("stream write error: {}", e));
            }
            batch.clear();
        }
        None
    });

    // Track last heartbeat pong received (millis since start for atomic access).
    let start_time = Instant::now();
    let last_pong = Arc::new(AtomicU64::new(start_time.elapsed().as_millis() as u64));
    let last_pong_inbound = last_pong.clone();
    let last_pong_heartbeat = last_pong.clone();

    // Outbound task: TUN -> frame IP packet -> channel -> writer task.
    let mut outbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let mut read_storage = uninitialized_vec(buffer_size);
        // Long-lived framing arena: frames are appended and split off as
        // refcounted Bytes views, amortizing allocations across packets.
        let mut arena = BytesMut::with_capacity(FRAME_ARENA_CHUNK);
        // Reusable buffers for software-materializing offload super-frames when
        // GSO was not negotiated with the peer.
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut pending_frames: Vec<Bytes> = Vec::new();
        // Software GRO: on a non-GSO local TUN, coalesce consecutive same-flow
        // TCP segments into offload-tagged super-frames so a GSO-capable peer
        // can hand them to its kernel via TSO.
        let software_gro = !tun_reader.vnet_hdr_enabled();
        if software_gro {
            log::info!(
                "Software GRO enabled for outbound TCP (local TUN has no offload support)"
            );
        }
        let mut gro_table = TcpGroTable::new();
        // Persistent ReadBuf: tracks the initialized region across iterations so
        // the TUN reader only zeroes the buffer once instead of on every read.
        let mut packet_buf = ReadBuf::uninit(&mut read_storage);
        loop {
            packet_buf.clear();
            // Event-driven GRO: keep pulling segments already queued on the TUN;
            // the instant it drains, flush every pending coalesced group and
            // block for the next packet.
            let read_result = if software_gro && !gro_table.is_empty() {
                match tun_reader.try_read_buf(&mut packet_buf) {
                    Some(read_result) => read_result,
                    None => {
                        if !send_gro_outputs(&gro_table.flush_all(), &mut arena, &outbound_tx).await
                        {
                            return None;
                        }
                        tun_reader.read_buf(&mut packet_buf).await
                    }
                }
            } else {
                tun_reader.read_buf(&mut packet_buf).await
            };
            match read_result {
                Ok(()) if !packet_buf.filled().is_empty() => {
                    let raw_packet = packet_buf.filled();
                    let (offload, packet) = match tun_reader.split_frame(raw_packet) {
                        Ok(parts) => parts,
                        Err(e) => {
                            log::warn!("Failed to parse TUN frame: {}", e);
                            continue;
                        }
                    };

                    if software_gro {
                        // Non-GSO TUN frames never carry offload metadata; push
                        // the plain IP packet through the GRO table.
                        let result = gro_table.push(packet);
                        if !send_gro_outputs(&result.outputs, &mut arena, &outbound_tx).await {
                            return None;
                        }
                        if !result.pass_through {
                            continue;
                        }
                        // Pass-through: fall through to plain framing below.
                    }

                    if let Some(meta) = offload
                        && !negotiated_gso
                    {
                        // Segment directly into the framing arena: each emitted
                        // segment is framed in place and handed out as a
                        // refcounted Bytes view, with no per-segment Vec.
                        let materialized =
                            materialize_offload_into(&meta, packet, &mut seg_scratch, |packet| {
                                let frame_size = 1 + 4 + 1 + packet.len();
                                if arena.capacity() - arena.len() < frame_size {
                                    arena.reserve(FRAME_ARENA_CHUNK.max(frame_size));
                                }
                                let written = append_ip_packet_v2(&mut arena, None, packet)
                                    .map_err(|e| e.to_string())?;
                                pending_frames.push(arena.split_to(written).freeze());
                                Ok(())
                            });
                        if let Err(e) = materialized {
                            pending_frames.clear();
                            log::warn!("Failed to materialize offload packet: {}", e);
                            continue;
                        }
                        for frame in pending_frames.drain(..) {
                            if outbound_tx.send(frame).await.is_err() {
                                log::warn!("Outbound channel closed");
                                return None;
                            }
                        }
                        continue;
                    }

                    // Append frame to the arena and split it off as a Bytes view.
                    let frame_size = 1
                        + 4
                        + 1
                        + offload
                            .map(|_| crate::vpn_core::offload::VIRTIO_NET_HDR_LEN)
                            .unwrap_or(0)
                        + packet.len();
                    if arena.capacity() - arena.len() < frame_size {
                        arena.reserve(FRAME_ARENA_CHUNK.max(frame_size));
                    }
                    let written = match append_ip_packet_v2(&mut arena, offload.as_ref(), packet) {
                        Ok(written) => written,
                        Err(e) => {
                            log::warn!("Failed to frame packet: {}", e);
                            continue;
                        }
                    };

                    if outbound_tx
                        .send(arena.split_to(written).freeze())
                        .await
                        .is_err()
                    {
                        log::warn!("Outbound channel closed");
                        return None;
                    }
                }
                Ok(()) => {}
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    // Flush pending coalesced groups before shutting down.
                    send_gro_outputs(&gro_table.flush_all(), &mut arena, &outbound_tx).await;
                    return Some(format!("TUN read error: {}", e));
                }
            }
        }
    });

    // Inbound channel decouples stream draining from TUN write syscalls. The
    // TUN writer task owns the TunWriter.
    let (tun_write_tx, mut tun_write_rx) =
        mpsc::channel::<InboundTunWrite>(INBOUND_TUN_CHANNEL_SIZE);

    // Dedicated TUN writer task. Batched channel receives reduce task wakeups;
    // write_batch coalesces consecutive same-flow TCP segments into GSO
    // super-frames on Linux, and otherwise issues one TUN write per packet.
    let mut tun_writer_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        const MAX_TUN_WRITE_FAILURES: u32 = 10;
        let mut consecutive_tun_failures = 0u32;
        let mut note_write_result = |result: VpnResult<()>| -> Option<String> {
            match result {
                Ok(()) => {
                    consecutive_tun_failures = 0;
                    None
                }
                Err(e) => {
                    consecutive_tun_failures += 1;
                    if consecutive_tun_failures >= MAX_TUN_WRITE_FAILURES {
                        log::error!(
                            "Too many consecutive TUN write failures ({}), disconnecting: {}",
                            consecutive_tun_failures,
                            e
                        );
                        return Some(format!("TUN write failures exceeded: {}", e));
                    }
                    log::warn!(
                        "Failed to write to TUN ({}/{}): {}",
                        consecutive_tun_failures,
                        MAX_TUN_WRITE_FAILURES,
                        e
                    );
                    None
                }
            }
        };
        let mut batch: Vec<InboundTunWrite> = Vec::with_capacity(WRITE_BATCH_SIZE);
        // Run buffer of consecutive metadata-less packets, flushed through
        // write_batch so same-flow TCP segments coalesce into GSO super-frames
        // on Linux (one TUN write instead of N).
        let mut plain_run: Vec<Bytes> = Vec::with_capacity(WRITE_BATCH_SIZE);
        loop {
            let count = tun_write_rx.recv_many(&mut batch, WRITE_BATCH_SIZE).await;
            if count == 0 {
                log::trace!("TUN writer task exiting");
                return None;
            }
            for req in batch.drain(..) {
                let Some(meta) = req.offload else {
                    plain_run.push(req.packet);
                    continue;
                };
                if !plain_run.is_empty() {
                    let result = tun_writer.write_batch(&plain_run).await;
                    plain_run.clear();
                    if let Some(reason) = note_write_result(result) {
                        return Some(reason);
                    }
                }
                let result = tun_writer.write_packet(Some(&meta), &req.packet).await;
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
            if !plain_run.is_empty() {
                let result = tun_writer.write_batch(&plain_run).await;
                plain_run.clear();
                if let Some(reason) = note_write_result(result) {
                    return Some(reason);
                }
            }
        }
    });

    // Inbound task: stream -> frame reader -> TUN writer channel.
    let inbound_start_time = start_time;
    let mut inbound_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        // Exact frame reader: fills frame payload storage directly from the
        // stream without zero-initializing the payload buffer.
        let mut reader = FrameReader::new(data_recv, MAX_IP_PACKET_SIZE);
        let mut seg_scratch: Vec<u8> = Vec::new();
        let mut seg_arena = BytesMut::new();
        let mut pending_segments: Vec<Bytes> = Vec::new();
        loop {
            let frame = match reader.next_frame().await {
                Ok(Some(FrameEvent::IpFrame(frame))) => frame,
                Ok(Some(FrameEvent::HeartbeatPong)) => {
                    let now = inbound_start_time.elapsed().as_millis() as u64;
                    last_pong_inbound.store(now, Ordering::Relaxed);
                    log::trace!("Heartbeat pong received");
                    continue;
                }
                Ok(Some(FrameEvent::HeartbeatPing)) => {
                    // Reply with a pong (the loop is symmetric: both ends ping).
                    if outbound_tx_pong
                        .send(Bytes::from_static(HEARTBEAT_PONG_BYTE))
                        .await
                        .is_err()
                    {
                        log::trace!("Outbound channel closed (pong)");
                        return None;
                    }
                    continue;
                }
                Ok(Some(FrameEvent::Capabilities)) => {
                    // Capabilities are exchanged once at stream setup and should
                    // not appear later in steady-state traffic.
                    log::trace!("Unexpected capabilities message received");
                    continue;
                }
                Ok(None) => {
                    log::error!("Data stream closed by peer");
                    return Some("data stream closed by peer".to_string());
                }
                Err(FrameError::Read(e)) => {
                    log::error!("Failed to read data frame: {}", e);
                    return Some(e);
                }
                Err(e) => {
                    log::error!("Failed to read data frame: {}", e);
                    return Some(e.to_string());
                }
            };

            let (offload, packet) = match parse_ip_packet_v2(&frame) {
                Ok(parts) => parts,
                Err(e) => {
                    log::warn!("Invalid IP frame from peer: {}", e);
                    continue;
                }
            };

            if let Some(meta) = offload {
                if !local_gso_enabled {
                    let materialized =
                        materialize_offload_into(&meta, packet, &mut seg_scratch, |seg| {
                            seg_arena.extend_from_slice(seg);
                            pending_segments.push(seg_arena.split_to(seg.len()).freeze());
                            Ok(())
                        });
                    if let Err(e) = materialized {
                        pending_segments.clear();
                        log::warn!("Dropping packet with unsupported offload metadata: {}", e);
                        continue;
                    }
                    for packet in pending_segments.drain(..) {
                        let req = InboundTunWrite {
                            packet,
                            offload: None,
                        };
                        if tun_write_tx.send(req).await.is_err() {
                            log::trace!("TUN writer channel closed");
                            return None;
                        }
                    }
                } else {
                    let req = InboundTunWrite {
                        packet: frame.slice_ref(packet),
                        offload: Some(meta),
                    };
                    if tun_write_tx.send(req).await.is_err() {
                        log::trace!("TUN writer channel closed");
                        return None;
                    }
                }
            } else {
                let req = InboundTunWrite {
                    packet: frame.slice_ref(packet),
                    offload: None,
                };
                if tun_write_tx.send(req).await.is_err() {
                    log::trace!("TUN writer channel closed");
                    return None;
                }
            }
        }
    });

    // Heartbeat task: sends pings via the outbound channel, checks for timeout.
    let mut heartbeat_handle: tokio::task::JoinHandle<Option<String>> = tokio::spawn(async move {
        let heartbeat_start = start_time;
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;

            let now_ms = heartbeat_start.elapsed().as_millis() as u64;
            let last_pong_ms = last_pong_heartbeat.load(Ordering::Relaxed);
            let elapsed_ms = now_ms.saturating_sub(last_pong_ms);

            if elapsed_ms > HEARTBEAT_TIMEOUT.as_millis() as u64 {
                log::error!(
                    "Heartbeat timeout: no pong received for {:.1}s (threshold: {:.1}s)",
                    elapsed_ms as f64 / 1000.0,
                    HEARTBEAT_TIMEOUT.as_secs_f64()
                );
                return Some(format!(
                    "Heartbeat timeout: no pong for {:.1}s",
                    elapsed_ms as f64 / 1000.0
                ));
            }

            let ping = Bytes::from_static(HEARTBEAT_PING_BYTE);
            if outbound_tx_heartbeat.send(ping).await.is_err() {
                log::warn!("Failed to send heartbeat ping: channel closed");
                return None;
            }
            log::trace!("Heartbeat ping sent");
        }
    });

    // Wait for any task to complete (or error), then clean up the rest.
    let (first_task, first_result, remaining) = tokio::select! {
        result = &mut outbound_handle => {
            ("outbound", result, vec![("inbound", inbound_handle), ("heartbeat", heartbeat_handle), ("writer", writer_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut inbound_handle => {
            ("inbound", result, vec![("outbound", outbound_handle), ("heartbeat", heartbeat_handle), ("writer", writer_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut heartbeat_handle => {
            ("heartbeat", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("writer", writer_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut writer_handle => {
            ("writer", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("heartbeat", heartbeat_handle), ("tun-writer", tun_writer_handle)])
        }
        result = &mut tun_writer_handle => {
            ("tun-writer", result, vec![("outbound", outbound_handle), ("inbound", inbound_handle), ("heartbeat", heartbeat_handle), ("writer", writer_handle)])
        }
    };

    for (_, handle) in &remaining {
        handle.abort();
    }

    let mut all_results = vec![(first_task, first_result)];
    for (name, handle) in remaining {
        all_results.push((name, handle.await));
    }

    let mut reasons = Vec::new();
    for (name, result) in &all_results {
        match result {
            Ok(Some(error_reason)) => reasons.push(error_reason.clone()),
            Ok(None) => reasons.push(format!("{} task ended", name)),
            Err(e) if e.is_cancelled() => {}
            Err(e) if e.is_panic() => reasons.push(format!("{} task panicked: {}", name, e)),
            Err(e) => reasons.push(format!("{} task failed: {}", name, e)),
        }
    }

    let reason = if reasons.is_empty() {
        "all tasks cancelled".to_string()
    } else {
        reasons.join("; ")
    };
    log::debug!("VPN loop ended: {}", reason);

    Err(VpnError::ConnectionLost(reason))
}

/// Frame software-GRO outputs and send them on the outbound channel. Returns
/// `false` if the channel has closed (the writer task is gone).
async fn send_gro_outputs(
    outputs: &[CoalescedOutput],
    arena: &mut BytesMut,
    outbound_tx: &mpsc::Sender<Bytes>,
) -> bool {
    for output in outputs {
        let (offload, packet): (Option<&VirtioNetHdr>, &[u8]) = match output {
            CoalescedOutput::Coalesced(hdr, packet) => (Some(hdr), packet.as_slice()),
            CoalescedOutput::Single(packet) => (None, packet.as_slice()),
        };
        let frame_size = 1
            + 4
            + 1
            + offload
                .map(|_| crate::vpn_core::offload::VIRTIO_NET_HDR_LEN)
                .unwrap_or(0)
            + packet.len();
        if arena.capacity() - arena.len() < frame_size {
            arena.reserve(FRAME_ARENA_CHUNK.max(frame_size));
        }
        let written = match append_ip_packet_v2(arena, offload, packet) {
            Ok(written) => written,
            Err(e) => {
                log::warn!("Failed to frame coalesced packet: {}", e);
                continue;
            }
        };
        if outbound_tx
            .send(arena.split_to(written).freeze())
            .await
            .is_err()
        {
            log::warn!("Outbound channel closed");
            return false;
        }
    }
    true
}
