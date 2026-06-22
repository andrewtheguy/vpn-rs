//! Kernel UDP GSO (`UDP_SEGMENT`) / GRO (`UDP_GRO`) offload for the transport.
//!
//! [`crate::vpn_core::datagram::datagram_cap_for_mtu`] segments GSO super-frames
//! into ≤MTU datagrams so they never IP-fragment on the wire. That correctness
//! win turns one ~64 KB super-frame into many small datagrams, which naively
//! means one `send`/`recv` syscall each. This module restores batching:
//!
//! - **Send:** a run of equal-sized datagrams is handed to the kernel in a single
//!   `sendmsg` carrying a `UDP_SEGMENT` control message; the kernel (or NIC)
//!   emits each as an independent path-MTU UDP packet.
//! - **Recv:** `UDP_GRO` lets a single `recvmsg` return several coalesced packets
//!   at once; the segment size comes back in a control message and the caller
//!   splits the buffer back into individual datagrams.
//!
//! Each wire packet is still one independent ≤MTU UDP datagram, so a single lost
//! packet costs exactly one TCP segment — the no-fragmentation guarantee holds.
//!
//! Everything degrades safely. On non-Linux, or if the kernel/NIC rejects GSO,
//! the code falls back to one plain `send`/`recv` per datagram (identical wire
//! behavior, just more syscalls).

use bytes::Bytes;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use tokio::io::Interest;

/// Largest total payload handed to one `sendmsg(UDP_SEGMENT)` (one IP datagram's
/// worth). The kernel splits it into ≤`seg_size` pieces.
#[cfg(target_os = "linux")]
const UDP_GSO_MAX_BYTES: usize = 65535;

/// Maximum number of segments per GSO send (Linux `UDP_MAX_SEGMENTS`).
#[cfg(target_os = "linux")]
const UDP_GSO_MAX_SEGMENTS: usize = 64;

// UDP socket-option numbers (not always present in older `libc`).
#[cfg(target_os = "linux")]
const UDP_SEGMENT: libc::c_int = 103;
#[cfg(target_os = "linux")]
const UDP_GRO: libc::c_int = 104;

/// Host-wide flag: does this kernel/NIC accept `UDP_SEGMENT`? Cleared on the
/// first hard failure so we stop trying (GSO support is a property of the host).
#[cfg(target_os = "linux")]
static UDP_GSO_AVAILABLE: AtomicBool = AtomicBool::new(true);

/// 8-byte-aligned scratch for an ancillary-data (cmsg) buffer.
#[cfg(target_os = "linux")]
#[repr(align(8))]
struct CmsgBuf([u8; 64]);

/// A planned send for a contiguous slice of datagrams.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendPlan {
    /// Send datagram at this index on its own.
    Plain(usize),
    /// GSO send of `count` datagrams `[start, start+count)`: the first
    /// `count - 1` are exactly `seg_size` bytes and the last is ≤ `seg_size`.
    Gso {
        start: usize,
        count: usize,
        seg_size: usize,
    },
}

/// Plan how to transmit datagrams of the given `sizes` as a sequence of plain
/// sends and GSO runs, honoring the `UDP_SEGMENT` invariant (every segment but
/// the last in a run is exactly `seg_size`) plus the byte / segment-count caps.
pub(crate) fn plan_gso_batches(sizes: &[usize], max_bytes: usize, max_segs: usize) -> Vec<SendPlan> {
    let mut plans = Vec::new();
    let mut i = 0;
    while i < sizes.len() {
        let s = sizes[i];
        // A datagram too large for the byte budget, or with no segment budget at
        // all, can't anchor a GSO run: emit it on its own. Without this guard the
        // inner loop below can't advance `j`, so `end == i` yields a zero-count
        // Gso plan and `i = end` spins forever. (Unreachable via current callers,
        // where `s <= max_bytes` and `max_segs == 64`, but keeps the planner total.)
        if s > max_bytes || max_segs == 0 {
            plans.push(SendPlan::Plain(i));
            i += 1;
            continue;
        }
        // Grow a run of equal-size `s`, capped by segment count and byte budget.
        let mut j = i;
        let mut bytes = 0;
        while j < sizes.len() && sizes[j] == s && (j - i) < max_segs && bytes + s <= max_bytes {
            bytes += s;
            j += 1;
        }
        // Optionally append one smaller trailing datagram as the GSO "last".
        let mut end = j;
        if j < sizes.len() && sizes[j] < s && (j - i) < max_segs && bytes + sizes[j] <= max_bytes {
            end = j + 1;
        }
        if end - i == 1 {
            plans.push(SendPlan::Plain(i));
        } else {
            plans.push(SendPlan::Gso {
                start: i,
                count: end - i,
                seg_size: s,
            });
        }
        i = end;
    }
    plans
}

/// Best-effort: enable `UDP_GRO` so inbound packets coalesce into one `recvmsg`.
/// A failure (old kernel, non-Linux) just means GRO stays off — recv still works.
pub fn enable_udp_gro(socket: &UdpSocket) {
    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        let on: libc::c_int = 1;
        // SAFETY: `fd` is a valid socket; `on` outlives the call.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_UDP,
                UDP_GRO,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            log::debug!("UDP_GRO not enabled: {}", io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = socket;
}

/// Send all `datagrams`, batching equal-sized runs via UDP GSO where supported.
///
/// `dest` is `Some(addr)` for an unconnected socket (server `send_to`) or `None`
/// for a connected socket (client `send`). Wire behavior is identical to sending
/// each datagram individually; GSO only reduces syscalls.
pub async fn send_datagrams(
    socket: &UdpSocket,
    dest: Option<SocketAddr>,
    datagrams: &[Bytes],
) -> io::Result<()> {
    if datagrams.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        if datagrams.len() > 1 && UDP_GSO_AVAILABLE.load(Ordering::Relaxed) {
            return send_datagrams_gso(socket, dest, datagrams).await;
        }
    }
    send_plain(socket, dest, datagrams).await
}

/// Send each datagram with one plain `send`/`send_to`.
async fn send_plain(
    socket: &UdpSocket,
    dest: Option<SocketAddr>,
    datagrams: &[Bytes],
) -> io::Result<()> {
    for d in datagrams {
        match dest {
            Some(addr) => socket.send_to(d, addr).await?,
            None => socket.send(d).await?,
        };
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_datagrams_gso(
    socket: &UdpSocket,
    dest: Option<SocketAddr>,
    datagrams: &[Bytes],
) -> io::Result<()> {
    let sizes: Vec<usize> = datagrams.iter().map(Bytes::len).collect();
    let plans = plan_gso_batches(&sizes, UDP_GSO_MAX_BYTES, UDP_GSO_MAX_SEGMENTS);
    let dest_sa = dest.map(socket2::SockAddr::from);

    for plan in plans {
        match plan {
            SendPlan::Plain(idx) => send_plain(socket, dest, &datagrams[idx..idx + 1]).await?,
            SendPlan::Gso {
                start,
                count,
                seg_size,
            } => {
                let batch = &datagrams[start..start + count];
                if let Err(e) = send_gso_run(socket, dest_sa.as_ref(), batch, seg_size).await {
                    // Only a capability error means the kernel/NIC fundamentally
                    // cannot segment — latch GSO off host-wide for that. Transient
                    // or size-specific errors (e.g. EMSGSIZE from a momentary MTU
                    // mismatch) fall back for just this batch without poisoning the
                    // global flag, so one bad send can't permanently disable GSO.
                    let permanent = matches!(
                        e.raw_os_error(),
                        Some(libc::EINVAL) | Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP)
                    );
                    if permanent {
                        UDP_GSO_AVAILABLE.store(false, Ordering::Relaxed);
                    }
                    log::warn!(
                        "UDP GSO send failed ({e}); falling back to per-datagram sends \
                         (gso_latched_off={permanent})"
                    );
                    send_plain(socket, dest, batch).await?;
                }
            }
        }
    }
    Ok(())
}

/// One `sendmsg(UDP_SEGMENT)` for a validated GSO run. WouldBlock is handled by
/// awaiting writability and retrying, so the returned error is always terminal.
#[cfg(target_os = "linux")]
async fn send_gso_run(
    socket: &UdpSocket,
    dest: Option<&socket2::SockAddr>,
    batch: &[Bytes],
    seg_size: usize,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let seg = seg_size as u16;
    loop {
        socket.writable().await?;
        // SAFETY: `batch`/`dest` outlive the synchronous syscall; `fd` is valid.
        let res = socket.try_io(Interest::WRITABLE, || unsafe {
            raw_sendmsg_gso(fd, dest, batch, seg)
        });
        match res {
            Ok(_) => return Ok(()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Issue a single `sendmsg` with a `UDP_SEGMENT` control message of `seg_size`.
///
/// # Safety
/// `batch` and `dest` must remain valid for the duration of the call.
#[cfg(target_os = "linux")]
unsafe fn raw_sendmsg_gso(
    fd: RawFd,
    dest: Option<&socket2::SockAddr>,
    batch: &[Bytes],
    seg_size: u16,
) -> io::Result<usize> {
    unsafe {
        // Zero-copy gather: one iovec per datagram; the kernel concatenates them
        // and re-splits on `seg_size` boundaries (aligned to datagram boundaries).
        let mut iovs: Vec<libc::iovec> = batch
            .iter()
            .map(|b| libc::iovec {
                iov_base: b.as_ptr() as *mut libc::c_void,
                iov_len: b.len(),
            })
            .collect();

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = iovs.as_mut_ptr();
        msg.msg_iovlen = iovs.len() as _;
        if let Some(sa) = dest {
            msg.msg_name = sa.as_ptr() as *mut libc::c_void;
            msg.msg_namelen = sa.len();
        }

        let mut cbuf = CmsgBuf([0u8; 64]);
        msg.msg_control = cbuf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = UDP_SEGMENT;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        std::ptr::write_unaligned(data, seg_size);

        let n = libc::sendmsg(fd, &msg, 0);
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// Receive one UDP datagram (or a GRO-coalesced batch) into `buf`.
///
/// Returns `(n, seg_size, peer)`: `buf[..n]` holds the data; iterate
/// `buf[..n].chunks(seg_size)` to recover individual datagrams (one chunk when
/// no coalescing occurred). `peer` is the source address (always `Some` for an
/// unconnected socket).
pub async fn recv_split(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, usize, Option<SocketAddr>)> {
    #[cfg(target_os = "linux")]
    {
        let fd = socket.as_raw_fd();
        loop {
            socket.readable().await?;
            // The raw pointer is derived and consumed entirely inside the
            // synchronous closure, so it never crosses an await (which would make
            // the future `!Send`). SAFETY: `buf` is uniquely borrowed for the call.
            let res = socket.try_io(Interest::READABLE, || {
                let ptr = buf.as_mut_ptr();
                let len = buf.len();
                unsafe { raw_recvmsg_gro(fd, ptr, len) }
            });
            match res {
                Ok((n, gso, peer)) => {
                    // A bogus segment size (0, or larger than the buffer) means
                    // "treat the whole recv as one datagram".
                    let seg = gso.filter(|g| *g > 0 && *g <= n).unwrap_or_else(|| n.max(1));
                    return Ok((n, seg, peer));
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (n, peer) = socket.recv_from(buf).await?;
        Ok((n, n.max(1), Some(peer)))
    }
}

/// Issue a single `recvmsg`, extracting the `UDP_GRO` segment size if present.
///
/// # Safety
/// `ptr`/`len` must describe a valid, uniquely-borrowed buffer for the call.
#[cfg(target_os = "linux")]
unsafe fn raw_recvmsg_gro(
    fd: RawFd,
    ptr: *mut u8,
    len: usize,
) -> io::Result<(usize, Option<usize>, Option<SocketAddr>)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: ptr as *mut libc::c_void,
            iov_len: len,
        };
        let mut name: libc::sockaddr_storage = std::mem::zeroed();
        let mut cbuf = CmsgBuf([0u8; 64]);

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &mut name as *mut libc::sockaddr_storage as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_control = cbuf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cbuf.0.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;

        // If the control buffer was too small the kernel sets MSG_CTRUNC and drops
        // cmsgs — including the UDP_GRO segment size. Reading that as "no
        // coalescing" would collapse a multi-datagram batch into one corrupt
        // datagram, so fail loudly instead. (Cannot happen today: only one small
        // cmsg is ever requested and CmsgBuf is far larger than it needs.)
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recvmsg control data truncated (MSG_CTRUNC); cannot split GRO batch",
            ));
        }

        let mut gso: Option<usize> = None;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == UDP_GRO {
                let data = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                gso = Some(std::ptr::read_unaligned(data) as usize);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        // SAFETY: `name`/`msg_namelen` were populated by the kernel.
        let peer = socket2::SockAddr::new(name, msg.msg_namelen).as_socket();
        Ok((n, gso, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(plans: &[SendPlan]) -> Vec<(usize, usize, usize)> {
        // (kind, a, b) where kind 0 = Plain(a); kind 1 = Gso{start:a,count:b}.
        plans
            .iter()
            .map(|p| match *p {
                SendPlan::Plain(i) => (0, i, 0),
                SendPlan::Gso { start, count, .. } => (1, start, count),
            })
            .collect()
    }

    #[test]
    fn test_plan_single_datagram_is_plain() {
        assert_eq!(plan_gso_batches(&[1000], 65535, 64), vec![SendPlan::Plain(0)]);
    }

    #[test]
    fn test_plan_equal_run_with_short_last() {
        // [S, S, S, last<S] -> one GSO run covering all four, seg_size S.
        let plans = plan_gso_batches(&[1400, 1400, 1400, 600], 65535, 64);
        assert_eq!(
            plans,
            vec![SendPlan::Gso {
                start: 0,
                count: 4,
                seg_size: 1400
            }]
        );
    }

    #[test]
    fn test_plan_all_equal_no_short_last() {
        let plans = plan_gso_batches(&[1400, 1400, 1400], 65535, 64);
        assert_eq!(
            plans,
            vec![SendPlan::Gso {
                start: 0,
                count: 3,
                seg_size: 1400
            }]
        );
    }

    #[test]
    fn test_plan_size_increase_splits_runs() {
        // A larger datagram cannot extend the run; it starts a new one.
        let plans = plan_gso_batches(&[1400, 1400, 1500, 1500], 65535, 64);
        assert_eq!(
            kinds(&plans),
            vec![(1, 0, 2), (1, 2, 2)],
            "two separate GSO runs by size"
        );
    }

    #[test]
    fn test_plan_short_then_more_is_separate() {
        // After a short "last" segment closes a run, the next equal-size group is
        // its own run (a GSO buffer may hold only one short trailing segment).
        let plans = plan_gso_batches(&[1400, 600, 1400, 1400], 65535, 64);
        assert_eq!(kinds(&plans), vec![(1, 0, 2), (1, 2, 2)]);
    }

    #[test]
    fn test_plan_respects_segment_cap() {
        let sizes = vec![100usize; 10];
        let plans = plan_gso_batches(&sizes, 65535, 4);
        // 10 segments / max 4 -> runs of 4, 4, 2.
        assert_eq!(kinds(&plans), vec![(1, 0, 4), (1, 4, 4), (1, 8, 2)]);
    }

    #[test]
    fn test_plan_respects_byte_cap() {
        // max_bytes 2500 with 1000-byte datagrams -> 2 per send.
        let plans = plan_gso_batches(&[1000, 1000, 1000, 1000, 1000], 2500, 64);
        assert_eq!(kinds(&plans), vec![(1, 0, 2), (1, 2, 2), (0, 4, 0)]);
    }

    #[test]
    fn test_plan_reconstructs_every_datagram_once() {
        // Whatever the plan, the union of covered indices is exactly 0..n in order.
        let sizes = [1400, 1400, 1400, 700, 1400, 1500, 100, 100];
        let plans = plan_gso_batches(&sizes, 65535, 64);
        let mut covered = Vec::new();
        for p in &plans {
            match *p {
                SendPlan::Plain(i) => covered.push(i),
                SendPlan::Gso { start, count, .. } => covered.extend(start..start + count),
            }
        }
        assert_eq!(covered, (0..sizes.len()).collect::<Vec<_>>());
    }

    #[test]
    fn test_plan_empty() {
        assert!(plan_gso_batches(&[], 65535, 64).is_empty());
    }

    #[test]
    fn test_plan_oversized_or_zero_segs_terminates() {
        // A datagram larger than the byte budget can't anchor a GSO run; it goes
        // out plain. (Termination: this test completing at all proves the planner
        // doesn't spin on a zero-count run.)
        assert_eq!(
            plan_gso_batches(&[100_000], 65535, 64),
            vec![SendPlan::Plain(0)]
        );
        // A zero segment budget forces every datagram out on its own.
        assert_eq!(
            plan_gso_batches(&[100, 100], 65535, 0),
            vec![SendPlan::Plain(0), SendPlan::Plain(1)]
        );
        // A too-large datagram between normal ones doesn't desync the plan.
        assert_eq!(
            kinds(&plan_gso_batches(&[100, 100, 100_000, 200, 200], 65535, 64)),
            vec![(1, 0, 2), (0, 2, 0), (1, 3, 2)]
        );
    }

    /// Exercise the real `sendmsg(UDP_SEGMENT)` / `recvmsg(UDP_GRO)` path over
    /// loopback and confirm an equal-sized run (plus a short last) round-trips
    /// byte-for-byte — whether the kernel coalesces it or falls back to plain.
    #[tokio::test]
    async fn test_gso_gro_loopback_roundtrip() {
        use std::time::Duration;

        let rx = UdpSocket::bind("127.0.0.1:0").await.expect("bind rx");
        enable_udp_gro(&rx);
        let rx_addr = rx.local_addr().unwrap();

        let tx = UdpSocket::bind("127.0.0.1:0").await.expect("bind tx");
        tx.connect(rx_addr).await.expect("connect");

        // Distinct fill bytes so a misaligned GSO split would corrupt the result.
        let sent: Vec<Bytes> = vec![
            Bytes::from(vec![1u8; 1400]),
            Bytes::from(vec![2u8; 1400]),
            Bytes::from(vec![3u8; 1400]),
            Bytes::from(vec![4u8; 1400]),
            Bytes::from(vec![5u8; 600]),
        ];
        send_datagrams(&tx, None, &sent).await.expect("send batch");

        let mut buf = vec![0u8; 70_000];
        let mut got: Vec<Vec<u8>> = Vec::new();
        while got.len() < sent.len() {
            let (n, seg, _peer) = tokio::time::timeout(Duration::from_secs(3), recv_split(&rx, &mut buf))
                .await
                .expect("recv did not time out")
                .expect("recv ok");
            for d in buf[..n].chunks(seg) {
                got.push(d.to_vec());
            }
        }

        assert_eq!(got.len(), sent.len(), "datagram count must match");
        for (i, (a, b)) in sent.iter().zip(got.iter()).enumerate() {
            assert_eq!(a.as_ref(), b.as_slice(), "datagram {i} corrupted");
        }
    }

    /// A single datagram (no GSO) must also round-trip through `recv_split`.
    #[tokio::test]
    async fn test_single_datagram_loopback_roundtrip() {
        use std::time::Duration;

        let rx = UdpSocket::bind("127.0.0.1:0").await.expect("bind rx");
        enable_udp_gro(&rx);
        let rx_addr = rx.local_addr().unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.expect("bind tx");

        let payload = Bytes::from(vec![7u8; 1200]);
        send_datagrams(&tx, Some(rx_addr), std::slice::from_ref(&payload))
            .await
            .expect("send one");

        let mut buf = vec![0u8; 70_000];
        let (n, seg, peer) = tokio::time::timeout(Duration::from_secs(3), recv_split(&rx, &mut buf))
            .await
            .expect("recv did not time out")
            .expect("recv ok");
        let dgrams: Vec<&[u8]> = buf[..n].chunks(seg).collect();
        assert_eq!(dgrams.len(), 1);
        assert_eq!(dgrams[0], payload.as_ref());
        assert!(peer.is_some(), "unconnected recv must report the source addr");
    }
}
