//! Transport-agnostic chunked writer for the VPN data channel.
//!
//! The hot-path writer task drains a batch of framed packets (`&mut [Bytes]`)
//! and writes them to the transport in one go. iroh's `SendStream` exposes a
//! vectored `write_all_chunks`; plain TCP does not. This trait lets the shared
//! [`run_tunnel`](crate::vpn_core::client::run_tunnel) packet loop stay generic
//! over the transport while keeping the iroh path byte-for-byte identical (still
//! a single vectored `write_all_chunks` call per batch). The TCP transport, used
//! by the dummy benchmark mode, sends the batch with vectored `writev` so it too
//! issues roughly one syscall per batch rather than one per frame.

use bytes::Bytes;
use std::io;

/// Write every byte of every chunk to the underlying transport.
///
/// `Send` is required because the writer task moves the writer into a spawned
/// tokio task. The `chunks` slice may be mutated by the implementation (iroh
/// advances the buffers it consumes), so callers must `clear()` and refill it
/// rather than relying on its contents after the call.
pub trait ChunkedWrite: Send {
    fn write_all_chunks(
        &mut self,
        chunks: &mut [Bytes],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

impl ChunkedWrite for iroh::endpoint::SendStream {
    async fn write_all_chunks(&mut self, chunks: &mut [Bytes]) -> io::Result<()> {
        // Fully qualified to call iroh's inherent vectored method, not this
        // trait method (which would recurse).
        iroh::endpoint::SendStream::write_all_chunks(self, chunks)
            .await
            .map_err(io::Error::other)
    }
}

impl ChunkedWrite for tokio::net::tcp::OwnedWriteHalf {
    async fn write_all_chunks(&mut self, chunks: &mut [Bytes]) -> io::Result<()> {
        use std::io::IoSlice;
        use tokio::io::AsyncWriteExt;

        // Send the whole batch with vectored writes (one `writev` syscall when
        // the socket accepts it all), matching iroh's batched `write_all_chunks`
        // rather than one `write_all` syscall per frame. A cursor (chunk index +
        // byte offset into that chunk) tracks progress so partial writes just
        // resume from where `writev` stopped.
        let mut chunk_idx = 0;
        let mut offset = 0;
        while chunk_idx < chunks.len() {
            let mut slices: Vec<IoSlice<'_>> = Vec::with_capacity(chunks.len() - chunk_idx);
            slices.push(IoSlice::new(&chunks[chunk_idx][offset..]));
            for chunk in &chunks[chunk_idx + 1..] {
                slices.push(IoSlice::new(chunk));
            }

            let mut written = self.write_vectored(&slices).await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "TCP write accepted zero bytes",
                ));
            }
            // Advance the cursor past the accepted bytes.
            while written > 0 {
                let remaining = chunks[chunk_idx].len() - offset;
                if written < remaining {
                    offset += written;
                    written = 0;
                } else {
                    written -= remaining;
                    chunk_idx += 1;
                    offset = 0;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    /// Sends a multi-MB batch over loopback TCP — large enough to fill the
    /// socket buffer and force several partial `writev`s — and verifies every
    /// byte arrives in order, exercising the cursor/partial-write logic.
    #[tokio::test]
    async fn tcp_write_all_chunks_writes_every_byte_in_order() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (_client_read, mut client_write) = client.into_split();

        // 128 chunks of 64 KiB, each filled with a distinct byte so order and
        // boundaries are verifiable.
        let mut chunks: Vec<Bytes> = (0..128u32)
            .map(|i| Bytes::from(vec![(i % 251) as u8; 64 * 1024]))
            .collect();
        let expected: Vec<u8> = chunks.iter().flatten().copied().collect();

        let writer = tokio::spawn(async move {
            client_write.write_all_chunks(&mut chunks).await.unwrap();
            // Dropping the write half shuts down the stream (sends FIN).
        });

        let mut got = Vec::with_capacity(expected.len());
        let mut server = server;
        server.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();

        assert_eq!(got.len(), expected.len());
        assert_eq!(got, expected);
    }
}
