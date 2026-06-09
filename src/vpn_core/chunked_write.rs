//! Transport-agnostic chunked writer for the VPN data channel.
//!
//! The hot-path writer task drains a batch of framed packets (`&mut [Bytes]`)
//! and writes them to the transport in one go. iroh's `SendStream` exposes a
//! vectored `write_all_chunks`; plain TCP does not. This trait lets the shared
//! [`run_tunnel`](crate::vpn_core::client::run_tunnel) packet loop stay generic
//! over the transport while keeping the iroh path byte-for-byte identical (still
//! a single vectored `write_all_chunks` call per batch). Only the TCP transport,
//! used by the dummy benchmark mode, falls back to writing each chunk in turn.

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
        use tokio::io::AsyncWriteExt;
        for chunk in chunks.iter() {
            self.write_all(chunk).await?;
        }
        Ok(())
    }
}
