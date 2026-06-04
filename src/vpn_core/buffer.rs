//! Buffer utilities for high-performance packet I/O.
//!
//! This module provides buffer allocation helpers using `MaybeUninit` and
//! `ReadBuf` to skip zeroing overhead for buffers that will be immediately
//! overwritten.

use std::future::poll_fn;
use std::io;
use std::mem::MaybeUninit;
use std::pin::Pin;
use tokio::io::{AsyncRead, ReadBuf};

/// Allocate an uninitialized byte buffer of the specified capacity.
///
/// Returns a `Vec<MaybeUninit<u8>>` where all bytes are uninitialized.
/// This is type-safe because `MaybeUninit<u8>` explicitly represents
/// that the bytes may contain uninitialized memory.
///
/// # Usage
///
/// ```ignore
/// let mut buf = uninitialized_vec(1500);
/// let mut read_buf = tokio::io::ReadBuf::uninit(&mut buf);
/// tun_reader.read_buf(&mut read_buf).await?;
/// let packet = read_buf.filled();
/// ```
///
/// # Performance
///
/// For high packet rates (1M+ pps), avoiding zeroing can reduce CPU overhead
/// significantly since each packet requires a buffer allocation.
#[inline]
pub fn uninitialized_vec(capacity: usize) -> Vec<MaybeUninit<u8>> {
    let mut buf = Vec::with_capacity(capacity);
    // MaybeUninit::uninit() returns uninitialized memory.
    // resize_with extends the Vec to capacity, filling with uninitialized values.
    // This avoids the unsafe set_len() by using the safe resize_with API.
    buf.resize_with(capacity, MaybeUninit::uninit);
    buf
}

/// Read until the unfilled portion of `buf` is full.
///
/// Tokio's `ReadBuf` safely tracks which bytes were initialized by the reader,
/// letting callers avoid zeroing large packet buffers without converting
/// uninitialized memory to `&mut [u8]`.
#[inline]
pub async fn read_exact_uninit<R>(reader: &mut R, buf: &mut ReadBuf<'_>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    while buf.remaining() > 0 {
        let filled_before = buf.filled().len();
        poll_fn(|cx| Pin::new(&mut *reader).poll_read(cx, buf)).await?;
        if buf.filled().len() == filled_before {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "early eof",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninitialized_vec_capacity() {
        let buf = uninitialized_vec(1500);
        assert_eq!(buf.len(), 1500);
        assert!(buf.capacity() >= 1500);
    }

    #[test]
    fn test_uninitialized_vec_zero_capacity() {
        let buf = uninitialized_vec(0);
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn test_uninitialized_vec_write_then_read() {
        let mut buf = uninitialized_vec(100);
        let mut read_buf = ReadBuf::uninit(&mut buf);
        let data = b"hello world";
        read_buf.put_slice(data);
        assert_eq!(read_buf.filled(), data);
    }
}
