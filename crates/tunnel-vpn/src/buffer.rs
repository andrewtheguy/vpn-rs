//! Buffer utilities for high-performance packet I/O.
//!
//! This module provides unsafe buffer allocation helpers that skip
//! zeroing overhead for buffers that will be immediately overwritten.

/// Allocate an uninitialized byte vector of the specified capacity.
///
/// This is an unsafe optimization that skips the zeroing overhead of `vec![0u8; size]`.
/// The returned Vec has length equal to capacity, but the contents are uninitialized.
///
/// # Safety
///
/// The caller MUST ensure that:
/// 1. The buffer is completely overwritten before any of its contents are read
/// 2. Only the portion that was actually written to is accessed (e.g., `&buf[..n]` after a read)
///
/// This is safe for TUN read operations because:
/// - `read()` writes data into the buffer before returning
/// - Only `&buf[..n]` (the written portion) is ever accessed
/// - The uninitialized portion beyond `n` is never read
///
/// # Example
///
/// ```ignore
/// // Safe usage - buffer is overwritten before reading
/// let mut buf = unsafe { uninitialized_vec(1500) };
/// let n = tun_reader.read(&mut buf).await?;
/// let packet = &buf[..n];  // Only access written portion
/// ```
///
/// # Performance
///
/// For high packet rates (1M+ pps), avoiding zeroing can reduce CPU overhead
/// significantly since each packet requires a buffer allocation.
#[inline]
#[allow(clippy::uninit_vec)]
pub unsafe fn uninitialized_vec(capacity: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(capacity);
    // SAFETY: Caller must ensure buffer is written before reading.
    // set_len() marks the buffer as having `capacity` bytes, but they
    // contain uninitialized memory until overwritten.
    buf.set_len(capacity);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uninitialized_vec_capacity() {
        let buf = unsafe { uninitialized_vec(1500) };
        assert_eq!(buf.len(), 1500);
        assert!(buf.capacity() >= 1500);
    }

    #[test]
    fn test_uninitialized_vec_write_then_read() {
        let mut buf = unsafe { uninitialized_vec(100) };
        // Simulate a read operation that writes data
        let data = b"hello world";
        buf[..data.len()].copy_from_slice(data);
        // Only access the written portion
        assert_eq!(&buf[..data.len()], data);
    }
}
