//! Buffer utilities for high-performance packet I/O.
//!
//! This module provides buffer allocation helpers using `MaybeUninit` to skip
//! zeroing overhead for buffers that will be immediately overwritten.

use std::mem::MaybeUninit;

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
/// let slice = unsafe { as_mut_byte_slice(&mut buf) };
/// let n = tun_reader.read(slice).await?;
/// let packet = &slice[..n];  // Only access written portion
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

/// Convert a MaybeUninit buffer to a mutable byte slice for I/O operations.
///
/// # Safety
///
/// The caller MUST ensure that:
/// 1. Only the portion written to is subsequently read (e.g., `&slice[..n]` after read returns `n`)
/// 2. The unwritten portion is never read
///
/// This is safe for read operations because:
/// - `read()` writes data into the buffer before returning
/// - Only the written portion (`&buf[..n]`) is accessed afterward
#[inline]
pub unsafe fn as_mut_byte_slice(buf: &mut [MaybeUninit<u8>]) -> &mut [u8] {
    // SAFETY: MaybeUninit<u8> has the same memory layout as u8.
    // The caller ensures only written bytes are read.
    // Note: MaybeUninit::slice_as_mut_ptr is unstable, so we use as_mut_ptr().cast().
    std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len())
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
        // Convert to byte slice for writing
        let slice = unsafe { as_mut_byte_slice(&mut buf) };
        // Simulate a read operation that writes data
        let data = b"hello world";
        slice[..data.len()].copy_from_slice(data);
        // Only access the written portion
        assert_eq!(&slice[..data.len()], data);
    }
}
