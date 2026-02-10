//! Single-instance lock for VPN client.
//!
//! Ensures only one VPN client instance runs at a time to prevent
//! routing conflicts and TUN device issues.
//!
//! # Platform Support
//!
//! This module supports Linux, macOS, and Windows.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("VPN lock is only supported on Linux, macOS, and Windows");

use crate::vpn_core::error::{VpnError, VpnResult};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

/// Lock file name for VPN client.
const LOCK_FILE_NAME: &str = "vpn-rs.lock";

/// A file-based lock to ensure single VPN client instance.
pub struct VpnLock {
    /// Path to the lock file.
    path: PathBuf,
    /// The lock file handle (kept open to maintain lock).
    #[allow(dead_code)]
    file: File,
}

impl VpnLock {
    /// Acquire the VPN client lock.
    ///
    /// Returns an error if another VPN client is already running.
    pub fn acquire() -> VpnResult<Self> {
        let path = Self::lock_path();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| VpnError::config_with_source("Failed to create lock directory", e))?;
        }

        // Open or create the lock file (do not truncate before acquiring lock)
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| VpnError::config_with_source("Failed to open lock file", e))?;

        // Try to acquire exclusive lock (non-blocking)
        file.try_lock_exclusive().map_err(|_| {
            VpnError::config("Another VPN client is already running. Only one instance allowed.")
        })?;

        // Now that we hold the lock, truncate and write our PID
        file.set_len(0)
            .map_err(|e| VpnError::config_with_source("Failed to truncate lock file", e))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VpnError::config_with_source("Failed to seek lock file", e))?;
        writeln!(file, "{}", std::process::id())
            .map_err(|e| VpnError::config_with_source("Failed to write PID to lock file", e))?;

        log::debug!("Acquired VPN lock: {}", path.display());

        Ok(Self { path, file })
    }

    /// Get the path to the lock file.
    fn lock_path() -> PathBuf {
        // Windows: use system temp directory (handles %TEMP%/%TMP% with proper fallbacks)
        #[cfg(target_os = "windows")]
        {
            return std::env::temp_dir().join(LOCK_FILE_NAME);
        }

        // Unix: use XDG runtime dir on Linux, TMPDIR on macOS, or /tmp as fallback
        #[cfg(not(target_os = "windows"))]
        {
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                PathBuf::from(runtime_dir).join(LOCK_FILE_NAME)
            } else if let Ok(tmpdir) = std::env::var("TMPDIR") {
                // macOS uses TMPDIR
                PathBuf::from(tmpdir).join(LOCK_FILE_NAME)
            } else {
                PathBuf::from("/tmp").join(LOCK_FILE_NAME)
            }
        }
    }

}

impl Drop for VpnLock {
    fn drop(&mut self) {
        // The lock is automatically released when the file is closed,
        // which happens when self.file is dropped. We don't remove the lock file
        // to avoid a race condition where another process could acquire a lock
        // on the about-to-be-unlinked inode while a third process creates a new
        // file with the same name.
        log::debug!("Released VPN lock: {}", self.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_acquire_release() {
        // Acquire lock
        let lock = VpnLock::acquire().expect("Should acquire lock");

        // A second lock attempt should fail while first lock is held.
        assert!(VpnLock::acquire().is_err());

        // Drop releases lock
        drop(lock);

        // Should be able to acquire again
        let _lock2 = VpnLock::acquire().expect("Should acquire lock again");
    }
}
