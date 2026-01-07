//! Single-instance lock for VPN client.
//!
//! Ensures only one VPN client instance runs at a time to prevent
//! routing conflicts and TUN device issues.

use crate::error::{VpnError, VpnResult};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Lock file name for VPN client.
const LOCK_FILE_NAME: &str = "tunnel-vpn.lock";

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
            std::fs::create_dir_all(parent).map_err(|e| {
                VpnError::Config(format!("Failed to create lock directory: {}", e))
            })?;
        }

        // Try to create/open the lock file with exclusive access
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);

        #[cfg(unix)]
        {
            // Use flock for Unix systems
            opts.custom_flags(libc::O_CLOEXEC);
        }

        let file = opts.open(&path).map_err(|e| {
            VpnError::Config(format!("Failed to open lock file: {}", e))
        })?;

        // Try to acquire exclusive lock
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                return Err(VpnError::Config(
                    "Another VPN client is already running. Only one instance allowed.".into(),
                ));
            }
        }

        // Write PID to lock file for debugging
        let mut file = file;
        let _ = writeln!(file, "{}", std::process::id());

        log::debug!("Acquired VPN lock: {}", path.display());

        Ok(Self { path, file })
    }

    /// Get the path to the lock file.
    fn lock_path() -> PathBuf {
        // Use XDG runtime dir on Linux, or /tmp as fallback
        if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(runtime_dir).join(LOCK_FILE_NAME)
        } else if let Ok(tmpdir) = std::env::var("TMPDIR") {
            // macOS uses TMPDIR
            PathBuf::from(tmpdir).join(LOCK_FILE_NAME)
        } else {
            PathBuf::from("/tmp").join(LOCK_FILE_NAME)
        }
    }

    /// Check if a VPN client is already running (without acquiring lock).
    pub fn is_locked() -> bool {
        let path = Self::lock_path();
        if !path.exists() {
            return false;
        }

        // Try to acquire lock non-blocking to check
        let file = match OpenOptions::new().read(true).open(&path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                return true; // Lock is held by another process
            }
            // We got the lock - it will be released when file is dropped
        }

        false
    }
}

impl Drop for VpnLock {
    fn drop(&mut self) {
        // flock is automatically released when the file descriptor is closed,
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
        assert!(VpnLock::is_locked());

        // Drop releases lock
        drop(lock);

        // Should be able to acquire again
        let _lock2 = VpnLock::acquire().expect("Should acquire lock again");
    }
}
