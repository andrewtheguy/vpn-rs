//! Time abstraction for testable timeout behavior.
//!
//! This module provides a mockable `Instant` type that can be controlled in tests
//! to verify timeout and expiry behavior without waiting for real time to pass.
//!
//! In production, this uses `std::time::Instant` directly.
//! In tests, this uses `mock_instant::thread_local::Instant` which can be advanced
//! via `MockClock`. The `thread_local` module is used because our unit tests are
//! single-threaded, and it provides per-thread time isolation.
//!
//! # Example (in tests)
//!
//! ```ignore
//! use super::clock::MockClock;
//! use std::time::Duration;
//!
//! // Reset clock to known state at start of test
//! MockClock::set_time(Duration::ZERO);
//!
//! // Create a mapping
//! let translator = Nat64Translator::new(&config, server_ip);
//! translator.translate_6to4(&packet).unwrap();
//!
//! // Advance time past the timeout
//! MockClock::advance(Duration::from_secs(120));
//!
//! // Now cleanup should remove the expired entry
//! let removed = translator.cleanup();
//! assert_eq!(removed, 1);
//! ```

// In tests, use mock_instant for time control.
// The `thread_local` module provides per-thread time isolation,
// which is appropriate for single-threaded unit tests.
#[cfg(test)]
pub use mock_instant::thread_local::Instant;

// In production, use standard library Instant
#[cfg(not(test))]
pub use std::time::Instant;

// Re-export MockClock for tests
#[cfg(test)]
pub use mock_instant::thread_local::MockClock;
