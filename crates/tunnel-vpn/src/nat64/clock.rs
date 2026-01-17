//! Time abstraction for testable timeout behavior.
//!
//! This module provides a mockable `Instant` type that can be controlled in tests
//! to verify timeout and expiry behavior without waiting for real time to pass.
//!
//! In production, this uses `std::time::Instant` directly.
//! In tests, this uses `mock_instant::Instant` which can be advanced via `MockClock`.
//!
//! # Example (in tests)
//!
//! ```ignore
//! use mock_instant::MockClock;
//! use std::time::Duration;
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

// In tests, use mock_instant for time control
#[cfg(test)]
pub use mock_instant::Instant;

// In production, use standard library Instant
#[cfg(not(test))]
pub use std::time::Instant;

// Re-export MockClock for tests
#[cfg(test)]
pub use mock_instant::MockClock;
