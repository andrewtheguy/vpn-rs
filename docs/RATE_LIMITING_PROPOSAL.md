# Rate Limiting for Token Authentication

**Status:** Proposal (not yet implemented)

## Problem

Currently, there's no rate limiting for invalid token attempts. An attacker can brute-force tokens by making many connections/streams up to `max_sessions`, enabling online guessing or resource abuse.

## Current State

- Token validation happens per-stream in `multi_source.rs`
- `remote_id` (EndpointId) is ephemeral and changes per connection - not suitable for tracking
- Session semaphore limits concurrent sessions but not auth failures
- No tracking of failed auth attempts

## Proposed Solution: Hybrid Rate Limiting (Per-Token + Global)

### Design

Two-tier protection:
1. **Per-token limit**: Handles typos - lock out individual token after N failures
2. **Global limit**: Detects distributed attacks - lock out globally if many different tokens fail fast

**Key insight**: Track by submitted auth token, not EndpointId. Auth tokens are persistent identifiers that clients use, while EndpointId is ephemeral (changes each connection).

```rust
struct AuthRateLimiter {
    // Per-token tracking (by submitted token string)
    token_failures: DashMap<String, TokenFailureRecord>,
    max_token_failures: u32,        // default: 5
    token_lockout_duration: Duration,   // default: 60 seconds

    // Global tracking (distributed attack detection)
    recent_failures: Mutex<VecDeque<(Instant, String)>>,  // sliding window of (time, token)
    global_lockout_until: AtomicU64,    // millis since UNIX_EPOCH, 0 = not locked
    global_failure_window: Duration,    // default: 10 seconds
    global_failure_threshold: u32,      // default: 10 unique tokens
    global_lockout_duration: Duration,  // default: 60 seconds

    // Valid tokens from config (bypass rate limiting)
    valid_tokens: Arc<HashSet<String>>,
}

struct TokenFailureRecord {
    count: u32,
    locked_until: Option<Instant>,
}
```

### Behavior

**Per-Token (handles typos):**
1. On invalid token X: Increment X's failure count
2. After N failures for same token X: Lock out attempts with token X
3. On valid token: Token is in `valid_tokens` set, no tracking needed

**Global (detects distributed attacks):**
1. Track recent failures in sliding window (last 10 seconds)
2. If failures from N unique tokens in window: Trigger global lockout
3. Global lockout: Reject ALL new auth attempts (except already-valid tokens)
4. After lockout expires: Clear window, allow new attempts

**Valid tokens**: Tokens in the server's configured `valid_tokens` set bypass both per-token and global limits

### Configuration Options

**Per-token:**
- `--max-token-auth-failures <N>` (default: 5)
- `--token-lockout-duration <SECONDS>` (default: 60)

**Global (distributed attack):**
- `--global-auth-failure-window <SECONDS>` (default: 10)
- `--global-auth-failure-threshold <N>` (default: 10 unique tokens)
- `--global-lockout-duration <SECONDS>` (default: 60)

Config file options: `max_token_auth_failures`, `token_lockout_duration`, `global_auth_failure_window`, `global_auth_failure_threshold`, `global_lockout_duration`

### Logging

- Per-token: `log::warn!("Token [redacted] locked out after {} failed attempts", count)`
- Global: `log::warn!("Distributed attack detected ({} unique tokens failed in {}s), global lockout for {}s", count, window, duration)`

## Implementation Plan

### Files to Modify

1. **`crates/tunnel-iroh/src/auth.rs`**
   - Add `AuthRateLimiter` struct with `DashMap<String, FailureRecord>`
   - Add methods: `check_rate_limit()`, `record_failure()`, `is_valid_token()`
   - Add periodic cleanup for expired entries

2. **`crates/tunnel-iroh/src/iroh_mode/multi_source.rs`**
   - Add `Arc<AuthRateLimiter>` to server state
   - Pass rate limiter to `handle_multi_source_connection()` and `handle_multi_source_stream()`
   - Check rate limit before token validation
   - Record failure on invalid token

3. **`crates/tunnel-rs/src/main.rs`**
   - Add CLI args: `--max-auth-failures`, `--auth-lockout-duration`
   - Add to `ServerIrohParams` struct

4. **`crates/tunnel-common/src/config.rs`**
   - Add `max_auth_failures: Option<u32>` to `IrohConfig`
   - Add `auth_lockout_duration: Option<u64>` to `IrohConfig`

5. **`server.toml.example`**
   - Add commented examples for new config options

6. **`Cargo.toml` (tunnel-iroh)**
   - Add `dashmap` dependency for concurrent HashMap

### Code Sketch

#### In `auth.rs` - New rate limiter:

```rust
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct AuthRateLimiter {
    // Per-token tracking
    token_failures: DashMap<String, TokenFailureRecord>,
    max_token_failures: u32,
    token_lockout_duration: Duration,

    // Global tracking
    recent_failures: Mutex<VecDeque<(Instant, String)>>,
    global_lockout_until: AtomicU64,
    global_failure_window: Duration,
    global_failure_threshold: u32,
    global_lockout_duration: Duration,

    // Valid tokens bypass rate limiting
    valid_tokens: Arc<HashSet<String>>,
}

struct TokenFailureRecord {
    count: u32,
    locked_until: Option<Instant>,
}

impl AuthRateLimiter {
    pub fn new(valid_tokens: Arc<HashSet<String>>, /* config params */) -> Self { ... }

    /// Check if token is allowed to attempt auth
    /// Returns Ok(()) if allowed, Err with remaining lockout time if blocked
    pub fn check_allowed(&self, token: &str) -> Result<(), Duration> {
        // Valid tokens bypass rate limit entirely
        if self.valid_tokens.contains(token) {
            return Ok(());
        }
        // Check per-token lockout, then global lockout
        // ...
    }

    /// Record a failed auth attempt, returns true if global lockout triggered
    pub fn record_failure(&self, token: &str) -> bool {
        // Don't track valid tokens (they won't fail anyway)
        if self.valid_tokens.contains(token) {
            return false;
        }
        // Increment per-token failure count
        // Add to sliding window
        // Check if global threshold reached
        // ...
    }
}
```

#### In `multi_source.rs` - Integration:

```rust
// In run_multi_source_server(), after creating auth_tokens Arc:
let rate_limiter = Arc::new(AuthRateLimiter::new(
    auth_tokens.clone(),
    /* config */
));

// In handle_multi_source_stream(), before token validation:
let token_str = request.auth_token.as_str();
if let Err(remaining) = rate_limiter.check_allowed(token_str) {
    log::warn!("Rate limit active, rejecting auth attempt for {:?}", remaining);
    let response = SourceResponse::rejected("Too many failed attempts, try again later");
    // ... send response and return
}

// After invalid token:
if rate_limiter.record_failure(token_str) {
    log::warn!("Global auth rate limit reached, lockout activated");
}

// Valid tokens don't need explicit success recording - they're in valid_tokens set
```

## Testing

- Unit tests for `AuthRateLimiter` (failure counting, lockout, decay)
- Integration test: verify lockout after N failures
- Verify legitimate clients with valid tokens unaffected

## Alternatives Considered

1. **Per-EndpointId tracking**: EndpointId is ephemeral, changes each connection - ineffective
2. **Global only**: Punishes legitimate users for attacker's actions
3. **Per-connection tracking only**: Attacker can just reconnect
4. **IP-based tracking**: IP not available in iroh, and NAT issues
5. **Token-based delay**: Slows legitimate clients too

## Dependencies

- `dashmap` crate for DashMap (concurrent HashMap)
