# Rate Limiting for Token Authentication

**Status:** Proposal (not yet implemented)

## Problem

Currently, there's no rate limiting for invalid token attempts. An attacker can brute-force tokens by making many connections/streams up to `max_sessions`, enabling online guessing or resource abuse.

## Current State

- Token validation happens per-connection via dedicated auth stream in `multi_source.rs`
- Authentication occurs immediately after QUIC connection (10s timeout), before any source requests
- `remote_id` (EndpointId) is ephemeral and changes per connection - not suitable for tracking
- Session semaphore limits concurrent sessions but not auth failures
- No tracking of failed auth attempts

## Proposed Solution: Hybrid Rate Limiting (Per-Token + Global)

### Design

Two-tier protection:
1. **Per-token limit**: Handles typos - lock out individual token after N failures
2. **Global limit**: Detects distributed attacks - lock out globally if many different tokens fail fast

**Key insight**: Track by submitted auth token, not EndpointId. Auth tokens are persistent identifiers that clients use, while EndpointId is ephemeral (changes each connection).

**Token normalization**: The rate limiter tracks tokens exactly as submitted (case-sensitive, no whitespace trimming). This matches the behavior of the token validator in `auth.rs`. Operators should ensure tokens in configuration are consistently formatted (e.g., all lowercase, no leading/trailing whitespace). The rate limiter does NOT normalize tokens because:
- Attackers may probe with case/whitespace variations; treating them as distinct catches more attack patterns
- Consistent with the token validator which does exact string comparison

```rust
struct AuthRateLimiter {
    // Per-token tracking (by submitted token string)
    token_failures: DashMap<String, TokenFailureRecord>,
    max_token_failures: u32,        // default: 5
    token_lockout_duration: Duration,   // default: 60 seconds

    // Global tracking (distributed attack detection)
    // Sliding window of recent failures. Cleanup happens synchronously in record_failure():
    //   1. Lock mutex
    //   2. Push new (Instant::now(), token) entry
    //   3. Pop entries from front while oldest.0 + global_failure_window < now
    //   4. Count unique tokens in remaining window
    // This approach avoids background tasks and keeps cleanup O(n) where n = window entries.
    // Mutex contention is acceptable since failures are infrequent in normal operation;
    // under attack, the global lockout activates quickly, stopping further window updates.
    recent_failures: Mutex<VecDeque<(Instant, String)>>,
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
4. After lockout expires: Clear sliding window and resume normal operation

**Behavior during global lockout:**
- Failed auth attempts during lockout are rejected immediately with "Too many failed attempts, try again later"
- To avoid log spam under sustained attack, rejections are logged using **sampled logging**: only every Nth rejection is logged (default N=100), with a count of total rejections since lockout began
- The sliding window is NOT updated during lockout to prevent attackers from keeping the system locked indefinitely
- When lockout expires, the sliding window is cleared and the rejection counter is reset

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
- Global lockout trigger: `log::warn!("Distributed attack detected ({} unique tokens failed in {}s), global lockout for {}s", count, window, duration)`
- During lockout: Sampled at 1st and every 100th rejection to avoid log spam under attack

**Operator note:** The sample interval (default 100) can be adjusted via `lockout_log_sample_interval`. For high-traffic deployments under sustained attack, operators may also configure external log filtering or rate limiting at the log aggregator level.

## Implementation Plan

### Files to Modify

1. **`crates/tunnel-iroh/src/auth.rs`**
   - Add `AuthRateLimiter` struct with `DashMap<String, FailureRecord>`
   - Add methods: `check_rate_limit()`, `record_failure()`, `is_valid_token()`
   - Add periodic cleanup for expired entries

2. **`crates/tunnel-iroh/src/iroh_mode/multi_source.rs`**
   - Add `Arc<AuthRateLimiter>` to server state
   - Pass rate limiter to `handle_multi_source_connection()`
   - Check rate limit in auth phase before token validation
   - Record failure on invalid token (closes connection immediately)

3. **`crates/tunnel-rs/src/main.rs`**
   - Add CLI args: `--max-token-auth-failures`, `--token-lockout-duration`, `--global-auth-failure-window`, `--global-auth-failure-threshold`, `--global-lockout-duration`
   - Add to `ServerIrohParams` struct

4. **`crates/tunnel-common/src/config.rs`**
   - Add `max_token_auth_failures: Option<u32>` to `IrohConfig`
   - Add `token_lockout_duration: Option<u64>` to `IrohConfig`
   - Add `global_auth_failure_window: Option<u64>` to `IrohConfig`
   - Add `global_auth_failure_threshold: Option<u32>` to `IrohConfig`
   - Add `global_lockout_duration: Option<u64>` to `IrohConfig`

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

    // Global tracking (see struct definition above for cleanup strategy)
    recent_failures: Mutex<VecDeque<(Instant, String)>>,
    global_lockout_until: AtomicU64,
    global_failure_window: Duration,
    global_failure_threshold: u32,
    global_lockout_duration: Duration,

    // Lockout rejection counter for sampled logging (avoids log spam under attack)
    lockout_rejections: AtomicU64,
    lockout_log_sample_interval: u64,  // Log every Nth rejection (default: 100)

    // Valid tokens bypass rate limiting
    valid_tokens: Arc<HashSet<String>>,
}

struct TokenFailureRecord {
    count: u32,
    locked_until: Option<Instant>,
}

impl AuthRateLimiter {
    pub fn new(
        valid_tokens: Arc<HashSet<String>>,
        max_token_failures: u32,
        token_lockout_duration: Duration,
        global_failure_window: Duration,
        global_failure_threshold: u32,
        global_lockout_duration: Duration,
    ) -> Self {
        Self {
            token_failures: DashMap::new(),
            max_token_failures,
            token_lockout_duration,
            recent_failures: Mutex::new(VecDeque::new()),
            global_lockout_until: AtomicU64::new(0),
            global_failure_window,
            global_failure_threshold,
            global_lockout_duration,
            lockout_rejections: AtomicU64::new(0),
            lockout_log_sample_interval: 100,  // Log every 100th rejection; adjust as needed
            valid_tokens,
        }
    }

    /// Check if token is allowed to attempt auth
    /// Returns Ok(()) if allowed, Err with remaining lockout time if blocked
    pub fn check_allowed(&self, token: &str) -> Result<(), Duration> {
        // Valid tokens bypass rate limit entirely
        if self.valid_tokens.contains(token) {
            return Ok(());
        }
        // Check per-token lockout
        if let Some(record) = self.token_failures.get(token) {
            if let Some(locked_until) = record.locked_until {
                if Instant::now() < locked_until {
                    return Err(locked_until - Instant::now());
                }
            }
        }
        // Check global lockout
        let lockout_until_millis = self.global_lockout_until.load(Ordering::Relaxed);
        if lockout_until_millis > 0 {
            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            if now_millis < lockout_until_millis {
                let remaining = Duration::from_millis(lockout_until_millis - now_millis);
                return Err(remaining);
            }
        }
        Ok(())
    }

    /// Record a failed auth attempt, returns true if global lockout triggered
    pub fn record_failure(&self, token: &str) -> bool {
        // Don't track valid tokens (they won't fail anyway)
        if self.valid_tokens.contains(token) {
            return false;
        }

        // Skip recording if global lockout is active (don't extend/retrigger)
        let lockout_until_millis = self.global_lockout_until.load(Ordering::Relaxed);
        if lockout_until_millis > 0 {
            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            if now_millis < lockout_until_millis {
                // Sampled logging: only log every Nth rejection to avoid log spam
                let count = self.lockout_rejections.fetch_add(1, Ordering::Relaxed) + 1;
                if count % self.lockout_log_sample_interval == 0 || count == 1 {
                    log::warn!("Auth rejected during global lockout ({} rejections, {}ms remaining)",
                        count, lockout_until_millis - now_millis);
                }
                return false;
            }
            // Lockout expired - clear window and reset counters
            self.global_lockout_until.store(0, Ordering::Relaxed);
            self.lockout_rejections.store(0, Ordering::Relaxed);
            self.recent_failures.lock().unwrap().clear();
        }

        let now = Instant::now();

        // Update per-token failure count
        let mut entry = self.token_failures.entry(token.to_string()).or_insert(
            TokenFailureRecord { count: 0, locked_until: None }
        );
        entry.count += 1;
        if entry.count >= self.max_token_failures {
            entry.locked_until = Some(now + self.token_lockout_duration);
        }

        // Update sliding window (synchronous cleanup)
        let mut window = self.recent_failures.lock().unwrap();
        window.push_back((now, token.to_string()));

        // Prune old entries: pop from front while oldest is outside window
        let cutoff = now - self.global_failure_window;
        while let Some((timestamp, _)) = window.front() {
            if *timestamp < cutoff {
                window.pop_front();
            } else {
                break;
            }
        }

        // Count unique tokens in window
        let unique_tokens: HashSet<&String> = window.iter().map(|(_, t)| t).collect();
        if unique_tokens.len() as u32 >= self.global_failure_threshold {
            // Trigger global lockout
            let lockout_until = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + self.global_lockout_duration.as_millis() as u64;
            self.global_lockout_until.store(lockout_until, Ordering::Relaxed);
            return true;
        }

        false
    }
}
```

#### Configuration Flow

CLI args and config file values flow through `ServerIrohParams` into `run_multi_source_server()`:

```
CLI / config.toml
       │
       ▼
┌─────────────────────────────────────────────────┐
│ ServerIrohParams {                              │
│   auth_tokens: Vec<String>,                     │
│   max_token_auth_failures: u32,      // default 5     │
│   token_lockout_duration: u64,       // default 60s   │
│   global_auth_failure_window: u64,   // default 10s   │
│   global_auth_failure_threshold: u32, // default 10   │
│   global_lockout_duration: u64,      // default 60s   │
│   ...                                           │
│ }                                               │
└─────────────────────────────────────────────────┘
       │
       ▼
run_multi_source_server(params: ServerIrohParams)
       │
       ▼
AuthRateLimiter::new(
    valid_tokens,
    params.max_token_auth_failures,
    Duration::from_secs(params.token_lockout_duration),
    Duration::from_secs(params.global_auth_failure_window),
    params.global_auth_failure_threshold,
    Duration::from_secs(params.global_lockout_duration),
)
```

In `main.rs`, CLI args merge with config file (CLI takes precedence):
```rust
let max_token_auth_failures = args.max_token_auth_failures
    .or(config.iroh.as_ref().and_then(|c| c.max_token_auth_failures))
    .unwrap_or(5);
```

#### In `multi_source.rs` - Integration:

```rust
// In run_multi_source_server(), after creating auth_tokens Arc:
let rate_limiter = Arc::new(AuthRateLimiter::new(
    auth_tokens.clone(),
    params.max_token_auth_failures,
    Duration::from_secs(params.token_lockout_duration),
    Duration::from_secs(params.global_auth_failure_window),
    params.global_auth_failure_threshold,
    Duration::from_secs(params.global_lockout_duration),
));

// In handle_multi_source_connection(), during auth phase:
let token_str = request.auth_token.as_str();
if let Err(remaining) = rate_limiter.check_allowed(token_str) {
    log::warn!("Rate limit active, rejecting auth attempt for {:?}", remaining);
    let response = AuthResponse::rejected("Too many failed attempts, try again later");
    send_stream.write_all(&encode_auth_response(&response)?).await?;
    send_stream.finish()?;
    conn.close(3u32.into(), b"rate_limited");
    return Ok(());
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

## Metrics and Observability

Beyond logging, consider exposing metrics for monitoring dashboards:

**Counters** (monotonically increasing):
- `auth_attempts_total` - Total auth attempts (labels: `result={success,rejected_invalid,rejected_rate_limited}`)
- `token_lockouts_total` - Number of times individual tokens were locked out
- `global_lockouts_total` - Number of times global lockout was triggered

**Gauges** (current state):
- `tokens_currently_locked` - Number of tokens currently in per-token lockout
- `global_lockout_active` - Boolean (0/1) indicating if global lockout is active
- `global_lockout_remaining_seconds` - Seconds remaining in current global lockout (0 if not active)

**Example with `metrics` crate:**
```rust
use metrics::{counter, gauge};

// On auth success
counter!("auth_attempts_total", "result" => "success").increment(1);

// On rate limit rejection
counter!("auth_attempts_total", "result" => "rejected_rate_limited").increment(1);

// On global lockout trigger
counter!("global_lockouts_total").increment(1);
gauge!("global_lockout_active").set(1.0);

// On global lockout expiry
gauge!("global_lockout_active").set(0.0);
```

**Implementation note**: If adding metrics, consider using `metrics` crate with a compatible exporter (e.g., `metrics-exporter-prometheus` for Prometheus). This is optional and can be added in a follow-up PR.

## Alternatives Considered

1. **Per-EndpointId tracking**: EndpointId is ephemeral, changes each connection - ineffective
2. **Global only**: Punishes legitimate users for attacker's actions
3. **Per-connection tracking only**: Attacker can just reconnect
4. **IP-based tracking**: IP not available in iroh, and NAT issues
5. **Token-based delay**: Slows legitimate clients too

## Dependencies

- `dashmap` crate for DashMap (concurrent HashMap)
