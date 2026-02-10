# Rate Limiting for VPN Token Authentication

**Status:** Proposal (not yet implemented)

## Problem

`vpn-rs` validates an auth token during the VPN handshake. Without rate limiting, an attacker can repeatedly attempt invalid tokens and consume server resources.

### Brute-Force Considerations

- **Token strength:** Generated tokens are high entropy, but online attempts still need limits.
- **Online vs. offline:** The relevant threat is online guessing via repeated connection attempts.
- **Resource abuse:** Even failed handshakes consume CPU, socket, and scheduler resources.

## Current State

- Token validation happens early in the server-side handshake.
- Session limits cap concurrent clients, not failed auth attempts over time.
- No built-in tracking of invalid token attempts per source/token/time window.

## Goals

1. Reduce feasibility of online token guessing.
2. Preserve usability for legitimate users who mistype tokens occasionally.
3. Keep memory and CPU overhead bounded.

## Proposed Design: Hybrid Rate Limiting

Two-tier controls:

1. **Per-token limiter** for typo resilience and focused abuse
2. **Global limiter** for distributed attack detection

### Why Track by Submitted Token

During auth, submitted tokens are stable identifiers for attempts. Endpoint identifiers may be ephemeral and less useful for repeated-failure aggregation.

### Optional Secondary Keying

For additional defense, optionally combine token tracking with source-derived signals (for example, observed remote endpoint metadata) where available.

## Data Model

```rust
struct AuthRateLimiter {
    per_token: HashMap<String, TokenState>,
    global: GlobalState,
    config: RateLimitConfig,
}

struct TokenState {
    failures_in_window: u32,
    first_failure_at: Instant,
    blocked_until: Option<Instant>,
}

struct GlobalState {
    failures_in_window: u32,
    first_failure_at: Instant,
    blocked_until: Option<Instant>,
}

struct RateLimitConfig {
    per_token_max_failures: u32,
    per_token_window_secs: u64,
    per_token_block_secs: u64,

    global_max_failures: u32,
    global_window_secs: u64,
    global_block_secs: u64,

    max_tracked_tokens: usize,
}
```

## Enforcement Flow

1. Receive handshake with token.
2. Check global block state.
3. Check per-token block state.
4. Validate token.
5. On success:
- Reset that token's failure counters.
- Continue normal handshake.
6. On failure:
- Increment token and global counters.
- Apply per-token block if threshold reached.
- Apply global block if threshold reached.
- Return auth failure.

## Suggested Defaults

These values are intentionally conservative and should be tuned by deployment:

- `per_token_max_failures = 5`
- `per_token_window_secs = 300`
- `per_token_block_secs = 900`
- `global_max_failures = 100`
- `global_window_secs = 60`
- `global_block_secs = 120`
- `max_tracked_tokens = 10000`

## Operational Behavior

### Legitimate Typos

A user with occasional mistakes only affects that token's bucket and should recover after block expiration.

### Distributed Guessing

Attackers trying many tokens quickly trip the global limiter even if each token has few failures.

### Memory Bound

`max_tracked_tokens` prevents unbounded map growth. Evict least-recently-updated entries or expired entries first.

## Logging and Metrics

Add structured events:

- `auth_failed_invalid_token`
- `auth_blocked_per_token`
- `auth_blocked_global`
- `auth_rate_limit_state_eviction`

Metrics to expose:

- Failed auth count
- Per-token blocks active
- Global block active (boolean)
- Eviction count
- Top failing token fingerprints (hashed/redacted)

## Security Notes

- Never log raw tokens.
- Compare tokens in constant time where applicable.
- Use monotonic clock for limiter windows.
- Protect limiter state with low-contention synchronization.

## Configuration Sketch

Server config section:

```toml
[iroh.auth_rate_limit]
enabled = true
per_token_max_failures = 5
per_token_window_secs = 300
per_token_block_secs = 900
global_max_failures = 100
global_window_secs = 60
global_block_secs = 120
max_tracked_tokens = 10000
```

## Rollout Plan

1. Land implementation behind `enabled = false` by default.
2. Add metrics and logs first, run in observe-only mode.
3. Enable blocking in staging.
4. Tune thresholds from real traffic.
5. Enable in production/homelab defaults.

## Open Questions

- Should global limiting be fail-open or fail-closed on limiter state errors?
- Should there be separate thresholds for IPv4-only, IPv6-only, and dual-stack handshakes?
- Should successful auth clear only per-token state or also decay global pressure faster?
