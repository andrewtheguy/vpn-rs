# Iroh Relay Connection Trace

This document traces the exact API calls made when `endpoint.online()` is called in iroh v0.95.1. This is useful for troubleshooting relay connectivity issues.

## Problem Context

When using iroh-relay behind Cloudflare Tunnel:
- **Quick tunnels** (`*.trycloudflare.com`) work correctly
- **Named tunnels** (custom domains via Cloudflare dashboard) may fail

The root cause is that Cloudflare named tunnels may use HTTP/2 by default, which doesn't support the WebSocket `Upgrade` header mechanism required by iroh-relay.

## API Call Chain

### 1. Entry Point

```rust
// src/endpoint.rs:902-904
pub async fn online(&self) {
    self.msock.home_relay().initialized().await;
}
```

### 2. Watcher Chain

The `home_relay()` method watches for relay addresses to be populated:

```rust
// src/magicsock.rs:351-362
pub(crate) fn home_relay(&self) -> impl Watcher<Value = Vec<RelayUrl>> {
    self.local_addrs_watch.clone().map(|addrs| {
        addrs
            .into_iter()
            .filter_map(|addr| {
                if let transports::Addr::Relay(url, _) = addr {
                    Some(url)
                } else {
                    None
                }
            })
            .collect()
    })
}
```

The `local_addrs_watch` joins multiple transport watchers:

```rust
// src/magicsock/transports.rs:153-167
pub(crate) fn local_addrs_watch(&self) -> LocalAddrsWatch {
    let ips = n0_watcher::Join::new(self.ip.iter().map(|t| t.local_addr_watch()));
    let relays = n0_watcher::Join::new(self.relay.iter().map(|t| t.local_addr_watch()));
    // ... joins and maps these watchers
}
```

The relay transport watches `my_relay`:

```rust
// src/magicsock/transports/relay.rs:165-172
pub(super) fn local_addr_watch(&self) -> ... {
    let my_endpoint_id = self.my_endpoint_id;
    self.my_relay
        .watch()
        .map(move |url| url.map(|url| (url, my_endpoint_id)))
}
```

### 3. How `my_relay` Gets Set

The `my_relay` Watchable is updated when the network report determines a preferred relay:

```rust
// src/magicsock/transports/relay/actor.rs:977-995
async fn on_network_change(&mut self, report: Report) {
    let my_relay = self.config.my_relay.get();
    if report.preferred_relay == my_relay {
        return; // No change
    }
    let old_relay = self
        .config
        .my_relay
        .set(report.preferred_relay.clone())
        .unwrap_or_else(|e| e);
    // ...
}
```

The `preferred_relay` is determined by running latency probes to all configured relay servers.

### 4. The Actual Connection

When the RelayActor needs to connect to a relay server:

```rust
// src/magicsock/transports/relay/actor.rs:482-493
fn dial_relay(&self) -> impl Future<Output = Result<Client, DialError>> {
    let client_builder = self.relay_client_builder.clone();
    async move {
        match time::timeout(CONNECT_TIMEOUT, client_builder.connect()).await {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(err)) => Err(e!(DialError::Connect, err)),
            Err(_) => Err(e!(DialError::Timeout { timeout: CONNECT_TIMEOUT })),
        }
    }
}
```

### 5. ClientBuilder::connect() Details

Located in `iroh-relay/src/client.rs:212-302`:

```rust
pub async fn connect(&self) -> Result<Client, ConnectError> {
    // 1. URL setup
    let mut dial_url = (*self.url).clone();
    dial_url.set_path(RELAY_PATH);  // "/relay"
    dial_url.set_scheme(match self.url.scheme() {
        "http" => "ws",
        "ws" => "ws",
        _ => "wss",  // https -> wss
    })?;

    // 2. Establish TCP + TLS connection
    let stream = MaybeTlsStreamBuilder::new(dial_url.clone(), self.dns_resolver.clone())
        .prefer_ipv6(self.prefer_ipv6())
        .proxy_url(self.proxy_url.clone())
        .connect()
        .await?;

    // 3. WebSocket upgrade
    let mut builder = tokio_websockets::ClientBuilder::new()
        .uri(dial_url.as_str())?
        .add_header(
            SEC_WEBSOCKET_PROTOCOL,
            http::HeaderValue::from_static(RELAY_PROTOCOL_VERSION),  // "iroh-relay-v1"
        )?
        .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME_SIZE)));

    // Optional: TLS key export for client auth
    if let Some(client_auth) = KeyMaterialClientAuth::new(&self.secret_key, &stream) {
        builder = builder.add_header(CLIENT_AUTH_HEADER, client_auth.into_header_value())?;
    }

    let (conn, response) = builder.connect_on(stream).await?;

    // 4. Verify upgrade succeeded
    ensure!(
        response.status() == hyper::StatusCode::SWITCHING_PROTOCOLS,
        ConnectError::UnexpectedUpgradeStatus { code: response.status() }
    );

    // 5. Complete iroh-relay handshake
    let conn = Conn::new(conn, self.key_cache.clone(), &self.secret_key).await?;

    Ok(Client { conn, local_addr: Some(local_addr) })
}
```

### 6. MaybeTlsStreamBuilder::connect() Details

Located in `iroh-relay/src/client/tls.rs:62-108`:

```rust
pub async fn connect(self) -> Result<MaybeTlsStream<ProxyStream>, ConnectError> {
    // 1. Setup TLS config with webpki roots
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::client::ClientConfig::builder_with_provider(...)
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();

    // 2. Dial the URL (DNS + TCP)
    let tcp_stream = self.dial_url(&tls_connector).await?;

    // 3. TLS handshake if needed
    if self.use_tls() {
        let hostname = self.tls_servername()?;
        let tls_stream = tls_connector.connect(hostname, tcp_stream).await?;
        Ok(MaybeTlsStream::Tls(tls_stream))
    } else {
        Ok(MaybeTlsStream::Raw(tcp_stream))
    }
}
```

### 7. dial_url_direct() Details

```rust
// iroh-relay/src/client/tls.rs:139-160
async fn dial_url_direct(&self) -> Result<tokio::net::TcpStream, DialError> {
    // 1. DNS resolution
    let dst_ip = self.dns_resolver
        .resolve_host(&self.url, self.prefer_ipv6, DNS_TIMEOUT)
        .await?;

    // 2. TCP connect with timeout
    let port = url_port(&self.url)?;
    let addr = SocketAddr::new(dst_ip, port);
    let tcp_stream = time::timeout(DIAL_ENDPOINT_TIMEOUT, async move {
        TcpStream::connect(addr).await
    }).await??;

    tcp_stream.set_nodelay(true)?;
    Ok(tcp_stream)
}
```

## Key Constants and Timeouts

| Constant | Value | Location | Description |
|----------|-------|----------|-------------|
| `CONNECT_TIMEOUT` | 10s | `actor.rs:84` | Overall dial timeout |
| `DNS_TIMEOUT` | 1s | `defaults.rs:34` | DNS resolution timeout |
| `DIAL_ENDPOINT_TIMEOUT` | 1.5s | `defaults.rs:32` | TCP connect timeout |
| `RELAY_PATH` | `/relay` | `http.rs:12` | HTTP path for relay endpoint |
| `RELAY_PROTOCOL_VERSION` | `iroh-relay-v1` | `http.rs:20` | WebSocket sub-protocol |
| `CLIENT_AUTH_HEADER` | `x-iroh-relay-client-auth-v1` | `http.rs:22` | Optional auth header |

## HTTP Request/Response

### WebSocket Upgrade Request

```http
GET /relay HTTP/1.1
Host: your-relay-server.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Key: <random-base64>
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: iroh-relay-v1
X-Iroh-Relay-Client-Auth-V1: <optional-tls-keying-material>
```

### Expected Response

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: <computed-hash>
Sec-WebSocket-Protocol: iroh-relay-v1
```

## Cloudflare Tunnel Issue

### Why Quick Tunnels Work

Cloudflare quick tunnels (`*.trycloudflare.com`) automatically detect WebSocket traffic and handle the HTTP/1.1 upgrade correctly.

### Why Named Tunnels May Fail

Named tunnels configured via the Cloudflare dashboard may:
1. Use HTTP/2 by default for the connection to origin
2. HTTP/2 doesn't support the `Upgrade` header mechanism
3. The WebSocket upgrade fails silently or returns unexpected status codes

### Verification

You can verify this with curl:

```bash
# HTTP/2 (may fail) - returns 400 Bad Request
curl -v https://your-named-tunnel.example.com/relay

# HTTP/1.1 (should work) - returns 101 Switching Protocols
curl -v --http1.1 \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Protocol: iroh-relay-v1" \
  https://your-named-tunnel.example.com/relay
```

### Potential Solutions

1. **cloudflared config**: Set `http2Origin: false` in your cloudflared config
2. **Cloudflare Dashboard**: Check tunnel settings for HTTP/2 to origin options
3. **Origin Server**: Configure the relay server to signal HTTP/1.1 preference

## File References

- `iroh-0.95.1/src/endpoint.rs:902` - `online()` entry point
- `iroh-0.95.1/src/magicsock.rs:351` - `home_relay()` watcher
- `iroh-0.95.1/src/magicsock/transports/relay.rs:165` - relay transport watcher
- `iroh-0.95.1/src/magicsock/transports/relay/actor.rs:482` - `dial_relay()`
- `iroh-relay-0.95.1/src/client.rs:212` - `ClientBuilder::connect()`
- `iroh-relay-0.95.1/src/client/tls.rs:62` - `MaybeTlsStreamBuilder::connect()`
- `iroh-relay-0.95.1/src/http.rs` - HTTP constants
- `iroh-relay-0.95.1/src/defaults.rs` - timeout constants
