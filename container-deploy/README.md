# Container Deployment

Docker and Kubernetes configurations for running tunnel-rs in containerized environments.

> [!TIP]
> **Recommended Mode for Containers:** Use `iroh` mode for Docker and Kubernetes deployments. It includes relay fallback which ensures connectivity even when both peers are behind restrictive NATs (common in cloud environments). The `ice-nostr` and `ice-manual` modes use STUN-only NAT traversal which may fail in containerized environments.

## Mode Comparison

| Mode | Multi-Session | Dynamic Source | Use Case |
|------|---------------|----------------|----------|
| `iroh` | Yes | **Yes** | SSH-like tunneling, client chooses destination, best NAT traversal with relay fallback |
| `ice-nostr` | Yes | **Yes** | SSH-like tunneling, client chooses destination |
| `ice-manual` | No | No | Manual signaling, one-off tunnels |

**Multi-Session** = Multiple concurrent connections
**Dynamic Source** = Client specifies destination (iroh and ice-nostr modes)

## Dynamic Source Modes (iroh and ice-nostr)

Both `iroh` and `ice-nostr` modes use a **client-initiated** model similar to SSH `-L` tunneling:

| SSH Equivalent | tunnel-rs | Description |
|----------------|-----------|-------------|
| `ssh -L 8080:service:80` | Client with `--source` | Client requests what to tunnel |
| `sshd` with allowed hosts | Server with `--allowed-tcp` | Server whitelists allowed networks |

**Server** (runs on server, waits for connections):
- Uses `--allowed-tcp` / `--allowed-udp` with **CIDR notation** (e.g., `10.0.0.0/8`) to whitelist networks
- Does NOT specify ports — clients choose the destination
- Supports multiple concurrent sessions via `--max-sessions`

**Client** (initiates connection):
- Uses `--source` with **hostname:port** (e.g., `tcp://postgres:5432`) to request a specific service
- Uses `--target` to specify local listen address
- The source must resolve to an IP within server's allowed CIDR range

## iroh Mode Example

```bash
# Server: allow localhost and private networks
tunnel-rs server iroh \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 192.168.0.0/16 \
  --allowed-clients <CLIENT_NODE_ID>

# Client: request SSH and listen locally
tunnel-rs client iroh \
  --secret-file ./client.key \
  --node-id <server-node-id> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

> **Note:** Server requires `--allowed-clients` with client NodeIds. Generate keys with `tunnel-rs generate-iroh-key` and get NodeIds with `tunnel-rs show-iroh-node-id --secret-file <key>`.

## Docker

### Basic Example (iroh mode)

Expose an nginx service via tunnel-rs:

```bash
cd docker

# Generate client key first (you'll need the NodeId for the server)
tunnel-rs generate-iroh-key --output ./client.key
tunnel-rs show-iroh-node-id --secret-file ./client.key
# Output: 3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e

# Add client NodeId to docker-compose.yml or .env, then start
docker compose up -d

# Get server EndpointId
docker compose logs tunnel-server
# EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga

# On remote machine
tunnel-rs client iroh \
  --secret-file ./client.key \
  --node-id 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga \
  --source tcp://nginx:80 \
  --target 127.0.0.1:8080

# Access at http://127.0.0.1:8080
```

### ice-nostr Mode (automated signaling)

For persistent connections without manual EndpointId exchange:

```bash
# Generate keys
tunnel-rs generate-nostr-key --output server.nsec
# npub: npub1server...

tunnel-rs generate-nostr-key --output client.nsec
# npub: npub1client...

# Create .env with server's nsec and client's npub
cat > .env << EOF
SERVER_NSEC_FILE=./server.nsec
CLIENT_NPUB=npub1client...
EOF

docker compose -f docker-compose-nostr.yml up -d
```

### Self-Hosted Relay via Tor Hidden Service

> **⚠️ Experimental:** Tor hidden service support is experimental and might not work reliably.

Run your own iroh-relay as a Tor hidden service — no public IP required.

**Use Case:**
- Self-host relay infrastructure without exposing public IPs
- Works behind NAT, firewalls, or when Cloudflare tunnel fails (HTTP/2 breaks WebSocket upgrades)
- Direct P2P connections bypass Tor entirely (no performance impact)

```bash
cd docker

# Start Tor + iroh-relay + tunnel-rs server
docker compose -f docker-compose-tor-relay.yml up -d

# Wait for Tor to generate .onion address (30-60 seconds)
docker compose -f docker-compose-tor-relay.yml logs tor

# Get your .onion address
docker compose -f docker-compose-tor-relay.yml exec tor cat /var/lib/tor/hidden_service/hostname
# Example: abc123...xyz.onion

# Get server's EndpointId
docker compose -f docker-compose-tor-relay.yml logs tunnel-server
# EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
```

**On the client machine** (requires local Tor daemon):

```bash
# Start Tor SOCKS5 proxy
tor &  # Provides SOCKS5 on 127.0.0.1:9050

# Connect through Tor to the .onion relay
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./client.key \
  --node-id <ENDPOINT_ID> \
  --source tcp://nginx:80 \
  --target 127.0.0.1:8080

# Access at http://127.0.0.1:8080
```

> **Note:** The `--socks5-proxy` option is **Tor-only** — it requires `.onion` relay URLs and validates the proxy is Tor at startup. The server must have your client's NodeId in its `--allowed-clients` list. See [docs/tor-hidden-service.md](../docs/tor-hidden-service.md) for complete setup guide.

## Kubernetes

### Sidecar Pattern

Run tunnel-rs alongside your application:

```bash
kubectl apply -f kubernetes/deployment-sidecar.yaml

# Get EndpointId
kubectl logs -l app=myapp -c tunnel-server | grep EndpointId

# Connect from remote (replace "myapp" with your service name)
tunnel-rs client iroh \
  --secret-file ./client.key \
  --node-id <ID> \
  --source tcp://myapp:8080 \
  --target 127.0.0.1:8080
```

> **Note:** The `--source` specifies the service the server should connect to on your behalf.
> Replace `myapp:8080` with your actual service name and port (e.g., `myapp.namespace.svc:8080`).
> The server must have your client's NodeId in its `--allowed-clients` list.

### Expose Cluster Services (Multi-Session)

Access ClusterIP services from outside the cluster — like SSH tunneling but over P2P.

The server whitelists allowed sources, and clients request specific services:

```bash
# Create secrets
kubectl create secret generic tunnel-nostr-keys \
  --from-file=server.nsec=./server.nsec \
  --from-literal=peer-npub=npub1client...

kubectl apply -f kubernetes/tunnel-service.yaml
```

**Client examples** (run on your local machine):

```bash
# Tunnel to a web dashboard
tunnel-rs client ice-nostr \
  --source tcp://kubernetes-dashboard.kubernetes-dashboard.svc:443 \
  --target 127.0.0.1:8443 \
  --nsec-file ./client.nsec \
  --peer-npub <SERVER_NPUB>

# Tunnel to PostgreSQL
tunnel-rs client ice-nostr \
  --source tcp://postgres.database.svc:5432 \
  --target 127.0.0.1:5432 \
  --nsec-file ./client.nsec \
  --peer-npub <SERVER_NPUB>

# Tunnel to Redis
tunnel-rs client ice-nostr \
  --source tcp://redis.cache.svc:6379 \
  --target 127.0.0.1:6379 \
  --nsec-file ./client.nsec \
  --peer-npub <SERVER_NPUB>
```

**Advantages over `kubectl port-forward`:**
- Supports UDP (kubectl doesn't)
- Works across NAT without kubectl access
- Persistent connections with auto-reconnect
- No need for cluster credentials on client
- Multiple clients can connect simultaneously

### UDP Example (what kubectl can't do)

Tunnel UDP services like DNS or WireGuard:

```bash
# Expose cluster DNS (client requests source, server must allow it)
tunnel-rs client ice-nostr \
  --source udp://kube-dns.kube-system.svc.cluster.local:53 \
  --target 127.0.0.1:5353 \
  --nsec-file ./client.nsec \
  --peer-npub <SERVER_NPUB>

# Query cluster DNS locally
dig @127.0.0.1 -p 5353 kubernetes.default.svc.cluster.local
```

### Self-Hosted Relay via Tor Hidden Service

> **⚠️ Experimental:** Tor hidden service support is experimental and might not work reliably.

Deploy your own iroh-relay as a Tor hidden service — no LoadBalancer or Ingress required.

**Use Case:**
- Self-host relay infrastructure without public IPs or LoadBalancers
- Works in private clusters with no external ingress
- Direct P2P connections bypass Tor (no performance impact)

```bash
# Deploy Tor + iroh-relay + tunnel-server
kubectl apply -f kubernetes/tor-relay.yaml

# Wait for Tor to generate .onion address (1-2 minutes)
kubectl logs -n tunnel-tor -l app=tor-relay -c tor

# Get your .onion address
kubectl exec -n tunnel-tor deploy/tor-relay -c tor -- cat /var/lib/tor/hidden_service/hostname
# Example: abc123...xyz.onion

# Get server's EndpointId
kubectl logs -n tunnel-tor -l app=tor-relay -c tunnel-server
# EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
```

**On the client machine** (requires local Tor daemon):

```bash
# Start Tor SOCKS5 proxy
tor &  # Provides SOCKS5 on 127.0.0.1:9050

# Connect through Tor to the .onion relay
tunnel-rs client iroh \
  --relay-url http://YOUR_ADDRESS.onion \
  --socks5-proxy socks5h://127.0.0.1:9050 \
  --secret-file ./client.key \
  --node-id <ENDPOINT_ID> \
  --source tcp://my-service.default.svc:80 \
  --target 127.0.0.1:8080

# Access at http://127.0.0.1:8080
```

> **Note:** The manifest creates a `tunnel-tor` namespace with persistent storage for Tor hidden service keys. The `.onion` address persists across pod restarts. The server must have your client's NodeId in its `--allowed-clients` list.

## Use Cases

| Scenario | Mode | Description |
|----------|------|-------------|
| Quick dev access | iroh | Simple setup, relay fallback |
| Persistent tunnel | ice-nostr | Static keys, automated signaling |
| Dynamic service access | iroh/ice-nostr | Client chooses what to tunnel |
| Sidecar debugging | iroh | Access pod services directly |
| Cluster-wide access | iroh/ice-nostr | Single server, multiple services |
| UDP tunneling | any | DNS, WireGuard, game servers |
| No public IP / self-hosted relay | iroh + Tor | Relay via .onion hidden service |
