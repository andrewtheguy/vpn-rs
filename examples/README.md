# tunnel-rs Examples

Example configurations for running tunnel-rs in Docker and Kubernetes.

## Mode Comparison

| Mode | Multi-Session | Dynamic Source | Use Case |
|------|---------------|----------------|----------|
| `iroh-default` | Yes | No | Fixed service, multiple clients |
| `nostr` | Yes | **Yes** | SSH-like tunneling, receiver chooses destination |
| `iroh-manual` | No | No | Simple one-off tunnels |
| `custom` | No | No | Best NAT traversal, one-off tunnels |

**Multi-Session** = Multiple concurrent connections
**Dynamic Source** = Receiver specifies destination (only nostr supports this)

## Nostr Mode (Dynamic Source)

Nostr mode uses a **receiver-initiated** model similar to SSH `-L` tunneling:

| SSH Equivalent | tunnel-rs | Description |
|----------------|-----------|-------------|
| `ssh -L 8080:service:80` | Receiver with `--source` | Receiver requests what to tunnel |
| `sshd` with allowed hosts | Sender with `--allowed-tcp` | Sender whitelists allowed networks |

**Sender** (runs on server, waits for connections):
- Uses `--allowed-tcp` / `--allowed-udp` with **CIDR notation** (e.g., `10.0.0.0/8`) to whitelist networks
- Does NOT specify ports — receivers choose the destination
- Supports multiple concurrent sessions via `--max-sessions`

**Receiver** (initiates connection):
- Uses `--source` with **hostname:port** (e.g., `tcp://postgres:5432`) to request a specific service
- Uses `--target` to specify local listen address
- The source must resolve to an IP within sender's allowed CIDR range

## iroh-default Mode (Fixed Source)

For simpler setups where the sender exposes a single fixed service:

```bash
# Sender: expose SSH on port 22
tunnel-rs sender iroh-default --source tcp://127.0.0.1:22

# Receiver: connect and expose locally
tunnel-rs receiver iroh-default --node-id <ID> --target tcp://127.0.0.1:2222
```

## Docker

### Basic Example (iroh-default mode)

Expose an nginx service via tunnel-rs:

```bash
cd docker
docker compose up -d

# Get EndpointId
docker compose logs tunnel-sender
# EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga

# On remote machine
tunnel-rs receiver iroh-default \
  --node-id 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga \
  --target tcp://127.0.0.1:8080

# Access at http://127.0.0.1:8080
```

### Nostr Mode (automated signaling)

For persistent connections without manual EndpointId exchange:

```bash
# Generate keys
tunnel-rs generate-nostr-key --output sender.nsec
# npub: npub1sender...

tunnel-rs generate-nostr-key --output receiver.nsec
# npub: npub1receiver...

# Create .env with sender's nsec and receiver's npub
cat > .env << EOF
SENDER_NSEC_FILE=./sender.nsec
RECEIVER_NPUB=npub1receiver...
EOF

docker compose -f docker-compose-nostr.yml up -d
```

## Kubernetes

### Sidecar Pattern

Run tunnel-rs alongside your application:

```bash
kubectl apply -f kubernetes/deployment-sidecar.yaml

# Get EndpointId
kubectl logs -l app=myapp -c tunnel-sender | grep EndpointId

# Connect from remote
tunnel-rs receiver iroh-default --node-id <ID> --target tcp://127.0.0.1:8080
```

### Expose Cluster Services (Multi-Session)

Access ClusterIP services from outside the cluster — like SSH tunneling but over P2P.

The sender whitelists allowed sources, and receivers request specific services:

```bash
# Create secrets
kubectl create secret generic tunnel-nostr-keys \
  --from-file=sender.nsec=./sender.nsec \
  --from-literal=peer-npub=npub1receiver...

kubectl apply -f kubernetes/tunnel-service.yaml
```

**Receiver examples** (run on your local machine):

```bash
# Tunnel to a web dashboard
tunnel-rs receiver nostr \
  --source tcp://kubernetes-dashboard.kubernetes-dashboard.svc:443 \
  --target tcp://127.0.0.1:8443 \
  --nsec-file ./receiver.nsec \
  --peer-npub <SENDER_NPUB>

# Tunnel to PostgreSQL
tunnel-rs receiver nostr \
  --source tcp://postgres.database.svc:5432 \
  --target tcp://127.0.0.1:5432 \
  --nsec-file ./receiver.nsec \
  --peer-npub <SENDER_NPUB>

# Tunnel to Redis
tunnel-rs receiver nostr \
  --source tcp://redis.cache.svc:6379 \
  --target tcp://127.0.0.1:6379 \
  --nsec-file ./receiver.nsec \
  --peer-npub <SENDER_NPUB>
```

**Advantages over `kubectl port-forward`:**
- Supports UDP (kubectl doesn't)
- Works across NAT without kubectl access
- Persistent connections with auto-reconnect
- No need for cluster credentials on client
- Multiple receivers can connect simultaneously

### UDP Example (what kubectl can't do)

Tunnel UDP services like DNS or WireGuard:

```bash
# Expose cluster DNS (receiver requests source, sender must allow it)
tunnel-rs receiver nostr \
  --source udp://kube-dns.kube-system.svc.cluster.local:53 \
  --target udp://127.0.0.1:5353 \
  --nsec-file ./receiver.nsec \
  --peer-npub <SENDER_NPUB>

# Query cluster DNS locally
dig @127.0.0.1 -p 5353 kubernetes.default.svc.cluster.local
```

## Use Cases

| Scenario | Mode | Description |
|----------|------|-------------|
| Quick dev access | iroh-default | Simple setup, ephemeral EndpointId |
| Persistent tunnel | nostr | Static keys, automated signaling |
| Dynamic service access | nostr (multi-session) | Receiver chooses what to tunnel |
| Sidecar debugging | iroh-default | Access pod services directly |
| Cluster-wide access | nostr | Single sender, multiple services |
| UDP tunneling | any | DNS, WireGuard, game servers |
