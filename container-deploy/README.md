# Container Deployment

Docker and Kubernetes configurations for running tunnel-rs in containerized environments.

Note: The container image `ghcr.io/andrewtheguy/tunnel-rs:latest` is iroh-only.
The `tunnel-rs-ice` binary is published in GitHub releases but is not containerized.

> [!TIP]
> **Recommended Mode:** Use `iroh` mode for all deployments. It provides the best NAT traversal with relay fallback, client authentication via NodeId, and multi-source capability where clients choose what to tunnel.

## How It Works

tunnel-rs uses a **client-initiated** model similar to SSH `-L` tunneling:

| SSH Equivalent | tunnel-rs | Description |
|----------------|-----------|-------------|
| `ssh -L 8080:service:80` | Client with `--source` | Client requests what to tunnel |
| `sshd` with allowed hosts | Server with `--allowed-tcp` | Server whitelists allowed networks |

**Server** (runs in container, waits for connections):
- Uses `--allowed-tcp` / `--allowed-udp` with **CIDR notation** (e.g., `10.0.0.0/8`) to whitelist networks
- Uses `--allowed-clients` or `--allowed-clients-file` to authenticate clients by NodeId
- Does NOT specify ports — clients choose the destination

**Client** (initiates connection from remote machine):
- Uses `--source` with **hostname:port** (e.g., `tcp://postgres:5432`) to request a specific service
- Uses `--target` to specify local listen address
- Uses `--secret-file` for authentication (server must have client's NodeId)

## Quick Start

```bash
# 1. Generate server key
tunnel-rs generate-iroh-key --output server.key

# 2. Generate client key and get NodeId
tunnel-rs generate-iroh-key --output client.key
tunnel-rs show-iroh-node-id --secret-file client.key
# Output: <CLIENT_NODE_ID>

# 3. Server: allow connections from authenticated clients
tunnel-rs server \
  --secret-file ./server.key \
  --allowed-tcp 127.0.0.0/8 \
  --allowed-tcp 192.168.0.0/16 \
  --allowed-clients <CLIENT_NODE_ID>
# Output: NodeId: <SERVER_NODE_ID>

# 4. Client: connect and request a service
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://127.0.0.1:22 \
  --target 127.0.0.1:2222
```

## Docker

Expose services via tunnel-rs with client authentication:

```bash
cd docker

# 1. Generate keys
docker run --rm ghcr.io/andrewtheguy/tunnel-rs:latest \
  generate-iroh-key --output - > server.key

docker run --rm ghcr.io/andrewtheguy/tunnel-rs:latest \
  generate-iroh-key --output - > client.key

# 2. Get client NodeId
docker run --rm -v ./client.key:/key:ro ghcr.io/andrewtheguy/tunnel-rs:latest \
  show-iroh-node-id --secret-file /key
# Output: <CLIENT_NODE_ID>

# 3. Create clients.txt
echo "<CLIENT_NODE_ID>" > clients.txt

# 4. Start services
docker compose up -d

# 5. Get server NodeId
docker compose logs tunnel-server | grep NodeId
# NodeId: <SERVER_NODE_ID>

# 6. On remote machine - connect to web service
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://web:80 \
  --target 127.0.0.1:8080

# 7. Or connect to database
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://db:5432 \
  --target 127.0.0.1:5432

# Access at http://127.0.0.1:8080 or localhost:5432
```

## Kubernetes

Access ClusterIP services from outside the cluster — like SSH tunneling but over P2P:

```bash
# 1. Generate keys
tunnel-rs generate-iroh-key --output server.key
tunnel-rs generate-iroh-key --output client.key
tunnel-rs show-iroh-node-id --secret-file client.key
# Output: <CLIENT_NODE_ID>

# 2. Create secrets
kubectl create secret generic tunnel-iroh-keys \
  --from-file=server.key=./server.key \
  --from-literal=clients.txt="<CLIENT_NODE_ID>"

# 3. Deploy
kubectl apply -f kubernetes/tunnel-deployment.yaml

# 4. Get server NodeId
kubectl logs -l app=tunnel-server | grep NodeId
```

**Client examples** (run on your local machine):

```bash
# Tunnel to PostgreSQL
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://postgres.database.svc:5432 \
  --target 127.0.0.1:5432

# Tunnel to Redis
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://redis.cache.svc:6379 \
  --target 127.0.0.1:6379

# Tunnel to a web dashboard
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source tcp://kubernetes-dashboard.kubernetes-dashboard.svc:443 \
  --target 127.0.0.1:8443
```

**Advantages over `kubectl port-forward`:**
- Supports UDP (kubectl doesn't)
- Works across NAT without kubectl access
- Persistent connections with auto-reconnect
- No need for cluster credentials on client
- Multiple clients can connect simultaneously

### UDP Example

Tunnel UDP services like DNS (something `kubectl port-forward` can't do):

```bash
# Expose cluster DNS
tunnel-rs client \
  --secret-file ./client.key \
  --server-node-id <SERVER_NODE_ID> \
  --source udp://kube-dns.kube-system.svc.cluster.local:53 \
  --target udp://127.0.0.1:5353

# Query cluster DNS locally
dig @127.0.0.1 -p 5353 kubernetes.default.svc.cluster.local
```

## Use Cases

| Scenario | Description |
|----------|-------------|
| Dev/staging access | Access services without exposing them publicly |
| Cluster-wide access | Single server, multiple services |
| UDP tunneling | DNS, WireGuard, game servers |
| NAT traversal | Works behind restrictive firewalls |
