# tunnel-rs Examples

Example configurations for running tunnel-rs in Docker and Kubernetes.

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
# npub1sender...

tunnel-rs generate-nostr-key --output receiver.nsec
# npub1receiver...

# Create .env
cat > .env << EOF
SENDER_NSEC=nsec1...
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

### Expose Cluster Services

Access ClusterIP services from outside the cluster (alternative to `kubectl port-forward`):

```bash
# Create secrets
kubectl create secret generic tunnel-nostr-keys \
  --from-file=sender.nsec=./sender.nsec \
  --from-literal=peer-npub=npub1...

kubectl apply -f kubernetes/tunnel-service.yaml
```

**Advantages over `kubectl port-forward`:**
- Supports UDP (kubectl doesn't)
- Works across NAT without kubectl access
- Persistent connections
- No need for cluster credentials on client

### UDP Example (what kubectl can't do)

Tunnel UDP services like DNS or WireGuard:

```bash
# Expose cluster DNS
tunnel-rs receiver nostr \
  --target udp://127.0.0.1:5353 \
  --nsec <YOUR_NSEC> \
  --peer-npub <SENDER_NPUB>

# Query cluster DNS locally
dig @127.0.0.1 -p 5353 kubernetes.default.svc.cluster.local
```

## Use Cases

| Scenario | Mode | Example |
|----------|------|---------|
| Quick dev access | iroh-default | `docker-compose.yml` |
| Persistent tunnel | nostr | `docker-compose-nostr.yml` |
| Sidecar debugging | iroh-default | `deployment-sidecar.yaml` |
| Cluster service access | nostr | `tunnel-service.yaml` |
| UDP tunneling | any | See UDP examples |
