#!/bin/bash
set -e

# Script to generate WireGuard test configuration
# This creates server and client configs for testing the UDP tunnel

# Configuration variables
WG_SUBNET="10.99.0.0/24"
WG_SERVER_IP="10.99.0.1"
WG_CLIENT_IP="10.99.0.2"
WG_SERVER_PORT="51763"
WG_TUNNEL_PORT="51763"
ALLOWED_IPS="10.99.0.0/24"

echo "WireGuard Test Configuration Generator"
echo "======================================"
echo ""
echo "Subnet: $WG_SUBNET"
echo "Server IP: $WG_SERVER_IP"
echo "Client IP: $WG_CLIENT_IP"
echo ""

# Check if wg command exists
if ! command -v wg &> /dev/null; then
    echo "Error: wireguard-tools not found. Please install it:"
    echo "  macOS: brew install wireguard-tools"
    echo "  Linux: sudo apt-get install wireguard-tools"
    exit 1
fi

# Create directory for configs (remove old files first)
rm -rf wg-test
mkdir -p wg-test
cd wg-test

echo "Generating server keypair..."
SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

echo "Generating client keypair..."
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)

# Server configuration
cat > server.conf <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $WG_SERVER_IP/24
ListenPort = $WG_SERVER_PORT

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $WG_CLIENT_IP/32
EOF

# Client configuration (for direct connection without tunnel)
cat > client-direct.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $WG_CLIENT_IP/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 127.0.0.1:$WG_SERVER_PORT
AllowedIPs = $ALLOWED_IPS
EOF

# Client configuration (for tunneled connection)
cat > client-tunnel.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $WG_CLIENT_IP/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = 127.0.0.1:$WG_TUNNEL_PORT
AllowedIPs = $ALLOWED_IPS
EOF

echo ""
echo "Configuration files generated in ./wg-test/"
echo ""
echo "Server configuration: wg-test/server.conf"
echo "Client configuration (direct): wg-test/client-direct.conf"
echo "Client configuration (tunnel): wg-test/client-tunnel.conf"
echo ""
echo "Server Public Key: $SERVER_PUBLIC_KEY"
echo "Client Public Key: $CLIENT_PUBLIC_KEY"
echo ""
echo "Testing Instructions:"
echo "===================="
echo ""
echo "1. Start WireGuard server (in Terminal 1):"
echo "   sudo wg-quick up ./wg-test/server.conf"
echo ""
echo "2. Test direct connection (without tunnel):"
echo "   sudo wg-quick up ./wg-test/client-direct.conf"
echo "   ping $WG_SERVER_IP"
echo "   sudo wg-quick down ./wg-test/client-direct.conf"
echo ""
echo "3. Test with UDP tunnel:"
echo ""
echo "   Terminal 2 - Start sender (on server side):"
echo "   udp-tunnel sender --target 127.0.0.1:$WG_SERVER_PORT"
echo "   # Note the EndpointId"
echo ""
echo "   Terminal 3 - Start receiver (on client side):"
echo "   udp-tunnel receiver --node-id <ENDPOINT_ID> --listen-port $WG_TUNNEL_PORT"
echo ""
echo "   Terminal 4 - Start client with tunnel:"
echo "   sudo wg-quick up ./wg-test/client-tunnel.conf"
echo "   ping $WG_SERVER_IP"
echo ""
echo "4. Cleanup:"
echo "   sudo wg-quick down ./wg-test/server.conf"
echo "   sudo wg-quick down ./wg-test/client-tunnel.conf"
echo ""
echo "Note: On macOS, you may need to use the WireGuard app instead of wg-quick."
echo "      Import the .conf files into the app."
