#!/bin/bash
# MeshGuard WireGuard Benchmark: LXC Edition
#
# Uses LXC containers to compare Userspace (Zig) vs Kernel WG.
# LXC shares the host kernel, so the wireguard module is available.
#
# Requires: lxc, zig build done, wireguard kernel module loaded
set -e

MESHGUARD_SRC="$(cd "$(dirname "$0")/.." && pwd)"
MESHGUARD_BIN="$MESHGUARD_SRC/zig-out/bin/meshguard"
CT_A="mg-bench-a"
CT_B="mg-bench-b"
PROFILE="default"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  MeshGuard WireGuard LXC Benchmark                       ║"
echo "║  Userspace (Zig) vs Kernel WG — Same Kernel              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
if [ ! -f "$MESHGUARD_BIN" ]; then
    echo "ERROR: meshguard binary not found at $MESHGUARD_BIN"
    echo "Run: cd $MESHGUARD_SRC && zig build -Doptimize=ReleaseSafe"
    exit 1
fi

if ! lsmod | grep -q wireguard; then
    echo "Loading wireguard kernel module..."
    sudo modprobe wireguard
fi

cleanup() {
    echo ""
    echo "[cleanup] Deleting LXC containers..."
    lxc delete "$CT_A" --force 2>/dev/null || true
    lxc delete "$CT_B" --force 2>/dev/null || true
}

# Clean start
echo "[1/8] Cleaning up previous runs..."
cleanup 2>/dev/null

# Create containers
echo "[2/8] Creating LXC containers..."
lxc launch ubuntu:24.04 "$CT_A" 2>/dev/null
lxc launch ubuntu:24.04 "$CT_B" 2>/dev/null

# Wait for network
echo "[3/8] Waiting for containers to start..."
sleep 5

# Get IPs
IP_A=$(lxc list "$CT_A" --format=csv -c4 | head -1 | awk '{print $1}')
IP_B=$(lxc list "$CT_B" --format=csv -c4 | head -1 | awk '{print $1}')
echo "  Container A IP: $IP_A"
echo "  Container B IP: $IP_B"

# Install deps and push binary
echo "[4/8] Installing dependencies and pushing binary..."
for CT in "$CT_A" "$CT_B"; do
    lxc exec "$CT" -- apt-get update -qq 2>/dev/null
    lxc exec "$CT" -- apt-get install -y -qq iproute2 wireguard-tools iputils-ping iperf3 2>/dev/null
    lxc file push "$MESHGUARD_BIN" "$CT/usr/local/bin/meshguard"
    lxc exec "$CT" -- chmod +x /usr/local/bin/meshguard
    lxc exec "$CT" -- mkdir -p /etc/meshguard
done

# Generate identities
echo "[5/8] Generating identities and trust..."
lxc exec "$CT_A" -- env MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard keygen
lxc exec "$CT_B" -- env MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard keygen

KEY_A=$(lxc exec "$CT_A" -- cat /etc/meshguard/identity.pub)
KEY_B=$(lxc exec "$CT_B" -- cat /etc/meshguard/identity.pub)
echo "  Key A: $KEY_A"
echo "  Key B: $KEY_B"

# Mutual trust
lxc exec "$CT_A" -- env MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard trust "$KEY_B" --name node-b
lxc exec "$CT_B" -- env MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard trust "$KEY_A" --name node-a

run_test() {
    local MODE=$1
    local MODE_FLAG=""
    local MODE_LABEL=""

    if [ "$MODE" = "kernel" ]; then
        MODE_FLAG="--kernel"
        MODE_LABEL="Kernel WG"
    else
        MODE_LABEL="Userspace WG (Zig)"
    fi

    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Testing: $MODE_LABEL"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""

    # Start meshguard on both containers
    echo "  Starting meshguard ($MODE_LABEL)..."
    lxc exec "$CT_A" -- bash -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up $MODE_FLAG &" 2>/dev/null
    sleep 2
    lxc exec "$CT_B" -- bash -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up $MODE_FLAG --seed $IP_A:51821 &" 2>/dev/null

    # Wait for handshakes
    echo "  Waiting 8s for peer discovery and handshakes..."
    sleep 8

    # Get mesh IPs
    local MESH_IP_A=""
    local MESH_IP_B=""
    if [ "$MODE" = "kernel" ]; then
        MESH_IP_A=$(lxc exec "$CT_A" -- ip -4 addr show wg0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 || true)
        MESH_IP_B=$(lxc exec "$CT_B" -- ip -4 addr show wg0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 || true)
    else
        MESH_IP_A=$(lxc exec "$CT_A" -- ip -4 addr show mg0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 || true)
        MESH_IP_B=$(lxc exec "$CT_B" -- ip -4 addr show mg0 2>/dev/null | grep inet | awk '{print $2}' | cut -d/ -f1 || true)
    fi

    echo "  Mesh IP A: ${MESH_IP_A:-NOT_FOUND}"
    echo "  Mesh IP B: ${MESH_IP_B:-NOT_FOUND}"

    if [ -z "$MESH_IP_A" ]; then
        echo "  ERROR: Could not detect mesh IP for container A"
        echo "  Logs:"
        lxc exec "$CT_A" -- ip addr 2>/dev/null
        # Stop meshguard
        lxc exec "$CT_A" -- pkill meshguard 2>/dev/null || true
        lxc exec "$CT_B" -- pkill meshguard 2>/dev/null || true
        sleep 2
        return
    fi

    # Start iperf3 server on A
    lxc exec "$CT_A" -- iperf3 -s -D 2>/dev/null

    # Latency test
    echo ""
    echo "  ── Latency (ping 50 packets) ──"
    lxc exec "$CT_B" -- ping -c 50 -i 0.05 "$MESH_IP_A" 2>&1 | tail -3

    # Throughput test (download)
    echo ""
    echo "  ── Throughput Download (iperf3, 10s) ──"
    lxc exec "$CT_B" -- iperf3 -c "$MESH_IP_A" -t 10 2>&1 | tail -4

    # Throughput test (upload)
    echo ""
    echo "  ── Throughput Upload (iperf3 -R, 10s) ──"
    lxc exec "$CT_B" -- iperf3 -c "$MESH_IP_A" -t 10 -R 2>&1 | tail -4

    # Stop meshguard and iperf3
    echo ""
    echo "  Stopping services..."
    lxc exec "$CT_A" -- pkill iperf3 2>/dev/null || true
    lxc exec "$CT_A" -- pkill meshguard 2>/dev/null || true
    lxc exec "$CT_B" -- pkill meshguard 2>/dev/null || true
    sleep 3

    # Clean up WG interface for next run
    lxc exec "$CT_A" -- ip link del mg0 2>/dev/null || true
    lxc exec "$CT_A" -- ip link del wg0 2>/dev/null || true
    lxc exec "$CT_B" -- ip link del mg0 2>/dev/null || true
    lxc exec "$CT_B" -- ip link del wg0 2>/dev/null || true
    sleep 1
}

# Run both tests
echo "[6/8] Running Userspace WG benchmark..."
run_test "userspace"

echo ""
echo "[7/8] Running Kernel WG benchmark..."
run_test "kernel"

echo ""
echo "[8/8] Cleaning up..."
cleanup

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  LXC Benchmark complete!                                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
