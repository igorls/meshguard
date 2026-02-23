#!/bin/bash
# MeshGuard WireGuard Benchmark: Userspace (Zig) vs Kernel
#
# Measures throughput and latency over encrypted WG tunnels.
# Requires: docker compose, zig build already done.
set -e

COMPOSE="docker compose -f docker-compose.bench.yml"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  MeshGuard WireGuard Benchmark                       ║"
echo "║  Userspace (Zig) vs Kernel WG                        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Clean start
echo "[1/6] Cleaning up previous runs..."
$COMPOSE down --volumes 2>/dev/null || true

# Build
echo "[2/6] Building containers..."
$COMPOSE up --build -d 2>&1 | tail -5

# Wait for handshakes
echo "[3/6] Waiting 15s for handshakes to complete..."
sleep 15

# Get mesh IPs
echo "[4/6] Collecting mesh IPs..."
ZIG_SERVER_IP=$($COMPOSE exec zig-server sh -c 'ip -4 addr show mg0 | grep inet | awk "{print \$2}" | cut -d/ -f1' 2>/dev/null)
KERNEL_SERVER_IP=$($COMPOSE exec kernel-server sh -c 'ip -4 addr show mg0 2>/dev/null | grep inet | awk "{print \$2}" | cut -d/ -f1 || ip -4 addr show wg0 2>/dev/null | grep inet | awk "{print \$2}" | cut -d/ -f1' 2>/dev/null)

echo "  Zig server mesh IP:    $ZIG_SERVER_IP"
echo "  Kernel server mesh IP: $KERNEL_SERVER_IP"
echo ""

# Show handshake logs
echo "── Handshake summary ──"
$COMPOSE logs 2>&1 | grep -E "(handshake|WG handshake|mode:|TUN device)" | head -16
echo ""

if [ -z "$ZIG_SERVER_IP" ]; then
    echo "ERROR: Could not get Zig server mesh IP. Showing logs:"
    $COMPOSE logs zig-server 2>&1 | tail -10
    echo ""
    echo "Falling back to ping test only..."
fi

# Ping latency test
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Latency Test (ping, 20 packets)                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ -n "$ZIG_SERVER_IP" ]; then
    echo "── Userspace WG (Zig) ──"
    $COMPOSE exec zig-client ping -c 20 -i 0.1 "$ZIG_SERVER_IP" 2>&1 | tail -3
    echo ""
fi

if [ -n "$KERNEL_SERVER_IP" ]; then
    echo "── Kernel WG ──"
    $COMPOSE exec kernel-client ping -c 20 -i 0.1 "$KERNEL_SERVER_IP" 2>&1 | tail -3
    echo ""
fi

# iperf3 throughput test
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Throughput Test (iperf3, 10 seconds)                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ -n "$ZIG_SERVER_IP" ]; then
    echo "── Userspace WG (Zig) ──"
    $COMPOSE exec zig-client iperf3 -c "$ZIG_SERVER_IP" -t 10 2>&1 | tail -4
    echo ""
fi

if [ -n "$KERNEL_SERVER_IP" ]; then
    echo "── Kernel WG ──"
    $COMPOSE exec kernel-client iperf3 -c "$KERNEL_SERVER_IP" -t 10 2>&1 | tail -4
    echo ""
fi

# Reverse (upload) test
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Upload Test (iperf3 -R, 10 seconds)                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

if [ -n "$ZIG_SERVER_IP" ]; then
    echo "── Userspace WG (Zig) ──"
    $COMPOSE exec zig-client iperf3 -c "$ZIG_SERVER_IP" -t 10 -R 2>&1 | tail -4
    echo ""
fi

if [ -n "$KERNEL_SERVER_IP" ]; then
    echo "── Kernel WG ──"
    $COMPOSE exec kernel-client iperf3 -c "$KERNEL_SERVER_IP" -t 10 -R 2>&1 | tail -4
    echo ""
fi

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Benchmark complete!                                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Run '$COMPOSE down --volumes' to clean up."
