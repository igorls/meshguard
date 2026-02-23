#!/bin/bash
# MeshGuard 4-Way WireGuard Benchmark
#
# Compares on the SAME LXC containers:
#   1. Kernel WG        (raw wg module)
#   2. MeshGuard        (Zig userspace)
#   3. wireguard-go     (Go userspace)
#   4. boringtun        (Rust userspace)
#
# Prerequisites:
#   - LXC containers mg-bench-a and mg-bench-b running
#   - All binaries installed: meshguard, wireguard-go, boringtun
#   - iperf3, wireguard-tools, iproute2 installed
#
# Usage:
#   bash docker/lxc-4way-bench.sh [duration]  # default: 10s
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
DURATION="${1:-10}"
WG_PORT=51900
IPERF_PORT=5201
MESH_IP_A="10.88.0.1"
MESH_IP_B="10.88.0.2"

# Pre-generated WG keys (static for repeatability)
WG_PRIV_A=""
WG_PUB_A=""
WG_PRIV_B=""
WG_PUB_B=""

IP_A=""
IP_B=""

header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    printf "║  %-56s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

cleanup_interfaces() {
    lxc exec $CT_A -- ip link del wg0 2>/dev/null || true
    lxc exec $CT_B -- ip link del wg0 2>/dev/null || true
    lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
    lxc exec $CT_A -- pkill wireguard-go 2>/dev/null || true
    lxc exec $CT_B -- pkill wireguard-go 2>/dev/null || true
    lxc exec $CT_A -- pkill boringtun 2>/dev/null || true
    lxc exec $CT_B -- pkill boringtun 2>/dev/null || true
    sleep 1
}

setup_wg_keys() {
    WG_PRIV_A=$(lxc exec $CT_A -- wg genkey)
    WG_PUB_A=$(echo "$WG_PRIV_A" | lxc exec $CT_A -- wg pubkey)
    WG_PRIV_B=$(lxc exec $CT_B -- wg genkey)
    WG_PUB_B=$(echo "$WG_PRIV_B" | lxc exec $CT_B -- wg pubkey)
    IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
    IP_B=$(lxc exec $CT_B -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
}

# Setup kernel WG interface
setup_kernel_wg() {
    lxc exec $CT_A -- ip link add wg0 type wireguard
    lxc exec $CT_A -- ip addr add $MESH_IP_A/24 dev wg0
    echo "$WG_PRIV_A" | lxc exec $CT_A -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_B allowed-ips $MESH_IP_B/32 endpoint $IP_B:$WG_PORT"
    lxc exec $CT_A -- ip link set wg0 up

    lxc exec $CT_B -- ip link add wg0 type wireguard
    lxc exec $CT_B -- ip addr add $MESH_IP_B/24 dev wg0
    echo "$WG_PRIV_B" | lxc exec $CT_B -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_A allowed-ips $MESH_IP_A/32 endpoint $IP_A:$WG_PORT"
    lxc exec $CT_B -- ip link set wg0 up
}

# Setup userspace WG interface (wireguard-go or boringtun)
setup_userspace_wg() {
    local binary=$1

    # Create TUN + start userspace daemon on A
    lxc exec $CT_A -T -- bash -c "WG_QUICK_USERSPACE_IMPLEMENTATION=$binary $binary wg0 >/dev/null 2>&1 &"
    sleep 1
    lxc exec $CT_A -- ip addr add $MESH_IP_A/24 dev wg0
    echo "$WG_PRIV_A" | lxc exec $CT_A -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_B allowed-ips $MESH_IP_B/32 endpoint $IP_B:$WG_PORT"
    lxc exec $CT_A -- ip link set wg0 up

    # Create TUN + start userspace daemon on B
    lxc exec $CT_B -T -- bash -c "WG_QUICK_USERSPACE_IMPLEMENTATION=$binary $binary wg0 >/dev/null 2>&1 &"
    sleep 1
    lxc exec $CT_B -- ip addr add $MESH_IP_B/24 dev wg0
    echo "$WG_PRIV_B" | lxc exec $CT_B -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_A allowed-ips $MESH_IP_A/32 endpoint $IP_A:$WG_PORT"
    lxc exec $CT_B -- ip link set wg0 up
}

setup_meshguard_wg() {
    # Kill any existing meshguard
    lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
    lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
    lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
    lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
    sleep 1

    local mg_ip_a=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")

    lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up </dev/null >/dev/null 2>&1 &"
    sleep 2
    lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up --seed $mg_ip_a:51821 </dev/null >/dev/null 2>&1 &"
    sleep 8

    # Get mesh IP for A
    MESH_IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
    echo "  MeshGuard mesh IP A: $MESH_IP_A"
}

run_benchmark() {
    local label=$1
    local target_ip=$2

    echo "  Target: $target_ip"

    # Start iperf3 server
    lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
    sleep 0.5
    lxc exec $CT_A -T -- sh -c "iperf3 -s -p $IPERF_PORT -D"
    sleep 0.5

    # Ping
    echo "  ── Latency (50 pkts) ──"
    lxc exec $CT_B -- ping -c 50 -i 0.05 "$target_ip" 2>&1 | tail -2

    # Download
    echo "  ── Download (${DURATION}s) ──"
    lxc exec $CT_B -- iperf3 -c "$target_ip" -p $IPERF_PORT -t $DURATION 2>&1 | grep -E "sender|receiver" | tail -2

    # Upload
    echo "  ── Upload (${DURATION}s) ──"
    lxc exec $CT_B -- iperf3 -c "$target_ip" -p $IPERF_PORT -t $DURATION -R 2>&1 | grep -E "sender|receiver" | tail -2

    # Cleanup
    lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
}

# ════════════════════════════════════════════════════════════
header "MeshGuard 4-Way WireGuard Benchmark"
echo "  Duration: ${DURATION}s per test"
echo "  Containers: $CT_A, $CT_B"

# Generate keys
echo ""
echo "  Generating WG keys..."
setup_wg_keys
echo "  Container A: $IP_A"
echo "  Container B: $IP_B"

# ═══ Test 1: Kernel WG ═══
header "1. KERNEL WG (Linux module)"
cleanup_interfaces
setup_kernel_wg
run_benchmark "Kernel WG" "$MESH_IP_A"
cleanup_interfaces
MESH_IP_A="10.88.0.1"  # Reset

# ═══ Test 2: MeshGuard (Zig) ═══
header "2. MESHGUARD (Zig userspace)"
setup_meshguard_wg
run_benchmark "MeshGuard" "$MESH_IP_A"
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
sleep 2
MESH_IP_A="10.88.0.1"  # Reset

# ═══ Test 3: wireguard-go ═══
if lxc exec $CT_A -- which wireguard-go >/dev/null 2>&1; then
    header "3. WIREGUARD-GO (Go userspace)"
    cleanup_interfaces
    setup_userspace_wg wireguard-go
    sleep 1
    run_benchmark "wireguard-go" "$MESH_IP_A"
    cleanup_interfaces
else
    header "3. WIREGUARD-GO — SKIPPED (not installed)"
fi

# ═══ Test 4: boringtun ═══
if lxc exec $CT_A -- which boringtun-cli >/dev/null 2>&1; then
    header "4. BORINGTUN (Rust userspace)"
    cleanup_interfaces
    # boringtun needs --disable-drop-privileges in containers
    lxc exec $CT_A -T -- bash -c "WG_SUDO=1 boringtun-cli wg0 --disable-drop-privileges -f >/dev/null 2>&1 &"
    sleep 2
    lxc exec $CT_A -- ip addr add $MESH_IP_A/24 dev wg0
    echo "$WG_PRIV_A" | lxc exec $CT_A -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_B allowed-ips $MESH_IP_B/32 endpoint $IP_B:$WG_PORT"
    lxc exec $CT_A -- ip link set wg0 up
    lxc exec $CT_B -T -- bash -c "WG_SUDO=1 boringtun-cli wg0 --disable-drop-privileges -f >/dev/null 2>&1 &"
    sleep 2
    lxc exec $CT_B -- ip addr add $MESH_IP_B/24 dev wg0
    echo "$WG_PRIV_B" | lxc exec $CT_B -- bash -c "cat | wg set wg0 private-key /dev/stdin listen-port $WG_PORT peer $WG_PUB_A allowed-ips $MESH_IP_A/32 endpoint $IP_A:$WG_PORT"
    lxc exec $CT_B -- ip link set wg0 up
    sleep 1
    run_benchmark "boringtun" "$MESH_IP_A"
    lxc exec $CT_A -- pkill boringtun-cli 2>/dev/null || true
    lxc exec $CT_B -- pkill boringtun-cli 2>/dev/null || true
    cleanup_interfaces
else
    header "4. BORINGTUN — SKIPPED (not installed)"
fi

header "Benchmark complete!"
echo "  Containers $CT_A and $CT_B are still running."
echo "  Re-run: bash docker/lxc-4way-bench.sh [duration]"
