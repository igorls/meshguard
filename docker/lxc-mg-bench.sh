#!/bin/bash
# MeshGuard Standalone Benchmark
#
# Runs only the MeshGuard (Zig userspace) benchmark on LXC containers.
# Faster iteration loop: deploy → bench → tweak → repeat.
#
# Usage:
#   bash docker/lxc-mg-bench.sh [duration] [encrypt-workers]
#   bash docker/lxc-mg-bench.sh 10          # 10s, default workers
#   bash docker/lxc-mg-bench.sh 10 8        # 10s, 8 encrypt workers
#   bash docker/lxc-mg-bench.sh 10 0        # 10s, serial mode
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
DURATION="${1:-10}"
ENCRYPT_WORKERS="${2:-}"
IPERF_PORT=5201

header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    printf "║  %-56s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

header "MeshGuard Standalone Benchmark"
echo "  Duration: ${DURATION}s"
if [ -n "$ENCRYPT_WORKERS" ]; then
    echo "  Encrypt workers: $ENCRYPT_WORKERS"
fi
echo "  Containers: $CT_A, $CT_B"

# ── Cleanup ──
echo ""
echo "[1/4] Cleaning up..."
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
sleep 1

# ── Start MeshGuard ──
echo "[2/4] Starting MeshGuard..."
MG_IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")

EXTRA_ARGS=""
if [ -n "$ENCRYPT_WORKERS" ]; then
    EXTRA_ARGS="--encrypt-workers $ENCRYPT_WORKERS"
fi

lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up $EXTRA_ARGS </dev/null >/dev/null 2>/tmp/meshguard.stderr &"
sleep 2
lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up --seed $MG_IP_A:51821 $EXTRA_ARGS </dev/null >/dev/null 2>/tmp/meshguard.stderr &"
sleep 8

# Get mesh IP
MESH_IP=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
if [ -z "$MESH_IP" ]; then
    echo "ERROR: MeshGuard did not come up. Checking logs..."
    lxc exec $CT_A -- sh -c "journalctl -u meshguard --no-pager -n 20 2>/dev/null || true"
    exit 1
fi
echo "  Mesh IP A: $MESH_IP"

# ── Benchmark ──
echo "[3/4] Running benchmark..."

# Start iperf3 server
lxc exec $CT_A -T -- sh -c "iperf3 -s -p $IPERF_PORT -D"
sleep 0.5

header "Latency (50 packets)"
lxc exec $CT_B -- ping -c 50 -i 0.05 "$MESH_IP" 2>&1 | tail -2

header "Download (${DURATION}s)"
lxc exec $CT_B -- iperf3 -c "$MESH_IP" -p $IPERF_PORT -t $DURATION 2>&1 | grep -E "sender|receiver" | tail -2

header "Upload (${DURATION}s)"
lxc exec $CT_B -- iperf3 -c "$MESH_IP" -p $IPERF_PORT -t $DURATION -R 2>&1 | grep -E "sender|receiver" | tail -2

# ── Cleanup ──
echo "[4/4] Cleaning up..."
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true

# ── Show diagnostics ──
GSO_LOG_A=$(lxc exec $CT_A -- cat /tmp/meshguard.stderr 2>/dev/null | head -5)
GSO_LOG_B=$(lxc exec $CT_B -- cat /tmp/meshguard.stderr 2>/dev/null | head -5)
if [ -n "$GSO_LOG_A" ] || [ -n "$GSO_LOG_B" ]; then
    echo ""
    echo "── Diagnostics (stderr) ──"
    [ -n "$GSO_LOG_B" ] && echo "  sender: $GSO_LOG_B"
    [ -n "$GSO_LOG_A" ] && echo "  receiver: $GSO_LOG_A"
fi

header "Done!"
echo "  Re-run: bash docker/lxc-mg-bench.sh [duration] [encrypt-workers]"
