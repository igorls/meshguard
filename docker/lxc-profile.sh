#!/bin/bash
# Profile MeshGuard with perf + flamegraph on LXC containers.
#
# Runs from the HOST — perf records the meshguard process via host-side PIDs.
# Requires: perf (host), sudo, FlameGraph scripts (auto-downloaded).
#
# Usage:
#   bash docker/lxc-profile.sh [duration] [encrypt-workers]
#   bash docker/lxc-profile.sh 10 8     # 10s, 8 workers
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
DURATION="${1:-10}"
ENCRYPT_WORKERS="${2:-8}"
IPERF_PORT=5201
RESULTS_DIR="./bench-results"

header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    printf "║  %-56s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

mkdir -p "$RESULTS_DIR"

# ── Ensure FlameGraph scripts are available ──
if [ ! -d "$RESULTS_DIR/FlameGraph" ]; then
    echo "Downloading FlameGraph scripts..."
    git clone --depth 1 https://github.com/brendangregg/FlameGraph.git "$RESULTS_DIR/FlameGraph" 2>/dev/null
fi

header "MeshGuard Profiling (perf + flamegraph)"
echo "  Duration: ${DURATION}s"
echo "  Encrypt workers: $ENCRYPT_WORKERS"
echo "  Output: $RESULTS_DIR/"

# ── Step 1: Build with debug symbols ──
echo ""
echo "[1/6] Building with debug symbols (ReleaseSafe)..."
zig build -Doptimize=ReleaseSafe 2>&1
echo "  Built: zig-out/bin/meshguard"

# ── Step 2: Deploy ──
echo "[2/6] Deploying..."
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
sleep 0.5
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
lxc file push zig-out/bin/meshguard "$CT_A/usr/local/bin/meshguard" --mode=0755
lxc file push zig-out/bin/meshguard "$CT_B/usr/local/bin/meshguard" --mode=0755
echo "  Deployed to both containers"

# ── Step 3: Start MeshGuard ──
echo "[3/6] Starting MeshGuard..."
MG_IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")

EXTRA_ARGS=""
if [ -n "$ENCRYPT_WORKERS" ] && [ "$ENCRYPT_WORKERS" != "0" ]; then
    EXTRA_ARGS="--encrypt-workers $ENCRYPT_WORKERS"
fi

lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up $EXTRA_ARGS </dev/null >/dev/null 2>/tmp/meshguard.stderr &"
sleep 2
lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up --seed $MG_IP_A:51821 $EXTRA_ARGS </dev/null >/dev/null 2>/tmp/meshguard.stderr &"
sleep 8

MESH_IP=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
if [ -z "$MESH_IP" ]; then
    echo "ERROR: MeshGuard did not come up."
    exit 1
fi
echo "  Mesh IP A: $MESH_IP"

# ── Step 4: Start iperf3 server ──
lxc exec $CT_A -T -- sh -c "iperf3 -s -p $IPERF_PORT -D"
sleep 0.5

# ── Step 5: Profile ──
echo "[4/6] Recording perf profile (${DURATION}s)..."

# Find the host-side PID of meshguard in container B (sender)
# The container process is visible from the host with a different PID
HOST_PID=$(sudo nsenter -t $(lxc info $CT_B | grep 'PID:' | head -1 | awk '{print $2}') -p -- sh -c "pidof meshguard" 2>/dev/null || true)

if [ -z "$HOST_PID" ]; then
    # Fallback: find meshguard processes and pick the sender
    echo "  Trying alternative PID discovery..."
    HOST_PID=$(sudo pgrep -f "meshguard up.*seed" | head -1)
fi

if [ -z "$HOST_PID" ]; then
    # Last resort: profile ALL meshguard processes
    echo "  Profiling all meshguard processes..."
    HOST_PID=$(sudo pgrep meshguard | head -1)
fi

if [ -z "$HOST_PID" ]; then
    echo "ERROR: Cannot find meshguard PID. Is it running?"
    exit 1
fi
echo "  Host PID for sender: $HOST_PID"

# Start iperf3 client in background
lxc exec $CT_B -T -- sh -c "iperf3 -c $MESH_IP -p $IPERF_PORT -t $DURATION >/tmp/iperf3.log 2>&1 &"
sleep 1  # let iperf3 warm up

# Record perf data from the HOST (needs sudo for perf_event_paranoid=4)
echo "  Recording samples (${DURATION}s)..."
sudo perf record -F 999 -p $HOST_PID -g --call-graph dwarf,16384 -o "$RESULTS_DIR/perf.data" -- sleep $DURATION 2>/dev/null || \
    sudo perf record -F 999 -p $HOST_PID -g -o "$RESULTS_DIR/perf.data" -- sleep $DURATION 2>/dev/null || \
    sudo perf record -F 99 -p $HOST_PID -o "$RESULTS_DIR/perf.data" -- sleep $DURATION 2>/dev/null || \
    echo "  WARNING: perf record failed"

# Show iperf3 results
echo ""
echo "  iperf3 results:"
lxc exec $CT_B -- cat /tmp/iperf3.log 2>/dev/null | grep -E "sender|receiver" | tail -2 || true

# ── Step 6: Generate flamegraph ──
echo ""
echo "[5/6] Generating flamegraph..."

if [ -f "$RESULTS_DIR/perf.data" ]; then
    sudo chown $USER "$RESULTS_DIR/perf.data"

    # Generate text report
    sudo perf report -i "$RESULTS_DIR/perf.data" --stdio --no-children 2>/dev/null | head -60 > "$RESULTS_DIR/perf-report.txt" || true

    # Generate flamegraph
    sudo perf script -i "$RESULTS_DIR/perf.data" 2>/dev/null > "$RESULTS_DIR/perf.script" || true

    if [ -s "$RESULTS_DIR/perf.script" ]; then
        "$RESULTS_DIR/FlameGraph/stackcollapse-perf.pl" "$RESULTS_DIR/perf.script" > "$RESULTS_DIR/perf.folded" 2>/dev/null
        "$RESULTS_DIR/FlameGraph/flamegraph.pl" --minwidth 0.5 "$RESULTS_DIR/perf.folded" > "$RESULTS_DIR/flamegraph.svg" 2>/dev/null
        echo "  Flamegraph: $RESULTS_DIR/flamegraph.svg"
    else
        echo "  WARNING: perf script produced no output"
    fi

    if [ -s "$RESULTS_DIR/perf-report.txt" ]; then
        echo ""
        echo "── Top hotspots ──"
        cat "$RESULTS_DIR/perf-report.txt" | grep -E "^\s+[0-9]" | head -20
    fi
else
    echo "  WARNING: no perf data collected"
fi

# ── Cleanup ──
echo ""
echo "[6/6] Cleaning up..."
lxc exec $CT_A -- pkill iperf3 2>/dev/null || true
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true

# Show diagnostics
GSO_LOG=$(lxc exec $CT_B -- cat /tmp/meshguard.stderr 2>/dev/null | head -3)
[ -n "$GSO_LOG" ] && echo "  sender diagnostics: $GSO_LOG"

header "Profiling complete!"
echo "  Flamegraph: $RESULTS_DIR/flamegraph.svg"
echo "  Report:     $RESULTS_DIR/perf-report.txt"
echo ""
echo "  View flamegraph: xdg-open $RESULTS_DIR/flamegraph.svg"
echo "  View report:     cat $RESULTS_DIR/perf-report.txt"
