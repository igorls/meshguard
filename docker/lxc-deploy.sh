#!/bin/bash
# Build meshguard and push to LXC benchmark containers.
#
# Usage:
#   bash docker/lxc-deploy.sh                    # ReleaseFast (default)
#   bash docker/lxc-deploy.sh debug              # Debug build
#   bash docker/lxc-deploy.sh fast               # ReleaseFast
#   bash docker/lxc-deploy.sh safe               # ReleaseSafe
#   bash docker/lxc-deploy.sh small              # ReleaseSmall
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"
MODE="${1:-fast}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Map friendly names to zig optimize flags
case "$MODE" in
    debug)   OPT_FLAG="-Doptimize=Debug" ;;
    safe)    OPT_FLAG="-Doptimize=ReleaseSafe" ;;
    small)   OPT_FLAG="-Doptimize=ReleaseSmall" ;;
    fast|*)  OPT_FLAG="-Doptimize=ReleaseFast" ;;
esac

header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    printf "║  %-56s ║\n" "$1"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
}

header "Build & Deploy MeshGuard to LXC"
echo "  Mode: $MODE ($OPT_FLAG)"
echo "  Containers: $CT_A, $CT_B"
echo ""

# ── Step 1: Build ──
echo "[1/4] Building meshguard ($MODE)..."
cd "$PROJECT_DIR"
zig build $OPT_FLAG -Dcpu=native 2>&1
BINARY="zig-out/bin/meshguard"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Build failed — $BINARY not found."
    exit 1
fi

SIZE=$(du -h "$BINARY" | cut -f1)
echo "  Built: $BINARY ($SIZE)"

# ── Step 2: Kill running meshguard ──
echo "[2/4] Stopping running meshguard..."
lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
sleep 1

# ── Step 3: Push binary ──
echo "[3/4] Pushing to containers..."
lxc file push "$BINARY" "$CT_A/usr/local/bin/meshguard" --mode=0755
lxc file push "$BINARY" "$CT_B/usr/local/bin/meshguard" --mode=0755
echo "  Pushed to $CT_A:/usr/local/bin/meshguard"
echo "  Pushed to $CT_B:/usr/local/bin/meshguard"

# ── Step 4: Verify ──
echo "[4/4] Verifying..."
VER_A=$(lxc exec $CT_A -- meshguard --version 2>&1 || echo "unknown")
VER_B=$(lxc exec $CT_B -- meshguard --version 2>&1 || echo "unknown")
echo "  $CT_A: $VER_A"
echo "  $CT_B: $VER_B"

header "Deploy complete!"
echo "  Run benchmark:  bash docker/lxc-4way-bench.sh [duration]"
echo "  Quick test:     bash docker/lxc-4way-bench.sh 5"
