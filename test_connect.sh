#!/bin/bash
# Automated Coordinated Punch E2E test
# Prerequisites: ssh-copy-id igorls@blade14  (one-time setup)
# Usage: ./test_connect.sh
set -euo pipefail

REMOTE="igorls@blade14"
BIN="./zig-out/bin/meshguard"
FIFO="/tmp/mg_stdin_fifo"
LOCAL_OUT="/tmp/mg_local_out"
REMOTE_OUT="/tmp/mg_remote_out"

cleanup() {
    rm -f "$FIFO" "$LOCAL_OUT" "$REMOTE_OUT"
    kill %1 %2 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

echo "════════════════════════════════════════════"
echo "  Automated Coordinated Punch Test"
echo "════════════════════════════════════════════"
echo ""

if [ "$(id -u)" -eq 0 ]; then
    echo "ERROR: Do not run with sudo. The script uses sudo internally."
    echo "Usage: ./test_connect.sh"
    exit 1
fi

# ── Warm up remote sudo (enter password once, cached for 15 min) ──
echo "Caching sudo on remote (enter remote password once)..."
ssh -t "$REMOTE" "sudo true"
echo "  ✓ remote sudo cached"
echo ""

# ── Step 1: Transfer binary to remote ──
echo "[1/8] Transferring binary to remote..."
ssh "$REMOTE" "sudo systemctl stop meshguard 2>/dev/null || true; sudo rm -f /usr/local/bin/meshguard"
scp -q "$BIN" "$REMOTE:/tmp/meshguard"
ssh "$REMOTE" "sudo cp /tmp/meshguard /usr/local/bin/meshguard && sudo chmod +x /usr/local/bin/meshguard"
echo "  ✓ binary installed on remote"

# ── Step 2: Ensure identity on remote ──
echo "[2/8] Ensuring identity on remote..."
ssh "$REMOTE" "sudo meshguard keygen 2>/dev/null || echo '  (identity already exists)'"
echo "  ✓ identity ready"

# ── Step 3: Install latest binary locally ──
echo "[3/8] Installing binary locally..."
sudo systemctl stop meshguard 2>/dev/null || true
sleep 1
sudo rm -f /usr/local/bin/meshguard
sudo cp "$BIN" /usr/local/bin/meshguard
echo "  ✓ binary installed locally"

# ── Step 4: Setup FIFOs ──
rm -f "$FIFO" "$LOCAL_OUT" "$REMOTE_OUT"
mkfifo "$FIFO"
touch "$LOCAL_OUT" "$REMOTE_OUT"
exec 3<>"$FIFO"

# ── Step 5: Start initiator (local) ──
echo "[4/8] Starting initiator (local, --generate --in 2)..."
sudo meshguard connect --generate --in 1 <&3 > "$LOCAL_OUT" 2>&1 &
LOCAL_PID=$!

echo "  waiting for token..."
for i in $(seq 1 20); do
    sleep 1
    if grep -q "connect --join" "$LOCAL_OUT" 2>/dev/null; then break; fi
    if ! kill -0 "$LOCAL_PID" 2>/dev/null; then
        echo "  ERROR: initiator exited early"; cat "$LOCAL_OUT"; exit 1
    fi
done

TOKEN=$(grep -oP 'connect --join \Kmg://\S+' "$LOCAL_OUT" || true)
if [ -z "$TOKEN" ]; then
    echo "  ERROR: could not extract token:"; cat "$LOCAL_OUT"; exit 1
fi
echo "  ✓ token: ${TOKEN:0:50}..."

# ── Step 6: Run join on remote (background, sudo cached) ──
echo "[5/8] Running join on remote..."
ssh "$REMOTE" "echo '' | sudo meshguard connect --join '$TOKEN'" > "$REMOTE_OUT" 2>&1 &
REMOTE_PID=$!

echo "  waiting for response token..."
for i in $(seq 1 30); do
    sleep 1
    if grep -q "mg://" "$REMOTE_OUT" 2>/dev/null; then break; fi
    if ! kill -0 "$REMOTE_PID" 2>/dev/null; then break; fi
done

RESP_TOKEN=$(grep -P '^\s+mg://' "$REMOTE_OUT" | head -1 | tr -d ' \t\r\n' || true)
if [ -z "$RESP_TOKEN" ]; then
    echo "  ERROR: no response token:"; cat "$REMOTE_OUT"; exit 1
fi
echo "  ✓ response: ${RESP_TOKEN:0:50}..."

# ── Step 7: Feed response to initiator ──
echo "[6/8] Feeding response token..."
echo "$RESP_TOKEN" >&3
exec 3>&-

echo "[7/8] Waiting for punch (up to 3 min)..."
for i in $(seq 1 180); do
    # Check if both are done
    LOCAL_DONE=true; kill -0 "$LOCAL_PID" 2>/dev/null && LOCAL_DONE=false
    REMOTE_DONE=true; kill -0 "$REMOTE_PID" 2>/dev/null && REMOTE_DONE=false
    if $LOCAL_DONE && $REMOTE_DONE; then break; fi
    # Print progress every 10s
    if [ $((i % 10)) -eq 0 ]; then
        echo "  ... ${i}s elapsed (local: $( $LOCAL_DONE && echo done || echo waiting), remote: $( $REMOTE_DONE && echo done || echo waiting))"
    fi
    sleep 1
done

echo ""
echo "── Local output ──"
cat "$LOCAL_OUT"
echo ""
echo "── Remote output ──"
cat "$REMOTE_OUT"

# ── Step 8: Test connectivity ──
echo ""
echo "[8/8] Testing connectivity..."
sleep 3

REMOTE_IP=$(grep -oP 'peer: \K10\.\d+\.\d+\.\d+' "$LOCAL_OUT" | head -1 || true)
if [ -n "$REMOTE_IP" ]; then
    echo "  pinging $REMOTE_IP..."
    if ping -c 3 -W 2 "$REMOTE_IP"; then
        echo "  ✓ CONNECTIVITY TEST PASSED"
    else
        echo "  ✗ ping failed"
    fi
fi

echo ""
echo "  local status:"
sudo meshguard status
echo ""
echo "  remote status:"
ssh "$REMOTE" "sudo meshguard status"

echo ""
echo "════════════════════════════════════════════"
echo "  Test complete"
echo "════════════════════════════════════════════"
