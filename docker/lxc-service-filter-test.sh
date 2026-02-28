#!/bin/bash
# MeshGuard Service Filter Integration Test (LXC)
#
# Tests service access control on real WireGuard mesh using LXC containers.
# Uses the same mg-bench-a / mg-bench-b containers from the benchmark.
#
# Tests:
#   1. CLI commands (list, allow, deny, default, show, reset)
#   2. Mesh establishment with service policies
#   3. Allowed port reachable through mesh
#   4. Denied port blocked through mesh
#   5. Reset → allow-all restores access
set -e

CT_A="mg-bench-a"
CT_B="mg-bench-b"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() { echo -e "${RED}✗ FAIL${NC}: $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${YELLOW}→${NC} $1"; }

FAILURES=0

cleanup() {
    info "Cleaning up..."
    lxc exec $CT_A -- pkill meshguard 2>/dev/null || true
    lxc exec $CT_B -- pkill meshguard 2>/dev/null || true
    lxc exec $CT_A -- ip link del mg0 2>/dev/null || true
    lxc exec $CT_B -- ip link del mg0 2>/dev/null || true
    lxc exec $CT_A -- pkill nc 2>/dev/null || true
    lxc exec $CT_A -- pkill python3 2>/dev/null || true
    lxc exec $CT_A -- rm -rf /etc/meshguard/services 2>/dev/null || true
    lxc exec $CT_B -- rm -rf /etc/meshguard/services 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

# Initial cleanup
cleanup 2>/dev/null

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  MeshGuard Service Filter Test (LXC)                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─── Test 1: CLI Commands ───
info "Test 1: CLI commands"

# Empty state
OUTPUT=$(lxc exec $CT_A -- meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "No service policies"; then
    pass "Initial state: no policies"
else
    fail "Expected no policies, got: $OUTPUT"
fi

# Add rules
lxc exec $CT_A -- meshguard service allow tcp 22
lxc exec $CT_A -- meshguard service allow tcp 443
lxc exec $CT_A -- meshguard service deny all
lxc exec $CT_A -- meshguard service default deny

OUTPUT=$(lxc exec $CT_A -- meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "allow tcp 22" && echo "$OUTPUT" | grep -q "deny all" && echo "$OUTPUT" | grep -q "Default: deny"; then
    pass "List shows rules + default"
else
    fail "List mismatch: $OUTPUT"
fi

# Show summary
OUTPUT=$(lxc exec $CT_A -- meshguard service show 2>&1)
if echo "$OUTPUT" | grep -q "Default: deny" && echo "$OUTPUT" | grep -q "Global policy: yes"; then
    pass "Show displays correct summary"
else
    fail "Show mismatch: $OUTPUT"
fi

# Peer rule
lxc exec $CT_A -- meshguard service allow --peer node-b tcp 5432
OUTPUT=$(lxc exec $CT_A -- meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "Peer: node-b"; then
    pass "Peer rule created"
else
    fail "Peer rule missing: $OUTPUT"
fi

# Reset
lxc exec $CT_A -- meshguard service reset
OUTPUT=$(lxc exec $CT_A -- meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "No service policies"; then
    pass "Reset clears all"
else
    fail "Reset failed: $OUTPUT"
fi

# ─── Test 2: Live mesh with service filter ───
info ""
info "Test 2: Live mesh with service filter"

# Configure service policy on node-A: allow port 2222 + 443, deny all else
lxc exec $CT_A -- meshguard service allow tcp 2222
lxc exec $CT_A -- meshguard service allow tcp 443
lxc exec $CT_A -- meshguard service deny all

info "Service policy configured on $CT_A:"
lxc exec $CT_A -- meshguard service list 2>&1

# Get IPs for seeding
IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
info "Starting meshguard daemons ($CT_A: $IP_A)..."

# Start daemons
lxc exec $CT_A -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up </dev/null >/var/log/meshguard.log 2>&1 &"
sleep 3
lxc exec $CT_B -T -- sh -c "MESHGUARD_CONFIG_DIR=/etc/meshguard meshguard up --seed $IP_A:51821 </dev/null >/var/log/meshguard.log 2>&1 &"

info "Waiting for mesh to establish (12s)..."
sleep 12

# Get mesh IPs
MESH_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show mg0 | grep inet | awk '{print \$2}' | cut -d/ -f1" 2>/dev/null || true)
MESH_B=$(lxc exec $CT_B -- sh -c "ip -4 addr show mg0 | grep inet | awk '{print \$2}' | cut -d/ -f1" 2>/dev/null || true)

if [ -n "$MESH_A" ] && [ -n "$MESH_B" ]; then
    pass "Mesh established: A=$MESH_A B=$MESH_B"
else
    info "Node A log:"
    lxc exec $CT_A -- tail -15 /var/log/meshguard.log 2>/dev/null || true
    fail "Mesh not established (A='$MESH_A' B='$MESH_B')"
fi

# Check handshake
HS=$(lxc exec $CT_A -- grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
if [ "$HS" -gt 0 ]; then
    pass "WG handshake completed ($HS entries)"
else
    info "No handshake yet, waiting 8s more..."
    sleep 8
    HS=$(lxc exec $CT_A -- grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
    if [ "$HS" -gt 0 ]; then
        pass "WG handshake completed after extra wait ($HS entries)"
    else
        info "Node A log:"
        lxc exec $CT_A -- tail -10 /var/log/meshguard.log 2>/dev/null || true
        fail "WG handshake not detected"
    fi
fi

# Show node-A log for service policy line
info "Node A startup log (services line):"
lxc exec $CT_A -- grep 'services:' /var/log/meshguard.log 2>/dev/null || echo "  (no services line)"

# ─── Test 3: Verify connectivity (ping) ───
if [ -n "$MESH_A" ]; then
    info ""
    info "Test 3: Mesh connectivity via ping"
    PING_OUT=$(lxc exec $CT_B -- ping -c 3 -W 2 "$MESH_A" 2>&1 || true)
    PING_RX=$(echo "$PING_OUT" | grep -oP '\d+ received' | grep -oP '\d+' || echo 0)
    if [ "$PING_RX" -gt 0 ]; then
        pass "Ping through mesh works ($PING_RX/3 received)"
    else
        info "$PING_OUT"
        fail "Ping through mesh failed"
    fi
fi

# ─── Test 4: Start listeners, verify allowed vs denied ports ───
if [ -n "$MESH_A" ]; then
    info ""
    info "Test 4: Service filter — allowed vs denied ports"

    # Start persistent listeners on node-A (ports 2222 and 8080)
    lxc exec $CT_A -T -- sh -c 'python3 -c "
import socket,threading
def serve(port, msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", port))
    s.listen(5)
    while True:
        c, _ = s.accept()
        c.sendall(msg.encode())
        c.close()
threading.Thread(target=serve, args=(2222, \"ALLOWED-OK\"), daemon=True).start()
threading.Thread(target=serve, args=(8080, \"DENIED-OK\"), daemon=True).start()
import time; time.sleep(3600)
" &'
    sleep 2

    # Verify listener is up locally
    LOCAL_CHECK=$(lxc exec $CT_A -- sh -c 'echo | nc -w 1 127.0.0.1 2222' 2>/dev/null || true)
    if echo "$LOCAL_CHECK" | grep -q "ALLOWED-OK"; then
        pass "Local listener on :2222 responding"
    else
        info "Local :2222 check: '$LOCAL_CHECK'"
    fi

    # Test ALLOWED port (2222) through mesh
    info "Testing TCP 2222 via mesh (should be ALLOWED)..."
    RESULT=$(lxc exec $CT_B -- sh -c "echo | nc -w 3 $MESH_A 2222" 2>/dev/null || true)
    if echo "$RESULT" | grep -q "ALLOWED-OK"; then
        pass "TCP 2222 ALLOWED through mesh ✓"
    else
        info "TCP 2222 result: '$RESULT'"
        # Retry once
        sleep 2
        RESULT=$(lxc exec $CT_B -- sh -c "echo | nc -w 3 $MESH_A 2222" 2>/dev/null || true)
        if echo "$RESULT" | grep -q "ALLOWED-OK"; then
            pass "TCP 2222 ALLOWED through mesh (retry) ✓"
        else
            fail "TCP 2222 should be allowed but got: '$RESULT'"
        fi
    fi

    # Test DENIED port (8080) through mesh
    info "Testing TCP 8080 via mesh (should be DENIED)..."
    RESULT=$(lxc exec $CT_B -- sh -c "echo | nc -w 3 $MESH_A 8080" 2>/dev/null || true)
    if [ -z "$RESULT" ] || ! echo "$RESULT" | grep -q "DENIED-OK"; then
        pass "TCP 8080 DENIED by service filter ✓"
    else
        fail "TCP 8080 should be denied but got: '$RESULT'"
    fi

    # Verify 8080 works locally (proving the filter blocked it, not the listener)
    LOCAL_8080=$(lxc exec $CT_A -- sh -c 'echo | nc -w 1 127.0.0.1 8080' 2>/dev/null || true)
    if echo "$LOCAL_8080" | grep -q "DENIED-OK"; then
        pass "Local :8080 works (filter blocked it, not listener)"
    else
        info "Local :8080 check: '$LOCAL_8080' (listener may not be up)"
    fi
fi

# ─── Test 5: Reset → allow-all restores access ───
if [ -n "$MESH_A" ]; then
    info ""
    info "Test 5: Reset to allow-all"

    # NOTE: Service filter is loaded at daemon start — can't hot-reload yet.
    # This test verifies the reset CLI works. A full restart would be needed
    # to test runtime behavior change (Phase 4: hot-reload).
    lxc exec $CT_A -- meshguard service reset
    OUTPUT=$(lxc exec $CT_A -- meshguard service list 2>&1)
    if echo "$OUTPUT" | grep -q "No service policies"; then
        pass "Reset to allow-all confirmed"
    else
        fail "Reset didn't clear: $OUTPUT"
    fi
fi

# ─── Results ───
echo ""
echo "════════════════════════════════════════════════════════════"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}$FAILURES test(s) failed${NC}"
fi
echo "════════════════════════════════════════════════════════════"

exit $FAILURES
