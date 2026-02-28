#!/usr/bin/env bash
# Integration test: meshguard service access control on Docker network
#
# Tests:
#   1. Two nodes establish mesh + WireGuard tunnel
#   2. Node-A applies service policies (allow SSH, deny all)
#   3. Verify SSH port (22) is reachable through mesh
#   4. Verify blocked port (8080) is NOT reachable through mesh
#   5. Verify command: meshguard service list
#   6. Verify command: meshguard service show
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

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
    docker compose -f "$SCRIPT_DIR/docker-compose.test.yml" down -v 2>/dev/null || true
    docker rmi meshguard-test 2>/dev/null || true
}
trap cleanup EXIT

# ─── Build ───
info "Building meshguard binary (ReleaseFast)..."
cd "$PROJECT_DIR"
zig build -Doptimize=ReleaseFast

info "Building Docker image..."
docker build -t meshguard-test -f "$SCRIPT_DIR/Dockerfile" "$PROJECT_DIR"

# ─── Start nodes ───
info "Starting node-a and node-b..."
docker compose -f "$SCRIPT_DIR/docker-compose.test.yml" up -d

# Wait for containers to start
sleep 2

# ─── Generate keys and trust ───
info "Generating identities..."
docker exec meshguard-node-a meshguard keygen --force
docker exec meshguard-node-b meshguard keygen --force

info "Establishing mutual trust..."
# Create authorized_keys directories
docker exec meshguard-node-a mkdir -p /etc/meshguard/authorized_keys
docker exec meshguard-node-b mkdir -p /etc/meshguard/authorized_keys

# Copy node-b's pubkey to node-a's authorized_keys
docker exec meshguard-node-b cat /etc/meshguard/identity.pub > /tmp/mg-node-b.pub
docker cp /tmp/mg-node-b.pub meshguard-node-a:/etc/meshguard/authorized_keys/node-b.pub

# Copy node-a's pubkey to node-b's authorized_keys
docker exec meshguard-node-a cat /etc/meshguard/identity.pub > /tmp/mg-node-a.pub
docker cp /tmp/mg-node-a.pub meshguard-node-b:/etc/meshguard/authorized_keys/node-a.pub

# ─── Test 1: Service CLI ───
info "Testing service CLI commands..."

# Test initial state
OUTPUT=$(docker exec meshguard-node-a meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "No service policies"; then
    pass "Initial state: no policies configured"
else
    fail "Initial state should show no policies"
fi

# Test adding rules
docker exec meshguard-node-a meshguard service allow tcp 22
docker exec meshguard-node-a meshguard service allow tcp 443
docker exec meshguard-node-a meshguard service deny all
docker exec meshguard-node-a meshguard service default deny

# Test list
OUTPUT=$(docker exec meshguard-node-a meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "allow tcp 22" && echo "$OUTPUT" | grep -q "deny all" && echo "$OUTPUT" | grep -q "Default: deny"; then
    pass "Service list shows all rules and default"
else
    fail "Service list output unexpected: $OUTPUT"
fi

# Test show (summary)
OUTPUT=$(docker exec meshguard-node-a meshguard service show 2>&1)
if echo "$OUTPUT" | grep -q "Default: deny" && echo "$OUTPUT" | grep -q "Global policy: yes"; then
    pass "Service show displays correct summary"
else
    fail "Service show output unexpected: $OUTPUT"
fi

# Test peer-specific rule
docker exec meshguard-node-a meshguard service allow --peer node-b tcp 5432
OUTPUT=$(docker exec meshguard-node-a meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "Peer: node-b" && echo "$OUTPUT" | grep -q "allow tcp 5432"; then
    pass "Peer-specific rule added correctly"
else
    fail "Peer rule not visible in list: $OUTPUT"
fi

# Test reset
docker exec meshguard-node-a meshguard service reset
OUTPUT=$(docker exec meshguard-node-a meshguard service list 2>&1)
if echo "$OUTPUT" | grep -q "No service policies"; then
    pass "Service reset clears all policies"
else
    fail "Service reset didn't clear policies: $OUTPUT"
fi

# ─── Test 2: Live mesh with service filtering ───
info "Setting up service policies for live test..."

# Node-A: allow SSH (22), deny everything else
docker exec meshguard-node-a meshguard service allow tcp 22
docker exec meshguard-node-a meshguard service deny all

info "Starting meshguard daemons (open mode for test simplicity)..."

# Get node-b's IP on the Docker network for seeding
NODE_B_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' meshguard-node-b)
NODE_A_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' meshguard-node-a)

info "Node A IP: $NODE_A_IP, Node B IP: $NODE_B_IP"

# Start daemons in background — open mode for simplicity (no trust enforcement)
docker exec -d meshguard-node-a sh -c "meshguard up --open --seed $NODE_B_IP:51821 > /var/log/meshguard.log 2>&1"
docker exec -d meshguard-node-b sh -c "meshguard up --open --seed $NODE_A_IP:51821 > /var/log/meshguard.log 2>&1"

info "Waiting for mesh to establish (20s)..."
sleep 20

# Check if mesh IPs were assigned
NODE_A_MESH=$(docker exec meshguard-node-a ip addr show mg0 2>/dev/null | grep -oP '10\.99\.\d+\.\d+' | head -1 || true)
NODE_B_MESH=$(docker exec meshguard-node-b ip addr show mg0 2>/dev/null | grep -oP '10\.99\.\d+\.\d+' | head -1 || true)

if [ -n "$NODE_A_MESH" ] && [ -n "$NODE_B_MESH" ]; then
    pass "Mesh IPs assigned: node-a=$NODE_A_MESH, node-b=$NODE_B_MESH"
else
    info "Node A mesh: '$NODE_A_MESH', Node B mesh: '$NODE_B_MESH'"
    info "Node A log:"
    docker exec meshguard-node-a cat /var/log/meshguard.log 2>/dev/null | tail -20 || true
    info "Node B log:"
    docker exec meshguard-node-b cat /var/log/meshguard.log 2>/dev/null | tail -20 || true
    fail "Mesh IPs not assigned — tunnel may not have established"
fi

# Verify WG handshake happened by checking logs
info "Checking WireGuard handshake status..."
HS_A=$(docker exec meshguard-node-a grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
HS_B=$(docker exec meshguard-node-b grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
if [ "$HS_A" -gt 0 ] || [ "$HS_B" -gt 0 ]; then
    pass "WireGuard handshake detected (A:${HS_A} B:${HS_B} log entries)"
else
    info "No WG handshake entries found — waiting 10s more..."
    sleep 10
    HS_A=$(docker exec meshguard-node-a grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
    HS_B=$(docker exec meshguard-node-b grep -c 'handshake' /var/log/meshguard.log 2>/dev/null || echo 0)
    if [ "$HS_A" -gt 0 ] || [ "$HS_B" -gt 0 ]; then
        pass "WireGuard handshake detected after extra wait (A:${HS_A} B:${HS_B})"
    else
        info "Node A log:"
        docker exec meshguard-node-a cat /var/log/meshguard.log 2>/dev/null | tail -20 || true
        info "WARNING: No WG handshake detected — live filter tests may fail"
    fi
fi

# Start test services on node-a using python for persistent listeners
info "Starting test services on node-a (SSH mock on :22, HTTP mock on :8080)..."
docker exec -d meshguard-node-a sh -c 'python3 -c "
import socket, threading
def serve(port, msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((\"0.0.0.0\", port))
    s.listen(5)
    while True:
        c, _ = s.accept()
        c.sendall(msg.encode())
        c.close()
threading.Thread(target=serve, args=(22, \"SSH OK\"), daemon=True).start()
threading.Thread(target=serve, args=(8080, \"HTTP OK\"), daemon=True).start()
import time; time.sleep(3600)
" > /var/log/services.log 2>&1'

sleep 2

# ─── Test 3: Verify allowed port (22) ───
if [ -n "$NODE_A_MESH" ]; then
    # First verify the listener works via Docker network (bypass mesh)
    DIRECT_CHECK=$(docker exec meshguard-node-b timeout 3 nc -w 2 "$NODE_A_IP" 22 2>/dev/null || true)
    if [ -z "$DIRECT_CHECK" ]; then
        info "Warning: direct TCP 22 check failed (listener might not be ready)"
    fi

    info "Testing TCP 22 via mesh (should be ALLOWED)..."
    RESULT=$(docker exec meshguard-node-b timeout 5 nc -w 3 "$NODE_A_MESH" 22 2>/dev/null || true)
    if echo "$RESULT" | grep -q "SSH OK"; then
        pass "TCP 22 reachable through mesh (as allowed by policy)"
    else
        # The connection may succeed but the response may be empty if timing is tight
        # Try one more time
        sleep 1
        RESULT=$(docker exec meshguard-node-b timeout 5 nc -w 3 "$NODE_A_MESH" 22 2>/dev/null || true)
        if echo "$RESULT" | grep -q "SSH OK"; then
            pass "TCP 22 reachable through mesh (as allowed by policy, 2nd try)"
        else
            info "TCP 22 result: '$RESULT'"
            fail "TCP 22 should be reachable (allowed by policy)"
        fi
    fi

    # ─── Test 4: Verify blocked port (8080) ───
    info "Testing TCP 8080 (should be DENIED by policy)..."
    RESULT=$(docker exec meshguard-node-b timeout 5 nc -w 3 "$NODE_A_MESH" 8080 2>/dev/null || true)
    if [ -z "$RESULT" ]; then
        pass "TCP 8080 blocked by service policy (connection timed out or refused)"
    else
        fail "TCP 8080 should be blocked but got: '$RESULT'"
    fi
fi

# ─── Results ───
echo ""
echo "================================"
if [ $FAILURES -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}$FAILURES test(s) failed${NC}"
fi
echo "================================"

exit $FAILURES
