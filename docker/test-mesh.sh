#!/bin/bash
# MeshGuard Docker mesh test script
#
# Usage: ./docker/test-mesh.sh
#
# Builds, starts 3 nodes, waits for mesh formation,
# then verifies connectivity and tears down.

set -e

COMPOSE="docker compose"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES + 1)); }

FAILURES=0

echo "═══════════════════════════════════════"
echo "  MeshGuard Docker Mesh Test"
echo "═══════════════════════════════════════"
echo

# 1. Build
echo "▶ Building containers..."
$COMPOSE build --quiet

# 2. Start
echo "▶ Starting 3-node mesh..."
$COMPOSE up -d

# 3. Wait for mesh formation
echo "▶ Waiting 10s for SWIM gossip to converge..."
sleep 10

# 4. Check that all nodes have mg0 interface
echo
echo "▶ Checking interfaces..."
for node in node-a node-b node-c; do
    if $COMPOSE exec -T $node ip link show mg0 >/dev/null 2>&1; then
        pass "$node has mg0 interface"
    else
        fail "$node missing mg0 interface"
    fi
done

# 5. Check WireGuard status
echo
echo "▶ Checking WireGuard config..."
for node in node-a node-b node-c; do
    wg_output=$($COMPOSE exec -T $node wg show mg0 2>/dev/null || echo "FAILED")
    if echo "$wg_output" | grep -q "listening port"; then
        peer_count=$(echo "$wg_output" | grep -c "peer:" || echo "0")
        pass "$node: WireGuard active, $peer_count peer(s)"
    else
        fail "$node: WireGuard not configured"
    fi
done

# 6. Get mesh IPs
echo
echo "▶ Mesh IPs:"
for node in node-a node-b node-c; do
    mesh_ip=$($COMPOSE exec -T $node ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )\S+' || echo "none")
    echo "  $node: $mesh_ip"
done

# 7. Ping test (will work once peers are connected)
echo
echo "▶ Ping test (mesh connectivity):"
node_a_ip=$($COMPOSE exec -T node-a ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' || echo "")
if [ -n "$node_a_ip" ]; then
    if $COMPOSE exec -T node-b ping -c 1 -W 2 "$node_a_ip" >/dev/null 2>&1; then
        pass "node-b → node-a ($node_a_ip) ping OK"
    else
        fail "node-b → node-a ($node_a_ip) ping FAILED"
    fi
else
    fail "Could not determine node-a mesh IP"
fi

# 8. Summary
echo
echo "═══════════════════════════════════════"
if [ $FAILURES -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed!${NC}"
else
    echo -e "  ${RED}$FAILURES check(s) failed${NC}"
fi
echo "═══════════════════════════════════════"

# 9. Logs (brief)
echo
echo "▶ Recent logs:"
$COMPOSE logs --tail=5

echo
echo "▶ Cleanup: docker compose down"
$COMPOSE down
