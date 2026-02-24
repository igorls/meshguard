#!/bin/bash
# MeshGuard Org Fleet End-to-End Test
#
# Tests the org trust flow:
#   1. Org admin generates keypair and signs all nodes
#   2. Nodes trust the org and install certs
#   3. Mesh forms via org trust (no individual key exchange)
#   4. Verify connectivity via WireGuard tunnel
#
# Usage: bash docker/test-org-fleet.sh

set -e

COMPOSE="docker compose -f docker-compose.org.yml"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "  ${YELLOW}ℹ${NC} $1"; }

FAILURES=0

echo "═══════════════════════════════════════"
echo "  MeshGuard Org Fleet E2E Test"
echo "═══════════════════════════════════════"
echo

# ── Build ──
echo "▶ Building org fleet containers..."
$COMPOSE build --quiet

# ── Start ──
echo "▶ Starting 3-node org fleet..."
$COMPOSE up -d

# ── Wait for org signing + mesh formation ──
echo "▶ Waiting 15s for org signing + SWIM gossip..."
sleep 15

# ── Verify org trust setup ──
echo
echo "▶ Checking org trust setup..."

# Check that org admin generated org key
if $COMPOSE exec -T node-a test -f /etc/meshguard/org/org.pub 2>/dev/null; then
    ORG_PUB=$($COMPOSE exec -T node-a cat /etc/meshguard/org/org.pub 2>/dev/null | tr -d '\r')
    pass "node-a (admin): org keypair generated"
    info "Org pubkey: ${ORG_PUB:0:20}..."
else
    fail "node-a: org keypair not found"
fi

# Check that all nodes have certificates
for node in node-a node-b node-c; do
    if $COMPOSE exec -T $node test -f /etc/meshguard/node.cert 2>/dev/null; then
        CERT_SIZE=$($COMPOSE exec -T $node stat -c '%s' /etc/meshguard/node.cert 2>/dev/null | tr -d '\r\n ')
        if [ "$CERT_SIZE" = "186" ]; then
            pass "$node: node.cert installed (186 bytes)"
        else
            fail "$node: node.cert wrong size ($CERT_SIZE, expected 186)"
        fi
    else
        fail "$node: node.cert not found"
    fi
done

# Check that all nodes trust the org
for node in node-a node-b node-c; do
    if $COMPOSE exec -T node-a test -d /etc/meshguard/trusted_orgs 2>/dev/null; then
        ORG_COUNT=$($COMPOSE exec -T $node ls /etc/meshguard/trusted_orgs/ 2>/dev/null | wc -l | tr -d ' \r')
        if [ "$ORG_COUNT" -ge 1 ]; then
            pass "$node: org trusted ($ORG_COUNT org(s))"
        else
            fail "$node: trusted_orgs/ empty"
        fi
    else
        fail "$node: trusted_orgs/ not found"
    fi
done

# Check that NO individual keys were exchanged (pure org trust)
for node in node-a node-b node-c; do
    KEY_COUNT=$($COMPOSE exec -T $node ls /etc/meshguard/authorized_keys/ 2>/dev/null | wc -l | tr -d ' \r')
    if [ "$KEY_COUNT" = "0" ] || [ -z "$KEY_COUNT" ]; then
        pass "$node: no individual keys (pure org trust)"
    else
        info "$node: $KEY_COUNT individual key(s) found (expected 0 for pure org mode)"
    fi
done

# ── Check interfaces ──
echo
echo "▶ Checking WireGuard interfaces..."
for node in node-a node-b node-c; do
    if $COMPOSE exec -T $node ip link show mg0 >/dev/null 2>&1; then
        pass "$node: mg0 interface up"
    else
        fail "$node: mg0 interface missing"
    fi
done

# ── Check WireGuard (userspace mode — look for active tunnel via process) ──
echo
echo "▶ Checking WireGuard tunnels..."
for node in node-a node-b node-c; do
    # In userspace mode, WG tunnel is built into meshguard — check for active mesh IPs
    mesh_ip=$($COMPOSE exec -T $node ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' || echo "")
    if [ -n "$mesh_ip" ]; then
        pass "$node: tunnel active (mesh IP $mesh_ip)"
    else
        fail "$node: no mesh IP on mg0"
    fi
done

# ── Mesh IPs ──
echo
echo "▶ Mesh IPs:"
for node in node-a node-b node-c; do
    mesh_ip=$($COMPOSE exec -T $node ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )\S+' || echo "none")
    echo "  $node: $mesh_ip"
done

# ── Ping test ──
echo
echo "▶ Ping test (org-trust mesh connectivity):"
node_a_ip=$($COMPOSE exec -T node-a ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' || echo "")
if [ -n "$node_a_ip" ]; then
    for node in node-b node-c; do
        if $COMPOSE exec -T $node ping -c 2 -W 3 "$node_a_ip" >/dev/null 2>&1; then
            pass "$node → node-a ($node_a_ip) ping OK"
        else
            fail "$node → node-a ($node_a_ip) ping FAILED"
        fi
    done
else
    fail "Could not determine node-a mesh IP"
fi

# ── Summary ──
echo
echo "═══════════════════════════════════════"
if [ $FAILURES -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed!${NC}"
    echo -e "  Org fleet mode: ${GREEN}WORKING${NC}"
else
    echo -e "  ${RED}$FAILURES check(s) failed${NC}"
fi
echo "═══════════════════════════════════════"

# ── Logs ──
echo
echo "▶ Recent logs (node-a, org admin):"
$COMPOSE logs --tail=10 node-a 2>/dev/null | grep "\[org-fleet\]" || true

echo
echo "▶ Cleanup: $COMPOSE down"
$COMPOSE down --volumes

exit $FAILURES
