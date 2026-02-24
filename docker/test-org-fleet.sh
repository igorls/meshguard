#!/bin/bash
# MeshGuard Org Fleet End-to-End Test — Mixed Topology
#
# Tests the REAL org trust flow with mixed topology:
#   node-a: org admin (has cert, generates org key)
#   node-b: org member (has cert, auto-accepted via cert)
#   node-c: standalone (STANDALONE=1, NO cert, accepted via org vouch)
#
# Verifies:
#   1. Org keygen + cert signing for members
#   2. Org vouch for standalone node (no cert needed)
#   3. All three nodes form a mesh and can ping each other
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
echo "  Mixed Topology: org + standalone"
echo "═══════════════════════════════════════"
echo

# ── Build ──
echo "▶ Building org fleet containers..."
$COMPOSE build --quiet

# ── Start ──
echo "▶ Starting 3-node mixed fleet..."
$COMPOSE up -d

# ── Wait for org signing + mesh formation ──
echo "▶ Waiting 20s for org signing + vouching + SWIM gossip..."
sleep 20

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

# Check certs: node-a and node-b should have certs, node-c should NOT
for node in node-a node-b; do
    if $COMPOSE exec -T $node test -f /etc/meshguard/node.cert 2>/dev/null; then
        CERT_SIZE=$($COMPOSE exec -T $node stat -c '%s' /etc/meshguard/node.cert 2>/dev/null | tr -d '\r\n ')
        if [ "$CERT_SIZE" = "186" ]; then
            pass "$node (org member): node.cert installed (186 bytes)"
        else
            fail "$node: node.cert wrong size ($CERT_SIZE, expected 186)"
        fi
    else
        fail "$node: node.cert not found (org member should have one)"
    fi
done

# node-c MUST NOT have a cert (standalone)
if $COMPOSE exec -T node-c test -f /etc/meshguard/node.cert 2>/dev/null; then
    fail "node-c (standalone): has node.cert — should NOT have one!"
else
    pass "node-c (standalone): no cert (expected — relies on vouch)"
fi

# Check that all nodes trust the org
for node in node-a node-b node-c; do
    ORG_COUNT=$($COMPOSE exec -T $node ls /etc/meshguard/trusted_orgs/ 2>/dev/null | wc -l | tr -d ' \r')
    if [ "$ORG_COUNT" -ge 1 ]; then
        pass "$node: org trusted ($ORG_COUNT org(s))"
    else
        fail "$node: trusted_orgs/ empty"
    fi
done

# Check that node-c has no individual keys (pure vouch mode)
KEY_COUNT=$($COMPOSE exec -T node-c ls /etc/meshguard/authorized_keys/ 2>/dev/null | wc -l | tr -d ' \r')
if [ "$KEY_COUNT" = "0" ] || [ -z "$KEY_COUNT" ]; then
    pass "node-c: no individual keys (pure org trust/vouch)"
else
    info "node-c: $KEY_COUNT individual key(s) found"
fi

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

# ── Check tunnels ──
echo
echo "▶ Checking WireGuard tunnels..."
for node in node-a node-b node-c; do
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

# ── Ping tests ──
echo
echo "▶ Ping test — org member (node-b) → org admin (node-a):"
node_a_ip=$($COMPOSE exec -T node-a ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' || echo "")
if [ -n "$node_a_ip" ]; then
    if $COMPOSE exec -T node-b ping -c 2 -W 3 "$node_a_ip" >/dev/null 2>&1; then
        pass "node-b → node-a ($node_a_ip) ping OK"
    else
        fail "node-b → node-a ($node_a_ip) ping FAILED"
    fi
else
    fail "Could not determine node-a mesh IP"
fi

echo
echo "▶ Ping test — standalone (node-c) → org admin (node-a):"
if [ -n "$node_a_ip" ]; then
    if $COMPOSE exec -T node-c ping -c 2 -W 3 "$node_a_ip" >/dev/null 2>&1; then
        pass "node-c (standalone) → node-a ($node_a_ip) ping OK [VOUCH WORKS!]"
    else
        fail "node-c (standalone) → node-a ($node_a_ip) ping FAILED"
    fi
fi

echo
echo "▶ Ping test — org admin (node-a) → standalone (node-c):"
node_c_ip=$($COMPOSE exec -T node-c ip -4 addr show mg0 2>/dev/null | grep -oP '(?<=inet )[0-9.]+' || echo "")
if [ -n "$node_c_ip" ]; then
    if $COMPOSE exec -T node-a ping -c 2 -W 3 "$node_c_ip" >/dev/null 2>&1; then
        pass "node-a → node-c ($node_c_ip) ping OK [BIDIRECTIONAL VOUCH!]"
    else
        fail "node-a → node-c ($node_c_ip) ping FAILED"
    fi
fi

# ── Summary ──
echo
echo "═══════════════════════════════════════"
if [ $FAILURES -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed!${NC}"
    echo -e "  Mixed topology: ${GREEN}WORKING${NC}"
    echo -e "  Org vouch:      ${GREEN}VERIFIED${NC}"
else
    echo -e "  ${RED}$FAILURES check(s) failed${NC}"
fi
echo "═══════════════════════════════════════"

# ── Logs ──
echo
echo "▶ Recent logs (node-a, org admin):"
$COMPOSE logs --tail=15 node-a 2>/dev/null | grep "\[org-fleet\]" || true

echo
echo "▶ Recent logs (node-c, standalone):"
$COMPOSE logs --tail=10 node-c 2>/dev/null | grep "\[org-fleet\]" || true

echo
echo "▶ Cleanup: $COMPOSE down"
$COMPOSE down --volumes

exit $FAILURES
