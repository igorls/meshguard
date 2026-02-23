#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# MeshGuard ↔ Kernel WireGuard Interop Test
#
# Tests that MeshGuard's userspace Noise IK implementation can establish
# a tunnel with the Linux kernel WireGuard module and exchange data.
#
# Container A: kernel WireGuard (wg0)
# Container B: MeshGuard wg-interop-test (wg-test0, TUN-based)
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

CT_A="mg-bench-a"
CT_B="mg-bench-b"
INTEROP_BIN="zig-out/bin/wg-interop-test"
TUNNEL_NET="10.0.99"  # .1 for kernel, .2 for meshguard
KERNEL_PORT=51820
MESHGUARD_PORT=51830

echo "═══════════════════════════════════════════════"
echo "  MeshGuard ↔ Kernel WG Interop Test"
echo "═══════════════════════════════════════════════"

# ── Cleanup ──
echo ""
echo "Cleaning up previous state..."
for CT in $CT_A $CT_B; do
    lxc exec $CT -- pkill meshguard 2>/dev/null || true
    lxc exec $CT -- pkill wg-interop 2>/dev/null || true
    lxc exec $CT -- ip link del wg0 2>/dev/null || true
    lxc exec $CT -- ip link del wg-test0 2>/dev/null || true
done
sleep 1

# ── Push binary ──
echo "Pushing wg-interop-test binary to $CT_B..."
lxc file push "$INTEROP_BIN" $CT_B/usr/local/bin/wg-interop-test

# ── Generate keys on kernel side (Container A) ──
echo ""
echo "--- Container A: Kernel WireGuard ---"
KERN_PRIVKEY=$(lxc exec $CT_A -- wg genkey)
KERN_PUBKEY=$(echo "$KERN_PRIVKEY" | lxc exec $CT_A -T -- wg pubkey)
echo "  Private: ${KERN_PRIVKEY:0:8}..."
echo "  Public:  $KERN_PUBKEY"

# ── Generate keys for MeshGuard side (Container B) ──
echo ""
echo "--- Container B: MeshGuard (userspace) ---"
MG_PRIVKEY=$(lxc exec $CT_B -- wg genkey)
MG_PUBKEY=$(echo "$MG_PRIVKEY" | lxc exec $CT_B -T -- wg pubkey)
echo "  Private: ${MG_PRIVKEY:0:8}..."
echo "  Public:  $MG_PUBKEY"

# ── Get container IPs ──
IP_A=$(lxc exec $CT_A -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
IP_B=$(lxc exec $CT_B -- sh -c "ip -4 addr show eth0 | grep inet | awk '{print \$2}' | cut -d/ -f1")
echo ""
echo "Container IPs: A=$IP_A  B=$IP_B"

# ── Setup kernel WG on Container A ──
echo ""
echo "Setting up kernel WireGuard on $CT_A..."
lxc exec $CT_A -- ip link add wg0 type wireguard
lxc exec $CT_A -- sh -c "echo '$KERN_PRIVKEY' > /tmp/wg-priv.key"
lxc exec $CT_A -- wg set wg0 \
    private-key /tmp/wg-priv.key \
    listen-port $KERNEL_PORT \
    peer "$MG_PUBKEY" \
    allowed-ips "${TUNNEL_NET}.0/24" \
    endpoint "${IP_B}:${MESHGUARD_PORT}"
lxc exec $CT_A -- ip addr add ${TUNNEL_NET}.1/24 dev wg0
lxc exec $CT_A -- ip link set wg0 up
echo "  wg0 up: ${TUNNEL_NET}.1/24, listen=$KERNEL_PORT"

# ── Verify kernel WG config ──
echo ""
echo "Kernel WG config:"
lxc exec $CT_A -- wg show wg0

# ── Start MeshGuard interop binary on Container B ──
echo ""
echo "Starting wg-interop-test on $CT_B..."
lxc exec $CT_B -T -- sh -c \
    "wg-interop-test \
        --private-key '$MG_PRIVKEY' \
        --peer-pub '$KERN_PUBKEY' \
        --peer-endpoint '${IP_A}:${KERNEL_PORT}' \
        --local-ip '${TUNNEL_NET}.2/24' \
        --listen-port $MESHGUARD_PORT \
        </dev/null >/tmp/interop-test.log 2>&1 &"

echo "  Waiting for handshake (5s)..."
sleep 5

# ── Check handshake ──
echo ""
echo "MeshGuard log:"
lxc exec $CT_B -- cat /tmp/interop-test.log

# ── Check kernel side for handshake ──
echo ""
echo "Kernel WG status:"
lxc exec $CT_A -- wg show wg0

# ── Ping test ──
echo ""
echo "═══ Ping from MeshGuard → Kernel WG ═══"
lxc exec $CT_B -- ping -c 10 -i 0.2 ${TUNNEL_NET}.1 2>&1 || echo "(ping failed)"

echo ""
echo "═══ Ping from Kernel WG → MeshGuard ═══"
lxc exec $CT_A -- ping -c 10 -i 0.2 ${TUNNEL_NET}.2 2>&1 || echo "(ping failed)"

# ── Final status ──
echo ""
echo "═══ Final WG Status ═══"
lxc exec $CT_A -- wg show wg0

# ── Cleanup ──
echo ""
echo "Cleaning up..."
lxc exec $CT_B -- pkill wg-interop 2>/dev/null || true
lxc exec $CT_A -- ip link del wg0 2>/dev/null || true
lxc exec $CT_B -- ip link del wg-test0 2>/dev/null || true
echo "Done."
