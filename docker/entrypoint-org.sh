#!/bin/sh
# Org Fleet Mode entrypoint — trust via org certificates instead of individual keys.
#
# Architecture:
#   1. First node (SEED_DELAY=1) acts as org admin: generates org key, waits for peers
#   2. All nodes generate identities and publish pubkeys
#   3. Org admin signs all node keys, publishes certs + org pubkey
#   4. All nodes trust the org and install their cert
#
# Environment:
#   ORG_ADMIN=1       — this node generates the org keypair and signs peers
#   SEED_PEERS        — comma-separated seed endpoints
#   SEED_DELAY        — seconds to wait before starting

set -e

export MESHGUARD_CONFIG_DIR="/etc/meshguard"
SHARED_DIR="/shared/org"
mkdir -p "$MESHGUARD_CONFIG_DIR" "$SHARED_DIR/certs" "$SHARED_DIR/pubkeys"

# ── Step 1: Generate node identity ──
if [ ! -f "$MESHGUARD_CONFIG_DIR/identity.key" ]; then
    echo "[org-fleet] Generating node identity..."
    meshguard keygen
fi

OUR_KEY=$(cat "$MESHGUARD_CONFIG_DIR/identity.pub" 2>/dev/null || echo 'unknown')
HOSTNAME=$(hostname)
echo "[org-fleet] Node '$HOSTNAME' pubkey: $OUR_KEY"

# Publish our pubkey for the org admin to sign
echo "$OUR_KEY" > "$SHARED_DIR/pubkeys/$HOSTNAME.pub"

# ── Step 2: Org admin generates org key and signs all nodes ──
if [ "$ORG_ADMIN" = "1" ]; then
    echo "[org-fleet] === ORG ADMIN MODE ==="

    # Generate org keypair
    meshguard org-keygen
    ORG_PUB=$(cat "$MESHGUARD_CONFIG_DIR/org/org.pub")
    echo "[org-fleet] Org pubkey: $ORG_PUB"

    # Publish org public key for all nodes
    echo "$ORG_PUB" > "$SHARED_DIR/org.pub"

    # Wait for peer pubkeys to appear
    echo "[org-fleet] Waiting ${SEED_DELAY:-3}s for peer pubkeys..."
    sleep "${SEED_DELAY:-3}"

    # Sign all node pubkeys (including our own)
    for pubfile in "$SHARED_DIR/pubkeys"/*.pub; do
        [ -f "$pubfile" ] || continue
        PEER_NAME=$(basename "$pubfile" .pub)
        PEER_KEY=$(cat "$pubfile")
        echo "[org-fleet] Signing cert for: $PEER_NAME"

        meshguard org-sign "$pubfile" --name "$PEER_NAME" 2>/dev/null || true

        # Copy cert to shared dir
        if [ -f "$MESHGUARD_CONFIG_DIR/$PEER_NAME.cert" ]; then
            cp "$MESHGUARD_CONFIG_DIR/$PEER_NAME.cert" "$SHARED_DIR/certs/$PEER_NAME.cert"
            echo "[org-fleet]   → $PEER_NAME.cert signed"
        fi
    done

    # Signal that signing is complete
    touch "$SHARED_DIR/signing-done"
    echo "[org-fleet] All certs signed."
else
    # Wait for org admin to finish signing
    echo "[org-fleet] Waiting for org admin to sign certificates..."
    WAIT=0
    while [ ! -f "$SHARED_DIR/signing-done" ] && [ $WAIT -lt 30 ]; do
        sleep 1
        WAIT=$((WAIT + 1))
    done

    if [ ! -f "$SHARED_DIR/signing-done" ]; then
        echo "[org-fleet] ERROR: Timed out waiting for org admin"
        exit 1
    fi
fi

# ── Step 3: Trust the org (all nodes) ──
if [ -f "$SHARED_DIR/org.pub" ]; then
    ORG_PUB=$(cat "$SHARED_DIR/org.pub")
    echo "[org-fleet] Trusting org: $ORG_PUB"
    meshguard trust "$ORG_PUB" --org --name fleet 2>/dev/null || true
else
    echo "[org-fleet] WARNING: No org pubkey found"
fi

# ── Step 4: Install our node certificate ──
if [ -f "$SHARED_DIR/certs/$HOSTNAME.cert" ]; then
    cp "$SHARED_DIR/certs/$HOSTNAME.cert" "$MESHGUARD_CONFIG_DIR/node.cert"
    echo "[org-fleet] Installed node.cert ($(wc -c < "$MESHGUARD_CONFIG_DIR/node.cert") bytes)"
else
    echo "[org-fleet] WARNING: No cert found for $HOSTNAME"
fi

# ── Step 5: Start meshguard ──
SEED_ARGS=""
if [ -n "$SEED_PEERS" ]; then
    for peer in $SEED_PEERS; do
        SEED_ARGS="$SEED_ARGS --seed $peer"
    done
fi

echo "[org-fleet] Starting meshguard daemon (org fleet mode)..."
exec meshguard up $SEED_ARGS
