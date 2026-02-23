#!/bin/sh
set -e

# Each container gets its own identity
export MESHGUARD_CONFIG_DIR="/etc/meshguard"
SHARED_DIR="/shared/keys"
mkdir -p "$MESHGUARD_CONFIG_DIR" "$SHARED_DIR"

# Generate identity if not already present
if [ ! -f "$MESHGUARD_CONFIG_DIR/identity.key" ]; then
    echo "[entrypoint] Generating identity..."
    meshguard keygen
fi

# Read our public key
OUR_KEY=$(cat "$MESHGUARD_CONFIG_DIR/identity.pub" 2>/dev/null || echo 'unknown')
echo "[entrypoint] Public key: $OUR_KEY"

# Publish our key to the shared volume so other nodes can trust us
HOSTNAME=$(hostname)
echo "$OUR_KEY" > "$SHARED_DIR/$HOSTNAME.pub"

# Wait for other containers to publish their keys
if [ -n "$SEED_DELAY" ]; then
    echo "[entrypoint] Waiting ${SEED_DELAY}s for peer keys..."
    sleep "$SEED_DELAY"
fi

# Trust all peer keys found in the shared directory
for keyfile in "$SHARED_DIR"/*.pub; do
    [ -f "$keyfile" ] || continue
    PEER_KEY=$(cat "$keyfile")
    PEER_NAME=$(basename "$keyfile" .pub)

    # Skip our own key
    if [ "$PEER_KEY" = "$OUR_KEY" ]; then
        continue
    fi

    echo "[entrypoint] Trusting peer: $PEER_NAME ($PEER_KEY)"
    meshguard trust "$PEER_KEY" --name "$PEER_NAME" 2>/dev/null || true
done

# Build seed arguments
SEED_ARGS=""
if [ -n "$SEED_PEERS" ]; then
    for peer in $SEED_PEERS; do
        SEED_ARGS="$SEED_ARGS --seed $peer"
    done
fi

# Add --kernel flag if in kernel benchmark mode
if [ "$BENCH_MODE" = "kernel" ]; then
    SEED_ARGS="$SEED_ARGS --kernel"
    echo "[entrypoint] Mode: kernel WG"
else
    echo "[entrypoint] Mode: userspace WG (Zig)"
fi

# Start iperf3 server in background if this is a server node
if [ "$BENCH_ROLE" = "server" ]; then
    echo "[entrypoint] Starting iperf3 server in background..."
    iperf3 -s -D
fi

echo "[entrypoint] Starting meshguard daemon..."
exec meshguard up $SEED_ARGS
