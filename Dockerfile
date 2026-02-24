# MeshGuard container
#
# Build locally first: zig build -Doptimize=ReleaseSafe
# Then: docker compose up --build
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iproute2 wireguard-tools iputils-ping iperf3 libsodium23 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY zig-out/bin/meshguard /usr/local/bin/meshguard
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/meshguard

ENTRYPOINT ["/entrypoint.sh"]
