FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y iproute2 netcat-openbsd python3 libsodium-dev && \
    rm -rf /var/lib/apt/lists/*

COPY zig-out/bin/meshguard /usr/local/bin/meshguard
RUN chmod +x /usr/local/bin/meshguard

WORKDIR /etc/meshguard
