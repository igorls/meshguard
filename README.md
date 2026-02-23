# meshguard

[![CI](https://github.com/igorls/meshguard/actions/workflows/ci.yml/badge.svg)](https://github.com/igorls/meshguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Decentralized, serverless, WireGuard®-compatible mesh VPN daemon.**

Zero central authority. Trust-agnostic. Single static binary.

## The Problem

Building a secure mesh network between N nodes (blockchain validators, edge servers, IoT clusters) currently requires either:

- **Tailscale/ZeroTier** — needs a central control plane. Unacceptable in trustless environments.
- **Raw WireGuard** — no coordination. Managing N×(N-1)/2 peer entries manually breaks down at ~20 nodes.
- **EasyTier/Yggdrasil/Tinc** — decentralized, but no permissioned membership. Anyone can join.

**meshguard** fills the gap: auto-discovers peers, negotiates WireGuard tunnels, traverses NATs, and enforces membership — all serverless.

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                          meshguard                              │
│                                                                 │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────┐  │
│  │ Identity │  │   Discovery   │  │    WireGuard Engine      │  │
│  │          │  │               │  │                          │  │
│  │ Ed25519  │  │ SWIM Protocol │  │  Noise IK Handshake      │  │
│  │ Keys     │  │ Membership    │  │  ChaCha20-Poly1305       │  │
│  │ Trust    │  │ Seed peers    │  │  Transport tunnels       │  │
│  └──────────┘  └───────────────┘  │  Anti-replay window      │  │
│                                   └──────────────────────────┘  │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────┐  │
│  │   NAT    │  │   Protocol    │  │       Network I/O        │  │
│  │          │  │               │  │                          │  │
│  │ STUN     │  │ Wire codec    │  │  UDP socket (gossip)     │  │
│  │ Holepunch│  │ Message types │  │  TUN device (packets)    │  │
│  │ Relay    │  │ Binary format │  │  Netlink (kernel WG)     │  │
│  └──────────┘  └───────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

| Decision                     | Rationale                                                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Ed25519 identity keys**    | Separate from WireGuard X25519 — rotate transport keys without changing identity                                    |
| **Single-port multiplexing** | WireGuard, SWIM gossip, STUN, and hole punching share one UDP port (51821). Packet type classified by first 4 bytes |
| **SWIM gossip protocol**     | O(log N) convergence, built-in failure detection, no coordinator                                                    |
| **Dual WireGuard modes**     | Kernel module (fastest) or full userspace (portable, zero dependencies)                                             |
| **Trust-agnostic**           | `authorized_keys/` directory — you decide how keys get there                                                        |
| **Deterministic mesh IPs**   | Blake3(pubkey) → `10.99.X.Y`. No DHCP, no conflicts, no coordination                                                |

## Quick Start

```bash
# Build
zig build

# Generate identity
meshguard keygen

# Share your public key with peers
meshguard export > my-node.pub

# Trust a peer
meshguard trust /path/to/peer.pub --name validator-3

# Join the mesh (userspace WireGuard — default)
meshguard up --seed 1.2.3.4:51821

# Join the mesh (kernel WireGuard)
meshguard up --seed 1.2.3.4:51821 --kernel

# Check status
meshguard status

# Stop
meshguard down
```

## Trust Model

meshguard is **intentionally unopinionated** about key distribution. It reads public keys from `~/.config/meshguard/authorized_keys/`. How they get there is your choice:

- **Manual**: `scp` keys between nodes
- **Config management**: Ansible/Salt push keys to all nodes
- **Blockchain**: Query on-chain validator registry, write `.pub` files
- **Shared storage**: All nodes poll S3/IPFS for the latest keyset
- **Git**: Keep keys in a repo, `git pull` on a cron job

Trust is **bidirectional** — both peers must have each other's key in `authorized_keys/` for a tunnel to form.

## Architecture

### Identity & Addressing

- Ed25519 keypair per node (`identity.key` / `identity.pub`)
- Mesh IP deterministically derived: `Blake3(pubkey) → 10.99.X.Y`
- Authorized keys directory gates mesh membership

### Discovery (SWIM)

- Gossip-based failure detection with ping / ack / ping-req
- Lamport timestamps for crdt-like conflict resolution
- Membership events piggybacked on SWIM messages (up to 8 per packet, 89 bytes each)
- Peer states: alive → suspected → dead, with configurable timeout

### WireGuard Engine

- **Kernel mode**: `RTM_NEWLINK` + Genetlink peer configuration via netlink
- **Userspace mode**: Full Noise_IKpsk2 handshake, ChaCha20-Poly1305 transport, TUN device
- O(1) handshake routing via `decryptInitiatorStatic` + static key lookup table
- `IndexTable`: fixed-size open-addressed hash table with Fibonacci hashing (no allocator)
- Anti-replay: 2048-bit sliding window bitmap
- Key lifecycle: rekey at 120s / 2^60 messages, reject at 180s, keepalive at 10s

### NAT Traversal

- **STUN**: RFC 5389 Binding Request to discover public endpoint + NAT type
- **Hole punching**: Rendezvous-mediated UDP probing for cone NATs (4 concurrent, 5s timeout)
- **Relay**: Public-IP mesh member forwards WG ciphertext for symmetric NATs

### Wire Protocol

- Binary codec: type-tag-delimited, fixed-size fields, little-endian
- SWIM: Ping (`0x01`), Ack (`0x03`), PingReq (`0x02`)
- Handshake: Init (`0x10`), Resp (`0x11`) — signed Ed25519 + WG key exchange
- NAT: HolepunchRequest (`0x33`), HolepunchResponse (`0x34`), EndpointUpdate (`0x32`)

## Benchmarking

A 4-way benchmark compares meshguard against kernel WG, wireguard-go, and boringtun on LXC containers:

```bash
bash docker/lxc-4way-bench.sh 10   # 10-second tests
```

Measures latency (50 pings) and throughput (iperf3 download + upload) for each implementation.

## Docker

```bash
# Multi-node mesh with Docker Compose
docker compose up

# Benchmark configuration
docker compose -f docker-compose.bench.yml up
```

## Requirements

- **Zig 0.15+**
- **Linux** (kernel WireGuard module _or_ TUN device support)
- `sudo` or `CAP_NET_ADMIN` for interface creation

## Building

```bash
# Debug build
zig build

# Release (optimized, static binary)
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Cross-compile for aarch64
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
```

## Status

Core functionality is implemented and under active benchmarking:

- [x] Ed25519 keygen, save/load, sign/verify
- [x] Authorized keys directory management
- [x] Deterministic mesh IP derivation (Blake3)
- [x] CLI: `keygen`, `trust`, `revoke`, `export`, `up`, `down`, `status`, `version`
- [x] SWIM gossip protocol with Lamport clocks
- [x] Binary wire protocol codec
- [x] Kernel WireGuard via netlink (RTM_NEWLINK + Genetlink)
- [x] Full userspace WireGuard (Noise IK, ChaCha20-Poly1305, TUN)
- [x] STUN public endpoint discovery
- [x] UDP hole punching (rendezvous-mediated)
- [x] Relay selection for symmetric NAT
- [x] Daemon event loop (kernel + userspace modes)
- [x] Docker + LXC benchmarking infrastructure
- [ ] `recvmmsg`/`sendmmsg` batched I/O
- [ ] GRO/GSO via `IFF_VNET_HDR` for TUN
- [ ] Multi-queue TUN (`IFF_MULTI_QUEUE`)
- [ ] epoll/io_uring event loop
- [ ] IPv6 support
- [ ] DNS / mDNS seed discovery
- [ ] macOS support (utun)
- [ ] FreeBSD support
- [ ] Windows support (wintun)

## Documentation

Full documentation: **[igorls.github.io/meshguard](https://igorls.github.io/meshguard/)**

To run locally:

```bash
cd docs && bun install && bun run docs:dev
```

## License

MIT — see [LICENSE](LICENSE).

---

"WireGuard" and the "WireGuard" logo are [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld. meshguard is an independent, clean-room implementation of the [WireGuard protocol](https://www.wireguard.com/protocol/) and is not affiliated with or endorsed by the WireGuard project.
