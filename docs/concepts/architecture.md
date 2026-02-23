# Architecture

meshguard is a decentralized, serverless mesh VPN daemon that builds WireGuard tunnels automatically between trusted peers — with no coordinator, no control plane, and no single point of failure.

## Design Principles

1. **Zero coordination** — No central server. Every node is equal.
2. **Trust is local** — Each node manages its own `authorized_keys/` directory.
3. **Identity-driven networking** — IP addresses are derived deterministically from public keys.
4. **Self-healing** — The SWIM gossip protocol detects failures and propagates membership changes in O(log N) time.
5. **NAT-aware** — STUN discovery, UDP hole punching, and relay fallback handle real-world network topologies.

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                          meshguard                              │
│                                                                 │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────┐ │
│  │ Identity │  │   Discovery   │  │    WireGuard Engine      │ │
│  │          │  │               │  │                          │ │
│  │ Ed25519  │  │ SWIM Protocol │  │  Noise IK Handshake     │ │
│  │ Keys     │  │ Membership    │  │  ChaCha20-Poly1305      │ │
│  │ Trust    │  │ Seed peers    │  │  Transport tunnels       │ │
│  └──────────┘  └───────────────┘  │  Anti-replay window     │ │
│                                    └──────────────────────────┘ │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────────────┐ │
│  │   NAT    │  │   Protocol    │  │       Network I/O        │ │
│  │          │  │               │  │                          │ │
│  │ STUN     │  │ Wire codec    │  │  UDP socket (gossip)    │ │
│  │ Holepunch│  │ Message types │  │  TUN device (packets)   │ │
│  │ Relay    │  │ Binary format │  │  Netlink (kernel WG)    │ │
│  └──────────┘  └───────────────┘  └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Module Architecture

meshguard is organized into six top-level modules, each with a focused responsibility:

### `identity/` — Keys and trust

- **`keys.zig`** — Ed25519 keypair generation, saving, loading, signing, verification
- **`trust.zig`** — Manages `authorized_keys/` directory, validates keys, checks authorization

### `discovery/` — Peer discovery and failure detection

- **`swim.zig`** — SWIM gossip protocol: ping/ack, ping-req indirect probing, gossip dissemination, hole punch coordination
- **`membership.zig`** — Membership table: peer states (alive/suspected/dead), Lamport timestamps, suspicion expiry
- **`seed.zig`** — Seed peer resolution (static IPs, DNS, mDNS placeholders)

### `wireguard/` — Tunnel management

- **`noise.zig`** — Noise_IKpsk2 handshake: initiation, response, transport key derivation, `decryptInitiatorStatic` for O(1) routing
- **`device.zig`** — Userspace WG device: per-peer state, `IndexTable` (Fibonacci-hash open-addressing), `StaticKeyTable` for O(1) lookups
- **`tunnel.zig`** — ChaCha20-Poly1305 encrypt/decrypt, anti-replay sliding window (2048-bit), rekey/keepalive timers
- **`ip.zig`** — Deterministic mesh IP derivation from Ed25519 public keys via Blake3
- **`crypto.zig`** — HMAC-Blake2s, HKDF (kdf1/kdf2/kdf3), `mixHash`
- **`wg_config.zig`** — Kernel WireGuard configuration via WG_USERSPACE_IMPLEMENTATION
- **`netlink.zig`** / **`nlsocket.zig`** — Raw netlink socket for kernel WG setup
- **`rtnetlink.zig`** — Interface creation, IP assignment, route management via RTNETLINK

### `nat/` — NAT traversal

- **`stun.zig`** — STUN Binding Request/Response (RFC 5389), public endpoint discovery, NAT type detection
- **`holepunch.zig`** — Rendezvous-mediated UDP hole punching with probe magic packets
- **`relay.zig`** — Relay selection for symmetric NAT fallback

### `protocol/` — Wire format

- **`messages.zig`** — Message type definitions: Ping, Ack, PingReq, HandshakeInit/Resp, GossipEntry, HolepunchRequest/Response, EndpointUpdate, RelayRequest
- **`codec.zig`** — Binary serialization/deserialization (type-tag-delimited, fixed-size fields)

### `net/` — Low-level network I/O

- **`udp.zig`** — Non-blocking UDP socket with `sendTo`, `recvFrom`, `pollRead`
- **`tun.zig`** — Linux TUN device: open, read/write IP packets, `setMtu`, `setNonBlocking`
- **`io.zig`** — Event loop placeholder (Phase 2: epoll/io_uring)

## Packet Flow

### Outgoing (application → peer)

```
App writes to mg0 (TUN)
  → TUN read() captures IP packet
  → Lookup destination mesh IP → WgDevice peer slot
  → Tunnel.encrypt() → ChaCha20-Poly1305 + transport header
  → UDP sendTo() peer's endpoint
```

### Incoming (peer → application)

```
UDP recvFrom() on gossip port
  → PacketType.classify() by first 4 bytes
  → Type 4 (transport): WgDevice.decryptTransport()
    → IndexTable lookup by receiver_index → peer slot
    → Tunnel.decrypt() → strip padding via IP header length
    → TUN write() → inject into OS network stack
  → Type 1 (handshake init): decryptInitiatorStatic() → O(1) peer lookup → full consume
  → SWIM: decode → gossip handler → membership update
  → STUN: parse response → update public endpoint
```

### Multiplexing

All traffic shares a single UDP port (default `51821`). The `PacketType.classify()` function routes packets:

| First 4 bytes (LE u32)          | Type                  |
| ------------------------------- | --------------------- |
| 1                               | WG Handshake Init     |
| 2                               | WG Handshake Response |
| 3                               | WG Cookie Reply       |
| 4                               | WG Transport Data     |
| Magic `0x2112A442` at bytes 4–7 | STUN Response         |
| Anything else                   | SWIM gossip           |

## Kernel vs. Userspace WireGuard

meshguard supports two operation modes:

| Feature      | Kernel WG (`--kernel`)  | Userspace (default)        |
| ------------ | ----------------------- | -------------------------- |
| Performance  | Kernel-speed crypto     | User-space ChaCha20        |
| Setup        | `ip link add` + netlink | TUN + UDP socket           |
| Dependencies | `wireguard` kmod loaded | None                       |
| Portability  | Linux only              | Any Linux with TUN         |
| Debugging    | Harder                  | Easier (all in user space) |
