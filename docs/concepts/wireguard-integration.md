# WireGuard Integration

meshguard implements a full userspace WireGuard stack alongside kernel WireGuard support. This page covers how the tunnel engine works.

## Noise IK Handshake

WireGuard uses the **Noise_IKpsk2** handshake pattern. meshguard implements this in `wireguard/noise.zig`, following the kernel's `noise.c` line-for-line.

### Message Flow

```
Initiator                                          Responder
    │                                                   │
    │  ┌─────────────────────────────────────────────┐  │
    │  │ Type 1: Handshake Initiation (148 bytes)    │  │
    │  │  sender_index │ ephemeral │ encrypted_static │  │
    │  │  encrypted_timestamp │ mac1 │ mac2           │  │
    │──┤                                             ├──│
    │  └─────────────────────────────────────────────┘  │
    │                                                   │
    │  ┌─────────────────────────────────────────────┐  │
    │  │ Type 2: Handshake Response (92 bytes)       │  │
    │  │  sender_index │ receiver_index │ ephemeral  │  │
    │  │  encrypted_nothing │ mac1 │ mac2            │  │
    │──┤                                             ├──│
    │  └─────────────────────────────────────────────┘  │
    │                                                   │
    │         ◄── Transport keys derived ──►            │
```

### Cryptographic Primitives

| Primitive            | Algorithm           | Usage                          |
| -------------------- | ------------------- | ------------------------------ |
| Key agreement        | X25519              | DH for Noise handshake         |
| Symmetric encryption | ChaCha20-Poly1305   | AEAD for handshake + transport |
| Hashing              | Blake2s-256         | Hash chaining, MAC1/MAC2       |
| Key derivation       | HMAC-Blake2s + HKDF | kdf1, kdf2, kdf3               |
| Timestamps           | TAI64N              | Anti-replay in handshake       |

### O(1) Handshake Routing

When a handshake initiation arrives, meshguard needs to determine which peer sent it. The naive approach iterates all peers trying to decrypt — O(N). meshguard uses a two-step O(1) approach:

1. **`decryptInitiatorStatic()`** — performs the minimal Noise IK steps (e, es) to decrypt the initiator's static X25519 public key. This runs once regardless of peer count.
2. **`StaticKeyTable.get()`** — O(1) lookup of the decrypted key to find the peer slot.

## Transport Layer

After a successful handshake, `tunnel.zig` handles all encrypted data traffic.

### Packet Format (Type 4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤─┤
│     Type (4)      │    Receiver Index    │
├───────────────────┼─────────────────────┤
│                 Counter (8 bytes)                               │
├─────────────────────────────────────────────────────────────────┤
│             Encrypted Padded Payload + Auth Tag (16B)           │
└─────────────────────────────────────────────────────────────────┘
```

- **Padding**: Plaintext is zero-padded to a multiple of 16 bytes to prevent traffic analysis
- **Nonce**: 12-byte nonce built from 8-byte LE counter + 4 zero bytes
- **Depadding**: On decrypt, the IP header's total-length field is parsed (IPv4 bytes 2–3, IPv6 bytes 4–5 + 40) to strip padding

### Anti-Replay Protection

The `ReplayWindow` implements a **2048-bit sliding window bitmap**:

- New counters above the window are always accepted; the window shifts forward
- Counters within the window are checked against the bitmap — replays are rejected
- Counters older than the window are rejected outright

This matches the kernel WireGuard implementation in `noise.h`.

### Key Lifecycle

| Timer                  | Value | Action                                       |
| ---------------------- | ----- | -------------------------------------------- |
| `REKEY_AFTER_TIME`     | 120 s | Sets `needs_rekey = true`                    |
| `REJECT_AFTER_TIME`    | 180 s | Reject all encrypt/decrypt operations        |
| `KEEPALIVE_TIMEOUT`    | 10 s  | Send empty keepalive to maintain NAT mapping |
| `REKEY_AFTER_MESSAGES` | 2^60  | Message-count based rekey trigger            |

## WgDevice — Peer Management

The `WgDevice` struct in `device.zig` manages up to 64 peers:

### Index Lookup — `IndexTable`

The sender/receiver index is a `u32` used to route incoming packets to the correct peer. Instead of a 64K-entry array (wasteful) or a HashMap (allocator-dependent), meshguard uses a **fixed-size open-addressed hash table** with Fibonacci hashing:

- **Size**: 256 slots (power of 2, ~3× max active indices)
- **Hash**: `index *% 0x9E3779B9 % 256` (Fibonacci/golden ratio multiplicative hash)
- **Collision**: Linear probing
- **Deletion**: Robin Hood back-shifting (no tombstones)
- **Sentinel**: Index `0` is never used (always reserved)

### Static Key Lookup — `StaticKeyTable`

For O(1) handshake initiation routing, a secondary table maps X25519 public keys to peer slots:

- Linear scan table (MAX_PEERS = 64 entries, so scan is fast)
- Used by `handleInitiation()` after `decryptInitiatorStatic()`
- Updated on `addPeer()` / `removePeer()`

### Sender Index Allocation

Sender indices start from a **random seed** (drawn from CSPRNG at device init) and increment with wrapping, skipping zero. This provides some unpredictability for external observers.

## Kernel vs. Userspace

| Operation          | Kernel Mode                         | Userspace Mode                     |
| ------------------ | ----------------------------------- | ---------------------------------- |
| Interface creation | `RTM_NEWLINK` with kind `wireguard` | `TunDevice.open("mg0")`            |
| Peer management    | `WG_CMD_SET_DEVICE` via Genetlink   | `WgDevice.addPeer()` in memory     |
| Encryption         | Kernel crypto API                   | `ChaCha20Poly1305` from Zig stdlib |
| IP assignment      | `RTM_NEWADDR` via RTNETLINK         | `RTM_NEWADDR` via RTNETLINK        |
| Route setup        | `RTM_NEWROUTE` via RTNETLINK        | `RTM_NEWROUTE` via RTNETLINK       |
| MTU                | Set via `SIOCSIFMTU` ioctl          | `TunDevice.setMtu(1420)`           |
| Packet I/O         | Direct kernel path                  | TUN read/write + UDP send/recv     |

## Benchmarking

meshguard includes a 4-way benchmark script (`docker/lxc-4way-bench.sh`) that compares:

1. **Kernel WireGuard** — Linux kernel module
2. **meshguard** — Zig userspace
3. **wireguard-go** — Go userspace (reference implementation)
4. **boringtun** — Rust userspace (Cloudflare)

Run it on LXC containers:

```bash
bash docker/lxc-4way-bench.sh 10  # 10-second tests
```

Each test measures latency (50 pings) and throughput (iperf3 download + upload).
