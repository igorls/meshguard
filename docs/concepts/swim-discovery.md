# SWIM Discovery

meshguard uses the **SWIM** (Scalable Weakly-consistent Infection-style Process Group Membership) protocol for peer discovery and failure detection. SWIM provides O(log N) convergence and bounded network overhead regardless of mesh size.

## Protocol Overview

SWIM operates in periodic **protocol rounds** (default: 5 seconds). Each round, a node:

1. **Selects a random peer** from the membership table
2. **Sends a Ping** (with piggybacked gossip)
3. **Waits for an Ack**
4. If no ack → selects _k_ other peers for **indirect probing** via Ping-Req
5. If still no ack → marks the target as **suspected**
6. After a timeout → marks the target as **dead**

```
 Node A                    Node B                    Node C
   │                         │                         │
   │──── Ping (seq=42) ─────►│                         │
   │◄──── Ack (seq=42) ──────│                         │
   │                         │                         │
   │  (if Ping to D fails)   │                         │
   │── PingReq(target=D) ───►│                         │
   │                         │──── Ping(D) ───────────►│
   │                         │◄──── Ack(D) ────────────│
   │◄── Ack(seq) ────────────│  (indirect probe)       │
```

## Peer States

The membership table tracks each peer in one of three states:

```
  ┌───────┐                    ┌───────────┐              ┌──────┐
  │ Alive │──── ping timeout──►│ Suspected │──── expiry ─►│ Dead │
  └───────┘                    └───────────┘              └──────┘
      ▲                              │
      └────── ack received ──────────┘
```

| State         | Meaning                                         | Transition                |
| ------------- | ----------------------------------------------- | ------------------------- |
| **Alive**     | Node is responding normally                     | Initial state on join     |
| **Suspected** | Node failed to respond, may be temporarily down | Ack received → Alive      |
| **Dead**      | Node confirmed unreachable                      | Suspicion timeout expired (30s) |

## Lamport Timestamps

All state changes carry a **Lamport timestamp** — a logical clock incremented on every state transition. When a node receives gossip about a peer, it only applies the update if the incoming Lamport timestamp is **higher** than the locally stored one. This provides last-writer-wins conflict resolution without wall clocks.

## Gossip Dissemination

Gossip entries are **piggybacked** on Ping and Ack messages — no dedicated gossip channel. Each message can carry up to **8 gossip entries** (configurable), each containing:

| Field             | Size | Description                                      |
| ----------------- | ---- | ------------------------------------------------ |
| `subject_pubkey`  | 32 B | The node this entry is about                     |
| `event`           | 1 B  | join / alive / suspect / dead / leave            |
| `lamport`         | 8 B  | Lamport timestamp                                |
| `endpoint`        | 7 B  | Optional IPv4:port (1B flag + 4B addr + 2B port) |
| `wg_pubkey`       | 33 B | Optional X25519 public key for WireGuard         |
| `public_endpoint` | 7 B  | Optional STUN-discovered public endpoint         |
| `nat_type`        | 1 B  | public / cone / symmetric / unknown              |

**Total per entry: 89 bytes.** A fully-loaded Ping with 8 gossip entries is ~755 bytes — well under typical MTU limits.

## Handshake Flow

When two nodes first discover each other through gossip, they perform a signed handshake before establishing a WireGuard tunnel:

1. **Initiator** sends `HandshakeInit`:
   - Ed25519 pubkey, random nonce, signature over nonce
   - X25519 WG pubkey, mesh IP, WG port, gossip port

2. **Responder** checks authorization (`authorized_keys/`), then sends `HandshakeResp`:
   - Ed25519 pubkey, own nonce, echo of initiator's nonce
   - Signature over both nonces
   - X25519 WG pubkey, mesh IP, WG port, gossip port

3. Both sides configure their WireGuard peer with the exchanged X25519 key and endpoint.

## Hole Punch Integration

When SWIM discovers that a peer is behind NAT (from gossip `nat_type` fields), it coordinates hole punching:

1. SWIM identifies a **mutual public peer** (rendezvous)
2. Sends `HolepunchRequest` via the rendezvous
3. Target responds with `HolepunchResponse`
4. Both peers begin sending UDP probe packets (`MGHP` magic)
5. Once a probe succeeds, the WireGuard endpoint is updated

See [NAT Traversal](./nat-traversal.md) for full details.

## Implementation Details

The SWIM protocol is implemented in `discovery/swim.zig`. Key design decisions:

- **Random peer selection** uses `std.crypto.random` for uniform distribution
- **Pending pings** are tracked with sequence numbers and nanosecond timestamps
- **Gossip queue** accumulates events and drains during message encoding
- **Event handler** callback notifies `main.zig` of join/leave/failure events for WireGuard reconfiguration
- **Atomic `running` flag** enables clean shutdown from signal handlers
