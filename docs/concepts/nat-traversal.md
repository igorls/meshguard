# NAT Traversal

meshguard uses a three-tier strategy to establish direct connections between peers behind NAT:

1. **STUN** — discover your public IP and port
2. **UDP Hole Punching** — create direct paths through cone NATs
3. **Relay** — fallback for symmetric NATs

## Tier 1: STUN Discovery

On startup, meshguard sends STUN Binding Requests (RFC 5389) to discover the node's public endpoint:

```
Node                          STUN Server
  │  Binding Request ────────►  │
  │  ◄──── Binding Response ──  │
  │    (XOR-MAPPED-ADDRESS)     │
```

The response contains the **XOR-MAPPED-ADDRESS** attribute — the node's public IP and port as seen by the STUN server. By comparing the local and external ports:

| Local Port == External Port | NAT Type  | Implication                                |
| --------------------------- | --------- | ------------------------------------------ |
| Yes                         | `public`  | No NAT or full cone — direct connect works |
| No                          | `cone`    | Port-mapped NAT — hole punch will work     |
| _(STUN fails)_              | `unknown` | Likely symmetric NAT or firewall           |

The discovered public endpoint is then shared via gossip, so other peers know how to reach this node.

### STUN Servers

meshguard uses hardcoded STUN servers:

| Server                | IP               | Port  |
| --------------------- | ---------------- | ----- |
| `stun.l.google.com`   | `74.125.250.129` | 19302 |
| `stun.cloudflare.com` | `104.18.32.7`    | 3478  |

## Tier 2: UDP Hole Punching

When both peers are behind cone NATs, meshguard performs **rendezvous-mediated hole punching**:

### Protocol

```
Node A (NATed)          Rendezvous (Public)         Node B (NATed)
    │                         │                          │
    │── HolepunchRequest ────►│                          │
    │   (A's pub endpoint,    │── HolepunchRequest ─────►│
    │    target=B, token)     │   (forwarded)            │
    │                         │                          │
    │                         │◄── HolepunchResponse ────│
    │◄── HolepunchResponse ──-│   (B's pub endpoint,     │
    │   (forwarded)           │    token_echo)            │
    │                         │                          │
    │────── UDP Probe ───────────────────────────────────►│
    │◄───── UDP Probe ──────────────────────────────────-─│
    │          (MGHP magic: 0x4D474850)                  │
    │                                                    │
    │◄═══════ WireGuard tunnel established ══════════════►│
```

### Details

- **Rendezvous selection**: Any mutual public-IP peer in the membership table
- **Probe magic**: `MGHP` (`0x4D 0x47 0x48 0x50`) — 4-byte packet recognized by `Holepuncher.isProbe()`
- **Probe timing**: Every 200ms, up to 25 probes (5-second timeout)
- **Concurrency**: Up to 4 concurrent hole punch attempts
- **Token verification**: Random 16-byte nonce prevents spoofing

### When Hole Punching Fails

Hole punching works for **endpoint-independent mapping** (cone NAT). It fails for **symmetric NAT** where each destination gets a different external port. In that case, meshguard falls back to relay.

## Tier 3: Relay Fallback

When hole punching fails, a **public-IP mesh member** serves as a relay:

```
Node A (NATed) ←─WG─→ Relay (public) ←─WG─→ Node B (NATed)
```

Since WireGuard provides end-to-end encryption, the relay only handles ciphertext. No special relay protocol is needed — the relay is simply a WireGuard peer of both NATed nodes.

### Relay Selection

The `relay.zig` module selects the best relay candidate:

1. Must be **alive** in the membership table
2. Must be a **public** NAT type
3. Must be **relay-capable** (not at capacity — default max: 10 relay connections)
4. Prefer **lowest RTT** (measured by SWIM ping round-trips)

```zig
pub fn selectRelay(
    peers: *std.AutoHashMap([32]u8, Membership.Peer),
    exclude: ?[32]u8,
) ?*const Membership.Peer
```

### NAT Type Classification

Each node's NAT type is broadcast via gossip, so the mesh knows which peers need relaying:

| `NatType`   | Value | Meaning                                         |
| ----------- | ----- | ----------------------------------------------- |
| `public`    | 0     | No NAT — can receive unsolicited UDP            |
| `cone`      | 1     | Endpoint-independent mapping — hole punch works |
| `symmetric` | 2     | Endpoint-dependent mapping — relay required     |
| `unknown`   | 3     | STUN failed or undetermined                     |
