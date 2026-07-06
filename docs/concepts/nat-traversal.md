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

The response contains the **XOR-MAPPED-ADDRESS** attribute — the node's public IP and port as seen by the STUN server. meshguard compares observations from up to two STUN servers:

| Observation                                  | NAT Type    | Implication                                |
| -------------------------------------------- | ----------- | ------------------------------------------ |
| Stable mapping and local port matches         | `public`    | No NAT or directly reachable mapping       |
| Stable mapping and local port differs         | `cone`      | Endpoint-independent mapping; punch first  |
| Mapping changes between STUN servers          | `symmetric` | Endpoint-dependent mapping; prefer relay   |
| No STUN response                              | `unknown`   | Firewall or undetermined                   |

The discovered public endpoint is then shared via gossip, so other peers know how to reach this node.

### STUN Servers

The runtime STUN client resolves the configured `host:port` entries from
`Config.stun_servers`:

| Server                | Port  |
| --------------------- | ----- |
| `stun.l.google.com`   | 19302 |
| `stun.cloudflare.com` | 3478  |

If no configured server resolves, meshguard falls back to deterministic IPv4
endpoints for the same services so environments without working DNS still have a
stable startup path.

## Tier 2: UDP Hole Punching

When both peers are behind cone NATs, meshguard performs **rendezvous-mediated
hole punching** from SWIM membership:

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
- **Probe magic**: `MGHP` (`0x4D 0x47 0x48 0x50`) followed by the 16-byte punch token
- **Probe timing**: Every 200ms, up to 25 probes (5-second timeout)
- **Concurrency**: Up to 4 concurrent hole punch attempts
- **Token verification**: Random 16-byte nonce is bound to the initiator/target identities and echoed in probes

The `meshguard connect` token-exchange command uses a separate coordinated
punch path in `coordinated_punch.zig`. Its raw probe magic is `MGCP` and the
probe includes an 8-byte nonce from the signed token.

### When Hole Punching Fails

Hole punching works for **endpoint-independent mapping** (cone NAT). It fails for **symmetric NAT** where each destination gets a different external port. In that case, meshguard falls back to relay.

## Tier 3: Relay Fallback

When hole punching fails, a **public-IP relay** forwards an opaque relay frame:

```
Node A (NATed) -- RelayData(sender=A,target=B,payload=WG bytes) --> Relay
Relay          -- RelayData(sender=A,target=B,payload=WG bytes) --> Node B
```

The relay frame carries routing metadata plus a WireGuard/Noise packet payload (message types 1-4). The relay validates that the payload is shaped like a WireGuard packet, rate-limits by identity, and forwards the bytes unchanged. It is never a WireGuard peer for the relayed tunnel and never receives plaintext or authorization authority.

Hosted rendezvous registration is identity-authenticated: the relay issues a nonce, and the node signs `(identity pubkey, endpoint, nonce)` with its Ed25519 identity key before the relay stores the identity -> observed endpoint mapping.

### Relay Selection

The `relay.zig` module selects the best relay candidate and exposes the hosted relay/rendezvous core:

1. Must be **alive** in the membership table
2. Must be a **public** NAT type
3. Must be **relay-capable** (not at capacity — default max: 10 relay connections)
4. Prefer **lowest RTT** (measured by SWIM ping round-trips)
5. Prefer direct path, then hole punch, then relay

```zig
pub fn selectRelay(
    peers: *std.AutoHashMap([32]u8, Membership.Peer),
    exclude: ?[32]u8,
) ?*const Membership.Peer
```

Relay frames use wire type `0x31`:

```
[0x31][32B sender pubkey][32B target pubkey][2B payload length][WireGuard packet bytes]
```

### NAT Type Classification

Each node's NAT type is broadcast via gossip, so the mesh knows which peers need relaying:

| `NatType`   | Value | Meaning                                         |
| ----------- | ----- | ----------------------------------------------- |
| `public`    | 0     | No NAT — can receive unsolicited UDP            |
| `cone`      | 1     | Endpoint-independent mapping — hole punch works |
| `symmetric` | 2     | Endpoint-dependent mapping — relay required     |
| `unknown`   | 3     | STUN failed or undetermined                     |
