# Wire Protocol

All meshguard gossip traffic uses a **binary wire protocol** on a single UDP port (default `51821`). Messages are serialized with a minimal type-tag-delimited codec.

## Message Format

Every message starts with a **1-byte type tag**:

```
[1B type][payload...]
```

## Message Types

| Tag    | Name              | Category  | Direction       |
| ------ | ----------------- | --------- | --------------- |
| `0x01` | Ping              | SWIM      | A → B           |
| `0x02` | PingReq           | SWIM      | A → C (probe B) |
| `0x03` | Ack               | SWIM      | B → A           |
| `0x10` | HandshakeInit     | Handshake | A → B           |
| `0x11` | HandshakeResp     | Handshake | B → A           |
| `0x12` | HandshakeComplete | Handshake | A → B           |
| `0x20` | MemberJoin        | Gossip    | Piggybacked     |
| `0x21` | MemberLeave       | Gossip    | Piggybacked     |
| `0x22` | MemberSuspect     | Gossip    | Piggybacked     |
| `0x23` | MemberAlive       | Gossip    | Piggybacked     |
| `0x24` | MemberDead        | Gossip    | Piggybacked     |
| `0x30` | RelayRequest      | NAT       | A → Relay       |
| `0x31` | RelayData         | NAT       | Relay-forwarded |
| `0x32` | EndpointUpdate    | NAT       | Broadcast       |
| `0x33` | HolepunchRequest  | NAT       | A → Rendezvous  |
| `0x34` | HolepunchResponse | NAT       | B → Rendezvous  |

## Ping

```
[0x01][32B sender_pubkey][8B seq (LE)][1B gossip_count][N × gossip_entry]
```

Minimum size: **42 bytes** (no gossip).

## Ack

```
[0x03][32B sender_pubkey][8B seq (LE)][1B gossip_count][N × gossip_entry]
```

Same format as Ping. The `seq` echoes the Ping's sequence number.

## PingReq

```
[0x02][32B sender_pubkey][32B target_pubkey][8B seq (LE)]
```

Fixed size: **73 bytes**. Asks the recipient to probe `target_pubkey` on behalf of the sender.

## GossipEntry

Piggybacked on Ping and Ack messages:

```
[32B subject_pubkey]
[1B event]               # join=0, alive=1, suspect=2, dead=3, leave=4
[8B lamport (LE)]
[1B has_endpoint][4B addr][2B port (LE)]
[1B has_wg_pubkey][32B wg_pubkey]
[1B has_public_endpoint][4B addr][2B port (LE)]
[1B nat_type]            # public=0, cone=1, symmetric=2, unknown=3
```

Fixed size: **89 bytes** per entry. Up to 8 entries per message.

## HandshakeInit

```
[0x10]
[32B sender_pubkey]
[32B nonce]
[64B signature]          # sign(nonce, sender_privkey)
[32B wg_pubkey]          # X25519 WireGuard public key
[4B mesh_ip]
[2B wg_port (LE)]
[2B gossip_port (LE)]
```

Total: **169 bytes**.

## HandshakeResp

```
[0x11]
[32B sender_pubkey]
[32B nonce]              # Responder's nonce
[32B init_nonce]         # Echo of initiator's nonce
[64B signature]          # sign(init_nonce || nonce, responder_privkey)
[32B wg_pubkey]
[4B mesh_ip]
[2B wg_port (LE)]
[2B gossip_port (LE)]
```

Total: **201 bytes**.

## HolepunchRequest

```
[0x33][32B sender_pubkey][32B target_pubkey][4B addr][2B port (LE)][16B token]
```

Total: **87 bytes**.

## HolepunchResponse

```
[0x34][32B sender_pubkey][4B addr][2B port (LE)][16B token_echo]
```

Total: **55 bytes**.

## Endpoint Encoding

All IPv4 endpoints are encoded as:

```
[4B addr][2B port (LE)]
```

With a **1-byte presence flag** when optional:

- `0x00` = absent (6 zero bytes follow)
- `0x01` = present (4B addr + 2B port follow)

## Byte Order

All multi-byte integers use **little-endian** encoding, matching the WireGuard wire format.
