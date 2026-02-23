# Wire Protocol

All meshguard gossip traffic uses a **binary wire protocol** on a single UDP port (default `51821`). Messages are serialized with a minimal type-tag-delimited codec.

## Message Format

Packets are classified by their **first 4 bytes** (little-endian u32):

- **WireGuard**: Types 1, 2, 3, 4 (followed by 3 zero bytes).
- **STUN**: RFC 5389 magic cookie (`0x2112A442`) at bytes 4-7.
- **SWIM**: Anything else (typically starts with `0x01`-`0x34`).

SWIM messages use a **1-byte type tag**:

```
[1B type][payload...]
```

## Message Types

| Tag    | Name                | Category  | Direction       |
| ------ | ------------------- | --------- | --------------- |
| `0x01` | Ping                | SWIM      | A → B           |
| `0x02` | PingReq             | SWIM      | A → C (probe B) |
| `0x03` | Ack                 | SWIM      | B → A           |
| `0x01` | HandshakeInitiation | WireGuard | A → B           |
| `0x02` | HandshakeResponse   | WireGuard | B → A           |
| `0x03` | CookieReply         | WireGuard | B → A           |
| `0x04` | TransportData       | WireGuard | A ↔ B           |
| `0x33` | HolepunchRequest    | NAT       | A → Rendezvous  |
| `0x34` | HolepunchResponse   | NAT       | B → Rendezvous  |

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

## HandshakeInitiation (Type 1)

Standard Noise_IKpsk2 initiation message.

```
[4B type (1)][4B sender_index]
[32B unencrypted_ephemeral]
[48B encrypted_static + auth]
[28B encrypted_timestamp + auth]
[16B mac1]
[16B mac2]
```

Total: **148 bytes**.

## HandshakeResponse (Type 2)

Standard Noise_IKpsk2 response message.

```
[4B type (2)][4B sender_index][4B receiver_index]
[32B unencrypted_ephemeral]
[16B encrypted_nothing + auth]
[16B mac1]
[16B mac2]
```

Total: **92 bytes**.

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
