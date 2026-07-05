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

## SWIM / Protocol Codec Tags

The 1-byte tags below are handled by `protocol/codec.zig` after packet
classification has ruled out WireGuard and STUN:

| Tag    | Name              | Category  | Direction       |
| ------ | ----------------- | --------- | --------------- |
| `0x01` | Ping              | SWIM      | A → B           |
| `0x02` | PingReq           | SWIM      | A → C (probe B) |
| `0x03` | Ack               | SWIM      | B → A           |
| `0x33` | HolepunchRequest  | NAT       | A → Rendezvous  |
| `0x34` | HolepunchResponse | NAT       | B → Rendezvous  |
| `0x41` | OrgAliasAnnounce  | Org Trust | Gossip          |
| `0x42` | OrgCertRevoke     | Org Trust | Gossip          |
| `0x43` | OrgTrustVouch     | Org Trust | Gossip          |

`messages.zig` reserves additional enum values for future protocol messages,
but the codec currently decodes the tags listed above. WireGuard handshake,
cookie, and transport packets are classified by their 4-byte WireGuard type
(`1`-`4`), not by this 1-byte table. The FFI app-message path uses `0x50`
outside this codec.

## Ping

```
[0x01][32B sender_pubkey][8B seq (LE)][8B incarnation (LE)][1B gossip_count][N × gossip_entry][optional org cert extension]
```

Minimum size: **50 bytes** (no gossip, no org cert extension).

## Ack

```
[0x03][32B sender_pubkey][8B seq (LE)][8B incarnation (LE)][1B gossip_count][N × gossip_entry][optional org cert extension]
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
[1B has_endpoint][1B family][16B addr][2B port (LE)]
[1B has_wg_pubkey][32B wg_pubkey]
[1B has_public_endpoint][1B family][16B addr][2B port (LE)]
[1B nat_type]            # public=0, cone=1, symmetric=2, unknown=3
```

Fixed size: **115 bytes** per entry. Up to 8 entries are decoded per message.
A fully loaded Ping/Ack with 8 gossip entries is 970 bytes before the optional
org certificate extension.

The optional org certificate extension is appended to Ping/Ack after gossip as:

```
[1B present=1][186B NodeCertificate]
```

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
[0x33][32B sender_pubkey][32B target_pubkey][20B public_endpoint][16B token]
```

Total: **101 bytes**.

## HolepunchResponse

```
[0x34][32B sender_pubkey][20B public_endpoint][16B token_echo]
```

Total: **69 bytes**.

## OrgAliasAnnounce

Propagated via gossip to claim a human-readable `*.name.mesh` domain for an org.

```
[0x41][32B org_pubkey][32B alias (null-padded)][8B lamport (LE)][64B signature]
```

Total: **137 bytes**. Conflicts resolved by Lamport timestamp (earliest wins).

## OrgCertRevoke

Broadcast to invalidate a node certificate.

```
[0x42][32B org_pubkey][32B node_pubkey][1B reason][8B lamport (LE)][64B signature]
```

Total: **138 bytes**. Reason codes: `0`=unspecified, `1`=key_compromised, `2`=admin_removed.

## OrgTrustVouch

Propagated via gossip. Org admin vouches for an external standalone node — all nodes trusting the org auto-accept the vouched peer.

```
[0x43][32B org_pubkey][32B vouched_pubkey][8B lamport (LE)][64B signature]
```

Total: **137 bytes**. Signature covers `vouched_pubkey ‖ lamport`. Revocable via OrgCertRevoke.

## FFI AppMessage

The FFI application-message path uses `0x50` for end-to-end encrypted
application-level messages. This is documented here because it shares the UDP
port, but it is not decoded by `protocol/codec.zig`.

```
[0x50][32B dest_pubkey][32B sender_pubkey][12B nonce][N ciphertext][16B tag]
```

Minimum size: **93 bytes** (empty payload). Maximum payload: 1024 bytes.

- **Key derivation**: X25519(sender_private, dest_wg_pubkey) → HKDF("meshguard-app-v1") → symmetric key
- **AD**: sender's Ed25519 public key
- **Routing**: intermediate peers forward the entire packet as-is (encrypted, opaque) to the destination by pubkey lookup
- **Delivery**: when `dest_pubkey` matches our own, the message is decrypted and delivered via callback

## Endpoint Encoding

All protocol-codec endpoints are fixed-width and can carry IPv4 or IPv6:

```
[1B present][1B family][16B addr][2B port (LE)]
```

- `present=0` = absent; remaining bytes are zero
- `family=4` = IPv4 stored in the first 4 bytes of the 16-byte address field
- `family=6` = IPv6 stored in all 16 address bytes

## Byte Order

Protocol-codec integers use **little-endian** encoding. WireGuard packets follow
the WireGuard wire format, and STUN packets follow RFC 5389.
