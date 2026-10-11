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

The 1-byte tags below are handled after packet classification has ruled out
WireGuard and STUN. SWIM and hole-punch messages use `protocol/codec.zig`;
`RelayData` uses the ciphertext-only helpers in `nat/relay.zig`.

| Tag    | Name              | Category  | Direction       |
| ------ | ----------------- | --------- | --------------- |
| `0x01` | Ping              | SWIM      | A → B           |
| `0x02` | PingReq           | SWIM      | A → C (probe B) |
| `0x03` | Ack               | SWIM      | B → A           |
| `0x31` | RelayData         | NAT       | A → Relay → B   |
| `0x33` | HolepunchRequest  | NAT       | A → Rendezvous  |
| `0x34` | HolepunchResponse | NAT       | B → Rendezvous  |
| `0x41` | OrgAliasAnnounce  | Org Trust | Gossip          |
| `0x42` | OrgCertRevoke     | Org Trust | Gossip          |
| `0x43` | OrgTrustVouch     | Org Trust | Gossip          |

`messages.zig` reserves additional enum values for future protocol messages.
WireGuard handshake, cookie, and transport packets are classified by their
4-byte WireGuard type (`1`-`4`), not by this 1-byte table. The FFI app-message
path uses `0x50` outside this codec.

## Ping

```
[0x01][32B sender_pubkey][8B seq (LE)][8B incarnation (LE)][1B gossip_count][N × gossip_entry][optional extensions]
```

Minimum size: **50 bytes** (no gossip, no extensions).

## Ack

```
[0x03][32B sender_pubkey][8B seq (LE)][8B incarnation (LE)][1B gossip_count][N × gossip_entry][optional extensions]
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

## Ping/Ack extensions

Optional extensions follow the last gossip entry, in this order:

```
[0x01][314B NodeCertificate]                    org certificate
[0x02][32B wg_pubkey][64B Ed25519 signature]    signed WireGuard binding
```

New encoders emit the full 314-byte v2-sized certificate slot. Decoders also
accept the legacy `[0x01][186B NodeCertificate]` extension and zero-fill the
v2-only fields so v1 certificates continue to work during rollout; nothing
follows a legacy certificate.

The binding is the sender's own signature over its WireGuard key:

```
Ed25519.sign("meshguard-wg-binding-v1\0" || sender_pubkey || wg_pubkey)
```

Gossip carries WireGuard keys for third parties without any signature, so a
key learned that way could belong to anyone. A receiver that gets a valid
binding from the key's owner adopts that key in place of a gossip-learned one;
a key bound by a trusted v2 certificate still takes precedence, and gossip
never replaces a signed key. Mobile clients use a pinned relay's WireGuard key
only when the relay signed it or it is the X25519 form of the relay's identity
(daemon keys are derived that way). Decoders that predate the binding read
only a leading `0x01` and copy at most 314 bytes, so they ignore it.

Encoders keep a Ping/Ack within **1200 bytes** (below the 1280-byte IPv6
minimum MTU once IP and UDP headers are added) by sending fewer gossip
entries next to the extensions: 8 with none or only a binding, 7 with only a
certificate, 6 with both.

## Delivery status (0x51)

A relay that does not forward a sealed `0x50` frame may answer its sender:

```
[0x51][32B destination][12B nonce of the dropped frame][1B code][1B reserved]   47 bytes
```

Codes: `1` offline (destination not reachable here), `2` destination not
admitted, `3` sender rate limited, `4` handshake again (the sender's endpoint is
not proven for its key), `5` sender not admitted, `6` relay overloaded. A
status goes only to the frame's source address and is never larger than the
frame. Clients should accept statuses only from their relay's endpoint and only
for a frame they recently sent (matching destination and nonce).

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

## RelayData

Opaque relay frame for WireGuard/Noise packets when direct and punched paths are
unavailable. The relay routes by identity metadata and forwards the payload
unchanged; it is not a WireGuard peer for the relayed tunnel.

```
[0x31][32B sender_pubkey][32B target_pubkey][2B payload_len (BE)][N WireGuard packet bytes]
```

The payload must be shaped like WireGuard message type `1`, `2`, `3`, or `4`
using the standard little-endian WireGuard type field. Non-WireGuard payloads
are rejected by the relay frame decoder.

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

## HolepunchProbe

Raw probe packet, not decoded by `protocol/codec.zig`:

```
["MGHP"][16B punch token]
```

The token is the same identity/session-bound nonce from the corresponding
HolepunchRequest/HolepunchResponse exchange.

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

Minimum size: **93 bytes** (empty payload). Maximum **plaintext**: 1024 bytes.

- **Key derivation**: X25519(sender_private, dest_wg_pubkey) → HKDF("meshguard-app-v1") → symmetric key
- **AD**: sender's Ed25519 public key
- **Routing**: intermediate peers forward the entire packet as-is (encrypted, opaque) to the destination by pubkey lookup
- **Delivery**: when `dest_pubkey` matches our own, the message is decrypted and delivered via callback
- **Optional application framing**: decrypted plaintext that starts with `MGAPP1 `
  is demuxed onto an isolated per-channel queue (`APPSEND`/`APPRECV`). Unframed
  plaintext stays on the legacy `SEND`/`RECV` queue. See
  [Application messaging channels](../reference/app-channels.md).

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
