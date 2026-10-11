# Relay forwarding

A relay forwards sealed application frames (`0x50`) and relayed WireGuard
ciphertext (`0x31`) between clients that cannot reach each other directly. It
cannot read them. This page describes when it forwards and what it costs.

## Who may send through a relay

Two facts make a sender authentic:

- **Vouching.** An identity names its WireGuard key with its own Ed25519
  signature (the binding extension on every ping and ack; see
  `docs/concepts/wire-protocol.md`), through a trusted v2 certificate that
  binds the key, or by using the X25519 form of its Ed25519 key, as daemons
  do. The relay records this as a *claim*. A key that only third-party gossip
  claimed vouches for nothing.
- **Possession.** A WireGuard key is *proven* at a UDP endpoint when a Noise
  initiation from that endpoint decrypts under the key with a timestamp newer
  than any seen for it. The relay answers that initiation itself and keeps no
  session, so proof uses no WireGuard peer slot and works on gossip-only and
  kernel-mode relays. Mobile contexts with a pinned relay prove their endpoint
  at most every 15 seconds; browsers prove theirs through the gateway.

Proof is kept per WireGuard key, not per identity. An identity can sign
anyone's key, but cannot prove a key it does not hold, so signing someone
else's key neither locks them out nor lets anyone send in their name. A NAT
mapping belongs to the key that proved it last.

A frame is forwarded when:

1. it arrives from an endpoint where a key is proven,
2. its sender field names an admitted identity that vouches for that key,
3. that key is within its packet and byte budgets,
4. the destination identity's key is proven at some endpoint, and
5. the relay-wide forwarding budget allows it.

Frames addressed to the relay itself are delivered locally as before; the
application authenticates their sender end to end.

## Admission

A relay forwards only for identities it admits: authorized keys, holders of a
valid certificate from a trusted organization (`trusted_orgs/`), or everyone
with `--open`. With `--relay` and no keys or orgs, it admits nobody rather than
everybody. Trust lists reload on `SIGHUP` or the owner's control `RELOAD`
without a restart, and every client is re-checked on its next frame; a client
whose certificate expired is refused until it presents a renewed one. See
`docs/guide/trust-model.md`.

## Modes

| Node | Forwarding |
|---|---|
| `meshguard up --relay` | Only the rule above. |
| Other daemons | The rule above, or, for senders not proven yet, only from the sender's known endpoint (ping and ack never move a known endpoint). |
| Mobile contexts | Never forward frames addressed to others. |

`--legacy-wg-binding` lets a closed-trust relay accept a WireGuard key learned
from gossip for an admitted identity while older clients that send no binding
remain in use. Do not combine it with `--open`.

## Opaque relays

`meshguard up --opaque` (which implies `--relay`) tells clients nothing about
other clients. Every node that is not at one of the relay's seed endpoints is a
client:

- A client's ping refreshes its claim and is answered with an ACK whose only
  gossip entry describes the relay itself. Clients never enter the relay's
  membership, so nothing about them is gossiped, and `meshguard status` and
  `PEERS` count only mesh peers.
- The relay does not probe (ping-req) or rendezvous (hole punching) on behalf
  of clients.
- Clients learn each other's keys from their own applications (contacts), not
  from the relay, and send sealed frames addressed by key as before.

Other relays at the seed endpoints remain ordinary mesh peers.

## Delivery status

When a relay does not forward a sealed frame it answers the sender with a
47-byte `0x51` status (see `docs/concepts/wire-protocol.md`): `offline`,
`rate_limited`, `handshake_again` (the sender's endpoint is not proven for its
key; send a Noise initiation), `not_admitted` (for example an expired pass) or
`overloaded`. Statuses echo the frame's nonce, go only to its source address,
are smaller than any frame, and are limited per source address (2/s, burst 4)
and overall (2,000/s). They tell a sender whether a destination is reachable;
`--no-delivery-status` turns them off.

## Answers to pings

ACKs have their own budget (`--reply-pps`, 5,000/s, burst a fifth of that),
separate from the relay's own discovery traffic (500/s), so thousands of clients
pinging every few seconds all get answers.

## Limits

| Setting | Default | Meaning |
|---|---|---|
| `--max-clients` | 16384 with `--relay`, else 1024 | WireGuard keys tracked at once; a quarter may be unproven |
| `--client-pps` | 50, burst 100 | frames per second per key |
| `--client-kbps` | 256, burst 512 KiB | bytes per second per key |
| `--forward-pps` | 20000, burst 4000 | frames per second for all keys |
| handshakes | 4/s per source address, burst 8; 1000/s overall | proof responses |
| `--trusted-handshake-source` | none | an address limited per port instead, such as a co-located browser gateway whose sessions share loopback |

A flood of unproven claims displaces only other unproven claims, never proven
clients. Unproven keys are forgotten after 30 seconds and silent proven keys
after 120. Hash tables use a per-process random seed.

`meshguard status` reports `relay.clients`, `relay.proven`, `relay.claims`,
`relay.forwarded`, `relay.proofs`, `relay.handshakes_refused`, and
`relay.dropped` by reason: `unproven_sender`, `spoofed_sender`,
`not_admitted`, `rate_limited`, `unknown_destination`, `overloaded`.

## Limits of the guarantee

- An attacker who can forge the source address of a proven client can spend
  that client's budget, as with any endpoint-bound check. The frames stay
  sealed and the recipient still authenticates them.
- On-path attackers that can observe and race traffic are out of scope, as in
  WireGuard.
- In directory mode the relay still gossips its members to each other.
