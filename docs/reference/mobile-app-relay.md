# Mobile FFI application relay routing

The desktop control transport and mobile FFI use the same sealed `0x50` app
packet: destination Ed25519 identity, sender identity, random nonce, ciphertext,
and authentication tag. A relay forwards the original encrypted packet through
SWIM; it does not decrypt the application payload. This is distinct from the
`0x70` relay wrapper, which accepts WireGuard ciphertext only.

The mobile sender now follows the desktop control sender's direct-plus-relay
policy for NATed or unreachable peers. Candidate entries are copied while the
membership read lock is held. A relay must be alive, public, relay-capable, and
outside the sender/recipient pair. A dead recipient can still be attempted via
an eligible relay, matching the desktop transport.

## Explicit qualification route

`meshguard_set_app_relay(ctx, public_key_or_null, force)` configures an optional
pinned Ed25519 relay identity **before join**. It returns `-2` if already running
and `-3` if forced mode has no identity. Forced mode sends no direct copy and
returns `-11` while the pinned eligible relay is unavailable. There is no direct
fallback that could disguise a failed relay experiment.

`meshguard_app_route_stats(ctx, out_32_bytes)` writes four little-endian `u64`
counters: direct socket sends, relay socket sends, failed routes, and
cryptographically authenticated duplicate copies dropped. A socket-send count
is not a delivery receipt. Qualification must also obtain an authenticated
challenge echo from the opposite endpoint.

## Duplicate copies

Automatic direct-plus-relay delivery can produce two copies of one sealed frame.
The FFI keeps a bounded 128-entry sender/nonce cache on its single receive thread.
Only successfully authenticated, admitted packets are remembered. An invalid
tag cannot poison the cache. Full inboxes do not consume cache entries.

## Checks

Native tests cover forced routing without direct fallback, pre-join identity
configuration, and authenticated duplicate filtering after a rejected forged
copy. An isolated native integration test also exchanges two-way encrypted
messages via a normal MeshGuard gossip-only relay and asserts zero direct sends.
This test does not change the production relay or application identities.

## Authenticated endpoint mobility

An observed ping/ACK does not move a known peer's endpoint: these discovery
messages are not origin-authenticated. Keeping that protection exposed a stale
relay route after a mobile peer restarted or changed from cellular to Wi-Fi.

The userspace daemon now refreshes membership from a successful **direct** Noise
handshake. WG endpoint mutation and its identity snapshot occur together under
the device lock; relayed handshakes do not advertise the relay as the peer's
direct endpoint. Admission remains enforced. Invalid handshake packets leave
the prior endpoint unchanged.

A mobile client with a pinned app relay periodically re-authenticates that
relay using the existing WG protocol (at most once per 15 seconds while active).
This carries no application data and does not alter the app-send counters.
It gives the relay a verifiable current return address after an app restart
or network change. Every daemon answers these handshakes, gossip-only relays
included, without using a WireGuard peer slot (see `relay-forwarding.md`).
The client handshakes only when the relay's WireGuard key is signed by the
relay or derived from its identity.

Mobile contexts never forward frames addressed to others.

## Contacts and opaque relays

An opaque relay (`meshguard up --opaque`) describes only itself, so a client
cannot learn other clients' keys from it. The host registers the peers it
already knows (for example from signed contact cards):

- `meshguard_add_contact(ctx, ed25519[32], wg[32])` registers or replaces a
  contact (`-3` for an invalid or low-order key, `-5` past 4096 contacts);
  `meshguard_remove_contact`, `meshguard_clear_contacts` and
  `meshguard_contact_count` manage the set.
- Frames to and from a contact use its registered WireGuard key, which wins over
  any key learned from gossip. A contact the relay does not describe is sent to
  through the pinned relay only.
- `meshguard_set_contacts_only(ctx, true)` drops app frames from anyone else
  before any decryption.

## Delivery status

`meshguard_send_ex(ctx, peer, data, len, out_nonce[12])` sends like
`meshguard_send` and returns the frame's nonce. When the pinned relay does not
forward a frame it answers with a delivery status, delivered to
`meshguard_set_on_delivery_status(ctx, cb(destination, nonce, code))` on the
event loop: `1` offline, `2` destination not admitted, `3` rate limited,
`4` handshake again, `5` not admitted (for example an expired pass), `6` relay
overloaded. Statuses are accepted only from the pinned relay's endpoint and
only for one of the last 256 frames sent through it, each at most once. Code
`4` also re-proves the relay endpoint at once.

## Timers

`meshguard_set_keepalive_interval(ctx, ms)` sets the interval between pings
(3000 ms by default for mobile contexts; 1000 to 600000), and
`meshguard_set_relay_proof_interval(ctx, ms)` the interval between endpoint
proofs to the pinned relay (15000 ms by default; 5000 to 3600000). With
delivery statuses a client learns when its endpoint must be proven again, so
both can be longer to save battery and relay capacity. Changes apply on the
event loop.

## Several relays

A context talks through one pinned relay at a time.

- **Switching.** `meshguard_switch_relay(ctx, relay_pubkey, force, seed_ip,
  seed_port)` leaves the current network, pins the new relay and joins through
  it. Leaving forgets the old network: its peers, the WireGuard sessions with
  them and the relay proof state. The identity, contacts, certificate and
  timers carry over, so a host can move a running context without rebuilding
  it. `meshguard_leave` followed by `meshguard_set_app_relay` and
  `meshguard_join` does the same in steps.
- **At once.** To reach people on several relays simultaneously, create one
  context per relay from the same identity seed. Each binds its own socket,
  proves its own endpoint and has its own contacts; a relay pass is per
  organization, so each context installs the pass for its relay.

`meshguard_last_recv_time` and the other host-thread queries do not read SWIM
state, so they are safe to call while another thread leaves or joins.

## Relay passes

A relay that trusts an organization admits any holder of that organization's
valid v2 certificate for the client's own Ed25519 and WireGuard keys. The host
obtains one from its issuer (`meshguard_get_wg_pubkey` gives the WireGuard key
to bind) and installs it with `meshguard_set_org_cert(ctx, cert, len)`, before
or after joining. The context checks the certificate is its own, correctly
signed and valid now; it returns `-3` for a wrong length and `-4` otherwise.
A running context applies it on its event loop, pings its peers at once so the
relay sees it, and proves its relay endpoint again. Renew before expiry by
installing the next certificate the same way; `meshguard_clear_org_cert`
stops presenting one.

Tests cover admitted endpoint confirmation, refusal to move a known endpoint
from unsigned observation, invalid initiation/response packets, and successful
authenticated updates in both handshake directions.
