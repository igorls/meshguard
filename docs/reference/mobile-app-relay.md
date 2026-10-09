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
