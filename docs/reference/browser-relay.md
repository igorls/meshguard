# Browser relay and Android qualification

A MeshGuard WASM client can now exchange encrypted application packets with the
native Android library through the existing shared MeshGuard UDP relay. The
browser uses WSS, a narrow gateway forwards datagrams, and the native relay
forwards the original `0x50` ciphertext. The relay binary and packet format are
unchanged.

## Components and trust

`web/relay-protocol.mjs` provides `MeshguardRelayClient` and minimal native SWIM
ping/ACK/self-advertisement encoding. It uses the shared WASM packet engine and
the existing WireGuard Noise IK initiator to authenticate the relay and refresh
the browser's return route when the gateway assigns a new UDP port.

`gateway/server.mjs` runs on Bun 1.4.2. It binds HTTP and per-browser UDP sockets
to loopback by default. Its connected UDP sockets communicate only with one
operator-configured relay endpoint. The gateway receives public identity keys,
public WG keys, signatures, discovery metadata, and ciphertext. It receives no
private keys or application plaintext.

Before creating a UDP socket, the gateway requires a signature over a fresh,
connection-specific random challenge plus the browser's Ed25519/WG key binding.
The key pair must be on the operator's allowlist (`allowedIdentities`), or the
browser must present a valid pass (see below) from a trusted organization. Signatures use the domain
`meshguard-browser-gateway-v1\0`. The browser Origin must also be explicitly
allowed. Origin filtering complements identity authentication; it is not a
substitute for it.

The authentication message may also carry `binding`: the browser's signature
over its WireGuard key in the wire format's binding domain (see
`docs/concepts/wire-protocol.md`), which `MeshguardRelayClient` always sends.
The gateway verifies it once and then accepts the 262-byte self entry that
carries exactly that binding, as well as the 165-byte entry without one.

The packet gate accepts only the authenticated browser's own SWIM self entry,
WireGuard initiations, and size-bounded sealed app packets to configured
destinations. It rejects claimed third-party app senders and gossip subjects.
It limits pre-authentication time, packet rate, frame size, and output
backpressure. Unauthenticated upgrades have their own budget, separate from
admitted sessions: a global pending cap (`maxPending`, default 8), a per-source
pending cap (`maxPendingPerIp`, default 2), and a per-source upgrade token bucket
(`upgradeBurst` 5, refilled every `upgradeRefillMs` 2000); excess upgrades get
429/503 before any socket is created. Admitted sessions are bounded by the
allowlist (one per identity), so a flood of unauthenticated sockets cannot
consume their capacity. Reconnecting the same identity replaces its prior
gateway session; the replacement needs only a pending slot, never an extra
authenticated one. The per-source key is the socket address, or the
right-most `X-Forwarded-For` entry only when the TCP peer is in `trustedProxies`
(default: loopback). The nginx template overwrites that header and adds
`limit_conn`/`limit_req`. Residual risk: an attacker with many source addresses
can still occupy the small pending budget for up to the 10 s authentication
timeout; nginx limits and network-level controls are the mitigation. Ingress is restricted to the configured relay by the connected
UDP socket.

The browser pins the relay's WG key and each intended peer's Ed25519/WG keys.
Gossip identifies when a pinned peer is visible; it cannot replace those keys or
grant application contact trust. Only authenticated app packets enter a bounded
512-entry sender/nonce replay cache. Failed authentication cannot poison it.

The SDK's `identity.initiateHandshake(peerWgPublicKey)` creates the existing
148-byte native initiation using host-provided entropy and TAI64N time.
`identity.completeHandshake(response)` authenticates the 92-byte reply and
clears handshake state. The WASM exports are `mg_noise_initiate` and
`mg_noise_complete`; completion returns zero on success. Raw ABI hosts must
supply fresh ephemeral secrets, a nonzero sender index, and increasing TAI64N
timestamps. These APIs qualify routing, not a browser WireGuard tunnel.

## Run the adapter

```bash
zig build wasm wasm-test -Doptimize=ReleaseSmall
bun test tests/web
bun gateway/server.mjs /path/to/public-gateway-config.json
```

Example gateway configuration, containing public keys only:

```json
{
  "listenHost": "127.0.0.1",
  "listenPort": 4321,
  "udpBindHost": "127.0.0.1",
  "relayHost": "127.0.0.1",
  "relayPort": 51821,
  "allowedOrigins": ["https://your-app.example"],
  "trustedOrgs": ["<pass issuer organization Ed25519 Base64 key>"],
  "allowedIdentities": [
    { "publicKey": "<browser Ed25519 Base64 key>", "wgPublicKey": "<browser X25519 Base64 key>" }
  ],
  "allowedDestinations": ["<native peer Ed25519 Base64 key>"]
}
```

| Field | Default | Meaning |
|---|---|---|
| `trustedOrgs` | none | organizations whose passes admit a browser |
| `allowedIdentities` | none | key pairs admitted without a pass |
| `allowedDestinations` | none (any) | app-frame destinations a session may address; leave unset to let the relay decide |
| `maxSessions` | 4096 | admitted sessions at once |
| `maxSessionsPerIp` | 16 | admitted sessions per source address |
| `passSkewSeconds` | 300 | clock difference tolerated with the pass issuer |

The gateway refuses to start when neither `trustedOrgs` nor
`allowedIdentities` admits anyone. `SIGHUP` re-reads the configuration file and
closes sessions it no longer admits (`4003`); `meshguard-web.service` maps
`systemctl reload` to it.

The native relay must separately admit the browser identity. The browser and
native peer must also know each other's public WG keys, through an authenticated
pairing/configuration flow. Native application contact trust remains distinct
from shared relay membership.

Put the gateway behind verified TLS. `gateway/nginx-location.conf` provides
exact `/meshguard-web/ws` and `/meshguard-web/health` routes; it leaves existing
Meshrooms routes intact. `gateway/meshguard-web.service` illustrates a separate
service with a dynamic user, loopback listening, read-only filesystem access,
and resource limits. Adjust its Bun path to the local runtime.

The implementation follows the primary [Bun WebSocket API](https://bun.sh/docs/runtime/http/websockets)
and [connected UDP API](https://bun.sh/docs/runtime/networking/udp).

## Passes

A pass is a MeshGuard v2 node certificate (314 bytes; v1, 186 bytes, also
works) issued by an organization to the browser's own Ed25519 and WireGuard
keys. `gateway/pass.mjs` verifies it the same way the native code does
(`src/identity/org.zig`), including delegated issuers and clock skew; both are
checked against the shared fixtures in `src/identity/testdata/passes.json`.

- The browser sends `pass` (Base64) in its `authenticate` message. The `ready`
  reply includes `passExpiresAt` (0 = never).
- Self-advertisements may carry the pass, as the `0x01` extension before the
  binding; the gateway forwards only the session's own pass and binding, so a
  session cannot launder another identity's pass. A relay that trusts the same
  organization admits the browser from that extension.
- When the pass expires (plus the skew) the gateway closes the session with
  `4004`. Before that, the browser sends `{"type":"renew","pass":"..."}` in
  the open session and gets `renewed` (with the new `passExpiresAt`) or
  `renew-rejected` (with a reason, the old pass staying in force).
- `MeshguardRelayClient` takes `pass` in its constructor and `renewPass(pass)`
  to replace it; it switches its self-advertisements to the new pass only after
  `renewed`, emits `pass` events, and does not reconnect by itself after `4004`.
- A full gateway closes new sessions with `1013`; the client retries with
  jittered backoff.

## Contacts and delivery status

Behind an opaque relay a browser learns no peers from gossip. Register the ones
the application knows with `client.addContact(publicKey, wgPublicKey)` (it
returns the peer object `send` expects) and `client.removeContact(publicKey)`.
`send` returns the frame's 12-byte nonce, or `false`. A relay's delivery status
for a frame this client sent arrives as a `status` event with `destination`,
`nonce`, `code`, `reason` (`offline`, `destination-not-admitted`,
`rate-limited`, `handshake-again`, `not-admitted`, `overloaded`) and `peer`;
statuses for frames it did not send are ignored, and `handshake-again` also
starts a new handshake at once.

## Browser/native client

```javascript
const client = new MeshguardRelayClient({
  identity,
  url: 'wss://your-app.example/meshguard-web/ws',
  relay: trustedRelayKeys,
  trustedPeers: [trustedNativePeer],
});
client.addEventListener('message', event => handleBytes(event.detail.data));
client.addEventListener('state', event => showConnectionState(event.detail.state));
client.connect();
// Once connected:
client.send(trustedNativePeer, 'Hello from the browser');
```

The supplied peer object must be one of the client's configured pinned peers.
Socket-send counters do not prove delivery; application acknowledgements do.
This adapter retries connections but does not implement a durable message outbox.
The host application owns message IDs, receipts, history, and retry persistence.

## Live qualification — 2026-10-09

Run `pc-web-1a1229b5f86` used the real Pixel 7 Pro, the Codex in-app browser, and
the shared public relay at `meshrooms.wormdb.dev:51821/UDP`. Browser traffic used
`wss://meshrooms.wormdb.dev/meshguard-web/ws`. The Pixel's active default network was **Wi-Fi** for this
run. This is public-relay delivery with direct app sends disabled, not a cellular
qualification.

The Android app was a separate `io.rioblocks.peer_circle.webrelayprobe` debug
build of Peer Circle's existing `lib/main_relay_probe.dart`, using the already
pinned native FFI at `1bd5c25`. Its fresh test seed stayed in ignored mode-0600
build configuration. The browser generated its own identity and held its seed
in browser-local storage. Only public keys were added to restricted admission.
Profiles, contacts, and chat databases were not used by the probe.

| Check | Result |
| --- | --- |
| Android decrypted browser HELLO | Passed |
| Browser decrypted Android HELLO and ACK | Passed |
| Both clients acknowledged their own fresh challenge | Passed |
| Browser authenticated the existing relay via Noise | Passed |
| Browser identity survived page reload | Passed |
| New connection authenticated port 41407, then 44346 | Passed |
| Fresh acknowledgement after the return port changed | Passed |
| Pixel direct app sends | **0** |
| Pixel relay app sends in final capture | **6** |
| Pixel route failures | **0** |
| Final browser generation sent / received | **2 / 2** |
| Browser console warnings / errors | **0** |

Earlier connections also qualified ports 56977, 56568, and 33994. Each browser
reconnect used a new random challenge and the same persistent identity. The
relay refreshed its route after a direct native-compatible Noise handshake;
unsigned gossip was not given authority to move a known return endpoint.

Evidence: [Pixel screenshot](../evidence/android-web-relay-pixel.png) and
[browser DOM readout](../evidence/android-web-relay-browser.json). The local
proof page at `/relay.html` retains the completed test view until it is reloaded.

After qualification, both test public-key entries were removed. The original
four-peer relay admission policy was verified against its backup. Gateway
identity/destination lists were emptied, its sessions closed, and the Pixel was
returned to Peer Circle Preview. The loopback gateway and TLS health route remain
available with no admitted test identities. Repeating the test requires fresh
or explicitly re-admitted development keys.

The native relay binary and its admission policy were left unchanged.

Checks: WASM smoke and forged-Noise-response rejection passed with zero imports
and a 63,369-byte artifact. Real native FFI Noise response and six sealed-packet
exchanges passed against both the pre-extraction and refactored native library.
Eight gateway/client tests passed. The native suite passed 391 tests with two
existing skips; all eight native CLI/library/FFI build steps succeeded.

## Product work still required

This proves foreground encrypted Android-to-browser transport and authenticated
browser reconnect. Peer Circle still needs its browser platform adapter,
browser-local database/outbox, real profile/contact pairing and key-binding
verification, shared chat/receipt integration, and browser lifecycle UX.
Automatic user admission, background delivery, files, and calls need their own
acceptance runs. WASM initiator state does not expose tunnel transport keys.
