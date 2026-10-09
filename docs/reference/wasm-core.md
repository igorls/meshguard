# Browser WASM core

MeshGuard's identity and encrypted application-packet engine can run inside a
browser as WebAssembly. The native FFI and desktop daemon use the same
`src/app_packet.zig` implementation, preserving the existing `0x50` wire format.
The JavaScript wrapper lives in `web/meshguard.mjs`.

This target includes Ed25519 identity generation and signatures, X25519 key
agreement, ChaCha20-Poly1305 application packets, and a WireGuard Noise IK
initiator for authenticating relay return routes. It does not include the
daemon, full SWIM reactor, WireGuard tunnel data, sockets, or TUN interfaces.
The [browser relay adapter](browser-relay.md) supplies WSS transport, minimal
SWIM liveness, and explicitly pinned peer keys.

## Build and verify

Use Zig 0.16.0 and Node.js 24:

```bash
zig build wasm wasm-test -Doptimize=ReleaseSmall
# Equivalent standalone cross-compilation target:
zig build -Dtarget=wasm32-freestanding -Doptimize=ReleaseSmall
```

The artifact is `zig-out/bin/meshguard.wasm`. The qualified ReleaseSmall build is
63,369 bytes, has no imports, and reserves 256 KiB of fixed linear memory with a
64 KiB stack. It needs neither WASI nor libc. Artifact size can change with
compiler versions and source changes.

To see a live browser proof:

```bash
node tests/wasm/serve.mjs
# Open http://127.0.0.1:14339/
```

The server binds to loopback and exposes the proof assets and optional public
relay-test configuration. The core page at `/` uses public test seeds and does
not connect to a relay; `/relay.html` runs the separately configured adapter test.

To test native interoperability, build a native FFI library first:

```bash
zig build -Dcrypto-backend=std -Doptimize=ReleaseSafe
MESHGUARD_NATIVE_LIBRARY="$PWD/zig-out/lib/libmeshguard-ffi.dylib" \
  node tests/wasm/native-interop.mjs
# On Linux, use libmeshguard-ffi.so instead.
```

The harness exchanges packets with the real native FFI over loopback UDP. Its
small UDP adapter supplies the SWIM acknowledgement needed for native peer
admission; it is a test fixture, not a production browser gateway.

## JavaScript API

Serve the wrapper and `.wasm` file over HTTPS (localhost is also suitable for
development). Identity creation without a seed and packet sealing use the
browser's `crypto.getRandomValues`.

```javascript
import { MeshguardWasm } from './meshguard.mjs';

const core = await MeshguardWasm.load('./meshguard.wasm');
const alice = core.createIdentity();
const bob = core.createIdentity();
const peer = identity => ({
  publicKey: identity.publicKey(),
  wgPublicKey: identity.wgPublicKey(),
});

const alicePeer = peer(alice);
const bobPeer = peer(bob);
const packet = alice.seal(bobPeer, 'Hello from the browser');
const plaintext = bob.open(alicePeer, packet);
console.log(new TextDecoder().decode(plaintext));

const signature = alice.sign('identity possession');
console.log(core.verify(alicePeer.publicKey, 'identity possession', signature));
alice.destroy();
bob.destroy();
```

Messages can be UTF-8 strings or `Uint8Array` values. `open()` returns copied
bytes. Public keys and optional deterministic identity seeds contain 32 bytes;
signatures contain 64 bytes. Maximum plaintext and signing input size is 1,024
bytes. A sealed packet has 93 bytes of overhead, for a maximum size of 1,117
bytes. Use application framing and chunking for larger data.

The host must authenticate the binding between each peer's Ed25519 identity and
X25519 public key before passing it to `seal()` or `open()`. The core verifies
the expected sender, recipient, and AEAD tag, but does not implement peer
admission, a trust store, or a persistent replay ledger. Native admission and
replay filtering remain in their existing host paths. Browser hosts must also
perform replay filtering and verify any signed peer-key advertisements.

## Native compatibility

Identity derivation matches the existing mobile FFI: an Ed25519 identity is
generated deterministically from the seed, and the X25519 private key is the
same raw seed with the existing clamping applied. This is deliberately the FFI
convention, not a standard Ed25519-to-X25519 secret-key conversion.

Packets retain the native layout:

```text
0x50 | recipient Ed25519 key (32) | sender Ed25519 key (32)
     | nonce (12) | ciphertext (0..1024) | authentication tag (16)
```

The key derivation uses the existing `kdf2(shared, "meshguard-app-v1")` convention
and sender identity as AEAD associated data. No native protocol version change
is required.

Qualification on 2026-10-09:

- The actual browser proof passed all seven checks: zero imports, encrypted
  UTF-8 round trip, encrypted reverse reply, tamper rejection, signatures,
  maximum-size packets, and destroyed-identity rejection.
- Node exercised buffer bounds, overlap rejection, fresh nonces, size limits,
  all 16 identity slots, and stale handles after slot reuse.
- An independently built native FFI at commit `1bd5c25` received three
  WASM-sealed messages and sent three packets successfully opened by WASM:
  empty, Unicode, and 1,024-byte payloads. This compares against the native
  implementation before the shared-core extraction.
- The native test suite passed 391 tests with two existing skips. The desktop
  CLI, static library, and native FFI also built successfully.

These original checks qualify the portable packet core. Subsequent real
Android-to-browser delivery and authenticated reconnect evidence is recorded in
the [browser relay qualification](browser-relay.md). Background delivery and
Peer Circle's browser product flows remain separate acceptance work.

## ABI and memory lifecycle

ABI version 1 exports `mg_abi_version`, `mg_scratch_ptr`, `mg_scratch_size`,
`mg_max_payload`, `mg_identity_create`, `mg_identity_destroy`, `mg_public_key`,
`mg_wg_public_key`, `mg_seal`, `mg_open`, `mg_sign`, `mg_verify`,
`mg_noise_initiate`, and `mg_noise_complete`.

Pointers and lengths are unsigned 32-bit values confined to an 8 KiB scratch
arena. Invalid ranges and overlapping packet input/output buffers are rejected.
Identity handles encode a slot and generation, preventing a destroyed handle
from selecting a newly created identity. Up to 16 identities can be live in one
instance. Negative return values are errors; creation returns a positive
handle, seal/open/sign return output lengths, and other operations return zero
on success.

| Status | Meaning |
| --- | --- |
| -1 | Invalid or destroyed identity handle |
| -2 | Invalid buffer range or unsupported overlap |
| -3 | Payload, seed length, or output-capacity limit |
| -4 | Identity pool exhausted |
| -5 | Invalid key or packet |
| -6 | Authentication or signature verification failed |
| -7 | Unexpected sender or recipient |

Raw ABI users must supply a cryptographically random seed and a fresh 12-byte
nonce for every seal operation under a key. The JavaScript wrapper handles this
automatically and clears temporary scratch data after each call. Destruction
zeros persistent identity material; keypair, shared-secret, and derived-key
working buffers are explicitly cleared by the shared core. Outputs are copied
before scratch is cleared.

WASM memory is accessible to the embedding JavaScript. This is not a
non-exportable hardware keystore or protection against a compromised page.
Applications still need a trusted origin, careful script policy, identity
storage and recovery, and lifecycle handling. This initial wrapper keeps
identities in memory and does not persist them.

## Next integration step

The WSS-to-UDP adapter now carries existing sealed packets to native relays, with
browser identity authentication and native Noise-based return-route updates.
The next product step is browser-local Peer Circle storage, real profile/contact
pairing, the shared chat/receipt protocol, and browser lifecycle handling.
