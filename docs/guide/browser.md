# Using MeshGuard in the Browser

A web application can hold a MeshGuard identity and exchange end-to-end
encrypted messages with native MeshGuard peers (the daemon, or any application
embedding the C ABI library) and with other browsers. Two pieces make this
work:

- **`@meshguard/web`**, the browser runtime: the MeshGuard core compiled to
  WebAssembly (`meshguard.wasm`) with its JavaScript wrapper
  (`meshguard.mjs`), and `MeshguardRelayClient` (`relay-protocol.mjs`).
  Identities, signatures and packet encryption run in the page; private keys
  never leave it.
- **`@meshguard/gateway`**, the browser gateway: a small Bun service next to a
  native MeshGuard relay. Browsers cannot send UDP, so each browser session
  reaches the relay through an authenticated WebSocket that the gateway turns
  into a UDP socket. It forwards ciphertext only.

```text
browser (meshguard.wasm + MeshguardRelayClient)
   │ WSS, challenge-signed identity
   ▼
TLS reverse proxy ─► @meshguard/gateway (Bun, loopback)
                        │ UDP, one socket per session
                        ▼
                     native MeshGuard relay ─► native and browser peers
```

## Release assets

Every [release](https://github.com/igorls/meshguard/releases/latest) ships
both packages, listed in `checksums.txt`:

| Asset | Contents |
|---|---|
| `meshguard-web-<version>.tgz` | npm package `@meshguard/web`: `meshguard.wasm`, `meshguard.mjs`, `relay-protocol.mjs`, TypeScript declarations (`*.d.mts`), `SHA256SUMS`, `LICENSE` |
| `meshguard-gateway-<version>.tgz` | npm package `@meshguard/gateway`: `gateway/server.mjs`, `gateway/pass.mjs`, `web/relay-protocol.mjs`, `config.example.json`, systemd and nginx templates, `SHA256SUMS`, `LICENSE` |

Both are `npm pack` tarballs (files under `package/`). They are not published
to the npm registry; install them from the release asset. The version follows
the MeshGuard release.

## Install the runtime

```bash
curl -LO https://github.com/igorls/meshguard/releases/download/v<version>/meshguard-web-<version>.tgz
curl -LO https://github.com/igorls/meshguard/releases/download/v<version>/checksums.txt
sha256sum --check --ignore-missing checksums.txt
npm install ./meshguard-web-<version>.tgz
```

`npm install` records the tarball in `package.json` and its integrity hash in
the lockfile; keep the tarball in the repository (or an internal artifact
store) so installs stay reproducible. Bun, pnpm and Yarn install the same
tarball.

Without a package manager, unpack the tarball and serve `meshguard.wasm`,
`meshguard.mjs` and `relay-protocol.mjs` side by side. They import nothing
else, keep the file names of earlier releases, and `SHA256SUMS` lists their
hashes for pinning.

### Serving the files

- Serve `meshguard.wasm` as `application/wasm`.
- A Content Security Policy needs `'wasm-unsafe-eval'` in `script-src`, and
  the gateway's `wss://` origin in `connect-src`.
- `MeshguardWasm.load()` without arguments fetches the `meshguard.wasm` next
  to `meshguard.mjs` (`new URL('./meshguard.wasm', import.meta.url)`).
  Bundlers that understand that pattern (Vite, webpack 5, Parcel, esbuild with
  a file loader) emit the WASM as an asset. Otherwise copy
  `node_modules/@meshguard/web/meshguard.wasm` to your static files and pass its
  URL: `MeshguardWasm.load('/assets/meshguard.wasm')`.
- To pin a copied module with Subresource Integrity, convert its hash to
  Base64: `openssl dgst -sha256 -binary meshguard.mjs | openssl base64 -A`
  gives the value for `integrity="sha256-…"`.

The WASM ABI version is checked when the module loads: `meshguard.mjs` exports
`ABI_VERSION` and refuses a `meshguard.wasm` built for another ABI. Always
upgrade the three files together.

## Use the runtime

```javascript
import { MeshguardWasm } from '@meshguard/web';
import { MeshguardRelayClient } from '@meshguard/web/relay-protocol';

const core = await MeshguardWasm.load();
const identity = core.createIdentity(seed); // 32-byte seed; see "Identity storage"

// Pinned keys, from your own authenticated pairing or configuration flow.
const relay = { publicKey: relayKey, wgPublicKey: relayWgKey };

const client = new MeshguardRelayClient({
  identity,
  url: 'wss://app.example.com/meshguard-web/ws',
  relay,
  pass, // optional: a pass issued to this identity by an organization the gateway trusts
});
const friend = client.addContact(friendKey, friendWgKey);

client.addEventListener('state', event => console.log(event.detail.state));
client.addEventListener('message', event => {
  if (event.detail.peer === friend) handle(event.detail.data); // authenticated, decrypted bytes
});
client.addEventListener('status', event => {
  // The relay could not deliver a frame you sent: event.detail.reason is
  // 'offline', 'rate-limited', 'handshake-again', ...; event.detail.nonce matches send().
});
client.connect();

// Once the state is 'connected':
const nonce = client.send(friend, 'hello'); // the frame's 12-byte nonce, or false
```

- Message payloads are at most 1,024 bytes (`core.maxPayload`); frame and
  chunk larger data yourself.
- `send` returning a nonce means the frame left the browser, not that it was
  delivered. Use application acknowledgements, and keep your own outbox if
  messages must survive a reload.
- Pass only peer keys you obtained through an authenticated channel. Gossip
  from the relay can tell you a pinned peer is visible (`peer` events); it
  never adds or replaces keys.
- When the gateway closes with code `4004` the pass expired: get a new one,
  call `client.renewPass(pass)` and `client.reconnect()`. Renew before expiry
  with `renewPass` on the live session; a `pass` event reports the outcome.
- Use one identity handle per `MeshguardRelayClient`. To hold sessions on
  several relays, create one handle per relay from the same seed. The core
  holds 16 identity handles.
- `identity.destroy()` zeroes the identity in WASM memory (on sign-out, for
  example).

The TypeScript declarations describe every method and event payload. The
[WASM core reference](../reference/wasm-core.md) documents the packet format and
raw ABI; the [browser relay reference](../reference/browser-relay.md) documents
the client and the gateway protocol.

## Identity storage

A browser identity is its 32-byte seed: the same seed always gives the same
Ed25519 and WireGuard keys. MeshGuard does not store it for you, and the
choices are the application's:

- **Keep it on the device.** Never send the seed to a server or to the
  gateway; they need only the public keys.
- **Use IndexedDB, not `localStorage`.** IndexedDB can hold a non-extractable
  WebCrypto key, so the seed can be stored encrypted under a key that page
  scripts can use but not read out (example below). This keeps the raw seed out
  of storage dumps and backups. It does not protect against script running in
  your origin: such a script can use the key, or read identities from WASM
  memory. Treat cross-site scripting as full identity compromise, and use a
  strict Content Security Policy.
- **Ask for persistent storage.** Call `navigator.storage.persist()`;
  otherwise the browser may evict the origin's data under storage pressure.
  Clearing site data deletes the identity either way.
- **Plan recovery.** If losing the identity matters, offer an export (for
  example a passphrase-encrypted backup) or make identities cheap to replace:
  peers and relays then need to learn the new public keys through your pairing
  flow, and passes must be reissued.
- **Zero your copies.** `createIdentity(seed)` copies the seed and leaves your
  buffer as it was; fill it with zeros once the identity exists.
- **One writer.** Two tabs that create an identity at the same moment create
  two; use the Web Locks API (`navigator.locks.request`) around first-time
  creation.

```javascript
// Stores the seed in IndexedDB, encrypted with a non-extractable AES-GCM key.
function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('meshguard', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('identity');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function run(db, mode, operation) {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('identity', mode);
    const request = operation(transaction.objectStore('identity'));
    transaction.oncomplete = () => resolve(request.result);
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function loadSeed() {
  const db = await openStore();
  const stored = await run(db, 'readonly', store => store.get('seed'));
  if (stored) {
    const { key, iv, data } = stored;
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data));
  }
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, seed);
  await run(db, 'readwrite', store => store.put({ key, iv, data }, 'seed'));
  return seed;
}

const seed = await navigator.locks.request('meshguard-identity', loadSeed);
const identity = core.createIdentity(seed);
seed.fill(0);
```

## Deploy the gateway

Browsers reach a relay only through a gateway that the relay operator runs. In
short:

1. Run a native MeshGuard relay, and decide how it admits browser identities:
   their public keys on its allowlist, or passes issued by an organization it
   trusts.
2. Unpack `meshguard-gateway-<version>.tgz` on the relay host (for example to
   `/opt/meshguard-web/current`) and install Bun 1.4.2 or newer.
3. Copy `config.example.json` and set `relayHost`/`relayPort` (the relay's UDP
   endpoint), `allowedOrigins` (your web application's origins), and
   `trustedOrgs` and/or `allowedIdentities`. The configuration holds public
   keys only.
4. Start it with `bun gateway/server.mjs /etc/meshguard-web/config.json`, or
   install `gateway/meshguard-web.service` (systemd; `systemctl reload` re-reads
   the configuration).
5. Put it behind TLS: `gateway/nginx-location.conf` adds the
   `/meshguard-web/ws` and `/meshguard-web/health` locations, with connection
   and request limits, to an existing HTTPS server.

The gateway checks each browser's signature over a fresh challenge before it
opens a UDP socket, limits unauthenticated connections per source address, and
forwards only the session's own handshakes, self-advertisements and sealed
packets. The [browser relay reference](../reference/browser-relay.md) lists
every configuration field and limit, the pass and renewal protocol, and close
codes.

## Building from source

With Zig 0.16.0, Node.js 22 or newer, npm and Bun:

```bash
./scripts/build-web.sh
```

It builds `meshguard.wasm` (ReleaseSmall), assembles both packages under
`zig-out/web/`, checks that the wrapper and the module share an ABI version,
packs `meshguard-web-<version>.tgz` and `meshguard-gateway-<version>.tgz`, then
unpacks them and runs the WASM and gateway tests and a TypeScript check against
the unpacked packages. Set `MESHGUARD_BINARY` to a native `meshguard` binary to
include the browser-to-relay end-to-end test, and `MESHGUARD_NATIVE_LIBRARY`
to a native FFI library to include the WASM/native interoperability test.
