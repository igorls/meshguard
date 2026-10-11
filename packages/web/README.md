# @meshguard/web

MeshGuard in the browser. This package holds:

| File | What it is |
|---|---|
| `meshguard.wasm` | The MeshGuard WASM core (ReleaseSmall, no imports): Ed25519 identities, sealed `0x50` application packets, WireGuard Noise IK initiator |
| `meshguard.mjs` | `MeshguardWasm`, the JavaScript wrapper of the core |
| `relay-protocol.mjs` | `MeshguardRelayClient`, which reaches a native MeshGuard relay through the MeshGuard browser gateway (WSS) |
| `*.d.mts` | TypeScript declarations |
| `SHA256SUMS` | SHA-256 of `meshguard.wasm`, `meshguard.mjs` and `relay-protocol.mjs` |

Packets are byte-compatible with the native MeshGuard daemon and the C ABI
libraries for Linux, Windows, macOS, iOS and Android.

## Install

Every MeshGuard release ships `meshguard-web-<version>.tgz`, listed in the
release's `checksums.txt`. It is an npm package tarball:

```bash
sha256sum --check --ignore-missing checksums.txt
npm install ./meshguard-web-<version>.tgz
```

Without a package manager, unpack it (`tar -xzf`; the files are under
`package/`) and serve `meshguard.wasm`, `meshguard.mjs` and
`relay-protocol.mjs` from one directory. They import nothing else.

## Use

```javascript
import { MeshguardWasm } from '@meshguard/web';
import { MeshguardRelayClient } from '@meshguard/web/relay-protocol';

// Loads the meshguard.wasm next to meshguard.mjs; pass a URL to load it from elsewhere.
const core = await MeshguardWasm.load();
const identity = core.createIdentity(seed); // 32 bytes; omit for a random identity
```

`meshguard.wasm` must be served with `Content-Type: application/wasm`, and a
Content Security Policy needs `'wasm-unsafe-eval'` in `script-src`. With a
bundler, either let it emit the `.wasm` asset (it is referenced as
`new URL('./meshguard.wasm', import.meta.url)`) or copy
`@meshguard/web/meshguard.wasm` to your static files and pass its URL to
`load()`.

The full guide, including identity storage and gateway deployment, is
*Using MeshGuard in the browser* in the MeshGuard documentation:
https://igorls.github.io/meshguard/guide/browser

## License

MIT
