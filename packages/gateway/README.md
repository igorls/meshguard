# @meshguard/gateway

The MeshGuard browser gateway: it lets browser clients (`@meshguard/web`)
reach a native MeshGuard relay. A browser opens a WebSocket, proves that it
holds its Ed25519 and WireGuard keys by signing a fresh challenge, and is
admitted when its keys are on the allowlist or it presents a valid pass from a
trusted organization. Each admitted session gets its own UDP socket connected
to the one configured relay. The gateway forwards ciphertext only: it never
sees private keys or application plaintext, and it lets a session send only its
own handshakes, its own SWIM self-advertisement and sealed packets from its own
identity.

The gateway runs on Bun 1.4.2 or newer.

| File | What it is |
|---|---|
| `gateway/server.mjs` | The gateway (`startGateway`, and the `meshguard-gateway` command) |
| `gateway/pass.mjs` | Pass (organization certificate) verification |
| `web/relay-protocol.mjs` | Wire-format helpers shared with the browser client |
| `config.example.json` | Example configuration (public keys only) |
| `gateway/meshguard-web.service` | systemd unit template |
| `gateway/nginx-location.conf` | nginx TLS front-end template |
| `SHA256SUMS` | SHA-256 of the three modules |

## Run

```bash
tar -xzf meshguard-gateway-<version>.tgz   # files under package/
cd package
cp config.example.json config.json         # then edit it
bun gateway/server.mjs config.json
```

`npm start` in the package directory does the same with `config.json`, and
`npm install ./meshguard-gateway-<version>.tgz` installs a
`meshguard-gateway <config>` command.

The gateway listens on loopback; put it behind a TLS reverse proxy
(`gateway/nginx-location.conf`). `SIGHUP` reloads the configuration and closes
sessions it no longer admits; the systemd template maps `systemctl reload` to
it. The template expects the package contents in
`/opt/meshguard-web/current` and the configuration in
`/etc/meshguard-web/config.json`; adjust the Bun path to the local runtime.

Configuration fields, limits, passes and the relay side are described in the
browser relay reference:
https://igorls.github.io/meshguard/reference/browser-relay

## License

MIT
