// Browser clients holding passes reach each other through the gateway and a real, closed relay.
// Needs a native daemon: MESHGUARD_BINARY=zig-out/bin/meshguard bun test tests/web (Linux).
import { test, expect } from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { loadGateway, loadWeb, wasmBytes } from '../runtime.mjs';

const { startGateway } = await loadGateway();
const { MeshguardWasm, MeshguardRelayClient, b64, fromB64 } = await loadWeb();

const binary = process.env.MESHGUARD_BINARY;
const origin = 'http://relay-e2e.invalid';

const orgPrivate = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x52)]), format: 'der', type: 'pkcs8' });
const orgPublic = new Uint8Array(createPublicKey(orgPrivate).export({ format: 'der', type: 'spki' }).subarray(12));

function issuePass(identity) {
  const now = Math.floor(Date.now() / 1000);
  const wire = new Uint8Array(314), view = new DataView(wire.buffer);
  wire[0] = 2; wire.set(orgPublic, 1); wire.set(identity.publicKey(), 33);
  view.setBigInt64(97, BigInt(now - 10), true); view.setBigInt64(105, BigInt(now + 3600), true);
  wire.set(identity.wgPublicKey(), 186);
  const payload = new Uint8Array(178); payload.set(wire.subarray(0, 114)); payload.set(wire.subarray(186, 250), 114);
  wire.set(sign(null, payload, orgPrivate), 114);
  return wire;
}

const freePort = () => new Promise(resolve => {
  const s = createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const until = async (check, ms, what) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await check()) return; await new Promise(r => setTimeout(r, 50)); }
  throw new Error(`timed out waiting for ${what}`);
};

test.skipIf(!binary)('browsers with passes exchange messages through the gateway and a closed relay', async () => {
  const root = mkdtempSync(join(tmpdir(), 'meshguard-relay-e2e-'));
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('MESHGUARD_'))), MESHGUARD_CONFIG_DIR: join(root, 'config') };
  const run = (...args) => spawnSync(binary, args, { env, encoding: 'utf8', timeout: 30000 });
  expect(run('keygen').status).toBe(0);
  const shown = run('config', 'show').stdout;
  const relayKey = fromB64(/public key \(Ed25519\):\s+(\S+)/.exec(shown)[1]);
  const relayWg = fromB64(/public key \(WG X25519\):\s+(\S+)/.exec(shown)[1]);
  mkdirSync(join(root, 'config', 'trusted_orgs'), { recursive: true });
  writeFileSync(join(root, 'config', 'trusted_orgs', 'test.org'), b64(orgPublic) + '\n');

  const port = await freePort();
  const relay = spawn(binary, ['up', '--gossip-only', '--relay', '--announce', '127.0.0.1', '--gossip-port', String(port),
    '--control-path', join(root, 'control.sock'), '--trusted-handshake-source', '127.0.0.1'], { env, stdio: 'ignore' });
  const gateway = startGateway({ listenPort: 0, relayHost: '127.0.0.1', relayPort: port, allowedOrigins: [origin], trustedOrgs: [b64(orgPublic)] });
  const NativeWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = class extends NativeWebSocket { constructor(url) { super(url, { headers: { Origin: origin } }); } };
  const clients = [];
  try {
    const core = new MeshguardWasm((await WebAssembly.instantiate(wasmBytes(), {})).instance);
    const a = core.createIdentity(new Uint8Array(32).fill(0x61)), b = core.createIdentity(new Uint8Array(32).fill(0x62));
    const peer = identity => ({ publicKey: identity.publicKey(), wgPublicKey: identity.wgPublicKey() });
    const url = `ws://127.0.0.1:${gateway.server.port}/meshguard-web/ws`;
    const relayPeer = { publicKey: relayKey, wgPublicKey: relayWg };
    for (const [me, other] of [[a, b], [b, a]]) {
      const client = new MeshguardRelayClient({ identity: me, url, relay: relayPeer, trustedPeers: [peer(other)], pass: issuePass(me) });
      client.received = [];
      client.addEventListener('message', event => client.received.push(new TextDecoder().decode(event.detail.data)));
      client.connect(); clients.push(client);
    }
    // Both authenticate with passes and prove their gateway endpoints to the relay.
    await until(() => clients.every(c => c.ready), 20000, 'both browsers to complete the relay handshake');
    const [ca, cb] = clients;
    await until(() => {
      ca.send(ca.peers.get(b64(b.publicKey())), 'hello through a closed relay');
      return cb.received.length > 0;
    }, 20000, 'a message to arrive through the relay');
    expect(cb.received[0]).toBe('hello through a closed relay');
    expect(gateway.counters.authenticated).toBe(2);
  } finally {
    for (const c of clients) c.disconnect();
    globalThis.WebSocket = NativeWebSocket;
    gateway.stop(); relay.kill('SIGTERM');
    await new Promise(r => setTimeout(r, 200));
    rmSync(root, { recursive: true, force: true });
  }
}, 60000);

// A relay daemon trusting the test org, with a gateway in front of it.
async function relayWithGateway() {
  const root = mkdtempSync(join(tmpdir(), 'meshguard-relay-e2e-'));
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('MESHGUARD_'))), MESHGUARD_CONFIG_DIR: join(root, 'config') };
  const run = (...args) => spawnSync(binary, args, { env, encoding: 'utf8', timeout: 30000 });
  run('keygen');
  const shown = run('config', 'show').stdout;
  mkdirSync(join(root, 'config', 'trusted_orgs'), { recursive: true });
  writeFileSync(join(root, 'config', 'trusted_orgs', 'test.org'), b64(orgPublic) + '\n');
  const port = await freePort();
  const process_ = spawn(binary, ['up', '--gossip-only', '--relay', '--opaque', '--announce', '127.0.0.1', '--gossip-port', String(port),
    '--control-path', join(root, 'control.sock'), '--trusted-handshake-source', '127.0.0.1'], { env, stdio: 'ignore' });
  const gateway = startGateway({ listenPort: 0, relayHost: '127.0.0.1', relayPort: port, allowedOrigins: [origin], trustedOrgs: [b64(orgPublic)] });
  return {
    peer: { publicKey: fromB64(/public key \(Ed25519\):\s+(\S+)/.exec(shown)[1]), wgPublicKey: fromB64(/public key \(WG X25519\):\s+(\S+)/.exec(shown)[1]) },
    url: `ws://127.0.0.1:${gateway.server.port}/meshguard-web/ws`,
    stop() { gateway.stop(); process_.kill('SIGTERM'); setTimeout(() => rmSync(root, { recursive: true, force: true }), 200); },
  };
}

test.skipIf(!binary)('one browser identity holds a session on each of two relays, with a handle per relay', async () => {
  const relays = [await relayWithGateway(), await relayWithGateway()];
  const NativeWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = class extends NativeWebSocket { constructor(url) { super(url, { headers: { Origin: origin } }); } };
  const clients = [];
  try {
    const core = new MeshguardWasm((await WebAssembly.instantiate(wasmBytes(), {})).instance);
    const seed = new Uint8Array(32).fill(0x71);
    // Each relay client needs its own identity handle: a handle holds one handshake at a time.
    for (const relay of relays) {
      const identity = core.createIdentity(seed);
      const client = new MeshguardRelayClient({ identity, url: relay.url, relay: relay.peer, pass: issuePass(identity) });
      client.connect(); clients.push(client);
    }
    expect(b64(clients[0].identity.publicKey())).toBe(b64(clients[1].identity.publicKey()));
    await until(() => clients.every(c => c.ready), 20000, 'both relay sessions to complete their handshakes');
  } finally {
    for (const c of clients) c.disconnect();
    globalThis.WebSocket = NativeWebSocket;
    for (const r of relays) r.stop();
    await new Promise(r => setTimeout(r, 300));
  }
}, 60000);
