import { test, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { startGateway, validateOutbound } from '../../gateway/server.mjs';
import { MeshguardWasm } from '../../web/meshguard.mjs';
import { authPayload, b64, fromB64, selfAdvertisement, MeshguardRelayClient } from '../../web/relay-protocol.mjs';

const core = new MeshguardWasm((await WebAssembly.instantiate(readFileSync('zig-out/bin/meshguard.wasm'), {})).instance);
const a = core.createIdentity(new Uint8Array(32).fill(1));
const b = core.createIdentity(new Uint8Array(32).fill(2));
const peer = identity => ({ publicKey: identity.publicKey(), wgPublicKey: identity.wgPublicKey() });
const aPeer = peer(a), bPeer = peer(b);
const origin = 'http://gateway-test.invalid';

function channel(url) {
  const ws = new WebSocket(url, { headers: { Origin: origin } });
  ws.binaryType = 'arraybuffer';
  const queue = [], waiters = [];
  ws.addEventListener('message', event => waiters.length ? waiters.shift()(event.data) : queue.push(event.data));
  return { ws, next: () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Message timed out')), 2000);
    waiters.push(value => { clearTimeout(timeout); resolve(value); });
  }) };
}
async function fixture() {
  const packets = [];
  const udp = await Bun.udpSocket({ hostname: '127.0.0.1', port: 0, socket: {
    data(socket, frame, port, address) {
      packets.push(new Uint8Array(frame));
      if (frame[0] === 0x50) socket.send(b.seal(aPeer, 'native-shaped reply'), port, address);
    },
  } });
  const gateway = startGateway({ listenPort: 0, relayHost: '127.0.0.1', relayPort: udp.port,
    allowedOrigins: [origin], allowedIdentities: [{ publicKey: b64(aPeer.publicKey), wgPublicKey: b64(aPeer.wgPublicKey) }],
    allowedDestinations: [b64(bPeer.publicKey)] });
  return { gateway, packets, url: `ws://127.0.0.1:${gateway.server.port}/meshguard-web/ws`, stop() { gateway.stop(); udp.close(); } };
}
function authentication(challenge, identity = a, wg = identity.wgPublicKey()) {
  return { type: 'authenticate', publicKey: b64(identity.publicKey()), wgPublicKey: b64(wg),
    signature: b64(identity.sign(authPayload(fromB64(challenge), identity.publicKey(), wg))) };
}

test('authenticated gateway forwards unchanged ciphertext and returns sealed packets', async () => {
  const f = await fixture(); const c = channel(f.url);
  try {
    const challenge = JSON.parse(await c.next()); c.ws.send(JSON.stringify(authentication(challenge.challenge)));
    const ready = JSON.parse(await c.next()); expect(ready.type).toBe('ready');
    const frame = a.seal(bPeer, 'opaque request'); c.ws.send(frame);
    const reply = new Uint8Array(await c.next());
    expect(f.packets[0]).toEqual(frame);
    expect(new TextDecoder().decode(a.open(bPeer, reply))).toBe('native-shaped reply');
    expect(f.gateway.counters.authenticated).toBe(1);
    expect(f.gateway.counters.forwarded).toBe(1);
  } finally { c.ws.close(); f.stop(); }
});

for (const kind of ['unadmitted identity', 'wrong WG binding', 'invalid signature', 'cross-connection replay']) {
  test(`gateway rejects ${kind} before UDP forwarding`, async () => {
    const f = await fixture(); let c = channel(f.url), saved;
    try {
      let challenge = JSON.parse(await c.next());
      if (kind === 'cross-connection replay') {
        saved = authentication(challenge.challenge); c.ws.close(); c = channel(f.url); challenge = JSON.parse(await c.next());
      }
      const auth = saved ?? authentication(challenge.challenge, kind === 'unadmitted identity' ? b : a,
        kind === 'wrong WG binding' ? b.wgPublicKey() : undefined);
      if (kind === 'invalid signature') auth.signature = b64(new Uint8Array(64));
      const closed = new Promise(resolve => c.ws.addEventListener('close', resolve, { once: true }));
      c.ws.send(JSON.stringify(auth)); expect((await closed).code).toBe(4003);
      expect(f.gateway.counters.authenticated).toBe(0); expect(f.packets).toHaveLength(0);
    } finally { c.ws.close(); f.stop(); }
  });
}

test('packet gate rejects third-party sender, destination, gossip claims and invalid sizes', () => {
  const session = { ...aPeer, endpoint: { address: '127.0.0.1', port: 51000 } };
  const destinations = new Set([b64(bPeer.publicKey)]);
  const frame = a.seal(bPeer, 'sealed'); expect(validateOutbound(frame, session, destinations)).toBe(true);
  const spoof = frame.slice(); spoof.set(bPeer.publicKey, 33); expect(validateOutbound(spoof, session, destinations)).toBe(false);
  expect(validateOutbound(frame, session, new Set())).toBe(false);
  expect(validateOutbound(frame.slice(0, 92), session, destinations)).toBe(false);
  const gossip = selfAdvertisement(a, session.endpoint, 1, 1n, 1n);
  expect(validateOutbound(gossip, session, destinations)).toBe(true);
  gossip.set(bPeer.publicKey, 50); expect(validateOutbound(gossip, session, destinations)).toBe(false);
  expect(validateOutbound(new Uint8Array(1501), session, destinations)).toBe(false);
});

test('gateway requires an explicitly allowed browser Origin', async () => {
  const f = await fixture();
  try { expect((await fetch(f.url.replace('ws:', 'http:'), { headers: { Origin: 'https://unexpected.invalid' } })).status).toBe(403); }
  finally { f.stop(); }
});

test('client authenticates before remembering nonces and never changes pinned peer keys from gossip', () => {
  const client = new MeshguardRelayClient({ identity: a, url: 'ws://fixture.invalid', relay: bPeer, trustedPeers: [bPeer] });
  const received = [];
  client.addEventListener('message', event => received.push(event.detail.data));
  const valid = b.seal(aPeer, 'authenticated once'), forged = valid.slice(); forged[forged.length - 1] ^= 1;
  expect(() => client.packet(forged)).toThrow('Authentication');
  client.packet(valid); client.packet(valid);
  expect(received).toHaveLength(1); expect(client.stats.duplicates).toBe(1);
  const gossip = selfAdvertisement(b, { address: '127.0.0.1', port: 51000 }, 3, 1n, 1n);
  gossip.set(aPeer.wgPublicKey, 112);
  client.packet(gossip);
  expect(client.peers.get(b64(bPeer.publicKey)).wgPublicKey).toEqual(bPeer.wgPublicKey);
});
