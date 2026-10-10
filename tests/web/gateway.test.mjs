import { test, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { startGateway, validateOutbound, clientAddress } from '../../gateway/server.mjs';
import { verifyPass } from '../../gateway/pass.mjs';
import { MeshguardWasm } from '../../web/meshguard.mjs';
import { authPayload, bindingPayload, b64, fromB64, selfAdvertisement, MeshguardRelayClient } from '../../web/relay-protocol.mjs';

const core = new MeshguardWasm((await WebAssembly.instantiate(readFileSync('zig-out/bin/meshguard.wasm'), {})).instance);
const a = core.createIdentity(new Uint8Array(32).fill(1));
const b = core.createIdentity(new Uint8Array(32).fill(2));
const peer = identity => ({ publicKey: identity.publicKey(), wgPublicKey: identity.wgPublicKey() });
const aPeer = peer(a), bPeer = peer(b);
const origin = 'http://gateway-test.invalid';

function channel(url, headers = {}) {
  const ws = new WebSocket(url, { headers: { Origin: origin, ...headers } });
  ws.binaryType = 'arraybuffer';
  const queue = [], waiters = [];
  ws.addEventListener('message', event => waiters.length ? waiters.shift()(event.data) : queue.push(event.data));
  return { ws, next: () => queue.length ? Promise.resolve(queue.shift()) : new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Message timed out')), 2000);
    waiters.push(value => { clearTimeout(timeout); resolve(value); });
  }) };
}
async function fixture(overrides = {}) {
  const packets = [];
  const udp = await Bun.udpSocket({ hostname: '127.0.0.1', port: 0, socket: {
    data(socket, frame, port, address) {
      packets.push(new Uint8Array(frame));
      if (frame[0] === 0x50) { try { socket.send(b.seal(aPeer, 'native-shaped reply'), port, address); } catch {} }
    },
    error() {}, // ICMP refusals after a gateway session closes are expected in flood/timeout tests
  } });
  const gateway = startGateway({ listenPort: 0, relayHost: '127.0.0.1', relayPort: udp.port,
    allowedOrigins: [origin], allowedIdentities: [{ publicKey: b64(aPeer.publicKey), wgPublicKey: b64(aPeer.wgPublicKey) }],
    allowedDestinations: [b64(bPeer.publicKey)], ...overrides });
  return { gateway, packets, url: `ws://127.0.0.1:${gateway.server.port}/meshguard-web/ws`, stop() { gateway.stop(); setTimeout(() => udp.close(), 300); } };
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
  const pinnedWg = Uint8Array.from(bPeer.wgPublicKey), peerEvents = [];
  client.addEventListener('peer', event => peerEvents.push(event.detail));
  const received = [];
  client.addEventListener('message', event => received.push(event.detail.data));
  const valid = b.seal(aPeer, 'authenticated once'), forged = valid.slice(); forged[forged.length - 1] ^= 1;
  expect(() => client.packet(forged)).toThrow('Authentication');
  client.packet(valid); client.packet(valid);
  expect(received).toHaveLength(1); expect(client.stats.duplicates).toBe(1);
  const gossip = selfAdvertisement(b, { address: '127.0.0.1', port: 51000 }, 3, 1n, 1n);
  gossip.set(aPeer.wgPublicKey, 112);
  client.packet(gossip);
  expect(Array.from(client.peers.get(b64(bPeer.publicKey)).wgPublicKey)).toEqual(Array.from(pinnedWg));
  expect(peerEvents).toHaveLength(0); // a gossip claim with a different WG key is not even surfaced
});

const settle = ms => new Promise(resolve => setTimeout(resolve, ms));
const closing = c => new Promise(resolve => c.ws.addEventListener('close', resolve, { once: true }));
// Resolves 'open' or 'refused' for a raw WebSocket attempt.
const attempt = (url, headers = {}) => new Promise(resolve => {
  const c = channel(url, headers);
  c.ws.addEventListener('open', () => resolve({ c, result: 'open' }), { once: true });
  c.ws.addEventListener('error', () => resolve({ c, result: 'refused' }), { once: true });
});
async function admit(url, identity = a) {
  const c = channel(url); const challenge = JSON.parse(await c.next());
  c.ws.send(JSON.stringify(authentication(challenge.challenge, identity)));
  expect(JSON.parse(await c.next()).type).toBe('ready'); return c;
}

test('pending cap refuses unauthenticated sockets without touching admitted sessions', async () => {
  const f = await fixture({ maxPending: 2, maxPendingPerIp: 10, upgradeBurst: 100 }); const opened = [];
  try {
    const admitted = await admit(f.url);
    for (let i = 0; i < 2; i++) opened.push((await attempt(f.url)).c);
    const third = await attempt(f.url); opened.push(third.c);
    expect(third.result).toBe('refused'); expect(f.gateway.counters.limited).toBe(1);
    admitted.ws.send(a.seal(bPeer, 'still served')); await settle(100);
    expect(f.gateway.counters.forwarded).toBe(1);
    opened[0].ws.close(); await settle(100);
    const again = await attempt(f.url); opened.push(again.c); expect(again.result).toBe('open');
    admitted.ws.close();
  } finally { for (const c of opened) c.ws.close(); f.stop(); }
});

test('same identity replaces its session even when the pending budget is small', async () => {
  const f = await fixture({ maxPending: 1 });
  try {
    const first = await admit(f.url); const firstClosed = closing(first);
    const second = await admit(f.url);
    expect((await firstClosed).code).toBe(4001);
    second.ws.send(a.seal(bPeer, 'from replacement')); expect(new Uint8Array(await second.next())).toBeTruthy();
    second.ws.close();
  } finally { f.stop(); }
});

test('per-source pending cap uses X-Forwarded-For only from a trusted proxy', async () => {
  const forwarded = ip => ({ 'X-Forwarded-For': ip });
  const trusted = await fixture({ maxPendingPerIp: 1, upgradeBurst: 100 }); const opened = [];
  try {
    const one = await attempt(trusted.url, forwarded('198.51.100.1')), same = await attempt(trusted.url, forwarded('198.51.100.1'));
    const other = await attempt(trusted.url, forwarded('198.51.100.2'));
    opened.push(one.c, same.c, other.c);
    expect([one.result, same.result, other.result]).toEqual(['open', 'refused', 'open']);
  } finally { for (const c of opened) c.ws.close(); trusted.stop(); }
  const untrusted = await fixture({ maxPendingPerIp: 1, upgradeBurst: 100, trustedProxies: ['203.0.113.9'] }); const more = [];
  try {
    const one = await attempt(untrusted.url, forwarded('198.51.100.1')), two = await attempt(untrusted.url, forwarded('198.51.100.2'));
    more.push(one.c, two.c);
    expect([one.result, two.result]).toEqual(['open', 'refused']); // spoofed header ignored
  } finally { for (const c of more) c.ws.close(); untrusted.stop(); }
});

test('clientAddress ignores X-Forwarded-For from untrusted peers and malformed values', () => {
  const trusted = new Set(['127.0.0.1']);
  expect(clientAddress('127.0.0.1', '9.9.9.9, 198.51.100.7', trusted)).toBe('198.51.100.7');
  expect(clientAddress('::ffff:127.0.0.1', '198.51.100.7', trusted)).toBe('198.51.100.7');
  expect(clientAddress('127.0.0.1', 'not-an-ip', trusted)).toBe('127.0.0.1');
  expect(clientAddress('127.0.0.1', undefined, trusted)).toBe('127.0.0.1');
  expect(clientAddress('192.0.2.5', '198.51.100.7', trusted)).toBe('192.0.2.5');
});

test('per-source upgrade rate limit refuses reconnect floods', async () => {
  const f = await fixture({ upgradeBurst: 2, upgradeRefillMs: 60000, maxPendingPerIp: 10 });
  try {
    const results = [];
    for (let i = 0; i < 4; i++) { const r = await attempt(f.url); results.push(r.result); r.c.ws.close(); await settle(50); }
    expect(results).toEqual(['open', 'open', 'refused', 'refused']);
    expect(f.gateway.counters.limited).toBe(2);
  } finally { f.stop(); }
});

test('oversized WebSocket frames are refused by the payload limit', async () => {
  const f = await fixture();
  try {
    const c = await admit(f.url); const closed = closing(c);
    c.ws.send(new Uint8Array(2049)); expect([1006, 1009]).toContain((await closed).code); // dropped by the 2048-byte payload limit
    expect(f.packets).toHaveLength(0);
  } finally { f.stop(); }
});

test('packet rate limit closes a session that floods valid frames', async () => {
  const f = await fixture();
  try {
    const c = await admit(f.url); const closed = closing(c); const frame = a.seal(bPeer, 'flood');
    for (let i = 0; i < 100; i++) c.ws.send(frame);
    expect((await closed).code).toBe(1008);
    expect(f.gateway.counters.forwarded).toBeLessThan(100); expect(f.gateway.counters.rejected).toBeGreaterThan(0);
  } finally { f.stop(); }
});

test('authentication timeout closes silent sockets and a late signature is never accepted', async () => {
  const f = await fixture({ authTimeoutMs: 150 }); const c = channel(f.url);
  try {
    const challenge = JSON.parse(await c.next()); const closed = closing(c);
    const event = await closed; expect(event.code).toBe(4003); expect(event.reason).toBe('Authentication timeout');
    try { c.ws.send(JSON.stringify(authentication(challenge.challenge))); } catch {}
    await settle(100); expect(f.gateway.counters.authenticated).toBe(0); expect(f.packets).toHaveLength(0);
  } finally { f.stop(); }
});

test('truncated or extended gossip and app packets never reach the relay', async () => {
  const session = { ...aPeer, endpoint: { address: '127.0.0.1', port: 51000 } };
  const destinations = new Set([b64(bPeer.publicKey)]);
  const gossip = selfAdvertisement(a, session.endpoint, 1, 1n, 1n);
  expect(validateOutbound(gossip, session, destinations)).toBe(true);
  for (const length of [0, 1, 49, 148, 164]) expect(validateOutbound(gossip.slice(0, length), session, destinations)).toBe(false);
  expect(validateOutbound(Uint8Array.from([...gossip, 0]), session, destinations)).toBe(false);
  const f = await fixture();
  try {
    const c = await admit(f.url); const closed = closing(c);
    c.ws.send(gossip.slice(0, 164)); expect((await closed).code).toBe(1008);
    expect(f.packets).toHaveLength(0); expect(f.gateway.counters.forwarded).toBe(0);
  } finally { f.stop(); }
});

test('client drops known replays before decrypting and forged input cannot poison the replay cache', () => {
  const client = new MeshguardRelayClient({ identity: a, url: 'ws://fixture.invalid', relay: bPeer, trustedPeers: [bPeer] });
  let opens = 0; const real = client.identity;
  client.identity = { open: (...args) => { opens++; return real.open(...args); } };
  const received = []; client.addEventListener('message', event => received.push(event.detail.data));
  const valid = b.seal(aPeer, 'first'), forged = valid.slice(); forged[forged.length - 1] ^= 1;
  expect(() => client.packet(forged)).toThrow('Authentication');
  expect(client.seen.size).toBe(0);                       // failed authentication never enters the cache
  client.packet(valid); expect(received).toHaveLength(1); expect(client.seen.size).toBe(1);
  expect(opens).toBe(2);
  client.packet(valid); client.packet(forged);            // known token: no decryption at all
  expect(opens).toBe(2); expect(client.stats.duplicates).toBe(2); expect(received).toHaveLength(1);
});

const bindingOf = identity => identity.sign(bindingPayload(identity.publicKey(), identity.wgPublicKey()));

test('self-advertisements carry only the binding verified at authentication', () => {
  const binding = bindingOf(a);
  const session = { ...aPeer, endpoint: { address: '127.0.0.1', port: 51000 }, binding };
  const destinations = new Set();
  const frame = selfAdvertisement(a, session.endpoint, 1, 1n, 1n, binding);
  expect(frame.length).toBe(262);
  expect(validateOutbound(frame, session, destinations)).toBe(true);
  expect(validateOutbound(frame, { ...session, binding: null }, destinations)).toBe(false);
  const otherSignature = frame.slice(); otherSignature.set(bindingOf(b), 198);
  expect(validateOutbound(otherSignature, session, destinations)).toBe(false);
  const otherKey = frame.slice(); otherKey.set(b.wgPublicKey(), 166);
  expect(validateOutbound(otherKey, session, destinations)).toBe(false);
  const wrongTag = frame.slice(); wrongTag[165] = 1;
  expect(validateOutbound(wrongTag, session, destinations)).toBe(false);
  expect(validateOutbound(frame.slice(0, 200), session, destinations)).toBe(false);
});

test('gateway verifies the binding at authentication and forwards bound advertisements', async () => {
  const f = await fixture(); const c = channel(f.url);
  try {
    const challenge = JSON.parse(await c.next());
    c.ws.send(JSON.stringify({ ...authentication(challenge.challenge), binding: b64(bindingOf(a)) }));
    const ready = JSON.parse(await c.next()); expect(ready.type).toBe('ready');
    const frame = selfAdvertisement(a, ready.endpoint, 1, 1n, 1n, bindingOf(a));
    c.ws.send(frame); await settle(100);
    expect(f.packets.at(-1)).toEqual(frame);
  } finally { c.ws.close(); f.stop(); }
});

test('gateway rejects a binding signed for another key', async () => {
  const f = await fixture(); const c = channel(f.url);
  try {
    const challenge = JSON.parse(await c.next());
    const forged = a.sign(bindingPayload(a.publicKey(), b.wgPublicKey()));
    const closed = closing(c);
    c.ws.send(JSON.stringify({ ...authentication(challenge.challenge), binding: b64(forged) }));
    expect((await closed).code).toBe(4003);
    expect(f.gateway.counters.authenticated).toBe(0);
  } finally { c.ws.close(); f.stop(); }
});

test('the relay client signs its binding once and sends it with every advertisement', () => {
  const client = new MeshguardRelayClient({ identity: a, url: 'ws://fixture.invalid', relay: bPeer });
  expect(Array.from(client.binding)).toEqual(Array.from(bindingOf(a)));
  const sent = [];
  client.sendRaw = frame => { sent.push(frame); return true; };
  client.endpoint = { address: '127.0.0.1', port: 51000 };
  client.advertise();
  expect(sent[0].length).toBe(262);
  expect(Array.from(sent[0].slice(198))).toEqual(Array.from(client.binding));
});

test('binding signatures match the native core byte for byte', () => {
  // src/identity/binding.zig checks the same known answer.
  const identity = core.createIdentity(new Uint8Array(32).fill(7));
  const signature = identity.sign(bindingPayload(identity.publicKey(), new Uint8Array(32).fill(9)));
  expect(Buffer.from(signature).toString('hex')).toBe('16718f492c54ffe80a79fa28e66054faf3f94527239b0305f2b1787d05a718492025daade823f5f0ad24455594702627525cd3c51e82dbc759162537e2a00701');
});

// ─── Passes ───

const fixtures = JSON.parse(readFileSync('src/identity/testdata/passes.json', 'utf8'));

test('pass verdicts match the Zig implementation on shared fixtures', () => {
  const trustedOrgs = new Set(fixtures.trusted_orgs);
  for (const c of fixtures.cases) {
    const result = verifyPass(Buffer.from(c.pass, 'hex'), { publicKey: fromB64(c.public_key), wgPublicKey: fromB64(c.wg_public_key),
      trustedOrgs, now: c.now, skew: fixtures.skew });
    expect([c.name, typeof result === 'string' ? result : 'ok']).toEqual([c.name, c.expect]);
  }
});

const orgSeed = new Uint8Array(32).fill(0x51);
const orgPrivate = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), orgSeed]), format: 'der', type: 'pkcs8' });
const orgPublic = new Uint8Array(createPublicKey(orgPrivate).export({ format: 'der', type: 'spki' }).subarray(12));

/** A v2 pass from the test org for `identity`, valid from `issuedAt` to `expiresAt`. */
function issuePass(identity, { expiresAt = Math.floor(Date.now() / 1000) + 3600, issuedAt = Math.floor(Date.now() / 1000) - 10, wg = identity.wgPublicKey() } = {}) {
  const wire = new Uint8Array(314), view = new DataView(wire.buffer);
  wire[0] = 2; wire.set(orgPublic, 1); wire.set(identity.publicKey(), 33);
  view.setBigInt64(97, BigInt(issuedAt), true); view.setBigInt64(105, BigInt(expiresAt), true);
  wire.set(wg, 186);
  const payload = new Uint8Array(178); payload.set(wire.subarray(0, 114)); payload.set(wire.subarray(186, 250), 114);
  wire.set(sign(null, payload, orgPrivate), 114);
  return wire;
}

const passConfig = { allowedIdentities: [], trustedOrgs: [b64(orgPublic)], allowedDestinations: undefined };

async function admitWithPass(url, identity, pass, extra = {}) {
  const c = channel(url); const challenge = JSON.parse(await c.next());
  c.ws.send(JSON.stringify({ ...authentication(challenge.challenge, identity), pass: b64(pass), ...extra }));
  return { c, reply: JSON.parse(await c.next()) };
}

test('a pass from a trusted org admits a browser that is on no allowlist', async () => {
  const f = await fixture(passConfig);
  try {
    const { c, reply } = await admitWithPass(f.url, b, issuePass(b));
    expect(reply.type).toBe('ready'); expect(reply.passExpiresAt).toBeGreaterThan(Date.now() / 1000);
    // No destination allowlist: the relay decides who may be addressed.
    c.ws.send(b.seal(aPeer, 'to anyone the relay allows')); await settle(100);
    expect(f.gateway.counters.forwarded).toBe(1);
    c.ws.close();
  } finally { f.stop(); }
});

for (const [kind, makePass] of [
  ['another identity\'s pass', () => issuePass(a)],
  ['a pass for another WireGuard key', () => issuePass(b, { wg: a.wgPublicKey() })],
  ['an expired pass', () => issuePass(b, { expiresAt: Math.floor(Date.now() / 1000) - 1000 })],
  ['a tampered pass', () => { const p = issuePass(b); p[70] ^= 1; return p; }],
]) {
  test(`gateway refuses ${kind}`, async () => {
    const f = await fixture(passConfig);
    try {
      const c = channel(f.url); const challenge = JSON.parse(await c.next());
      const closed = closing(c);
      c.ws.send(JSON.stringify({ ...authentication(challenge.challenge, b), pass: b64(makePass()) }));
      expect((await closed).code).toBe(4003);
      expect(f.gateway.counters.authenticated).toBe(0);
    } finally { f.stop(); }
  });
}

test('a gateway with no allowlist and no trusted org refuses to start', () => {
  expect(() => startGateway({ relayHost: '127.0.0.1', relayPort: 9, allowedOrigins: [origin], allowedIdentities: [] })).toThrow('admits nobody');
});

test('self-advertisements carry only the session\'s own pass and binding', () => {
  const pass = issuePass(b), binding = bindingOf(b);
  const session = { ...bPeer, endpoint: { address: '127.0.0.1', port: 51000 }, binding, pass };
  const both = selfAdvertisement(b, session.endpoint, 1, 1n, 1n, binding, pass);
  expect(both.length).toBe(577);
  expect(validateOutbound(both, session, null)).toBe(true);
  expect(validateOutbound(selfAdvertisement(b, session.endpoint, 1, 1n, 1n, null, pass), session, null)).toBe(true);
  expect(validateOutbound(selfAdvertisement(b, session.endpoint, 1, 1n, 1n, binding, null), session, null)).toBe(true);
  // Laundering someone else's pass through this session is refused.
  expect(validateOutbound(selfAdvertisement(b, session.endpoint, 1, 1n, 1n, binding, issuePass(a)), session, null)).toBe(false);
  expect(validateOutbound(both, { ...session, pass: null }, null)).toBe(false);
  expect(validateOutbound(both.slice(0, 500), session, null)).toBe(false);
});

test('a session ends when its pass expires and can renew before that', async () => {
  const f = await fixture({ ...passConfig, passSkewSeconds: 0 });
  try {
    const now = Math.floor(Date.now() / 1000);
    const { c, reply } = await admitWithPass(f.url, b, issuePass(b, { expiresAt: now + 60 }));
    expect(reply.type).toBe('ready');

    const renewed = issuePass(b, { expiresAt: now + 3600 });
    c.ws.send(JSON.stringify({ type: 'renew', pass: b64(renewed) }));
    const answer = JSON.parse(await c.next());
    expect(answer).toEqual({ type: 'renewed', passExpiresAt: now + 3600 });
    // The renewed pass is now the one self-advertisements must carry.
    c.ws.send(selfAdvertisement(b, reply.endpoint, 1, 1n, 1n, null, renewed)); await settle(100);
    expect(f.packets.at(-1).length).toBe(480);

    c.ws.send(JSON.stringify({ type: 'renew', pass: b64(issuePass(a)) }));
    expect(JSON.parse(await c.next())).toEqual({ type: 'renew-rejected', reason: 'wrong-identity' });
    c.ws.close();

    const short = await admitWithPass(f.url, b, issuePass(b, { expiresAt: Math.ceil(Date.now() / 1000) + 1 }));
    expect(short.reply.type).toBe('ready');
    const ended = await closing(short.c);
    expect(ended.code).toBe(4004);
    expect(f.gateway.counters.expired).toBe(1);
  } finally { f.stop(); }
});

test('sessions are capped overall and per source address', async () => {
  const f = await fixture({ ...passConfig, maxSessions: 2, maxSessionsPerIp: 1, maxPendingPerIp: 10, upgradeBurst: 100 });
  try {
    const first = await admitWithPass(f.url, a, issuePass(a));
    expect(first.reply.type).toBe('ready');
    const c = channel(f.url); const challenge = JSON.parse(await c.next());
    const closed = closing(c);
    c.ws.send(JSON.stringify({ ...authentication(challenge.challenge, b), pass: b64(issuePass(b)) }));
    expect((await closed).code).toBe(1013);
    // Reconnecting the same identity replaces its session instead of counting twice.
    const again = await admitWithPass(f.url, a, issuePass(a));
    expect(again.reply.type).toBe('ready');
    again.c.ws.close();
  } finally { f.stop(); }
});

test('a reload that no longer trusts the org closes its sessions', async () => {
  const f = await fixture(passConfig);
  try {
    const { c, reply } = await admitWithPass(f.url, b, issuePass(b));
    expect(reply.type).toBe('ready');
    const closed = closing(c);
    f.gateway.reload({ allowedIdentities: [{ publicKey: b64(aPeer.publicKey), wgPublicKey: b64(aPeer.wgPublicKey) }] });
    expect((await closed).code).toBe(4003);
    expect(f.gateway.sessions()).toBe(0);
  } finally { f.stop(); }
});

test('the relay client presents its pass and renews it in the live session', () => {
  const pass = issuePass(a);
  const client = new MeshguardRelayClient({ identity: a, url: 'ws://fixture.invalid', relay: bPeer, pass });
  const sent = [];
  client.socket = { readyState: WebSocket.OPEN, bufferedAmount: 0, send: frame => sent.push(frame) };
  client.control({ type: 'challenge', challenge: b64(new Uint8Array(32).fill(3)) });
  expect(JSON.parse(sent[0]).pass).toBe(b64(pass));
  client.endpoint = { address: '127.0.0.1', port: 51000 };
  client.advertise();
  expect(sent[1].length).toBe(577);

  const next = issuePass(a, { expiresAt: Math.floor(Date.now() / 1000) + 7200 });
  client.renewPass(next);
  expect(JSON.parse(sent[2])).toEqual({ type: 'renew', pass: b64(next) });
  client.advertise();
  expect(Array.from(sent[3].slice(166, 166 + 314))).toEqual(Array.from(pass)); // old pass until accepted
  client.control({ type: 'renewed', passExpiresAt: 0 });
  client.advertise();
  expect(Array.from(sent[4].slice(166, 166 + 314))).toEqual(Array.from(next));
  clearInterval(client.timer);
});
