// Browser-side relay load: many WASM browser identities holding passes, each with its own
// WebSocket session through a real gateway process, to a real relay daemon. Linux; Bun 1.4.
//
//   bun bench/relay-load/browser.mjs --binary zig-out/bin/meshguard --sessions 2000 --rate 0.2
//
// Prints one JSON report: sessions admitted and ready, ramp time, messages sent and received,
// loss, latency percentiles, and the gateway's and relay's CPU time and peak memory.
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { createServer, connect } from 'node:net';
import { MeshguardWasm } from '../../web/meshguard.mjs';
import { MeshguardRelayClient, b64, fromB64 } from '../../web/relay-protocol.mjs';

const root = resolve(import.meta.dir, '../..');
const option = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const flag = name => process.argv.includes(`--${name}`);
const binary = resolve(option('binary', join(root, 'zig-out/bin/meshguard')));
const sessions = Number(option('sessions', 500));
const contacts = Number(option('contacts', 4));
const rate = Number(option('rate', 0.2)); // messages per second per session
const duration = Number(option('duration', 30));
const rampPerSecond = Number(option('ramp', 200));
const opaque = flag('opaque');
const maxLoss = option('max-loss', null);
const origin = 'https://browser-load.invalid';

const orgPrivate = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x53)]), format: 'der', type: 'pkcs8' });
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

const freeUdp = () => new Promise(r => { const s = createSocket('udp4'); s.bind(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => r(port)); }); });
const freeTcp = () => new Promise(r => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => r(port)); }); });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const cpuSeconds = pid => {
  const fields = readFileSync(`/proc/${pid}/stat`, 'utf8').split(')').pop().trim().split(/\s+/);
  return (Number(fields[11]) + Number(fields[12])) / 100;
};
const peakMiB = pid => Number(/VmHWM:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))[1]) / 1024;
const percentile = (sorted, p) => sorted.length ? sorted[Math.floor(p * (sorted.length - 1))] : 0;

function relayStatus(path) {
  return new Promise((resolveStatus, reject) => {
    const socket = connect(path); let data = '';
    socket.on('data', chunk => { data += chunk; if (data.endsWith('\n')) { socket.end(); resolveStatus(JSON.parse(data)); } });
    socket.on('error', reject); socket.write('STATUS\n');
  });
}

const temp = mkdtempSync(join(tmpdir(), 'meshguard-browser-load-'));
const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('MESHGUARD_'))), MESHGUARD_CONFIG_DIR: join(temp, 'config') };
const run = (...args) => spawnSync(binary, args, { env, encoding: 'utf8', timeout: 30000 });
if (run('keygen').status !== 0) throw new Error('keygen failed');
const shown = run('config', 'show').stdout;
const relayPeer = {
  publicKey: fromB64(/public key \(Ed25519\):\s+(\S+)/.exec(shown)[1]),
  wgPublicKey: fromB64(/public key \(WG X25519\):\s+(\S+)/.exec(shown)[1]),
};
mkdirSync(join(temp, 'config', 'trusted_orgs'), { recursive: true });
writeFileSync(join(temp, 'config', 'trusted_orgs', 'load.org'), b64(orgPublic) + '\n');

const relayPort = await freeUdp(), gatewayPort = await freeTcp();
const control = join(temp, 'control.sock');
const relay = spawn(binary, ['up', '--gossip-only', '--relay', ...(opaque ? ['--opaque'] : []), '--announce', '127.0.0.1',
  '--gossip-port', String(relayPort), '--control-path', control, '--trusted-handshake-source', '127.0.0.1',
  '--max-clients', String(Math.max(1024, Math.ceil(sessions * 1.25)))], { env, stdio: 'ignore' });
const gatewayConfig = join(temp, 'gateway.json');
writeFileSync(gatewayConfig, JSON.stringify({
  listenHost: '127.0.0.1', listenPort: gatewayPort, relayHost: '127.0.0.1', relayPort,
  allowedOrigins: [origin], trustedOrgs: [b64(orgPublic)],
  maxSessions: sessions + 16, maxSessionsPerIp: sessions + 16,
  maxPending: 512, maxPendingPerIp: 512, upgradeBurst: 1e6, upgradeRefillMs: 1,
}));
const gateway = spawn('bun', [join(root, 'gateway/server.mjs'), gatewayConfig], { stdio: ['ignore', 'pipe', 'ignore'] });
// Children never outlive the benchmark, even when it is interrupted.
const stopChildren = () => { gateway.kill('SIGTERM'); relay.kill('SIGTERM'); };
process.on('exit', stopChildren);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => process.exit(130));
await new Promise(r => gateway.stdout.once('data', r));
await sleep(500);

const NativeWebSocket = globalThis.WebSocket;
globalThis.WebSocket = class extends NativeWebSocket { constructor(url) { super(url, { headers: { Origin: origin } }); } };
// One WASM instance holds 16 identities, as a browser tab would hold one; compile once.
const wasm = await WebAssembly.compile(readFileSync(join(root, 'zig-out/bin/meshguard.wasm')));
let core;
const identities = Array.from({ length: sessions }, (_, i) => {
  if (i % 16 === 0) core = new MeshguardWasm(new WebAssembly.Instance(wasm, {}));
  // Distinct in bytes WireGuard key clamping keeps (it clears low bits of byte 0).
  const seed = new Uint8Array(32).fill(0x42); new DataView(seed.buffer).setUint32(4, i + 1, true);
  return core.createIdentity(seed);
});
const url = `ws://127.0.0.1:${gatewayPort}/meshguard-web/ws`;
const latencies = [];
let sent = 0, received = 0, measuring = false, measureStart = 0;
const clients = identities.map((identity, i) => {
  const client = new MeshguardRelayClient({ identity, url, relay: relayPeer, pass: issuePass(identity) });
  client.contactPeers = [];
  // Contacts are mutual, as in an application: send to the next ones, accept from both sides.
  for (let k = 1; k <= Math.min(contacts, sessions - 1); k++) {
    const next = identities[(i + k) % sessions], previous = identities[(i - k + sessions) % sessions];
    client.contactPeers.push(client.addContact(next.publicKey(), next.wgPublicKey()));
    client.addContact(previous.publicKey(), previous.wgPublicKey());
  }
  client.addEventListener('message', event => {
    const view = new DataView(event.detail.data.buffer, event.detail.data.byteOffset);
    const sentAt = view.getFloat64(0, true);
    if (measuring && sentAt >= measureStart) { received++; latencies.push(performance.now() - sentAt); }
  });
  return client;
});

const cpu0 = { relay: cpuSeconds(relay.pid), gateway: cpuSeconds(gateway.pid) };
const rampStart = performance.now();
for (let i = 0; i < clients.length; i++) {
  clients[i].connect();
  if ((i + 1) % rampPerSecond === 0) await sleep(1000);
}
const readyDeadline = performance.now() + 120000;
while (clients.some(c => !c.ready) && performance.now() < readyDeadline) await sleep(100);
const ready = clients.filter(c => c.ready).length;
const rampMs = Math.round(performance.now() - rampStart);

measuring = true; measureStart = performance.now();
const timers = clients.map(client => {
  const tick = () => {
    if (!measuring) return;
    if (client.ready) {
      const payload = new Uint8Array(64); new DataView(payload.buffer).setFloat64(0, performance.now(), true);
      const peer = client.contactPeers[Math.floor(Math.random() * client.contactPeers.length)];
      if (client.send(peer, payload)) sent++;
    }
    client.timer2 = setTimeout(tick, -Math.log(Math.max(Math.random(), 1e-9)) / rate * 1000);
  };
  client.timer2 = setTimeout(tick, Math.random() * 1000 / rate);
  return client;
});
await sleep(duration * 1000);
measuring = false;
await sleep(1500);
for (const c of timers) clearTimeout(c.timer2);

latencies.sort((a, b) => a - b);
const status = await relayStatus(control).catch(() => null);
const report = {
  sessions, opaque, ready, ramp_ms: rampMs, sent, received,
  loss: sent ? +(1 - received / sent).toFixed(6) : 0,
  latency_ms: { p50: +percentile(latencies, 0.5).toFixed(2), p95: +percentile(latencies, 0.95).toFixed(2), p99: +percentile(latencies, 0.99).toFixed(2) },
  gateway: { cpu_seconds: +(cpuSeconds(gateway.pid) - cpu0.gateway).toFixed(2), peak_rss_mib: +peakMiB(gateway.pid).toFixed(1) },
  relay: { cpu_seconds: +(cpuSeconds(relay.pid) - cpu0.relay).toFixed(2), peak_rss_mib: +peakMiB(relay.pid).toFixed(1), status: status?.relay ?? null },
};
for (const c of clients) c.disconnect();
globalThis.WebSocket = NativeWebSocket;
gateway.kill('SIGTERM'); relay.kill('SIGTERM');
await sleep(300);
rmSync(temp, { recursive: true, force: true });
console.log(JSON.stringify(report, null, 2));
// --max-loss F: fail when a session never became ready or loss exceeds F (CI smoke runs).
process.exit(maxLoss !== null && (ready < sessions || report.loss > Number(maxLoss)) ? 1 : 0);
