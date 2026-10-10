// Ciphertext-only, fixed-destination WSS -> UDP adapter. Requires Bun 1.4.2.
import { createPublicKey, verify, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { authPayload, fromB64, b64, same } from '../web/relay-protocol.mjs';

const keyBytes = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('Invalid public key');
  const bytes = fromB64(value); if (bytes.length !== 32) throw new Error('Invalid public key'); return bytes;
};
const edKey = bytes => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(bytes)]), format: 'der', type: 'spki' });

export function validateOutbound(frame, session, destinations) {
  if (frame.length === 148 && new DataView(frame.buffer, frame.byteOffset).getUint32(0, true) === 1) return true;
  if (frame[0] === 0x50) {
    return frame.length >= 93 && frame.length <= 1117 && same(frame.slice(33, 65), session.publicKey)
      && destinations.has(b64(frame.slice(1, 33)));
  }
  if (![1, 3].includes(frame[0]) || frame.length !== 165 || frame[49] !== 1) return false;
  const view = new DataView(frame.buffer, frame.byteOffset);
  return same(frame.slice(1, 33), session.publicKey) && same(frame.slice(50, 82), session.publicKey)
    && frame[82] === 1 && frame[91] === 1 && frame[92] === 4
    && same(frame.slice(93, 97), Uint8Array.from(session.endpoint.address.split('.').map(Number)))
    && frame.slice(97, 109).every(byte => byte === 0) && view.getUint16(109, true) === session.endpoint.port
    && frame[111] === 1 && same(frame.slice(112, 144), session.wgPublicKey)
    && frame.slice(144, 164).every(byte => byte === 0) && frame[164] === 3;
}

const LOOPBACK = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
const normalizeIp = value => (typeof value === 'string' && value.startsWith('::ffff:') && isIP(value.slice(7)) === 4) ? value.slice(7) : value;

// Source address for per-IP limits. X-Forwarded-For is honored only when the TCP peer is a
// configured trusted proxy, and then only its right-most entry (the one the proxy appended).
export function clientAddress(peer, forwardedFor, trustedProxies) {
  const socketAddress = normalizeIp(peer);
  if (!trustedProxies.has(socketAddress) || typeof forwardedFor !== 'string') return socketAddress;
  const candidate = normalizeIp(forwardedFor.split(',').pop().trim());
  return isIP(candidate) ? candidate : socketAddress;
}

export function startGateway(config) {
  if (isIP(config.relayHost) !== 4 || isIP(config.udpBindHost ?? '127.0.0.1') !== 4) throw new Error('Gateway requires configured IPv4 endpoints');
  if (!Number.isInteger(config.relayPort) || config.relayPort < 1 || config.relayPort > 65535) throw new Error('Invalid relay port');
  const allowed = new Map(config.allowedIdentities.map(peer => [b64(keyBytes(peer.publicKey)), keyBytes(peer.wgPublicKey)]));
  const destinations = new Set(config.allowedDestinations.map(value => b64(keyBytes(value))));
  const origins = new Set(config.allowedOrigins);
  const active = new Map(), sockets = new Set();
  // Unauthenticated connections get their own small budget so they cannot consume capacity needed by
  // admitted identities. Authenticated sessions are bounded by the allowlist (one per identity).
  const limits = { pending: config.maxPending ?? 8, pendingPerIp: config.maxPendingPerIp ?? 2,
    burst: config.upgradeBurst ?? 5, refillMs: config.upgradeRefillMs ?? 2000, tracked: 4096,
    authTimeoutMs: config.authTimeoutMs ?? 10000 };
  const trustedProxies = new Set((config.trustedProxies ?? LOOPBACK).map(normalizeIp));
  const sources = new Map(); // ip -> { tokens, refill, pending }
  let pending = 0;
  const source = (ip, now) => {
    let entry = sources.get(ip);
    if (!entry) {
      if (sources.size >= limits.tracked) {
        for (const [key, value] of sources) if (value.pending === 0 && now - value.refill > limits.refillMs * limits.burst) sources.delete(key);
        if (sources.size >= limits.tracked) return null;
      }
      entry = { tokens: limits.burst, refill: now, pending: 0 }; sources.set(ip, entry);
    }
    entry.tokens = Math.min(limits.burst, entry.tokens + (now - entry.refill) / limits.refillMs); entry.refill = now;
    return entry;
  };
  const releasePending = session => {
    if (!session.counted) return;
    session.counted = false; pending--;
    const entry = sources.get(session.ip); if (entry) entry.pending--;
  };
  const counters = { authenticated: 0, rejected: 0, forwarded: 0, received: 0, limited: 0 };
  const prefix = config.pathPrefix ?? '/meshguard-web';
  const server = Bun.serve({
    hostname: config.listenHost ?? '127.0.0.1', port: config.listenPort ?? 4321,
    fetch(request, server) {
      const path = new URL(request.url).pathname;
      if (path === `${prefix}/health`) return Response.json({ status: 'ok', protocol: 1 });
      if (path !== `${prefix}/ws`) return new Response('Not found', { status: 404 });
      if (!origins.has(request.headers.get('origin'))) return new Response('Origin not allowed', { status: 403 });
      const ip = clientAddress(server.requestIP(request)?.address, request.headers.get('x-forwarded-for'), trustedProxies);
      const now = Date.now(), entry = ip ? source(ip, now) : null;
      if (!entry) return new Response('Gateway busy', { status: 503 });
      if (entry.tokens < 1 || entry.pending >= limits.pendingPerIp) { counters.limited++; return new Response('Too many requests', { status: 429, headers: { 'Retry-After': '2' } }); }
      if (pending >= limits.pending) { counters.limited++; return new Response('Gateway busy', { status: 503, headers: { 'Retry-After': '2' } }); }
      entry.tokens--; entry.pending++; pending++;
      const data = { challenge: randomBytes(32), phase: 'pending', tokens: 60, refill: now, ip, counted: true };
      if (server.upgrade(request, { data })) return undefined;
      releasePending(data); return new Response('Upgrade required', { status: 426 });
    },
    websocket: {
      maxPayloadLength: 2048, backpressureLimit: 65536, closeOnBackpressureLimit: true,
      perMessageDeflate: false, idleTimeout: 45,
      open(ws) {
        sockets.add(ws);
        ws.data.deadline = setTimeout(() => ws.close(4003, 'Authentication timeout'), limits.authTimeoutMs);
        ws.send(JSON.stringify({ type: 'challenge', challenge: b64(ws.data.challenge) }));
      },
      async message(ws, message) {
        const session = ws.data;
        if (session.phase === 'pending') {
          session.phase = 'authenticating';
          try {
            if (typeof message !== 'string') throw new Error('Authentication required');
            const auth = JSON.parse(message);
            const publicKey = keyBytes(auth.publicKey), wgPublicKey = keyBytes(auth.wgPublicKey);
            const expectedWg = allowed.get(b64(publicKey));
            const signature = fromB64(auth.signature);
            if (auth.type !== 'authenticate' || !expectedWg || !same(wgPublicKey, expectedWg) || signature.length !== 64
              || !verify(null, authPayload(session.challenge, publicKey, wgPublicKey), edKey(publicKey), signature)) throw new Error('Identity not admitted');
            session.challenge.fill(0); clearTimeout(session.deadline);
            session.publicKey = publicKey; session.wgPublicKey = wgPublicKey;
            session.udp = await Bun.udpSocket({ hostname: config.udpBindHost ?? '127.0.0.1', port: 0,
              connect: { hostname: config.relayHost, port: config.relayPort },
              socket: {
                data(_, packet) {
                  if (session.phase !== 'ready' || packet.length > 1500) return;
                  if (packet[0] === 0x50 && (packet.length < 93 || !same(packet.subarray(1, 33), publicKey))) return;
                  counters.received++; ws.send(packet);
                },
                error() { ws.close(1011, 'Relay transport failed'); },
              },
            });
            if (!sockets.has(ws)) { session.udp.close(); return; }
            session.endpoint = { address: config.udpBindHost ?? '127.0.0.1', port: session.udp.port };
            const old = active.get(b64(publicKey));
            active.set(b64(publicKey), ws); old?.close(4001, 'Replaced by a new authenticated connection');
            session.phase = 'ready'; releasePending(session); counters.authenticated++;
            ws.send(JSON.stringify({ type: 'ready', endpoint: session.endpoint }));
          } catch { counters.rejected++; ws.close(4003, 'Identity not admitted'); }
          return;
        }
        if (session.phase !== 'ready' || typeof message === 'string') { counters.rejected++; ws.close(1008, 'Binary packets required'); return; }
        const frame = new Uint8Array(message);
        const now = Date.now(); session.tokens = Math.min(60, session.tokens + (now - session.refill) * .03); session.refill = now;
        if (session.tokens < 1 || !validateOutbound(frame, session, destinations)) { counters.rejected++; ws.close(1008, 'Packet rejected'); return; }
        session.tokens--; if (session.udp.send(frame)) counters.forwarded++;
      },
      close(ws) {
        sockets.delete(ws); releasePending(ws.data); clearTimeout(ws.data.deadline); ws.data.phase = 'closed'; ws.data.udp?.close();
        if (ws.data.publicKey && active.get(b64(ws.data.publicKey)) === ws) active.delete(b64(ws.data.publicKey));
      },
    },
  });
  return { server, counters, stop() { for (const ws of sockets) ws.close(1001, 'Gateway stopping'); server.stop(true); } };
}

if (import.meta.main) {
  if (!process.argv[2]) throw new Error('Usage: bun gateway/server.mjs /path/to/public-config.json');
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  const gateway = startGateway(config);
  console.log(JSON.stringify({ event: 'gateway-ready', host: gateway.server.hostname, port: gateway.server.port }));
  process.on('SIGTERM', () => { gateway.stop(); process.exit(0); });
  process.on('SIGINT', () => { gateway.stop(); process.exit(0); });
}
