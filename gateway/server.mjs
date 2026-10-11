// Ciphertext-only WSS -> UDP adapter for browser clients of a MeshGuard relay. Requires Bun 1.4.2.
//
// A browser authenticates its Ed25519/WireGuard key pair by signing a fresh challenge, and is
// admitted when the pair is in `allowedIdentities` or it presents a valid pass (an organization
// certificate) from one of `trustedOrgs`. Admitted sessions get one UDP socket connected to the
// relay; the packet gate forwards only the session's own WireGuard initiations, its own SWIM
// self-advertisement, and sealed app frames it sends.
import { createPublicKey, verify, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { authPayload, bindingPayload, fromB64, b64, same } from '../web/relay-protocol.mjs';
import { verifyPass, CERT_SIZE } from './pass.mjs';

const keyBytes = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('Invalid public key');
  const bytes = fromB64(value); if (bytes.length !== 32) throw new Error('Invalid public key'); return bytes;
};
const edKey = bytes => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(bytes)]), format: 'der', type: 'spki' });

/**
 * The packet gate. `destinations` is a Set of Base64 keys the session may address, or null to
 * leave destination policy to the relay.
 */
export function validateOutbound(frame, session, destinations) {
  if (frame.length === 148 && new DataView(frame.buffer, frame.byteOffset).getUint32(0, true) === 1) return true;
  if (frame[0] === 0x50) {
    return frame.length >= 93 && frame.length <= 1117 && same(frame.slice(33, 65), session.publicKey)
      && (destinations === null || destinations.has(b64(frame.slice(1, 33))));
  }
  if (![1, 3].includes(frame[0]) || frame.length < 165 || frame[49] !== 1) return false;
  // Optional extensions after the self entry, in wire order: the session's own pass, then its
  // own binding, each exactly as verified at authentication.
  let at = 165;
  if (at < frame.length && frame[at] === 1) {
    if (!session.pass || frame.length < at + 1 + CERT_SIZE || !same(frame.slice(at + 1, at + 1 + CERT_SIZE), session.pass)) return false;
    at += 1 + CERT_SIZE;
  }
  if (at < frame.length && frame[at] === 2) {
    if (!session.binding || frame.length < at + 97 || !same(frame.slice(at + 1, at + 33), session.wgPublicKey)
      || !same(frame.slice(at + 33, at + 97), session.binding)) return false;
    at += 97;
  }
  if (at !== frame.length) return false;
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

/** Admission policy from a config object; replaced as a whole on reload. */
function admissionPolicy(config) {
  const allowed = new Map((config.allowedIdentities ?? []).map(peer => [b64(keyBytes(peer.publicKey)), keyBytes(peer.wgPublicKey)]));
  const trustedOrgs = new Set((config.trustedOrgs ?? []).map(value => b64(keyBytes(value))));
  if (allowed.size === 0 && trustedOrgs.size === 0) throw new Error('Gateway admits nobody: set allowedIdentities or trustedOrgs');
  const destinations = config.allowedDestinations ? new Set(config.allowedDestinations.map(value => b64(keyBytes(value)))) : null;
  return { allowed, trustedOrgs, destinations, skew: config.passSkewSeconds ?? 300 };
}

export function startGateway(config) {
  if (isIP(config.relayHost) !== 4 || isIP(config.udpBindHost ?? '127.0.0.1') !== 4) throw new Error('Gateway requires configured IPv4 endpoints');
  if (!Number.isInteger(config.relayPort) || config.relayPort < 1 || config.relayPort > 65535) throw new Error('Invalid relay port');
  let policy = admissionPolicy(config);
  const origins = new Set(config.allowedOrigins);
  const active = new Map(), sockets = new Set();
  // Unauthenticated connections get their own small budget so they cannot consume capacity needed by
  // admitted identities. Admitted sessions are capped overall and per source address.
  const limits = { pending: config.maxPending ?? 8, pendingPerIp: config.maxPendingPerIp ?? 2,
    burst: config.upgradeBurst ?? 5, refillMs: config.upgradeRefillMs ?? 2000, tracked: 4096,
    authTimeoutMs: config.authTimeoutMs ?? 10000,
    sessions: config.maxSessions ?? 4096, sessionsPerIp: config.maxSessionsPerIp ?? 16 };
  const trustedProxies = new Set((config.trustedProxies ?? LOOPBACK).map(normalizeIp));
  const sources = new Map(); // ip -> { tokens, refill, pending, sessions }
  let pending = 0;
  const source = (ip, now) => {
    let entry = sources.get(ip);
    if (!entry) {
      if (sources.size >= limits.tracked) {
        for (const [key, value] of sources) if (value.pending === 0 && value.sessions === 0 && now - value.refill > limits.refillMs * limits.burst) sources.delete(key);
        if (sources.size >= limits.tracked) return null;
      }
      entry = { tokens: limits.burst, refill: now, pending: 0, sessions: 0 }; sources.set(ip, entry);
    }
    entry.tokens = Math.min(limits.burst, entry.tokens + (now - entry.refill) / limits.refillMs); entry.refill = now;
    return entry;
  };
  const releasePending = session => {
    if (!session.counted) return;
    session.counted = false; pending--;
    const entry = sources.get(session.ip); if (entry) entry.pending--;
  };
  const counters = { authenticated: 0, rejected: 0, forwarded: 0, received: 0, limited: 0, expired: 0, renewed: 0 };
  const prefix = config.pathPrefix ?? '/meshguard-web';

  // Which admission a key pair has right now: 'static', a pass check result, or null.
  const admit = (publicKey, wgPublicKey, passBytes) => {
    const expectedWg = policy.allowed.get(b64(publicKey));
    if (expectedWg && same(wgPublicKey, expectedWg)) return { kind: 'static' };
    if (!passBytes) return null;
    const result = verifyPass(passBytes, { publicKey, wgPublicKey, trustedOrgs: policy.trustedOrgs, skew: policy.skew });
    return typeof result === 'string' ? null : { kind: 'pass', wire: result.wire, expiresAt: result.expiresAt };
  };
  // Closes the session when its pass runs out (with the configured skew).
  const armExpiry = (ws, expiresAt) => {
    clearTimeout(ws.data.expiry);
    if (!expiresAt) return;
    const ms = Math.max(0, (expiresAt + policy.skew) * 1000 - Date.now());
    ws.data.expiry = setTimeout(() => { counters.expired++; ws.close(4004, 'Pass expired'); }, Math.min(ms, 2 ** 31 - 1));
  };

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
            const signature = fromB64(auth.signature);
            if (auth.type !== 'authenticate' || signature.length !== 64
              || !verify(null, authPayload(session.challenge, publicKey, wgPublicKey), edKey(publicKey), signature)) throw new Error('Identity not admitted');
            const admission = admit(publicKey, wgPublicKey, typeof auth.pass === 'string' ? fromB64(auth.pass) : null);
            if (!admission) throw new Error('Identity not admitted');
            // Optional: the identity's signature over its WireGuard key, which its
            // self-advertisements may then carry to the relay.
            let binding = null;
            if (auth.binding !== undefined) {
              binding = fromB64(auth.binding);
              if (binding.length !== 64 || !verify(null, bindingPayload(publicKey, wgPublicKey), edKey(publicKey), binding)) throw new Error('Invalid binding');
            }
            const key = b64(publicKey), entry = sources.get(session.ip);
            const replacing = active.get(key);
            const others = active.size - (replacing ? 1 : 0);
            const fromHere = (entry?.sessions ?? 0) - (replacing?.data.ip === session.ip ? 1 : 0);
            if (others >= limits.sessions || fromHere >= limits.sessionsPerIp) {
              counters.limited++; ws.close(1013, 'Gateway at capacity'); return;
            }
            session.challenge.fill(0); clearTimeout(session.deadline);
            session.publicKey = publicKey; session.wgPublicKey = wgPublicKey; session.binding = binding;
            session.pass = admission.kind === 'pass' ? admission.wire : null;
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
            active.set(key, ws); replacing?.close(4001, 'Replaced by a new authenticated connection');
            if (entry) entry.sessions++;
            session.admitted = true;
            session.phase = 'ready'; releasePending(session); counters.authenticated++;
            if (admission.kind === 'pass') armExpiry(ws, admission.expiresAt);
            ws.send(JSON.stringify({ type: 'ready', endpoint: session.endpoint, ...(session.pass && { passExpiresAt: admission.expiresAt }) }));
          } catch { counters.rejected++; ws.close(4003, 'Identity not admitted'); }
          return;
        }
        if (session.phase !== 'ready') { counters.rejected++; ws.close(1008, 'Binary packets required'); return; }
        if (typeof message === 'string') {
          // The only control message after authentication: a renewed pass.
          let renew;
          try { renew = JSON.parse(message); } catch { renew = null; }
          if (renew?.type !== 'renew' || typeof renew.pass !== 'string') { counters.rejected++; ws.close(1008, 'Binary packets required'); return; }
          const result = verifyPass(fromB64(renew.pass), { publicKey: session.publicKey, wgPublicKey: session.wgPublicKey,
            trustedOrgs: policy.trustedOrgs, skew: policy.skew });
          if (typeof result === 'string') { ws.send(JSON.stringify({ type: 'renew-rejected', reason: result })); return; }
          session.pass = result.wire; armExpiry(ws, result.expiresAt); counters.renewed++;
          ws.send(JSON.stringify({ type: 'renewed', passExpiresAt: result.expiresAt }));
          return;
        }
        const frame = new Uint8Array(message);
        const now = Date.now(); session.tokens = Math.min(60, session.tokens + (now - session.refill) * .03); session.refill = now;
        if (session.tokens < 1 || !validateOutbound(frame, session, policy.destinations)) { counters.rejected++; ws.close(1008, 'Packet rejected'); return; }
        session.tokens--; if (session.udp.send(frame)) counters.forwarded++;
      },
      close(ws) {
        sockets.delete(ws); releasePending(ws.data); clearTimeout(ws.data.deadline); clearTimeout(ws.data.expiry);
        ws.data.phase = 'closed'; ws.data.udp?.close();
        if (ws.data.admitted) { ws.data.admitted = false; const entry = sources.get(ws.data.ip); if (entry) entry.sessions--; }
        if (ws.data.publicKey && active.get(b64(ws.data.publicKey)) === ws) active.delete(b64(ws.data.publicKey));
      },
    },
  });

  /** Applies a new configuration's admission policy and closes sessions it no longer admits. */
  function reload(next) {
    policy = admissionPolicy(next);
    for (const ws of active.values()) {
      const s = ws.data;
      if (!admit(s.publicKey, s.wgPublicKey, s.pass)) ws.close(4003, 'Identity not admitted');
    }
  }

  return {
    server, counters, reload,
    sessions: () => active.size,
    stop() { for (const ws of sockets) ws.close(1001, 'Gateway stopping'); server.stop(true); },
  };
}

if (import.meta.main) {
  const path = process.argv[2];
  if (!path) throw new Error('Usage: bun gateway/server.mjs /path/to/public-config.json');
  const gateway = startGateway(JSON.parse(await readFile(path, 'utf8')));
  console.log(JSON.stringify({ event: 'gateway-ready', host: gateway.server.hostname, port: gateway.server.port }));
  process.on('SIGHUP', async () => {
    try { gateway.reload(JSON.parse(await readFile(path, 'utf8'))); console.log(JSON.stringify({ event: 'gateway-reloaded', sessions: gateway.sessions() })); }
    catch (error) { console.log(JSON.stringify({ event: 'gateway-reload-failed', error: error.message })); }
  });
  process.on('SIGTERM', () => { gateway.stop(); process.exit(0); });
  process.on('SIGINT', () => { gateway.stop(); process.exit(0); });
}
