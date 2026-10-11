// Minimal application-only SWIM adapter. WireGuard transport data is out of scope.
export const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
export const fromB64 = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
export const same = (a, b) => a.length === b.length && a.every((byte, i) => byte === b[i]);
export const authDomain = new TextEncoder().encode('meshguard-browser-gateway-v1\0');
export const bindingDomain = new TextEncoder().encode('meshguard-wg-binding-v1\0');
export function authPayload(challenge, publicKey, wgPublicKey) {
  const out = new Uint8Array(authDomain.length + 96);
  out.set(authDomain); out.set(challenge, authDomain.length);
  out.set(publicKey, authDomain.length + 32); out.set(wgPublicKey, authDomain.length + 64);
  return out;
}

// The identity's signature over its own WireGuard key (identity/binding.zig), so
// relays and peers can tell it from a key that gossip claims for this identity.
export function bindingPayload(publicKey, wgPublicKey) {
  const out = new Uint8Array(bindingDomain.length + 64);
  out.set(bindingDomain); out.set(publicKey, bindingDomain.length); out.set(wgPublicKey, bindingDomain.length + 32);
  return out;
}

// A pass (organization certificate) travels in its 314-byte v2 slot; v1 passes are zero-padded.
export const PASS_SIZE = 314;
export function padPass(pass) {
  if (!(pass instanceof Uint8Array) || (pass.length !== 186 && pass.length !== PASS_SIZE)) throw new Error('Invalid pass');
  const out = new Uint8Array(PASS_SIZE); out.set(pass); return out;
}

// Native SWIM header (50 bytes) followed by exactly one 115-byte self entry, then the
// optional extensions in wire order: [0x01][314-byte pass], [0x02][wg key][signature].
export function selfAdvertisement(identity, endpoint, type, sequence, incarnation, binding, pass) {
  const out = new Uint8Array(165 + (pass ? 1 + PASS_SIZE : 0) + (binding ? 97 : 0));
  const view = new DataView(out.buffer);
  out[0] = type; out.set(identity.publicKey(), 1);
  view.setBigUint64(33, sequence, true); view.setBigUint64(41, incarnation, true);
  out[49] = 1; out.set(identity.publicKey(), 50); out[82] = 1;
  view.setBigUint64(83, sequence, true);
  out[91] = 1; out[92] = 4;
  out.set(endpoint.address.split('.').map(Number), 93);
  view.setUint16(109, endpoint.port, true);
  out[111] = 1; out.set(identity.wgPublicKey(), 112); out[164] = 3;
  let at = 165;
  if (pass) { out[at] = 1; out.set(pass, at + 1); at += 1 + PASS_SIZE; }
  if (binding) { out[at] = 2; out.set(identity.wgPublicKey(), at + 1); out.set(binding, at + 33); }
  return out;
}

// Relay delivery status (0x51): [0x51][32B destination][12B nonce][1B code][1B reserved].
export const STATUS_CODES = { 1: 'offline', 2: 'destination-not-admitted', 3: 'rate-limited',
  4: 'handshake-again', 5: 'not-admitted', 6: 'overloaded' };
export function parseStatus(frame) {
  if (frame.length !== 47 || frame[0] !== 0x51) return null;
  return { destination: frame.slice(1, 33), nonce: frame.slice(33, 45), code: frame[45],
    reason: STATUS_CODES[frame[45]] ?? 'unknown' };
}

export function gossipKeys(frame) {
  if (frame.length < 50 || ![1, 3].includes(frame[0]) || frame.length < 50 + frame[49] * 115) return [];
  const peers = [];
  for (let n = 0; n < frame[49]; n++) {
    const at = 50 + n * 115;
    if ([0, 1].includes(frame[at + 32]) && frame[at + 61] === 1) {
      peers.push({ publicKey: frame.slice(at, at + 32), wgPublicKey: frame.slice(at + 62, at + 94) });
    }
  }
  return peers;
}

export class MeshguardRelayClient extends EventTarget {
  constructor({ identity, url, relay, trustedPeers = [], pass = null }) {
    super(); this.identity = identity; this.url = url; this.relay = relay;
    this.pass = pass ? padPass(pass) : null; this.pendingPass = null;
    this.binding = identity.sign(bindingPayload(identity.publicKey(), identity.wgPublicKey()));
    this.peers = new Map(trustedPeers.map(peer => [b64(peer.publicKey), peer]));
    this.stats = { sent: 0, received: 0, duplicates: 0, rejected: 0, handshakes: 0, connections: 0 };
    this.seen = new Map(); this.sequence = 1n; this.incarnation = BigInt(Date.now()) * 1000000n;
    this.sent = new Map(); // destination|nonce of recent frames, to match delivery statuses
    this.ready = false; this.closed = true; this.retry = 0;
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  connect() {
    this.closed = false; this.ready = false; this.endpoint = null;
    // A renewal still in flight when the last session ended applies to this one.
    if (this.pendingPass) { this.pass = this.pendingPass; this.pendingPass = null; }
    const socket = new WebSocket(this.url); this.socket = socket; socket.binaryType = 'arraybuffer';
    socket.addEventListener('message', event => {
      if (socket !== this.socket) return;
      try { typeof event.data === 'string' ? this.control(JSON.parse(event.data)) : this.packet(new Uint8Array(event.data)); }
      catch (error) { this.stats.rejected++; this.emit('rejected', error.message); }
    });
    socket.addEventListener('close', event => {
      if (socket !== this.socket) return;
      this.ready = false; this.endpoint = null; clearInterval(this.timer);
      this.emit('state', { state: 'disconnected', code: event.code });
      // 4004: the pass expired; renewPass() then reconnect(). Other closes back off with jitter.
      if (!this.closed && ![1008, 4001, 4003, 4004].includes(event.code)) {
        this.reconnectTimer = setTimeout(() => this.connect(), Math.random() * Math.min(10000, 500 * 2 ** this.retry++));
      }
    });
    socket.addEventListener('error', () => this.emit('state', { state: 'connection-error' }));
    this.emit('state', { state: 'connecting' });
  }
  control(message) {
    if (message.type === 'challenge') {
      const challenge = fromB64(message.challenge);
      if (challenge.length !== 32) throw new Error('Invalid gateway challenge');
      this.socket.send(JSON.stringify({ type: 'authenticate', publicKey: b64(this.identity.publicKey()),
        wgPublicKey: b64(this.identity.wgPublicKey()), binding: b64(this.binding),
        ...(this.pass && { pass: b64(this.pass) }),
        signature: b64(this.identity.sign(authPayload(challenge, this.identity.publicKey(), this.identity.wgPublicKey()))) }));
    } else if (message.type === 'ready') {
      this.endpoint = message.endpoint; this.stats.connections++; this.retry = 0;
      this.advertise(); this.handshake();
      clearInterval(this.timer);
      this.timer = setInterval(() => {
        this.advertise();
        if (Date.now() - this.lastHandshake > (this.ready ? 15000 : 4000)) this.handshake();
      }, 2000);
      this.emit('state', { state: 'authenticating-relay', endpoint: this.endpoint });
    } else if (message.type === 'renewed') {
      // Advertise the new pass only once the gateway has accepted it.
      if (this.pendingPass) { this.pass = this.pendingPass; this.pendingPass = null; }
      this.emit('pass', { state: 'renewed', expiresAt: message.passExpiresAt });
    } else if (message.type === 'renew-rejected') {
      this.pendingPass = null;
      this.emit('pass', { state: 'rejected', reason: message.reason });
    }
  }
  /** Replaces the pass: in the live session when connected, otherwise for the next connection. */
  renewPass(pass) {
    const padded = padPass(pass);
    if (this.endpoint && this.socket?.readyState === WebSocket.OPEN) {
      this.pendingPass = padded;
      this.socket.send(JSON.stringify({ type: 'renew', pass: b64(padded) }));
    } else {
      this.pass = padded;
    }
  }
  sendRaw(frame) {
    if (this.socket?.readyState !== WebSocket.OPEN || this.socket.bufferedAmount > 65536) return false;
    this.socket.send(frame); return true;
  }
  advertise(type = 1, sequence = this.sequence++) {
    if (this.endpoint) this.sendRaw(selfAdvertisement(this.identity, this.endpoint, type, sequence, this.incarnation, this.binding, this.pass));
  }
  handshake() {
    this.lastHandshake = Date.now();
    this.sendRaw(this.identity.initiateHandshake(this.relay.wgPublicKey));
  }
  packet(frame) {
    if (frame.length === 92 && new DataView(frame.buffer, frame.byteOffset).getUint32(0, true) === 2) {
      this.identity.completeHandshake(frame); this.ready = true; this.stats.handshakes++;
      this.emit('state', { state: 'connected', endpoint: this.endpoint }); return;
    }
    if ([1, 3].includes(frame[0]) && frame.length >= 50 && same(frame.slice(1, 33), this.relay.publicKey)) {
      if (frame[0] === 1) this.advertise(3, new DataView(frame.buffer, frame.byteOffset).getBigUint64(33, true));
      // Gossip is discovery only. It cannot replace explicitly trusted WG keys.
      for (const peer of gossipKeys(frame)) {
        const trusted = this.peers.get(b64(peer.publicKey));
        if (trusted && same(trusted.wgPublicKey, peer.wgPublicKey)) this.emit('peer', trusted);
      }
      return;
    }
    const status = parseStatus(frame);
    if (status) {
      // Only statuses for frames this client sent count; the relay is the only other end.
      const key = b64(status.destination) + b64(status.nonce);
      if (!this.sent.delete(key)) return;
      if (status.code === 4) this.handshake(); // prove the endpoint again now
      this.emit('status', { ...status, peer: this.peers.get(b64(status.destination)) ?? null });
      return;
    }
    if (frame[0] !== 0x50 || frame.length < 93 || frame.length > 1117) return;
    const peer = this.peers.get(b64(frame.slice(33, 65)));
    if (!peer) { this.stats.rejected++; return; }
    // Known replays are dropped before any X25519/AEAD work. Tokens enter `seen` only after
    // authentication succeeds, so forged input can neither poison nor evict the cache.
    const token = b64(frame.slice(33, 77));
    if (this.seen.has(token)) { this.stats.duplicates++; return; }
    const plaintext = this.identity.open(peer, frame);
    this.seen.set(token, Date.now());
    while (this.seen.size > 512) this.seen.delete(this.seen.keys().next().value);
    this.stats.received++; this.emit('message', { peer, data: plaintext });
  }
  /** Seals and sends; returns the frame's 12-byte nonce (truthy), or false. */
  send(peer, message) {
    if (!this.ready || this.peers.get(b64(peer.publicKey)) !== peer) return false;
    const frame = this.identity.seal(peer, message);
    if (!this.sendRaw(frame)) return false;
    const nonce = frame.slice(65, 77);
    this.sent.set(b64(peer.publicKey) + b64(nonce), Date.now());
    while (this.sent.size > 256) this.sent.delete(this.sent.keys().next().value);
    this.stats.sent++; return nonce;
  }
  /** Registers (or replaces) a contact the relay does not describe; returns the peer object. */
  addContact(publicKey, wgPublicKey) {
    if (publicKey?.length !== 32 || wgPublicKey?.length !== 32) throw new Error('Invalid contact keys');
    const peer = { publicKey: Uint8Array.from(publicKey), wgPublicKey: Uint8Array.from(wgPublicKey) };
    this.peers.set(b64(peer.publicKey), peer);
    return peer;
  }
  removeContact(publicKey) { return this.peers.delete(b64(publicKey)); }
  reconnect() {
    this.closed = true; clearTimeout(this.reconnectTimer); clearInterval(this.timer);
    this.socket?.close(); this.connect();
  }
  disconnect() {
    this.closed = true; this.ready = false;
    clearTimeout(this.reconnectTimer); clearInterval(this.timer); this.socket?.close();
  }
}
