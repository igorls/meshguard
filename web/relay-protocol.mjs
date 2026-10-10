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

// Native SWIM header (50 bytes) followed by exactly one 115-byte self entry, then
// the optional 97-byte binding extension: [0x02][wg key][signature].
export function selfAdvertisement(identity, endpoint, type, sequence, incarnation, binding) {
  const out = new Uint8Array(binding ? 262 : 165);
  const view = new DataView(out.buffer);
  out[0] = type; out.set(identity.publicKey(), 1);
  view.setBigUint64(33, sequence, true); view.setBigUint64(41, incarnation, true);
  out[49] = 1; out.set(identity.publicKey(), 50); out[82] = 1;
  view.setBigUint64(83, sequence, true);
  out[91] = 1; out[92] = 4;
  out.set(endpoint.address.split('.').map(Number), 93);
  view.setUint16(109, endpoint.port, true);
  out[111] = 1; out.set(identity.wgPublicKey(), 112); out[164] = 3;
  if (binding) { out[165] = 2; out.set(identity.wgPublicKey(), 166); out.set(binding, 198); }
  return out;
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
  constructor({ identity, url, relay, trustedPeers = [] }) {
    super(); this.identity = identity; this.url = url; this.relay = relay;
    this.binding = identity.sign(bindingPayload(identity.publicKey(), identity.wgPublicKey()));
    this.peers = new Map(trustedPeers.map(peer => [b64(peer.publicKey), peer]));
    this.stats = { sent: 0, received: 0, duplicates: 0, rejected: 0, handshakes: 0, connections: 0 };
    this.seen = new Map(); this.sequence = 1n; this.incarnation = BigInt(Date.now()) * 1000000n;
    this.ready = false; this.closed = true; this.retry = 0;
  }
  emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
  connect() {
    this.closed = false; this.ready = false;
    const socket = new WebSocket(this.url); this.socket = socket; socket.binaryType = 'arraybuffer';
    socket.addEventListener('message', event => {
      if (socket !== this.socket) return;
      try { typeof event.data === 'string' ? this.control(JSON.parse(event.data)) : this.packet(new Uint8Array(event.data)); }
      catch (error) { this.stats.rejected++; this.emit('rejected', error.message); }
    });
    socket.addEventListener('close', event => {
      if (socket !== this.socket) return;
      this.ready = false; clearInterval(this.timer);
      this.emit('state', { state: 'disconnected', code: event.code });
      if (!this.closed && ![1008, 4001, 4003].includes(event.code)) {
        this.reconnectTimer = setTimeout(() => this.connect(), Math.min(10000, 500 * 2 ** this.retry++));
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
    }
  }
  sendRaw(frame) {
    if (this.socket?.readyState !== WebSocket.OPEN || this.socket.bufferedAmount > 65536) return false;
    this.socket.send(frame); return true;
  }
  advertise(type = 1, sequence = this.sequence++) {
    if (this.endpoint) this.sendRaw(selfAdvertisement(this.identity, this.endpoint, type, sequence, this.incarnation, this.binding));
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
  send(peer, message) {
    if (!this.ready || this.peers.get(b64(peer.publicKey)) !== peer) return false;
    if (!this.sendRaw(this.identity.seal(peer, message))) return false;
    this.stats.sent++; return true;
  }
  reconnect() {
    this.closed = true; clearTimeout(this.reconnectTimer); clearInterval(this.timer);
    this.socket?.close(); this.connect();
  }
  disconnect() {
    this.closed = true; this.ready = false;
    clearTimeout(this.reconnectTimer); clearInterval(this.timer); this.socket?.close();
  }
}
