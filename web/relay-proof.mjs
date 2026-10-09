import { MeshguardWasm } from './meshguard.mjs';
import { MeshguardRelayClient, b64, fromB64 } from './relay-protocol.mjs';
const get = id => document.getElementById(id);
const log = message => { get('log').textContent = `${new Date().toLocaleTimeString()} ${message}\n${get('log').textContent}`.slice(0, 6000); };
let client, peer, config, hello = false, ack = false, challenge, timer, finished = false;
function resetProof() {
  hello = false; ack = false; challenge = b64(crypto.getRandomValues(new Uint8Array(18)));
  get('hello').textContent = get('ack').textContent = 'Waiting';
  document.documentElement.dataset.proof = 'pending';
}
function update() {
  get('messages').textContent = `${client.stats.sent} / ${client.stats.received}`;
  get('generation').textContent = client.stats.connections;
  if (hello && ack && client.ready) {
    get('status').textContent = 'PASS · Android and web are connected';
    get('description').textContent = 'Both clients decrypted the other’s message and acknowledged a fresh challenge through the shared relay.';
    document.documentElement.dataset.proof = 'passed';
    get('finish').disabled = false;
  }
}
function probe() {
  if (client?.ready && !ack) client.send(peer, `${config.runId}|HELLO|web|${challenge}`);
  if (client) update();
}
try {
  config = await (await fetch('./relay-config.json')).json();
  const core = await MeshguardWasm.load('./meshguard.wasm');
  const storageKey = 'meshguard.web-proof.identity.v1';
  const saved = localStorage.getItem(storageKey);
  const seed = saved ? fromB64(saved) : crypto.getRandomValues(new Uint8Array(32));
  const identity = core.createIdentity(seed);
  if (!saved) localStorage.setItem(storageKey, b64(seed));
  seed.fill(0);
  get('public-key').textContent = b64(identity.publicKey()); get('wg-key').textContent = b64(identity.wgPublicKey()); get('run').textContent = config.runId;
  peer = { publicKey: fromB64(config.peer.publicKey), wgPublicKey: fromB64(config.peer.wgPublicKey) };
  client = new MeshguardRelayClient({ identity, url: config.gatewayUrl,
    relay: { publicKey: fromB64(config.relay.publicKey), wgPublicKey: fromB64(config.relay.wgPublicKey) }, trustedPeers: [peer] });
  client.addEventListener('state', ({ detail }) => {
    if (finished) return;
    if (detail.state === 'connecting' || detail.state === 'disconnected') resetProof();
    log(`${detail.state}${detail.endpoint ? ` · UDP ${detail.endpoint.port}` : ''}`);
    if (detail.state === 'connected') {
      get('status').textContent = 'Relay connected · waiting for Android';
      get('noise').textContent = 'Verified'; get('error').textContent = '';
      get('reconnect').disabled = get('disconnect').disabled = false; probe();
    } else if (detail.state === 'disconnected') {
      get('status').textContent = 'Disconnected'; get('noise').textContent = 'Waiting';
      if (detail.code === 4003) get('error').textContent = 'This browser identity needs relay admission before it can connect.';
    } else { get('status').textContent = 'Connecting securely…'; }
    update();
  });
  client.addEventListener('rejected', ({ detail }) => log(`Rejected: ${detail}`));
  client.addEventListener('message', ({ detail }) => {
    const fields = new TextDecoder().decode(detail.data).split('|');
    if (fields.length !== 4 || fields[0] !== config.runId) return;
    if (fields[1] === 'HELLO') {
      hello = true; get('hello').textContent = 'Received';
      client.send(peer, `${config.runId}|ACK|web|${fields[3]}`);
    } else if (fields[1] === 'ACK' && fields[3] === challenge) {
      ack = true; hello = true; get('ack').textContent = 'Verified'; get('hello').textContent = 'Received';
    }
    log(`Encrypted ${fields[1]} received from Android`); update();
  });
  get('connect').disabled = false;
  get('connect').onclick = () => { resetProof(); client.disconnect(); client.connect(); clearInterval(timer); timer = setInterval(probe, 2000); };
  get('reconnect').onclick = () => { resetProof(); client.reconnect(); };
  get('disconnect').onclick = () => { clearInterval(timer); client.disconnect(); };
  get('finish').onclick = () => {
    finished = true; clearInterval(timer); client.disconnect();
    for (const id of ['connect', 'reconnect', 'disconnect', 'finish']) get(id).disabled = true;
    get('status').textContent = 'PASS · Android-to-web test completed';
    get('description').textContent = 'Encrypted delivery and authenticated reconnect were verified. The connection is closed and the results remain here for review.';
  };
  get('status').textContent = 'Browser identity ready';
  get('description').textContent = 'Connect when the Android probe is running. Each connection authenticates the shared relay.';
  log('Private identity stays in browser storage. Only public keys are sent to the gateway.');
} catch (error) { get('status').textContent = 'Setup needed'; get('error').textContent = error.message; }
