// Compiled (not run) by scripts/build-web.sh against the packed @meshguard/web declarations,
// through the package's `exports` map, with --strict.
import { ABI_VERSION, MeshguardWasm, type MeshguardIdentity } from '@meshguard/web';
import {
  MeshguardRelayClient, b64, fromB64, parseStatus, STATUS_CODES, PASS_SIZE,
  type MeshguardPeer, type RelayStatusDetail,
} from '@meshguard/web/relay-protocol';

const abi: 1 = ABI_VERSION;
const core: MeshguardWasm = await MeshguardWasm.load();
const fromUrl: MeshguardWasm = await MeshguardWasm.load(new URL('https://example.com/meshguard.wasm'));
const seed = new Uint8Array(32);
const identity: MeshguardIdentity = core.createIdentity(seed);
const other = fromUrl.createIdentity();
const peer: MeshguardPeer = { publicKey: other.publicKey(), wgPublicKey: other.wgPublicKey() };
const packet: Uint8Array = identity.seal(peer, 'hello');
const plaintext: Uint8Array = other.open({ publicKey: identity.publicKey(), wgPublicKey: identity.wgPublicKey() }, packet);
const signature = identity.sign(plaintext);
const valid: boolean = core.verify(identity.publicKey(), plaintext, signature);
const limit: number = core.maxPayload;

const client = new MeshguardRelayClient({
  identity,
  url: 'wss://example.com/meshguard-web/ws',
  relay: peer,
  trustedPeers: [peer],
  pass: new Uint8Array(PASS_SIZE),
});
client.addEventListener('state', event => {
  const state: string = event.detail.state;
  const code: number | undefined = event.detail.code;
  void state; void code;
});
client.addEventListener('message', event => {
  const data: Uint8Array = event.detail.data;
  const from: MeshguardPeer = event.detail.peer;
  void data; void from;
});
client.addEventListener('status', event => {
  const detail: RelayStatusDetail = event.detail;
  const nonce: Uint8Array = detail.nonce;
  void nonce;
});
client.addEventListener('pass', event => {
  if (event.detail.state === 'renewed') { const expires: number = event.detail.expiresAt; void expires; }
  else { const reason: string = event.detail.reason; void reason; }
});
client.addEventListener('rejected', event => { const message: string = event.detail; void message; });
client.connect();
const contact = client.addContact(fromB64(b64(other.publicKey())), other.wgPublicKey());
const sent: Uint8Array | false = client.send(contact, 'hi');
client.renewPass(new Uint8Array(186));
const removed: boolean = client.removeContact(contact.publicKey);
const status = parseStatus(new Uint8Array(47));
const reason: string = status?.reason ?? STATUS_CODES[1] ?? 'unknown';
// @ts-expect-error codes outside 1 to 6 have no entry
const listed: string = STATUS_CODES[99];
client.disconnect();
identity.destroy();

// @ts-expect-error keys are bytes, not strings
identity.seal({ publicKey: 'x', wgPublicKey: 'y' }, 'hello');
// @ts-expect-error send returns a nonce or false, never a number
const wrong: number = client.send(contact, 'hi');

void abi; void valid; void limit; void sent; void removed; void reason; void listed; void wrong;
