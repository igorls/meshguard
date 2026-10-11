// Type declarations for relay-protocol.mjs, the browser client of the MeshGuard browser gateway.
/// <reference lib="dom" />

/** A peer's pinned keys: 32-byte Ed25519 identity key and 32-byte X25519 (WireGuard) key. */
export interface MeshguardPeer {
  publicKey: Uint8Array;
  wgPublicKey: Uint8Array;
}

/** What `MeshguardRelayClient` needs from an identity (a `MeshguardIdentity` provides it). */
export interface RelayIdentity {
  publicKey(): Uint8Array;
  wgPublicKey(): Uint8Array;
  initiateHandshake(peerWgPublicKey: Uint8Array): Uint8Array;
  completeHandshake(response: Uint8Array): void;
  seal(peer: MeshguardPeer, message: string | Uint8Array): Uint8Array;
  open(peer: MeshguardPeer, frame: Uint8Array): Uint8Array;
  sign(message: Uint8Array): Uint8Array;
}

/** The UDP endpoint the gateway assigned to this session. */
export interface GatewayEndpoint {
  address: string;
  port: number;
}

export interface MeshguardRelayClientOptions {
  /** The browser's identity. Use one identity handle per client: a handle holds one handshake. */
  identity: RelayIdentity;
  /** The gateway's WebSocket URL, for example `wss://example.com/meshguard-web/ws`. */
  url: string | URL;
  /** The relay's pinned keys. */
  relay: MeshguardPeer;
  /** Peers this client may exchange messages with. More can be added with `addContact`. */
  trustedPeers?: MeshguardPeer[];
  /** A pass (organization certificate, 186 or 314 bytes) for gateways and relays that admit by pass. */
  pass?: Uint8Array | null;
}

export type RelayConnectionState =
  | 'connecting'
  | 'authenticating-relay'
  | 'connected'
  | 'disconnected'
  | 'connection-error';

export interface RelayStateDetail {
  state: RelayConnectionState;
  /** Set for `authenticating-relay` and `connected`. */
  endpoint?: GatewayEndpoint;
  /**
   * The WebSocket close code, for `disconnected`. 4001: replaced by a newer session of the same
   * identity; 4003: not admitted; 4004: pass expired (call `renewPass`, then `reconnect`);
   * 1013: gateway full (the client retries). The client does not reconnect after 1008, 4001,
   * 4003 or 4004.
   */
  code?: number;
}

export interface RelayMessageDetail {
  /** The pinned peer the message came from. */
  peer: MeshguardPeer;
  /** The authenticated, decrypted payload. */
  data: Uint8Array;
}

export type DeliveryStatusReason =
  | 'offline'
  | 'destination-not-admitted'
  | 'rate-limited'
  | 'handshake-again'
  | 'not-admitted'
  | 'overloaded'
  | 'unknown';

/** A relay delivery status (`0x51`) frame. */
export interface DeliveryStatus {
  /** The Ed25519 key the frame was addressed to. */
  destination: Uint8Array;
  /** The 12-byte nonce `send` returned for the frame. */
  nonce: Uint8Array;
  code: number;
  reason: DeliveryStatusReason;
}

export interface RelayStatusDetail extends DeliveryStatus {
  /** The pinned peer for `destination`, when the client knows it. */
  peer: MeshguardPeer | null;
}

export type RelayPassDetail =
  | { state: 'renewed'; /** Unix seconds; 0 means never. */ expiresAt: number }
  | { state: 'rejected'; reason: string };

export interface MeshguardRelayClientEventMap {
  state: CustomEvent<RelayStateDetail>;
  message: CustomEvent<RelayMessageDetail>;
  /** A pinned peer that gossip shows with the same keys. Discovery only; it grants no trust. */
  peer: CustomEvent<MeshguardPeer>;
  /** A delivery status for a frame this client sent. */
  status: CustomEvent<RelayStatusDetail>;
  /** The outcome of `renewPass` in a live session. */
  pass: CustomEvent<RelayPassDetail>;
  /** An incoming frame that failed to parse or authenticate; the detail is the error message. */
  rejected: CustomEvent<string>;
}

export interface RelayClientStats {
  sent: number;
  received: number;
  duplicates: number;
  rejected: number;
  handshakes: number;
  connections: number;
}

/**
 * Connects one identity to a MeshGuard relay through the browser gateway (WSS), authenticates
 * the relay with a Noise handshake, and exchanges sealed messages with pinned peers.
 */
export declare class MeshguardRelayClient extends EventTarget {
  constructor(options: MeshguardRelayClientOptions);
  readonly identity: RelayIdentity;
  readonly url: string | URL;
  readonly relay: MeshguardPeer;
  /** Pinned peers by Base64 Ed25519 key. */
  readonly peers: Map<string, MeshguardPeer>;
  readonly stats: RelayClientStats;
  /** True once the relay handshake completed in the current session. */
  readonly ready: boolean;
  /** The UDP endpoint of the current session, once the gateway admitted it. */
  readonly endpoint: GatewayEndpoint | null | undefined;
  /** Opens the session. Reconnects with jittered backoff until `disconnect()`. */
  connect(): void;
  /** Closes the current session and opens a new one at once. */
  reconnect(): void;
  /** Closes the session and stops reconnecting. */
  disconnect(): void;
  /**
   * Replaces the pass: in the live session when connected (a `pass` event reports the outcome),
   * otherwise for the next connection. Throws on a malformed pass.
   */
  renewPass(pass: Uint8Array): void;
  /**
   * Seals and sends `message` to `peer`, which must be the peer object this client holds (from
   * `trustedPeers` or `addContact`). Returns the frame's 12-byte nonce, which a later `status`
   * event refers to, or false when not connected or the socket is congested. Sending is not
   * delivery: use application acknowledgements.
   */
  send(peer: MeshguardPeer, message: string | Uint8Array): Uint8Array | false;
  /** Registers (or replaces) a contact; returns the peer object `send` expects. */
  addContact(publicKey: Uint8Array, wgPublicKey: Uint8Array): MeshguardPeer;
  /** Removes a contact; returns whether it was known. */
  removeContact(publicKey: Uint8Array): boolean;

  addEventListener<K extends keyof MeshguardRelayClientEventMap>(
    type: K,
    listener: (this: MeshguardRelayClient, event: MeshguardRelayClientEventMap[K]) => unknown,
    options?: boolean | AddEventListenerOptions,
  ): void;
  addEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
    options?: boolean | AddEventListenerOptions,
  ): void;
  removeEventListener<K extends keyof MeshguardRelayClientEventMap>(
    type: K,
    listener: (this: MeshguardRelayClient, event: MeshguardRelayClientEventMap[K]) => unknown,
    options?: boolean | EventListenerOptions,
  ): void;
  removeEventListener(
    type: string,
    listener: EventListenerOrEventListenerObject | null,
    options?: boolean | EventListenerOptions,
  ): void;
}

// Wire-format helpers, shared with the gateway.

/** Standard Base64 encoding of bytes. */
export declare function b64(bytes: ArrayBuffer | ArrayLike<number>): string;
/** Decodes standard Base64. */
export declare function fromB64(value: string): Uint8Array;
/** Byte-wise equality. */
export declare function same(a: Uint8Array, b: Uint8Array): boolean;
/** Signature domain of gateway authentication. */
export declare const authDomain: Uint8Array;
/** Signature domain of the identity's binding to its WireGuard key. */
export declare const bindingDomain: Uint8Array;
/** The message a browser signs to answer a gateway challenge. */
export declare function authPayload(challenge: Uint8Array, publicKey: Uint8Array, wgPublicKey: Uint8Array): Uint8Array;
/** The message an identity signs to bind its WireGuard key. */
export declare function bindingPayload(publicKey: Uint8Array, wgPublicKey: Uint8Array): Uint8Array;
/** Size of a pass on the wire (v2); v1 passes (186 bytes) are zero-padded to it. */
export declare const PASS_SIZE: 314;
/** Pads a 186- or 314-byte pass to `PASS_SIZE`. Throws on any other input. */
export declare function padPass(pass: Uint8Array): Uint8Array;
/** Encodes a SWIM ping (type 1) or ACK (type 3) carrying only this identity's self entry. */
export declare function selfAdvertisement(
  identity: Pick<RelayIdentity, 'publicKey' | 'wgPublicKey'>,
  endpoint: GatewayEndpoint,
  type: number,
  sequence: bigint,
  incarnation: bigint,
  binding?: Uint8Array | null,
  pass?: Uint8Array | null,
): Uint8Array;
/** Delivery status codes (1 to 6) and their reasons; other codes are not listed. */
export declare const STATUS_CODES: Readonly<{ [code: number]: Exclude<DeliveryStatusReason, 'unknown'> | undefined }>;
/** Parses a relay delivery status frame, or returns null for any other frame. */
export declare function parseStatus(frame: Uint8Array): DeliveryStatus | null;
/** The peers (with WireGuard keys) a SWIM ping or ACK describes. */
export declare function gossipKeys(frame: Uint8Array): MeshguardPeer[];
