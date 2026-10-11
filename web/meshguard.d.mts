// Type declarations for meshguard.mjs, the JavaScript wrapper of the MeshGuard WASM core.

/** Bytes accepted by the wrapper. Strings are not accepted where keys are expected. */
export type ByteInput = Uint8Array | ArrayBuffer | ArrayLike<number>;
/** A message: UTF-8 text or bytes. */
export type MessageInput = string | ByteInput;

/** A peer's public keys: its Ed25519 identity key and its X25519 (WireGuard) key, 32 bytes each. */
export interface PeerKeys {
  readonly publicKey: ByteInput;
  readonly wgPublicKey: ByteInput;
}

/** The ABI version this wrapper speaks. The module's `mg_abi_version()` must return it. */
export declare const ABI_VERSION: 1;

/**
 * One identity held inside the WASM core. All keys and outputs are fresh copies; the private key
 * never leaves WASM memory through this API. Every method throws once `destroy()` has run.
 */
export interface MeshguardIdentity {
  /** The 32-byte Ed25519 public key. */
  publicKey(): Uint8Array;
  /** The 32-byte X25519 (WireGuard) public key. */
  wgPublicKey(): Uint8Array;
  /** Starts a WireGuard Noise IK handshake to `peerWgPublicKey`; returns the 148-byte initiation. */
  initiateHandshake(peerWgPublicKey: ByteInput): Uint8Array;
  /** Authenticates the 92-byte handshake response. Throws when it does not match. */
  completeHandshake(response: ByteInput): void;
  /**
   * Encrypts `message` (at most `maxPayload` bytes) to `peer` and returns the `0x50` packet
   * (93 bytes of overhead). The caller must have authenticated the peer's key binding.
   */
  seal(peer: PeerKeys, message: MessageInput): Uint8Array;
  /** Authenticates and decrypts a `0x50` packet sent by `peer` to this identity. */
  open(peer: PeerKeys, frame: ByteInput): Uint8Array;
  /** Returns the 64-byte Ed25519 signature of `message` (at most `maxPayload` bytes). */
  sign(message: MessageInput): Uint8Array;
  /** Zeroes the identity and frees its slot. Calling it again does nothing. */
  destroy(): void;
}

export declare class MeshguardWasm {
  /** Wraps an instantiated module. Throws when its ABI version differs from `ABI_VERSION`. */
  constructor(instance: WebAssembly.Instance);
  /**
   * Fetches and instantiates the module. Without a URL, loads the `meshguard.wasm` next to
   * `meshguard.mjs`.
   */
  static load(url?: string | URL): Promise<MeshguardWasm>;
  /** The largest plaintext or signing input, in bytes (1024). */
  readonly maxPayload: number;
  /**
   * Creates an identity from a 32-byte seed, or from fresh random bytes when `seed` is omitted.
   * The same seed always yields the same keys. The caller's seed buffer is left untouched. The core
   * holds up to 16 identities at once.
   */
  createIdentity(seed?: ByteInput): MeshguardIdentity;
  /** Checks an Ed25519 signature; returns false for any invalid input. */
  verify(publicKey: ByteInput, message: MessageInput, signature: ByteInput): boolean;
}
