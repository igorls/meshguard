const encoder = new TextEncoder();
const bytes = value =>
  typeof value === 'string' ? encoder.encode(value)
    : value instanceof Uint8Array ? value : new Uint8Array(value);

const statusNames = {
  '-1': 'Invalid or destroyed identity',
  '-2': 'Invalid buffer',
  '-3': 'Payload or buffer size limit',
  '-4': 'Identity pool full',
  '-5': 'Invalid key or packet',
  '-6': 'Authentication failed',
  '-7': 'Wrong recipient or sender',
};

function check(status) {
  if (status < 0) {
    throw new Error(statusNames[status] || `MeshGuard error ${status}`);
  }
  return status;
}

function key(value) {
  const result = bytes(value);
  if (result.length !== 32) {
    throw new Error('Public keys and identity seeds must contain 32 bytes');
  }
  return result;
}

// Scratch layout is private to this wrapper. Inputs and output never overlap.
const offset = {
  publicKey: 32, wgKey: 64, nonce: 96, data: 256, signature: 2048, output: 4096,
};

export class MeshguardWasm {
  #exports;
  #base;

  constructor(instance) {
    this.#exports = instance.exports;
    if (this.#exports.mg_abi_version() !== 1) {
      throw new Error('Unsupported MeshGuard WASM ABI');
    }
    this.#base = this.#exports.mg_scratch_ptr();
  }

  static async load(url) {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Could not load MeshGuard WASM (${response.status})`);
    }
    const result = await WebAssembly.instantiate(await response.arrayBuffer(), {});
    return new MeshguardWasm(result.instance);
  }

  get maxPayload() {
    return this.#exports.mg_max_payload();
  }

  #write(position, value) {
    const array = bytes(value);
    new Uint8Array(this.#exports.memory.buffer, this.#base + position, array.length).set(array);
  }

  #read(position, length) {
    return new Uint8Array(this.#exports.memory.buffer, this.#base + position, length).slice();
  }

  #clear() {
    new Uint8Array(
      this.#exports.memory.buffer,
      this.#base,
      this.#exports.mg_scratch_size(),
    ).fill(0);
  }

  createIdentity(seed) {
    const material = seed === undefined
      ? crypto.getRandomValues(new Uint8Array(32))
      : new Uint8Array(key(seed));
    let handle;
    try {
      this.#write(0, material);
      handle = check(this.#exports.mg_identity_create(this.#base, 32));
    } finally {
      material.fill(0);
      this.#clear();
    }

    let destroyed = false;
    let lastTimestamp = 0n;
    const live = () => {
      if (destroyed) throw new Error('Identity has been destroyed');
    };
    const publicKey = () => {
      live();
      try {
        check(this.#exports.mg_public_key(handle, this.#base + offset.output));
        return this.#read(offset.output, 32);
      } finally {
        this.#clear();
      }
    };
    const wgPublicKey = () => {
      live();
      try {
        check(this.#exports.mg_wg_public_key(handle, this.#base + offset.output));
        return this.#read(offset.output, 32);
      } finally {
        this.#clear();
      }
    };

    return Object.freeze({
      publicKey,
      wgPublicKey,
      initiateHandshake: peerWgPublicKey => {
        live();
        const ephemeral = crypto.getRandomValues(new Uint8Array(32));
        const indexBytes = crypto.getRandomValues(new Uint8Array(4));
        const senderIndex = new DataView(indexBytes.buffer).getUint32(0, true) || 1;
        const now = BigInt(Date.now()) * 1000000n;
        lastTimestamp = now > lastTimestamp ? now : lastTimestamp + 1n;
        const timestamp = new Uint8Array(12);
        const view = new DataView(timestamp.buffer);
        view.setBigUint64(0, lastTimestamp / 1000000000n + 0x400000000000000an, false);
        view.setUint32(8, Number(lastTimestamp % 1000000000n), false);
        try {
          this.#write(offset.wgKey, key(peerWgPublicKey));
          this.#write(offset.data, ephemeral);
          this.#write(offset.nonce, timestamp);
          const size = check(this.#exports.mg_noise_initiate(
            handle, this.#base + offset.wgKey, this.#base + offset.data,
            this.#base + offset.nonce, senderIndex, this.#base + offset.output,
          ));
          return this.#read(offset.output, size);
        } finally {
          ephemeral.fill(0);
          this.#clear();
        }
      },
      completeHandshake: response => {
        live();
        const data = bytes(response);
        if (data.length !== 92) throw new Error('Invalid WireGuard response size');
        try {
          this.#write(offset.data, data);
          check(this.#exports.mg_noise_complete(handle, this.#base + offset.data, data.length));
        } finally {
          this.#clear();
        }
      },
      seal: (peer, message) => {
        live();
        const data = bytes(message);
        if (data.length > this.maxPayload) {
          throw new Error('Message exceeds MeshGuard payload limit');
        }
        const nonce = crypto.getRandomValues(new Uint8Array(12));
        try {
          this.#write(offset.publicKey, key(peer.publicKey));
          this.#write(offset.wgKey, key(peer.wgPublicKey));
          this.#write(offset.nonce, nonce);
          this.#write(offset.data, data);
          const size = check(this.#exports.mg_seal(
            handle,
            this.#base + offset.publicKey,
            this.#base + offset.wgKey,
            this.#base + offset.nonce,
            this.#base + offset.data,
            data.length,
            this.#base + offset.output,
            2048,
          ));
          return this.#read(offset.output, size);
        } finally {
          nonce.fill(0);
          this.#clear();
        }
      },
      open: (peer, frame) => {
        live();
        const data = bytes(frame);
        if (data.length < 93 || data.length > this.maxPayload + 93) {
          throw new Error('Invalid MeshGuard packet size');
        }
        try {
          this.#write(offset.publicKey, key(peer.publicKey));
          this.#write(offset.wgKey, key(peer.wgPublicKey));
          this.#write(offset.data, data);
          const size = check(this.#exports.mg_open(
            handle,
            this.#base + offset.publicKey,
            this.#base + offset.wgKey,
            this.#base + offset.data,
            data.length,
            this.#base + offset.output,
            1024,
          ));
          return this.#read(offset.output, size);
        } finally {
          this.#clear();
        }
      },
      sign: message => {
        live();
        const data = bytes(message);
        if (data.length > this.maxPayload) {
          throw new Error('Signing payload exceeds limit');
        }
        try {
          this.#write(offset.data, data);
          check(this.#exports.mg_sign(
            handle,
            this.#base + offset.data,
            data.length,
            this.#base + offset.output,
          ));
          return this.#read(offset.output, 64);
        } finally {
          this.#clear();
        }
      },
      destroy: () => {
        if (destroyed) return;
        check(this.#exports.mg_identity_destroy(handle));
        destroyed = true;
      },
    });
  }

  verify(publicKey, message, signature) {
    const data = bytes(message);
    const sig = bytes(signature);
    if (data.length > this.maxPayload || sig.length !== 64) return false;
    try {
      this.#write(offset.publicKey, key(publicKey));
      this.#write(offset.data, data);
      this.#write(offset.signature, sig);
      return this.#exports.mg_verify(
        this.#base + offset.publicKey,
        this.#base + offset.data,
        data.length,
        this.#base + offset.signature,
      ) === 0;
    } finally {
      this.#clear();
    }
  }
}
