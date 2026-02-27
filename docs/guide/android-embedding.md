# Android / Mobile Embedding

meshguard provides a **C-ABI shared library** (`libmeshguard-ffi.so`) for embedding mesh networking in mobile apps. The library exposes SWIM gossip discovery, LAN multicast, and end-to-end encrypted messaging — without the WireGuard TUN dataplane.

## What's Included

| Feature                  | CLI (`meshguard`) | FFI (`libmeshguard-ffi.so`) |
| ------------------------ | ----------------- | --------------------------- |
| SWIM gossip discovery    | ✅                | ✅                          |
| LAN multicast discovery  | ✅                | ✅                          |
| Encrypted app messages   | ✅                | ✅                          |
| Peer events (join/leave) | ✅                | ✅                          |
| WireGuard TUN tunnels    | ✅                | ❌                          |
| Kernel WireGuard         | ✅                | ❌                          |
| Trust enforcement        | ✅                | Open by default             |
| libsodium dependency     | ✅ (AVX2 accel)   | ❌ (`std.crypto` only)      |

## Building

```bash
# Android aarch64 (ARM64 devices)
zig build -Dtarget=aarch64-linux-android -Doptimize=ReleaseFast

# Android x86_64 (emulators)
zig build -Dtarget=x86_64-linux-android -Doptimize=ReleaseFast
```

Output: `zig-out/lib/libmeshguard-ffi.so`

No Android NDK required — Zig cross-compiles with its bundled Bionic libc headers.

## JNI Integration (Kotlin)

### 1. Place the shared library

Copy `libmeshguard-ffi.so` to your Android project:

```
app/src/main/jniLibs/arm64-v8a/libmeshguard-ffi.so
app/src/main/jniLibs/x86_64/libmeshguard-ffi.so
```

### 2. Declare native functions

```kotlin
object MeshGuardFFI {
    init {
        System.loadLibrary("meshguard-ffi")
    }

    // Lifecycle
    external fun meshguard_init(identitySeed: ByteArray?, listenPort: Int): Long
    external fun meshguard_destroy(ctx: Long)

    // Mesh join/leave
    external fun meshguard_join(ctx: Long, seedIp: ByteArray, seedPort: Int): Int
    external fun meshguard_join_lan(ctx: Long): Int
    external fun meshguard_leave(ctx: Long)

    // Messaging
    external fun meshguard_send(ctx: Long, peerPubkey: ByteArray, data: ByteArray, len: Int): Int
    external fun meshguard_recv(ctx: Long, outData: ByteArray, outLen: IntArray, outSender: ByteArray): Int

    // Query
    external fun meshguard_peer_count(ctx: Long): Int
    external fun meshguard_is_running(ctx: Long): Boolean
    external fun meshguard_get_bound_port(ctx: Long): Int
    external fun meshguard_get_pubkey_b64(ctx: Long, out: ByteArray)
}
```

### 3. Usage example

```kotlin
// Initialize with a persisted identity seed (or null to generate)
val ctx = MeshGuardFFI.meshguard_init(savedSeed, 0)

// Join via LAN multicast (no seed required)
MeshGuardFFI.meshguard_join_lan(ctx)

// Or join via a known seed server
val seedIp = byteArrayOf(10, 0, 0, 1)
MeshGuardFFI.meshguard_join(ctx, seedIp, 51821)

// Send a message to a peer
val message = "Hello from Android!".toByteArray()
MeshGuardFFI.meshguard_send(ctx, peerPubkey, message, message.size)

// Clean up
MeshGuardFFI.meshguard_leave(ctx)
MeshGuardFFI.meshguard_destroy(ctx)
```

## FFI API Reference

### Lifecycle

| Function                   | Signature                           | Description                                                                          |
| -------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------ |
| `meshguard_init`           | `(seed: ?[*]u8, port: u16) → ?*ctx` | Create instance. Pass `null` seed to auto-generate identity. Port `0` for ephemeral. |
| `meshguard_destroy`        | `(ctx) → void`                      | Stop networking and free all resources.                                              |
| `meshguard_get_pubkey`     | `(ctx, out: [*]u8) → void`          | Write 32-byte Ed25519 public key.                                                    |
| `meshguard_get_pubkey_b64` | `(ctx, out: [*]u8) → void`          | Write 44-byte base64 public key + null terminator.                                   |
| `meshguard_get_seed`       | `(ctx, out: [*]u8) → void`          | Write 32-byte Ed25519 seed for secure persistence.                                   |

### Mesh Operations

| Function                                  | Returns                                       | Description                           |
| ----------------------------------------- | --------------------------------------------- | ------------------------------------- |
| `meshguard_join(ctx, seed_ip, seed_port)` | `0` success, `-1` error, `-2` already running | Join via seed peer.                   |
| `meshguard_join_lan(ctx)`                 | `0` success, `-1` error                       | Join via LAN multicast (239.99.99.1). |
| `meshguard_leave(ctx)`                    | `void`                                        | Broadcast leave and stop event loop.  |

### Messaging

| Function                                             | Returns                             | Description                                      |
| ---------------------------------------------------- | ----------------------------------- | ------------------------------------------------ |
| `meshguard_send(ctx, peer_pk, data, len)`            | `0` success, negative on error      | Send encrypted message (max 1024 bytes).         |
| `meshguard_recv(ctx, out_data, out_len, out_sender)` | `0` received, `1` empty, `-1` error | Poll inbox for next message.                     |
| `meshguard_set_on_message(ctx, callback)`            | `void`                              | Set push callback for incoming messages.         |
| `meshguard_set_on_peer_event(ctx, callback)`         | `void`                              | Set push callback for peer join (1) / leave (2). |

### Query

| Function                                | Returns     | Description                                 |
| --------------------------------------- | ----------- | ------------------------------------------- |
| `meshguard_peer_count(ctx)`             | `u32`       | Number of alive peers.                      |
| `meshguard_is_running(ctx)`             | `bool`      | Whether the event loop is active.           |
| `meshguard_get_bound_port(ctx)`         | `u16`       | Actual UDP port (useful when binding to 0). |
| `meshguard_get_peers(ctx, out, max)`    | `u32` count | Write alive peer pubkeys (32B each).        |
| `meshguard_get_peer_info(ctx, pk, out)` | `0` or `-1` | Peer endpoint, mesh IP, state, WG pubkey.   |
| `meshguard_debug_info(ctx, out)`        | `void`      | Write 30-byte diagnostic struct.            |

## App Message Wire Format (`0x50`)

Messages are encrypted end-to-end using X25519 key agreement + ChaCha20-Poly1305:

```
[1B type=0x50][32B dest_pubkey][32B sender_pubkey][12B nonce][N ciphertext][16B tag]
```

- **Key derivation**: X25519(our_private, peer_wg_pubkey) → HKDF("meshguard-app-v1") → encryption key
- **Authentication**: Sender pubkey used as additional data (AD)
- **Relay**: Intermediate peers forward messages opaquely (can't decrypt, only route by dest_pubkey)
- **Max payload**: 1024 bytes

## Design Notes

- **No root required** — the FFI library only needs UDP sockets, no TUN/netlink
- **Battery-friendly** — gossip interval is 3s (vs 1s on server), ping timeout 5s
- **Ephemeral ports** — pass port `0` to `meshguard_init` for OS-assigned port (recommended on mobile)
- **Identity persistence** — use `meshguard_get_seed` to export the 32-byte seed, store in Android Keystore, and pass back to `meshguard_init` on restart
