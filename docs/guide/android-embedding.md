# Android / Mobile Embedding

meshguard provides a **C-ABI shared library** (`libmeshguard-ffi.so`) for embedding mesh networking in mobile apps. The library exposes SWIM gossip discovery, LAN multicast, end-to-end encrypted messaging, and WireGuard-encrypted data tunnels (suitable for VoIP audio or real-time data).

## What's Included

| Feature                  | CLI (`meshguard`) | FFI (`libmeshguard-ffi.so`) |
| ------------------------ | ----------------- | --------------------------- |
| SWIM gossip discovery    | ✅                | ✅                          |
| LAN multicast discovery  | ✅                | ✅                          |
| Encrypted app messages   | ✅                | ✅                          |
| Peer events (join/leave) | ✅                | ✅                          |
| WireGuard data tunnels   | ✅ (TUN)          | ✅ (ring buffer)            |
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

### 4. WireGuard tunnel for audio calling

The FFI library provides WireGuard-encrypted data tunnels suitable for VoIP audio or real-time data. Tunnel data is delivered via an in-process ring buffer — no TUN device or root required.

```kotlin
// In MeshGuardFFI object, add tunnel declarations:
object MeshGuardFFI {
    // ... existing declarations ...

    // Tunnels (WireGuard-encrypted data channels)
    external fun meshguard_tunnel_open(ctx: Long, peerPubkey: ByteArray): Int
    external fun meshguard_tunnel_send(ctx: Long, peerPubkey: ByteArray, data: ByteArray, len: Int): Int
    external fun meshguard_tunnel_recv(ctx: Long, outData: ByteArray, outLen: IntArray, outSender: ByteArray): Int
    external fun meshguard_tunnel_close(ctx: Long, peerPubkey: ByteArray)
}
```

**Usage**:

```kotlin
// Open a WireGuard tunnel to a peer (initiates Noise IK handshake)
val result = MeshGuardFFI.meshguard_tunnel_open(ctx, peerPubkey)
if (result == 0) {
    // Send audio frame through encrypted tunnel
    val opusFrame = encodeAudio() // e.g., Opus-encoded audio
    MeshGuardFFI.meshguard_tunnel_send(ctx, peerPubkey, opusFrame, opusFrame.size)

    // Receive from tunnel (poll in a separate thread)
    val buf = ByteArray(1500)
    val len = IntArray(1)
    val sender = ByteArray(32)
    while (MeshGuardFFI.meshguard_tunnel_recv(ctx, buf, len, sender) == 0) {
        val audioData = buf.copyOf(len[0])
        playAudio(audioData)
    }
}

// Close the tunnel when done
MeshGuardFFI.meshguard_tunnel_close(ctx, peerPubkey)
```

**Tunnel error codes** (`meshguard_tunnel_open`):

| Code | Meaning                      |
| ---- | ---------------------------- |
| `0`  | Success                      |
| `-2` | Not running                  |
| `-3` | Peer not found in membership |
| `-4` | Peer has no WG public key    |
| `-5` | Peer has no endpoint         |
| `-6` | Peer table full              |
| `-7` | Handshake failed             |
| `-8` | Send failed                  |

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

### Tunnel Operations

| Function                                                | Returns                             | Description                                          |
| ------------------------------------------------------- | ----------------------------------- | ---------------------------------------------------- |
| `meshguard_tunnel_open(ctx, peer_pk)`                   | `0` success, negative on error      | Open WG tunnel (Noise IK handshake + key exchange).  |
| `meshguard_tunnel_send(ctx, peer_pk, data, len)`        | `0` success, negative on error      | Send data through encrypted tunnel (max 1400 bytes). |
| `meshguard_tunnel_recv(ctx, out_data, out_len, out_pk)` | `0` received, `1` empty, `-1` error | Poll tunnel inbox for next decrypted message.        |
| `meshguard_tunnel_close(ctx, peer_pk)`                  | `void`                              | Close a tunnel, remove peer from WG device.          |

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
- **Tunnel ring buffer** — the tunnel inbox holds 256 messages (1500 bytes each). At 50 fps audio (20ms frames), this gives ~5 seconds of buffer before dropping. Poll `meshguard_tunnel_recv` from a dedicated thread.
