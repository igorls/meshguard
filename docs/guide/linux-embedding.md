# Linux / FreeBSD Embedding

Any Linux or FreeBSD application or service can embed MeshGuard through its C
ABI, whatever language it is written in: C or C++, Rust, Go (cgo), Python,
C#/.NET, Dart and so on. `libmeshguard-ffi.so` is the same library that ships
for Android, macOS, iOS and Windows, with the same `meshguard_*` exports and
behaviour: SWIM discovery, pinned and opaque relays, contacts, organization
certificates (relay passes), delivery statuses, LAN discovery and userspace
WireGuard tunnels.

The library needs no root, no `CAP_NET_ADMIN` and no TUN device, and it creates
no network interface. Each context uses one UDP socket. While LAN discovery runs
(`meshguard_join_lan`), the context also uses a multicast socket on UDP port
51820.

## Packages

Every [release](https://github.com/igorls/meshguard/releases/latest) ships these
assets, listed in `checksums.txt`:

| Asset | Contents | Runs on |
|---|---|---|
| `meshguard-ffi-linux-amd64.tar.gz` | `linux-amd64/lib/libmeshguard-ffi.so`, `lib/libmeshguard-ffi.a`, `include/meshguard.h`, `LICENSE` | x86_64 Linux with glibc 2.28 or newer |
| `meshguard-ffi-linux-arm64.tar.gz` | The same layout under `linux-arm64/` | aarch64 Linux with glibc 2.28 or newer |
| `meshguard-ffi-linux-armhf.tar.gz` | The same layout under `linux-armhf/` | 32-bit ARM Linux (ARMv7-A with NEON, hard-float, such as `armhf` distributions on Raspberry Pi 2 and newer) with glibc 2.28 or newer |
| `meshguard-ffi-freebsd-amd64.tar.gz` | The same layout under `freebsd-amd64/` | x86_64 FreeBSD 14.0 or newer |

The libraries use Zig `std.crypto`, so they need no libsodium. They depend only
on the C library: `libc.so.6` and `libpthread.so.0` (plus the dynamic loader) on
Linux, `libc.so.7` and `libthr.so.3` on FreeBSD. The shared library's soname is
`libmeshguard-ffi.so`. The packages target glibc; for a musl system such as
Alpine, build from source with `-Dtarget=x86_64-linux-musl` (or
`aarch64-linux-musl`, `arm-linux-musleabihf`).

Zig has no 64-bit atomic operations on 32-bit ARM, so there the library guards
its 64-bit values (the WireGuard send counter, route statistics and the last
receive time) with a short mutex. The send counter is read and advanced as one
step under the lock and never wraps, so no nonce is ever used twice. 64-bit
builds use lock-free atomics.

## Building from source

With Zig 0.16.0 on Linux:

```bash
MESHGUARD_LIBRARY_PLATFORMS="linux freebsd" ./scripts/build-libraries.sh
./scripts/test-libraries.sh
```

Both scripts accept an optional output directory; the default is
`zig-out/libraries`. The build script cross-compiles every package, so one Linux
machine builds them all (with an Android NDK it also builds the
[Android package](/guide/android-embedding#getting-the-library)). The test script
checks that each library exports exactly the `export fn` entry points of
`src/meshguard_ffi.zig`, that `include/meshguard.h` declares them all, and that
the libraries need nothing beyond the C library. It then compiles C hosts against
the shared and static library of each package, and runs the x86_64 Linux hosts.
It also runs the 32-bit ARM hosts when `qemu-arm` and an armhf glibc are
installed (`ARMHF_SYSROOT`, by default `/usr/arm-linux-gnueabihf` from the
`libc6-armhf-cross` package). The unit tests run on 32-bit ARM the same way:

```bash
zig build test -Dtarget=arm-linux-musleabihf -Dno-sodium=true -fqemu
```

A single library for the host machine:

```bash
zig build ffi -Doptimize=ReleaseFast -Dcrypto-backend=std
# zig-out/lib/libmeshguard-ffi.so and zig-out/lib/libmeshguard-ffi.a
```

On Linux, leaving out `-Dcrypto-backend=std` links libsodium when it is
installed (AVX2-accelerated ChaCha20-Poly1305), and the library then needs
`libsodium.so` at run time.

## Linking

The public header is `include/meshguard.h`. Dynamic linking, with the library
shipped in a `lib` directory next to the executable's `bin` directory:

```bash
cc -I meshguard/include app.c -L meshguard/lib -lmeshguard-ffi \
   -Wl,-rpath,'$ORIGIN/../lib' -o bin/app
```

Or install it system-wide (`/usr/local/lib`, then `ldconfig` on Linux) and drop
the rpath. Static linking needs the thread library:

```bash
cc -I meshguard/include app.c meshguard/lib/libmeshguard-ffi.a -pthread -o app
```

How other hosts load the library:

| Host | Loading |
|---|---|
| Python | `ctypes.CDLL("/path/to/libmeshguard-ffi.so")`, with `restype = c_void_p` on the `init` functions |
| Rust | `#[link(name = "meshguard-ffi")] extern "C" { ... }` with the library on the link path, or `libloading` |
| Go | cgo: `#cgo LDFLAGS: -lmeshguard-ffi` and `#include <meshguard.h>` |
| C# / .NET | `[DllImport("meshguard-ffi")]` resolves `libmeshguard-ffi.so`. Marshal `bool` as `[MarshalAs(UnmanagedType.U1)]` |
| Dart / Flutter | `DynamicLibrary.open('libmeshguard-ffi.so')` |

## A minimal C host

```c
#include <meshguard.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    /* Load a persisted 32-byte seed instead of NULL to keep the identity. */
    meshguard_context *ctx = meshguard_init(NULL, 0);
    if (!ctx) return 1;

    /* Pin the relay before joining; its identity comes from trusted config. */
    uint8_t relay[32] = {0};
    if (meshguard_set_app_relay(ctx, relay, true) != 0) return 1;
    const char *relay_host = "relay.example.net:51821";
    if (meshguard_join_host(ctx, (const uint8_t *)relay_host) != 0) return 1;

    uint8_t data[1024], sender[32];
    uint32_t len;
    for (int i = 0; i < 600; i++) {               /* poll for 30 seconds */
        while (meshguard_recv(ctx, data, &len, sender) == 0)
            printf("message of %u bytes\n", len);
        usleep(50 * 1000);
    }
    meshguard_destroy(ctx); /* leaves, stops the event loop, frees */
    return 0;
}
```

A join result of `0` means the event loop started, not that the relay admitted
the endpoint; watch peer state or received traffic for that. A successful send
means a socket accepted the packet. The
[FFI API reference](/guide/android-embedding#ffi-api-reference),
[relays, contacts and delivery status](/guide/ios-embedding#relays-contacts-and-delivery-status),
the [buffer sizes](/guide/ios-embedding#buffer-sizes-and-diagnostics) and
[mobile app relay routing](/reference/mobile-app-relay) apply unchanged.

## Threading and polling

The model is the same on every platform:

- `meshguard_init*` creates a context and binds its UDP socket. Joining
  (`meshguard_join*`) starts one background event-loop thread for that context.
  `meshguard_leave` and `meshguard_destroy` stop that thread and wait for it.
- Call the library from any host thread, with these ordering rules:
  - Set callbacks and `meshguard_set_app_relay` before joining.
    `meshguard_set_app_relay` returns `-2` while the context runs, and the
    callback setters are not synchronized with the event loop.
  - Serialize join, leave, relay switching and destruction for a context.
  - Contacts, certificates, timers, suspend and resume can change at any time.
  - Each queue has a single consumer, so poll it from one thread at a time.
  - Call `meshguard_destroy` only after every other thread has stopped using
    the context.
- Incoming data waits in per-context queues: 64 app messages, 64 delivery
  statuses and 256 tunnel frames. Poll them with `meshguard_recv`,
  `meshguard_recv_delivery_status` and `meshguard_tunnel_recv`, which return `0`
  for an item and `1` when the queue is empty. While a queue is full, newer
  items are dropped, so poll often, for example every 20–50 ms.
- Callbacks (`meshguard_set_on_message`, `meshguard_set_on_peer_event`,
  `meshguard_set_on_delivery_status`) run on the event-loop thread. Their
  pointers are valid only during the call. Return quickly, and never call
  `meshguard_leave`, `meshguard_destroy` or `meshguard_switch_relay` for the
  same context from a callback. Message callbacks do not consume the receive
  queue, so keep draining it. Runtimes that cannot run code synchronously on a
  foreign thread should poll instead.
- Several contexts can run in one process, for example one per relay.

## Linux and FreeBSD specifics

- **Ports.** Pass `0` as `listen_port` for an ephemeral port, and read it back
  with `meshguard_get_bound_port`.
- **Firewall.** Allow inbound UDP to the bound port when peers must reach the
  host directly. Through a relay, outbound UDP is enough.
- **Identity.** Protect the 32-byte seed from `meshguard_get_seed`, for example
  in a file readable only by the service user or in the desktop keyring, and pass
  it back to `meshguard_init` on the next start.
- **Diagnostics** go to stderr. `MESHGUARD_STATS=1` adds per-second counters.
- **Unsupported.** None of the `meshguard_*` exports are. TUN devices and kernel
  WireGuard are daemon features (`meshguard up`) and are not part of the library
  on any platform.

## Testing

```bash
zig build test -Dcrypto-backend=std
zig build -Doptimize=ReleaseFast -Dcrypto-backend=std
python3 scripts/test-relay.py zig-out/bin/meshguard zig-out/libraries/linux-amd64/lib/libmeshguard-ffi.so -v
```

`scripts/test-relay.py` starts relay daemons on loopback and drives contexts
loaded from the library through relay forwarding, relay passes, opaque relays
with contacts, relay switching and tunnels, and checks that every exported
function resolves. CI runs it against the packaged x86_64 Linux library.
