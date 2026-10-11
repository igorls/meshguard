# Windows Support

> **Status**: Supported for userspace daemon operation with Wintun. Key management
> and `meshguard up` work on Windows; `status` and `down` use the Windows named
> pipe control socket for running userspace daemons. Applications can also
> embed MeshGuard through `meshguard-ffi.dll`: see
> [Embedding MeshGuard](#embedding-meshguard-meshguard-ffi-dll).

## Install

```powershell
irm https://raw.githubusercontent.com/igorls/meshguard/main/install.ps1 | iex
```

This will:

- Download `meshguard.exe` and `wintun.dll` from the latest release
- Install to `%LOCALAPPDATA%\meshguard\`
- Add to your user PATH

::: tip Manual download
Download `meshguard-windows-amd64.exe` and `wintun.dll` from the [releases page](https://github.com/igorls/meshguard/releases/latest). Place both files in the same directory.
:::

## Quick Start

```powershell
# Generate identity (stored in %APPDATA%\meshguard\)
meshguard keygen

# Export your public key
meshguard export > my-node.pub

# Trust a peer
meshguard trust peer.pub --name my-peer

# Join the mesh (must run as Administrator)
meshguard up --seed 1.2.3.4:51821

# If the machine has a public IP, announce it
meshguard up --announce 203.0.113.42
```

::: warning Administrator Required
`meshguard up` creates a Wintun network adapter, which requires Administrator privileges. Right-click your terminal → **Run as Administrator**.
:::

## What Works

| Command | Status | Notes |
|---|---|---|
| `meshguard keygen` | ✅ | Keys stored in `%APPDATA%\meshguard\` |
| `meshguard export` | ✅ | |
| `meshguard trust` | ✅ | |
| `meshguard revoke` | ✅ | |
| `meshguard version` | ✅ | |
| `meshguard config show` | ✅ | |
| `meshguard up` | ✅ | Requires Admin + wintun.dll |
| `meshguard status` | ✅ | Queries `\\.\pipe\meshguard` while the daemon is running |
| `meshguard down` | ✅ | Requests graceful daemon shutdown through `\\.\pipe\meshguard` |

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    meshguard                          │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Identity │  │  Discovery   │  │  WireGuard     │  │
│  │ (keys,   │  │  (SWIM,      │  │  Engine        │  │
│  │  trust)  │  │   LAN, DNS)  │  │  (Noise IK,   │  │
│  │ ✅ DONE  │  │  ✅ DONE     │  │   ChaCha20)   │  │
│  └──────────┘  └──────────────┘  │  ✅ DONE      │  │
│                                   └────────────────┘  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Network │  │  TUN Device  │  │  Event Loop    │  │
│  │  (UDP)   │  │              │  │                │  │
│  │ ✅ DONE  │  │ ✅ Wintun    │  │ ✅ Single-thrd │  │
│  └──────────┘  └──────────────┘  └────────────────┘  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Control  │  │   Signals    │  │  Interface     │  │
│  │ Socket   │  │              │  │  Mgmt          │  │
│  │ ✅ Pipes │  │ ✅ CtrlHandler│ │ ✅ netsh       │  │
│  └──────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Platform Differences

| Feature | Linux | Windows |
|---|---|---|
| TUN driver | `/dev/net/tun` | Wintun (`wintun.dll`) |
| WG mode | Kernel or userspace | Userspace only |
| Crypto | libsodium (AVX2) | `std.crypto` |
| Control socket | Unix domain socket | Named pipe plumbing (`\\.\pipe\meshguard`) |
| Signal handling | `sigaction` | `SetConsoleCtrlHandler` |
| Interface config | Netlink / `ip` | `netsh` |
| Config directory | `/etc/meshguard/` or `~/.config/meshguard/` | `%APPDATA%\meshguard\` |
| Event loop | Multi-threaded (`--encrypt-workers`) | Single-threaded |

## Building from Source

```powershell
# Native Windows build
zig build -Doptimize=ReleaseFast
# → zig-out/bin/meshguard.exe + wintun.dll
# → zig-out/bin/meshguard-ffi.dll + zig-out/lib/meshguard-ffi.lib (embedding library)

# Cross-compile from Linux
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast

# Run tests (core and FFI library)
zig build test
```

The build system automatically copies `wintun.dll` from `deps/wintun/` alongside the binary.

## Dependencies

| Dependency | Purpose | Source |
|---|---|---|
| `wintun.dll` | TUN adapter driver (daemon only) | Bundled from [wintun.net](https://www.wintun.net/) |
| `ws2_32` | Winsock2 sockets | Linked by `build.zig` |
| `kernel32` | Named pipes, signals | System |

## Embedding MeshGuard (`meshguard-ffi.dll`)

Any Windows application or service can embed MeshGuard, whatever it is written
in: C or C++, C#/.NET, Python, Rust, Go, Dart/Flutter and so on.
`meshguard-ffi.dll` is the Windows build of the same C-ABI library that ships as
`libmeshguard-ffi.so` on Linux and Android and as `libmeshguard-ffi.dylib` (or
a static library) on macOS and iOS. It has the same `meshguard_*` exports and
the same behaviour: SWIM discovery, pinned and opaque relays, contacts,
organization certificates (relay passes), delivery statuses, LAN discovery and
userspace WireGuard tunnels.

The library needs neither Administrator rights nor Wintun, and it creates no
network adapter. Each context uses one UDP socket. While LAN discovery runs
(`meshguard_join_lan`), the context also uses a multicast socket on UDP port
51820.

### Getting the DLL

| Source | Files |
|---|---|
| [Release](https://github.com/igorls/meshguard/releases/latest) assets (in `checksums.txt`) | `meshguard-ffi-windows-amd64.dll`, `meshguard-ffi-windows-amd64.lib` |
| `zig build -Doptimize=ReleaseFast` on Windows | `zig-out/bin/meshguard-ffi.dll`, `zig-out/lib/meshguard-ffi.lib`, `zig-out/bin/meshguard-ffi.pdb` |
| `zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast` elsewhere | the same files |

Save the release files as `meshguard-ffi.dll` and `meshguard-ffi.lib`. The
import library refers to the DLL by that name. Hosts that load the DLL by path
at runtime can use any file name.

The DLL depends only on system libraries: `WS2_32.dll`, `KERNEL32.dll`,
`ntdll.dll` and the Universal C Runtime (`api-ms-win-crt-*`), which Windows 10
and later include. It needs no Visual C++ redistributable. Ship it next to
your executable or in a directory on the DLL search path. Releases currently
ship x86_64 (amd64) only.

### The C ABI

There is no public header yet, so declare the functions you use. The
signatures are the same on every platform:

```c
#include <stdbool.h>
#include <stdint.h>

typedef struct MeshguardContext MeshguardContext; /* opaque */

/* seed: 32 bytes, or NULL to generate an identity. port: 0 for an ephemeral port. */
MeshguardContext *meshguard_init(const uint8_t *seed, uint16_t listen_port);
void meshguard_destroy(MeshguardContext *ctx);
void meshguard_get_pubkey(MeshguardContext *ctx, uint8_t out[32]);
void meshguard_get_wg_pubkey(MeshguardContext *ctx, uint8_t out[32]);
void meshguard_get_seed(MeshguardContext *ctx, uint8_t out[32]);

/* Before joining: pin a relay identity (32 bytes) and optionally force app messages through it. */
int32_t meshguard_set_app_relay(MeshguardContext *ctx, const uint8_t *relay_pubkey, bool force);
int32_t meshguard_join(MeshguardContext *ctx, const uint8_t seed_ip[4], uint16_t seed_port);
int32_t meshguard_join_host(MeshguardContext *ctx, const char *host_and_port); /* "relay.example:51821" */
void meshguard_leave(MeshguardContext *ctx);

int32_t meshguard_add_contact(MeshguardContext *ctx, const uint8_t ed25519[32], const uint8_t wg[32]);
/* len <= 1024. Writes the frame's 12-byte nonce, which delivery statuses echo. */
int32_t meshguard_send_ex(MeshguardContext *ctx, const uint8_t peer[32], const uint8_t *data,
                          uint32_t len, uint8_t out_nonce[12]);
/* 0 = got one, 1 = queue empty, -1 = no context. out_data must hold 1024 bytes. */
int32_t meshguard_recv(MeshguardContext *ctx, uint8_t *out_data, uint32_t *out_len, uint8_t out_sender[32]);
int32_t meshguard_recv_delivery_status(MeshguardContext *ctx, uint8_t out_destination[32],
                                       uint8_t out_nonce[12], uint8_t *out_code);
```

The [FFI API reference](/guide/android-embedding#ffi-api-reference) and
[mobile app relay routing](/reference/mobile-app-relay) list every function,
return code and delivery status code. They apply unchanged on Windows.

How common hosts load the library:

| Host | Loading |
|---|---|
| C / C++ | Link `meshguard-ffi.lib`; ship `meshguard-ffi.dll` beside the executable |
| C# / .NET | `[DllImport("meshguard-ffi")]`. Marshal `bool` as `[MarshalAs(UnmanagedType.U1)]`: the ABI uses a one-byte C `bool`, not the four-byte Win32 `BOOL` |
| Python | `ctypes.CDLL(r"path\to\meshguard-ffi.dll")`, with `restype = c_void_p` on the `init` functions |
| Rust | `#[link(name = "meshguard-ffi")] extern "C" { ... }`, or `libloading` |
| Dart / Flutter | `DynamicLibrary.open('meshguard-ffi.dll')` |

On x86_64 Windows there is a single C calling convention, so no `stdcall`
annotations are needed.

### Threading and polling

The model is the same as on Android, iOS and Linux:

- `meshguard_init*` creates a context and binds its UDP socket. Joining
  (`meshguard_join*`) starts one background event-loop thread for that context.
  `meshguard_leave` and `meshguard_destroy` stop that thread and wait for it.
- Call the library from any host thread: a UI thread, a worker or a timer.
  Some calls have ordering rules:
  - Set callbacks and `meshguard_set_app_relay` before joining.
    `meshguard_set_app_relay` returns `-2` while the context runs, and the
    callback setters are not synchronized with the event loop.
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
  `meshguard_leave` or `meshguard_destroy` for the same context from a callback.
  Managed runtimes must keep the callback delegate alive while it is
  registered. Runtimes that cannot run code synchronously on a foreign thread,
  such as Dart isolates, should poll instead.

### Windows specifics

- **Ports.** Pass `0` as `listen_port`. Machines with Hyper-V, WSL or Docker
  reserve UDP port ranges (`netsh int ipv4 show excludedportrange protocol=udp`),
  and binding inside a reserved range fails with `WSAEACCES`, so
  `meshguard_init` returns `NULL` for a fixed port there. Some machines reserve
  the default gossip port 51821 and the LAN discovery port 51820. On those
  machines `meshguard_join_lan` still joins, but without LAN discovery: it logs
  `LAN discovery init failed`.
- **Winsock** is initialized by the library on first use. `WSAStartup` is
  reference-counted, and the library never calls `WSACleanup`.
- **Diagnostics** go to stderr. A GUI-subsystem application has no stderr, and
  there the library drops them. `MESHGUARD_STATS=1` adds per-second counters.
- **Firewall.** Windows Defender Firewall may ask the user to allow the host
  application the first time it receives UDP traffic from the network.
  Installers usually add an inbound rule for the application instead.
- **Identity.** Protect the 32-byte seed from `meshguard_get_seed`, for example
  with DPAPI (`CryptProtectData`) or the Credential Manager, and pass it back to
  `meshguard_init` on the next start.

### Unsupported functions

None. All `meshguard_*` exports work on Windows. The tunnel functions
(`meshguard_tunnel_open`, `_send`, `_recv`, `_close`) are userspace WireGuard
over the context's UDP socket: they need no Wintun adapter and no
Administrator rights. TUN devices and kernel WireGuard are daemon features
and are not part of the library on any platform.

### Testing

```powershell
zig build test                     # core and FFI unit tests
zig build -Doptimize=ReleaseSafe
python scripts/test-relay.py zig-out/bin/meshguard.exe zig-out/bin/meshguard-ffi.dll -v
```

`scripts/test-relay.py` starts relay daemons on loopback, reaching their
`STATUS` and `RELOAD` commands through a named pipe, and drives contexts loaded
from the DLL through these cases:

- relay forwarding and relay passes
- opaque relays with contacts, and offline delivery statuses
- switching relays
- tunnels
- a check that every exported function resolves

CI runs the same script on Windows and Linux.
