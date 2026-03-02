# Windows Support — Developer Guide

> **Status**: Phase 1 complete (compilation + CLI commands). Daemon runtime not yet functional.

## What Works on Windows Today

The codebase compiles for `x86_64-windows` and the following commands work:

| Command                 | Status   | Notes                                                       |
| ----------------------- | -------- | ----------------------------------------------------------- |
| `meshguard keygen`      | ✅       | chmod skipped via comptime guard                            |
| `meshguard export`      | ✅       |                                                             |
| `meshguard trust`       | ✅       |                                                             |
| `meshguard revoke`      | ✅       |                                                             |
| `meshguard version`     | ✅       |                                                             |
| `meshguard config show` | ✅       |                                                             |
| `meshguard up`          | ❌ exits | "userspace WG mode requires Linux (TUN device + rtnetlink)" |
| `meshguard down`        | ❌ exits | "only supported on Linux (requires netlink)"                |
| `meshguard status`      | ❌ exits | "only supported on Linux (requires netlink)"                |

## Cross-compilation

```bash
# Windows x86_64
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast

# The build system already handles:
#   - Excludes libsodium linking (uses std.crypto)
#   - Links ws2_32 for Winsock
#   - Skips TUN-related modules
```

## Architecture Overview

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
│  │ ✅ DONE  │  │ ❌ WINTUN    │  │ ❌ IOCP/poll   │  │
│  └──────────┘  └──────────────┘  └────────────────┘  │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Control  │  │   Signals    │  │  Interface     │  │
│  │ Socket   │  │              │  │  Mgmt          │  │
│  │ ❌ Pipes │  │ ❌ CtrlHandler│ │ ❌ No netlink  │  │
│  └──────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## What Needs to Be Done

### Phase 2: TUN Device (Wintun)

**Priority: HIGHEST** — This is the main blocker for the daemon.

**Location**: Create `src/net/wintun.zig`

Wintun is a lightweight TUN driver for Windows (used by the official WireGuard Windows client). It provides a userspace API via a DLL.

**Steps**:

1. Download `wintun.dll` from https://www.wintun.net and include in the repo or document download
2. Implement `WintunDevice` struct matching the `TunDevice` API surface:
   - `init() → WintunDevice` — call `WintunCreateAdapter`, `WintunStartSession`
   - `read(buf) → []u8` — call `WintunReceivePacket`, copy, `WintunReleaseReceivePacket`
   - `write(data)` — call `WintunAllocateSendPacket`, copy, `WintunSendPacket`
   - `close()` — call `WintunEndSession`, `WintunCloseAdapter`
3. Use `@import("builtin").os.tag == .windows` to switch between `TunDevice` and `WintunDevice`
4. Assign mesh IP on the Wintun adapter via `netsh` or Windows API

**Wintun API** (loaded dynamically from `wintun.dll`):

```
WintunCreateAdapter(name, tunnel_type) → ADAPTER
WintunCloseAdapter(adapter)
WintunStartSession(adapter, capacity) → SESSION
WintunEndSession(session)
WintunReceivePacket(session, *size) → *packet
WintunReleaseReceivePacket(session, packet)
WintunAllocateSendPacket(session, size) → *packet
WintunSendPacket(session, packet)
```

**Reference**: [wintun.h](https://git.zx2c4.com/wintun/tree/api/wintun.h)

### Phase 3: Event Loop

**Location**: `src/main.zig` — `userspaceEventLoop` function (line ~2466)

The current event loop uses `poll()` on three file descriptors (gossip UDP, TUN, signal pipe). Windows alternatives:

| Linux                | Windows                                       | Notes                            |
| -------------------- | --------------------------------------------- | -------------------------------- |
| `poll()` on TUN fd   | `WintunReceivePacket` (blocking with timeout) | Or use a reader thread           |
| `poll()` on UDP fd   | `WSAPoll()`                                   | Already implemented in `udp.zig` |
| Signal pipe          | `SetConsoleCtrlHandler` callback              | Set a global atomic flag         |
| `fcntl` non-blocking | `ioctlsocket(FIONBIO)`                        | Already in `udp.zig`             |

**Recommended approach**: Dual-thread architecture

- **Thread 1**: Wintun read loop → feed packets to WgDevice
- **Thread 2**: UDP poll loop (gossip + WG handshakes) — reuse existing `userspaceEventLoop` structure with `WSAPoll`

### Phase 4: Interface Management

**Location**: `src/wireguard/wg_config.zig` (currently Linux netlink only)

Replace netlink calls with Windows equivalents:

| Operation        | Linux          | Windows                                                           |
| ---------------- | -------------- | ----------------------------------------------------------------- |
| Create interface | `RTM_NEWLINK`  | Wintun creates the adapter                                        |
| Assign IP        | `RTM_NEWADDR`  | `netsh interface ip set address` or `CreateUnicastIpAddressEntry` |
| Set MTU          | `RTM_NEWLINK`  | `netsh interface ipv4 set subinterface`                           |
| Delete interface | `RTM_DELLINK`  | `WintunCloseAdapter`                                              |
| Add route        | `RTM_NEWROUTE` | `CreateIpForwardEntry2`                                           |

### Phase 5: Signal Handling

**Location**: `src/main.zig` — `installSignalHandler` (line ~1436)

```zig
if (comptime builtin.os.tag == .windows) {
    // Use SetConsoleCtrlHandler for Ctrl+C / service stop
    const kernel32 = std.os.windows.kernel32;
    _ = kernel32.SetConsoleCtrlHandler(&windowsCtrlHandler, 1);
}

fn windowsCtrlHandler(ctrl_type: u32) callconv(.C) c_int {
    if (ctrl_type == 0 or ctrl_type == 2) { // CTRL_C or CTRL_CLOSE
        if (g_swim_stop) |swim| swim.stop();
        return 1; // Handled
    }
    return 0;
}
```

### Phase 6: Control Socket

**Location**: `src/services/control.zig`

Unix domain sockets → Windows Named Pipes:

| Linux                 | Windows                                  |
| --------------------- | ---------------------------------------- |
| `AF_UNIX` socket      | `CreateNamedPipe` (`\\.\pipe\meshguard`) |
| `accept()` + `read()` | `ConnectNamedPipe` + `ReadFile`          |
| `write()`             | `WriteFile`                              |

The control socket already has `comptime` guard — listen() is a no-op on Windows.

## Comptime Guards Reference

All POSIX-only code is already guarded. Search for these patterns:

```zig
// Guard pattern (blocks on non-Linux):
if (comptime @import("builtin").os.tag != .linux) {
    try stderr.writeAll("error: ...\n");
    std.process.exit(1);
}

// Guard pattern (skips on Windows):
if (comptime @import("builtin").os.tag == .linux) {
    // Linux-only code
}

// Guard pattern (skips chmod on Windows):
if (comptime @import("builtin").os.tag != .windows) {
    try sk_file.chmod(0o600);
}
```

## Files to Create / Modify

| File                          | Action  | Purpose                                                   |
| ----------------------------- | ------- | --------------------------------------------------------- |
| `src/net/wintun.zig`          | **NEW** | Wintun adapter wrapper                                    |
| `src/main.zig`                | MODIFY  | Windows event loop branch, signal handler, interface name |
| `src/wireguard/wg_config.zig` | MODIFY  | Windows IP/route configuration                            |
| `src/services/control.zig`    | MODIFY  | Named pipe implementation                                 |
| `build.zig`                   | MODIFY  | Bundle `wintun.dll`, add Windows-specific link flags      |

## Testing on Windows

```powershell
# Build on Linux, copy to Windows:
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast
# → zig-out/bin/meshguard.exe

# Test CLI commands (should work today):
.\meshguard.exe keygen
.\meshguard.exe export
.\meshguard.exe trust <key>

# Test daemon (blocked on wintun):
.\meshguard.exe up --seed 1.2.3.4:51821
# → "error: userspace WireGuard mode requires Linux"
```

## Dependencies

| Dependency | Linux                 | Windows                       |
| ---------- | --------------------- | ----------------------------- |
| libsodium  | Required (AVX2 accel) | Not used (`std.crypto`)       |
| Wintun     | N/A                   | Required for TUN              |
| ws2_32     | N/A                   | Already linked in `build.zig` |
| kernel32   | N/A                   | For `SetConsoleCtrlHandler`   |
