# macOS Support — Developer Guide

> **Status**: Not yet started. Estimated effort: **moderate** — macOS is POSIX-compatible, but uses `utun` instead of `/dev/net/tun` and `route`/`ifconfig` instead of netlink.

## Compatibility Assessment

macOS shares most of Linux's POSIX API surface. The gap is much smaller than Windows:

| Layer                  | Linux                            | macOS                          | Effort               |
| ---------------------- | -------------------------------- | ------------------------------ | -------------------- |
| Identity (keys, trust) | ✅ works                         | ✅ works as-is                 | None                 |
| WireGuard Noise engine | ✅ works                         | ✅ works as-is                 | None                 |
| AEAD crypto            | libsodium (AVX2)                 | `std.crypto` (no libsodium)    | ✅ Already handled   |
| UDP sockets            | POSIX `socket()`                 | POSIX `socket()`               | None                 |
| `poll()`               | POSIX `poll()`                   | POSIX `poll()`                 | None                 |
| Unix domain sockets    | `AF_UNIX`                        | `AF_UNIX`                      | None                 |
| Signal handling        | `sigaction`                      | `sigaction`                    | None                 |
| **TUN device**         | `/dev/net/tun` + `ioctl`         | `utun` via `socket(PF_SYSTEM)` | **Rewrite**          |
| **Interface mgmt**     | Netlink (`RTM_*`)                | `ifconfig` / `route` / `ioctl` | **Rewrite**          |
| **GSO/GRO offloads**   | `IFF_VNET_HDR` + `TUNSETOFFLOAD` | Not available                  | Skip                 |
| **io_uring**           | Kernel 5.1+                      | Not available                  | Fallback to `poll()` |
| `chmod`                | POSIX                            | POSIX                          | None                 |

**Bottom line**: Only **2 modules** need platform-specific code: TUN device and interface management. Everything else works unchanged.

## What Needs to Be Done

### Phase 1: AEAD Backend (Already Done)

The `use_libsodium` flag already handles this:

```zig
// src/wireguard/tunnel.zig
const use_libsodium = (builtin.os.tag == .linux and builtin.target.abi != .android);
```

For macOS, this evaluates to `false` → uses `std.crypto.aead.chacha_poly.ChaCha20Poly1305`. No changes needed.

### Phase 2: utun Device

**Priority: HIGHEST** — main blocker for the daemon.

**Location**: Create `src/net/utun.zig`

macOS uses the `utun` kernel interface (same as WireGuard-Go and the official WireGuard macOS client):

```zig
// Pseudocode for utun creation
const PF_SYSTEM = 32;
const AF_SYS_CONTROL = 2;
const SYSPROTO_CONTROL = 2;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

pub fn open() !UtunDevice {
    // 1. Create a PF_SYSTEM socket
    const fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    // 2. Look up the utun control ID
    var info = ctl_info{ .ctl_name = UTUN_CONTROL_NAME };
    ioctl(fd, CTLIOCGINFO, &info);

    // 3. Connect with the unit number to create utunN
    var addr = sockaddr_ctl{
        .sc_id = info.ctl_id,
        .sc_unit = 0,          // 0 = auto-assign (utun0, utun1, ...)
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
    };
    connect(fd, &addr, sizeof(addr));

    // fd is now a utun device — read/write IP packets
    return .{ .fd = fd, .unit = addr.sc_unit - 1 };
}
```

**Key differences from Linux TUN**:

| Aspect        | Linux `/dev/net/tun`                        | macOS `utun`                                      |
| ------------- | ------------------------------------------- | ------------------------------------------------- |
| Open          | `open("/dev/net/tun")` + `ioctl(TUNSETIFF)` | `socket(PF_SYSTEM)` + `connect()`                 |
| Packet format | Raw IP (with `IFF_NO_PI`)                   | **4-byte AF header** + IP payload                 |
| Read          | `read(fd, buf)` → IP packet                 | `read(fd, buf)` → `[AF_INET/AF_INET6][IP packet]` |
| Write         | `write(fd, ip_packet)`                      | `write(fd, [AF_header][ip_packet])`               |
| Name          | Configurable (`mg0`)                        | Kernel-assigned (`utunN`)                         |
| GSO/GRO       | Supported via `IFF_VNET_HDR`                | **Not available**                                 |
| Multi-queue   | `IFF_MULTI_QUEUE`                           | **Not available**                                 |

**Critical**: macOS utun prepends a 4-byte protocol family header (`AF_INET = 2` for IPv4, `AF_INET6 = 30` for IPv6). You must:

- **Read**: Skip the first 4 bytes to get the IP packet
- **Write**: Prepend `[0, 0, 0, 2]` (AF_INET) before the IP packet

### Phase 3: Interface Configuration

**Location**: `src/wireguard/wg_config.zig` — add macOS branch

Replace netlink (`RTM_*`) calls with BSD equivalents:

| Operation        | Linux (netlink)          | macOS                                                                                |
| ---------------- | ------------------------ | ------------------------------------------------------------------------------------ |
| Create interface | `RTM_NEWLINK`            | utun creates it automatically                                                        |
| Assign IP        | `RTM_NEWADDR`            | `ifconfig utunN 10.99.X.Y 10.99.X.Y netmask 255.255.255.255` or `ioctl(SIOCSIFADDR)` |
| Set MTU          | `RTM_NEWLINK`            | `ifconfig utunN mtu 1420` or `ioctl(SIOCSIFMTU)`                                     |
| Add route        | `RTM_NEWROUTE`           | `route add -net 10.99.0.0/16 -interface utunN`                                       |
| Delete interface | `RTM_DELLINK`            | Closing the utun socket destroys the interface                                       |
| Bring up         | `RTM_NEWLINK` + `IFF_UP` | `ifconfig utunN up`                                                                  |

**Recommended approach**: Use `std.process.Child` to shell out to `ifconfig` and `route` for simplicity (same as WireGuard-Go on macOS), or use `ioctl(SIOCSIFADDR)` for a no-fork implementation.

### Phase 4: GSO/GRO — Skip

macOS utun does not support GSO offloads. The codebase already handles this gracefully — `vnet_hdr = false` disables all GSO paths and falls back to single-packet read/write. No changes needed.

### Phase 5: io_uring — Skip

The `io_uring` TUN reader is Linux-only and gated by comptime. macOS will use the standard `poll()` path, which is already the default fallback. No changes needed.

### Phase 6: Kernel WireGuard — Skip

macOS has no kernel WireGuard module. The `--kernel` flag already exits with an error on non-Linux. Userspace mode is the only option (same as Android).

## Files to Create / Modify

| File                          | Action  | Purpose                                                                            |
| ----------------------------- | ------- | ---------------------------------------------------------------------------------- |
| `src/net/utun.zig`            | **NEW** | macOS utun device wrapper                                                          |
| `src/net/tun.zig`             | MODIFY  | Add comptime switch: Linux → TunDevice, macOS → UtunDevice                         |
| `src/wireguard/wg_config.zig` | MODIFY  | Add macOS branch for IP/route config                                               |
| `src/main.zig`                | MODIFY  | Change `os.tag == .linux` guards to `os.tag == .linux or .macos` where appropriate |
| `build.zig`                   | MODIFY  | macOS target support, skip libsodium                                               |

## Guard Pattern Changes

Most current guards check `os.tag == .linux` or `os.tag != .linux`. For macOS, many of these should become:

```zig
// Before (Linux-only):
if (comptime builtin.os.tag == .linux) { ... }

// After (POSIX — Linux + macOS):
const is_posix = builtin.os.tag == .linux or builtin.os.tag == .macos;
if (comptime is_posix) { ... }
```

Specifically:

- **Signal handling** (`sigaction`) → works on macOS, change guard to `is_posix`
- **chmod** → works on macOS, already correct (`!= .windows`)
- **Control socket** (`AF_UNIX`) → works on macOS, change guard to `!= .windows`
- **libsodium init** → keep Linux-only (macOS uses `std.crypto`)
- **Netlink calls** → keep Linux-only (macOS uses ifconfig/route)
- **TUN** → new macOS-specific utun code

## Cross-compilation

```bash
# macOS x86_64
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# macOS Apple Silicon
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
```

## Testing on macOS

```bash
# CLI commands (should work immediately after guard changes):
./meshguard keygen
./meshguard export
./meshguard trust <key>

# Daemon (after utun + ifconfig implementation):
sudo ./meshguard up --seed 1.2.3.4:51821
# → Creates utunN interface, assigns 10.99.X.Y, starts SWIM
```

> **Note**: macOS requires `sudo` for utun creation (no `CAP_NET_ADMIN` equivalent). Alternatively, the binary can be code-signed with the `com.apple.developer.networking.networkextension` entitlement for rootless operation.

## Estimated Effort

| Task                              | Lines    | Difficulty                                |
| --------------------------------- | -------- | ----------------------------------------- |
| `utun.zig` (TUN wrapper)          | ~120     | Medium — BSD socket API, 4-byte AF header |
| Interface config (ifconfig/route) | ~80      | Easy — shell out or ioctl                 |
| Guard changes in `main.zig`       | ~30      | Easy — `== .linux` → `is_posix`           |
| Build system                      | ~10      | Easy                                      |
| **Total**                         | **~240** | **2-3 days**                              |
