# Windows Support

> **Status**: Supported for userspace daemon operation with Wintun. Key management
> and `meshguard up` work on Windows; `status` and `down` are still Linux-only in
> the current CLI.

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
| `meshguard status` | Linux-only | Windows control socket plumbing exists, but the CLI command is not wired yet |
| `meshguard down` | Linux-only | Stop the running process or service manually |

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

# Cross-compile from Linux
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast

# Run tests
zig build test
```

The build system automatically copies `wintun.dll` from `deps/wintun/` alongside the binary.

## Dependencies

| Dependency | Purpose | Source |
|---|---|---|
| `wintun.dll` | TUN adapter driver | Bundled from [wintun.net](https://www.wintun.net/) |
| `ws2_32` | Winsock2 sockets | Linked by `build.zig` |
| `kernel32` | Named pipes, signals | System |
