# macOS Support

> **Status**: Supported by the source tree and release workflow for userspace mode. The release assets are `meshguard-macos-amd64` and `meshguard-macos-arm64`.

## Build

```bash
# Intel Macs
zig build -Dtarget=x86_64-macos -Doptimize=ReleaseFast

# Apple Silicon
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
```

macOS builds use Zig `std.crypto`; no libsodium link is required.

## Runtime Model

meshguard uses:

| Layer | macOS implementation |
|---|---|
| TUN device | `utun` via `PF_SYSTEM` |
| Interface config | `ifconfig` / `route` |
| Event loop | POSIX `poll()` |
| WireGuard mode | Userspace only |
| Crypto backend | `std.crypto` |

## Quick Start

```bash
meshguard keygen
meshguard export > my-node.pub
meshguard trust /path/to/peer.pub --name peer-1
sudo meshguard up --seed 1.2.3.4:51821
```

`meshguard up` needs privileges to create and configure the `utun` interface.

## Gossip-only Relay Mode

For nodes that should participate in discovery and NAT rendezvous without
creating a TUN/WireGuard interface:

```bash
meshguard up --gossip-only --seed 1.2.3.4:51821
# --no-tun is an alias
```

## Notes

- Kernel WireGuard mode is Linux-only; macOS uses the portable userspace data plane.
- GSO/GRO and io_uring paths are Linux-specific and are not used on macOS.
- The default config directory follows the POSIX rules: `/etc/meshguard` as root, otherwise `$XDG_CONFIG_HOME/meshguard` or `~/.config/meshguard`.
