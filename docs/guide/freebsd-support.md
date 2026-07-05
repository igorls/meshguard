# FreeBSD Support

> **Status**: Supported by the source tree and release workflow for userspace mode. The release asset is `meshguard-freebsd-amd64`.

## Build

```bash
zig build -Dtarget=x86_64-freebsd -Doptimize=ReleaseFast
```

FreeBSD builds use Zig `std.crypto`; no libsodium link is required.

## Runtime Model

meshguard uses:

| Layer | FreeBSD implementation |
|---|---|
| TUN device | `tun(4)` clone device |
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

`meshguard up` needs sufficient privileges to open and configure the TUN device.

## Notes

- Kernel WireGuard mode is Linux-only; FreeBSD uses the portable userspace data plane.
- `meshguard status` and `meshguard down` use the Unix control socket while the userspace daemon is running.
- GSO/GRO and io_uring paths are Linux-specific and are not used on FreeBSD.
- The default config directory follows the POSIX rules: `/etc/meshguard` as root, otherwise `$XDG_CONFIG_HOME/meshguard` or `~/.config/meshguard`.
