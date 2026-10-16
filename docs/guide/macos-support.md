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

## Embedding in a macOS application

The C ABI is also available as static and dynamic libraries for macOS 13 or
later. It embeds UDP discovery, encrypted application messages, relay routing,
contacts and userspace WireGuard data tunnels. It does not create a `utun`
interface and does not need the daemon's interface-configuration privileges.

Build and verify the Apple packages on macOS with Zig 0.17 and Xcode tools:

```bash
./scripts/build-apple.sh
./scripts/test-apple-link.sh
```

The default output is `zig-out/apple`; either script accepts an output directory
as its first argument. Each of `macos-arm64`, `macos-x86_64`, and
`macos-universal` contains `lib/libmeshguard-ffi.dylib`,
`lib/libmeshguard-ffi.a`, `include/meshguard.h`, and `include/module.modulemap`.
The universal package includes both architectures. Release archives are named
`meshguard-ffi-macos-arm64.tar.gz`, `meshguard-ffi-macos-x86_64.tar.gz`, and
`meshguard-ffi-macos-universal.tar.gz`.

For Swift, add the package's `include` directory to the compiler's import search
path and link the chosen library. The module name is `MeshGuardFFI`:

```bash
swiftc -I zig-out/apple/macos-universal/include \
  Host.swift zig-out/apple/macos-universal/lib/libmeshguard-ffi.a \
  -o meshguard-host
```

```swift
import MeshGuardFFI
```

The static library becomes part of the executable. For dynamic linking, bundle
`libmeshguard-ffi.dylib` in the app's `Contents/Frameworks`, configure the loader's
runpath for that location, and include the library in the app's signing process.
A sandboxed app needs both
[`com.apple.security.network.client`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client)
and `com.apple.security.network.server` entitlements for sending and receiving
UDP mesh traffic. On macOS 15 and later, local-network discovery also needs
`NSLocalNetworkUsageDescription` and the user's local-network permission. The
iOS multicast entitlement is not required on macOS. See Apple's
[local network privacy guidance](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

Use the [Apple embedding guide](./ios-embedding.md) for the Swift polling example,
identity persistence, relay configuration, buffer sizes, and the threading
contract. Give each context one serial host queue and each receive queue one
consumer. Copy borrowed callback buffers before dispatching; never leave,
destroy, or switch relays from an event-loop callback. Sleep, network changes,
and app lifecycle transitions can invalidate reachability, so verify traffic
after resuming instead of treating `meshguard_is_running` as connectivity proof.

## Notes

- Kernel WireGuard mode is Linux-only; macOS uses the portable userspace data plane.
- `meshguard status` and `meshguard down` use the Unix control socket while the userspace daemon is running.
- GSO/GRO and io_uring paths are Linux-specific and are not used on macOS.
- The default config directory follows the POSIX rules: `/etc/meshguard` as root, otherwise `$XDG_CONFIG_HOME/meshguard` or `~/.config/meshguard`.
