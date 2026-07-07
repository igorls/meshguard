# meshguard

[![CI](https://github.com/igorls/meshguard/actions/workflows/ci.yml/badge.svg)](https://github.com/igorls/meshguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Decentralized, serverless, WireGuard-compatible mesh VPN daemon written in Zig.**

meshguard builds encrypted tunnels between trusted peers without a hosted
coordination service, control plane, or central address allocator. It is designed
for validators, edge fleets, lab networks, and embedded/mobile apps that need
automatic peer discovery while keeping trust local to each node or organization.

## Contents

- [Why meshguard](#why-meshguard)
- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Trust model](#trust-model)
- [Build from source](#build-from-source)
- [Platform support](#platform-support)
- [Performance](#performance)
- [Documentation](#documentation)
- [Security](#security)
- [License](#license)

## Why meshguard

Traditional mesh VPN setups usually force one of three tradeoffs:

| Approach | Tradeoff |
| --- | --- |
| Hosted control plane | Convenient, but every node depends on a coordinator. |
| Manual WireGuard config | Decentralized, but peer management grows poorly as the mesh expands. |
| Open discovery overlay | Easy to join, but membership is not permissioned by default. |

meshguard fills the middle ground: peers discover each other automatically,
negotiate WireGuard tunnels, traverse NATs, and enforce explicit membership
without a required server.

## Features

- **Serverless discovery** using SWIM gossip, static seed peers, DNS TXT seeds,
  and LAN mDNS discovery.
- **Local trust enforcement** with per-node authorized keys, optional org-signed
  node certificates, org revocation, and org vouching for external peers.
- **WireGuard-compatible data plane** with Linux kernel mode or a portable
  userspace implementation.
- **Deterministic addressing** from node public keys: IPv4 under `10.99.0.0/16`
  and IPv6 ULA under `fd99:6d67::/64`.
- **NAT traversal** with STUN, coordinated UDP hole punching, UPnP-IGD, and
  ciphertext-only relay fallback for difficult networks.
- **Service access control** for global, per-peer, and per-org port policies.
- **Mobile and embedded FFI** for Android and iOS app-level encrypted messaging
  and tunnel data channels.
- **Portable Zig build** with optional libsodium acceleration on Linux.

## Install

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/igorls/meshguard/main/install.ps1 | iex
```

Manual release downloads are available on the
[GitHub Releases](https://github.com/igorls/meshguard/releases/latest) page.

## Quick start

On each node, generate an identity:

```bash
meshguard keygen
```

Export and exchange public keys with the peers you want to trust:

```bash
meshguard export > my-node.pub
meshguard trust /path/to/peer.pub --name validator-3
```

Start the mesh with at least one reachable seed peer:

```bash
meshguard up --seed 1.2.3.4:51821
```

Useful follow-up commands:

```bash
meshguard status
meshguard down
meshguard config show
```

Linux can use the kernel WireGuard module instead of the userspace data plane:

```bash
meshguard up --seed 1.2.3.4:51821 --kernel
```

For direct peer setup without a long-lived seed, use coordinated tokens:

```bash
meshguard connect --generate
meshguard connect --join mg://...
```

See the [getting started guide](docs/guide/getting-started.md) and
[CLI reference](docs/reference/cli.md) for the complete command surface.

## Trust model

meshguard supports individual peer trust and organization trust. They can be used
separately or together.

### Individual trust

Each node keeps trusted peer keys in its config directory:

```text
~/.config/meshguard/
├── identity.key
├── identity.pub
└── authorized_keys/
    └── validator-3.pub
```

How keys arrive there is intentionally out of scope. You can exchange them
manually, distribute them with config management, sync them from Git, or derive
them from an external registry.

### Organization trust

For fleets, an org key can sign node identities so peers only need to trust the
org once:

```bash
meshguard org-keygen
meshguard org-sign /path/to/node.pub --name node-1 --wg-pubkey /path/to/node.wg.pub
meshguard trust <org-pubkey> --org --name example-org
```

Org admins can also revoke signed nodes or vouch for standalone external nodes.
Details live in the [trust model guide](docs/guide/trust-model.md).

## Build from source

meshguard requires Zig `0.16.0` or newer.

```bash
# Debug build
zig build

# Optimized release build
zig build -Doptimize=ReleaseFast

# Run tests
zig build test
```

Cross-compile examples:

```bash
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast -Dno-sodium=true
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
zig build -Dtarget=x86_64-freebsd -Doptimize=ReleaseFast
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-linux-android -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-ios -Doptimize=ReleaseFast
```

Crypto primitives are available through Zig `std.crypto`. libsodium is an
optional Linux acceleration backend and can be disabled with `-Dno-sodium=true`
or `-Dcrypto-backend=std`.

## Platform support

| Platform | Support |
| --- | --- |
| Linux | Userspace mode by default; kernel WireGuard mode with `--kernel`; optional libsodium acceleration. |
| macOS | Userspace mode through `utun`; no kernel WireGuard mode. |
| FreeBSD | Userspace mode through `tun(4)`; no kernel WireGuard mode. |
| Windows | Userspace mode through Wintun; `meshguard up` requires Administrator privileges. |
| Android | C-ABI shared library for app embedding; no CLI TUN interface. |
| iOS | C-ABI static library for app embedding; no CLI TUN interface. |

## Performance

Current userspace Linux benchmarks report roughly **3.93 Gbps download** and
**3.94 Gbps upload** in the documented LXC localhost test setup with 8 encrypt
workers. See [PERFORMANCE.md](PERFORMANCE.md) for methodology, optimization
history, and remaining performance work.

## Documentation

- [Full documentation site](https://igorls.github.io/meshguard/)
- [Getting started](docs/guide/getting-started.md)
- [Configuration](docs/guide/configuration.md)
- [Trust model](docs/guide/trust-model.md)
- [Service access control](docs/guide/services.md)
- [Android embedding](docs/guide/android-embedding.md)
- [Architecture](docs/concepts/architecture.md)
- [Wire protocol](docs/concepts/wire-protocol.md)
- [CLI reference](docs/reference/cli.md)
- [Module map](docs/reference/modules.md)

Run the docs site locally:

```bash
cd docs
bun install
bun run docs:dev
```

## Security

Please do not open public issues for security vulnerabilities. Use the process in
[SECURITY.md](SECURITY.md), which includes GitHub Security Advisories and direct
maintainer contact guidance.

For the security model and hardening notes, see
[docs/concepts/security.md](docs/concepts/security.md).

## License

MIT. See [LICENSE](LICENSE).

"WireGuard" and the "WireGuard" logo are
[registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A.
Donenfeld. meshguard is an independent, clean-room implementation of the
[WireGuard protocol](https://www.wireguard.com/protocol/) and is not affiliated
with or endorsed by the WireGuard project.
