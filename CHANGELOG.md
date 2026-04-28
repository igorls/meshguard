# Changelog

All notable changes to meshguard are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] — 2026-04-28

### Added
- **IPv6 dual-stack**: deterministic ULA mesh addressing (`fd99:6d67::/64`) derived from Ed25519 public keys via Blake3. Dual-stack IPv4+IPv6 assigned to TUN interfaces on all platforms.
- **FreeBSD support**: `tun(4)` clone device with `TUNSIFHEAD` AF-family headers, `ifconfig`/`route` network configuration, poll-based event loop. Cross-compiles cleanly with `zig build -Dtarget=x86_64-freebsd`.
- IPv6 endpoint tracking in SWIM gossip protocol (`addr6` field in `Endpoint`).
- IPv6 address/route management via `rtnetlink` (Linux), `ifconfig` (macOS/FreeBSD), `netsh` (Windows).
- `SO_REUSEPORT` support on FreeBSD (BSD socket option `0x0200`).
- FreeBSD cross-compilation in build system (excluded from libsodium linkage and kernel WG interop).

### Changed
- **Zig 0.16**: full port from Zig 0.15 (`std.Io`, `std.process.spawn` API changes).
- `Endpoint` struct now carries optional `addr6` field for IPv6 peer addresses.
- `UdpSocket` extended with `bindAddr6`, `recvFrom6`, `sendTo6` for IPv6 datagram handling.
- Binary wire protocol codec updated to serialize/deserialize IPv6 addresses.
- Version management: single source of truth in `src/version.zig`, validated by release CI.
- Release workflow: 6-target matrix (linux amd64/arm64, macOS amd64/arm64, FreeBSD amd64, Windows amd64).
- CHANGELOG.md introduced (retroactive to v0.3.0).

### Fixed
- `udp.zig` `pollRead` now includes FreeBSD in the POSIX `poll()` branch (was compile error).
- `build.zig` unused `is_macos` variable removed.

## [0.8.2] — 2026-03-09

### Added
- macOS support: `utun` TUN device, `darwincfg.zig` (ifconfig/route), macOS event loop.
- iOS platform support and unified Darwin code paths.
- FFI `on_undeliverable_cb` callback for failed message delivery.

### Fixed
- **[HIGH]** Buffer overflow in network encoding due to missing bounds check (#67).
- Timing-safe comparison for security-critical paths.
- Ctrl+C exit on Windows — use non-blocking `tickTimersOnly`.
- `build.zig.zon` version corrected (was stale since initial commit).

## [0.8.1] — 2026-03-06

### Added
- Bundled `wintun.dll` with release artifacts.
- Windows install script (`install.ps1`).

## [0.8.0] — 2026-03-06

### Added
- **Full Windows support**: Wintun adapter, named pipe IPC, `netsh` network configuration, Windows event loop.
- Unix domain socket control API for `meshguard status` queries.
- Windows cross-compilation in build system (`ws2_32` linkage).

### Fixed
- Insecure key file permissions TOCTOU race (#41).
- Zero key material in KDF functions (#38).
- Securely zero transport keys on peer removal (#45).

## [0.7.0] — 2026-02-28

### Added
- **Service access control**: per-peer, per-org, and global port-level allow/deny policies (`meshguard service` CLI).
- **WireGuard tunnel FFI API**: `meshguard_tunnel_open`, `_send`, `_recv`, `_close` for encrypted audio/data channels.
- Android FFI improvements.

## [0.6.0] — 2026-02-26

### Added
- **Android FFI shared library** (`libmeshguard-ffi.so`) with C-ABI.
- **App-level encrypted messaging** (wire type `0x50`).
- **LAN multicast discovery** — no seed server required on local networks.
- **Open mode** (`--open` flag for trust-free operation).
- Compile-time AEAD backend selection (libsodium on Linux, `std.crypto` on Android).

## [0.5.0] — 2026-02-26

### Added
- **UPnP-IGD port forwarding** for consumer routers behind NAT.

## [0.4.0] — 2026-02-26

### Added
- **Coordinated punch**: token-based direct connect (`meshguard connect --generate` / `--join`).
- **`meshguard upgrade`**: self-upgrade from GitHub Releases with semver comparison.
- `meshguard status` improvements.

### Fixed
- Prevent upgrade from downgrading (semver comparison).
- systemd service uses `/etc/meshguard` for config.
- ldconfig detection broken by `pipefail` + `grep -q` SIGPIPE.

## [0.3.1] — 2026-02-24

### Added
- systemd integration and service file.

### Fixed
- `meshguard up --help` output.

## [0.3.0] — 2026-02-24

### Added
- Ed25519 keygen, save/load, sign/verify.
- Deterministic mesh IP derivation (Blake3).
- SWIM gossip protocol with Lamport clocks.
- Binary wire protocol codec.
- Kernel WireGuard via netlink (RTM_NEWLINK + Genetlink).
- Full userspace WireGuard (Noise IK, ChaCha20-Poly1305, TUN).
- STUN public endpoint discovery.
- UDP hole punching (rendezvous-mediated).
- Relay selection for symmetric NAT.
- Org trust — hierarchical PKI with org certificates.
- Deterministic mesh DNS domains (Blake3 → `*.a1b2c3.mesh`).
- Org alias system, certificate revocation, and vouch via SWIM gossip.
- `recvmmsg`/`sendmmsg` batched I/O.
- GRO/GSO via `IFF_VNET_HDR` for TUN.
- libsodium AVX2 ChaCha20-Poly1305.
- UDP GRO on control-plane socket.
- NAPI busy-poll + GRO drain loop.
- Multi-queue TUN (`IFF_MULTI_QUEUE`).
- `io_uring` TUN reader infrastructure (runtime-disabled).
- Docker + LXC benchmarking infrastructure.
- DNS / mDNS seed discovery.
- Install script (`install.sh`).
- GitHub release workflow.

[0.9.0]: https://github.com/igorls/meshguard/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/igorls/meshguard/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/igorls/meshguard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/igorls/meshguard/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/igorls/meshguard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/igorls/meshguard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/igorls/meshguard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/igorls/meshguard/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/igorls/meshguard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/igorls/meshguard/releases/tag/v0.3.0
