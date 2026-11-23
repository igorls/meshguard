# Changelog

All notable changes to meshguard are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.10.0] — 2026-11-23

### Added
- **Embedding libraries for every platform**: release packages for Linux (amd64, arm64, armhf), FreeBSD amd64, Android (`arm64-v8a`, `armeabi-v7a`, `x86_64`, 16 KB page aligned), Windows (`meshguard-ffi.dll` + `.lib`), macOS (arm64, x86_64, universal) and an iOS device/simulator XCFramework. All of them ship the public `meshguard.h`, and Apple also ships a `MeshGuardFFI` Clang module for Swift. New guides cover Linux/FreeBSD, Android, Windows and Apple embedding.
- **Browser runtime and gateway**: `meshguard-web-<version>.tgz` (`@meshguard/web`: `meshguard.wasm`, `meshguard.mjs`, relay client, TypeScript declarations) and `meshguard-gateway-<version>.tgz` (`@meshguard/gateway`, with systemd and nginx templates) are attached as `npm pack` tarballs and listed in `checksums.txt`. They are not published to the npm registry. WASM clients can talk to native relays. New guide: *Using MeshGuard in the browser*.
- **Authenticated relay stack**: relays forward sealed `0x50`/`0x31` frames only between endpoints proven by a Noise handshake, within per-key and global budgets (`docs/reference/relay-forwarding.md`). Also new: ciphertext-only rendezvous for symmetric-NAT meshes, opaque relays (`up --opaque`), delivery status frames (`0x51`, `--no-delivery-status`), relay switching and several relays at once, and a separate ping reply budget (`--reply-pps`).
- **Signed WireGuard bindings**: every node, mobile context and browser client advertises its WireGuard key with its own Ed25519 signature (Ping/Ack extension `0x02`). Certificate v2 adds org-signed WireGuard key binding and delegation tiers. Older decoders ignore the extension.
- **Application channels and verified transfers** over the encrypted `0x50` path: `APPSEND`/`APPRECV`/`APPINFO` with isolated per-channel queues, and `XFER*` transfers of files up to 32 MiB with SHA-256 verification and resume after a receiver restart (`docs/reference/app-transfers.md`).
- Contacts and delivery status for mobile and browser clients (`meshguard_add_contact`, `meshguard_set_contacts_only`, `meshguard_send_ex`, `meshguard_set_on_delivery_status`, `meshguard_recv_delivery_status`, …).
- Trust lifecycle for relays: `SIGHUP` and the owner-only `RELOAD` command re-read `authorized_keys/`, `trusted_orgs/` and `node.cert` without a restart. Mobile contexts can install certificates at runtime (`meshguard_set_org_cert`).
- Browser gateway passes: admits browsers that hold an org certificate from `trustedOrgs`, with in-place renewal, `maxSessions`/`maxSessionsPerIp` caps and `SIGHUP` reload.
- Org certificate revocation CLI.
- `meshguard up --gossip-only` / `--no-tun` for discovery and rendezvous nodes, and macOS gossip-only relay support.
- Optional crypto backend: `-Dcrypto-backend=auto|std|sodium` and the `-Dno-sodium=true` alias. Linux desktop builds still use libsodium by default, and every other target uses Zig `std.crypto`.
- `--gossip-port` / `MESHGUARD_GOSSIP_PORT`, `--control-path` / `MESHGUARD_CONTROL_PATH`, and `meshguard_init_bind` plus `MESHGUARD_STATS=1` for the FFI.
- io_uring UDP event loop on Linux, used only where its timeouts work.
- Relay load harness (`bench/relay-load`, `zig build relay-loadgen`) and a browser load harness. Baselines are in `PERFORMANCE.md`.

### Changed
- **Breaking: Zig 0.17.0** is now required to build from source, and Zig 0.16 is no longer supported. Apple packaging uses Zig `0.18.0-dev.253+16d31ceed` for an upstream iOS fix.
- **Breaking:** `meshguard invite` requires `--seed <host:port>`, and `meshguard join` rejects tokens without a seed. There is no longer a built-in seed address.
- **Breaking:** `meshguard agent` refuses to start without `--host <pubkey>` or an explicit `--any-host`.
- **Breaking:** `meshguard up --relay` fails closed when it has no authorized keys or trusted orgs, and requires proof for all forwarding.
- **Breaking:** service policies fail closed. A malformed or unreadable policy file now stops `meshguard up` instead of running with allow-all.
- **Breaking:** on Unix, the control commands `SEND`, `RECV`, `MSGS`, `APPSEND` and `APPRECV` now require the daemon owner (same uid, or root). `STATUS`, `PEERS` and `APPINFO` stay open to every local user.
- `--name` for `trust`, `trust --org` and `org-sign` must be 1–64 characters from `[A-Za-z0-9._-]`. `org-sign --expires` rejects values it cannot parse.
- `meshguard upgrade`, `install.sh`, `install.ps1` and `dist/agent-join.sh` verify downloads against the release `checksums.txt` before installing anything.
- Relays ask for 8 MiB socket buffers, and the gateway unit allows 65,536 descriptors. Retained org revocations are re-sent every five minutes instead of every five seconds.
- Release validation checks `src/version.zig`, its semantic version components and `build.zig.zon`. The Linux ARM64 binary is built with `std.crypto`, so it needs no libsodium.
- Examples are neutral, with no hard-coded infrastructure defaults. The LAN app ID constant is renamed to `APP_ID_DEFAULT`, with the same value, so beacons stay compatible.
- CI actions are pinned to commit SHAs, and release permissions are narrowed.

### Fixed
- Idle daemons no longer keep a core busy: the io_uring UDP loop went from about 48% of a core to under 1%.
- Event loops no longer block forever in `recvfrom` on macOS/BSD/Windows once a peer is live, and control commands no longer wait out the 200 ms gossip poll.
- Hostname seeds given with `--seed` are resolved at startup even when DNS/mDNS discovery is off, so invites that carry a hostname seed can bootstrap `join`.
- WireGuard tunnels heal after a peer restarts (incarnation-based rejoin and periodic `wg_pubkey` re-advertising, #114). A daemon started at boot no longer ignores peer restarts for its first minute.
- Windows: Winsock is initialized before bind/poll, `WSAPoll` uses the correct flags, and LAN discovery sockets work (#112).
- macOS/FreeBSD interface configuration no longer fails with a false `OutOfMemory` (#113).
- `status` and `down` work through cross-platform control sockets, and configured STUN hostnames are used instead of embedded provider IPs.
- Mobile FFI initialization no longer overflows the stack on physical iPhones.
- UDP and DNS paths no longer treat raw syscall `-errno` values as lengths. Decoder and FFI receive paths tolerate truncated packets.
- WireGuard anti-replay check/update is atomic, and session expiry is honoured.

### Security
- Two adversarial hardening passes (June and November 2026) across the control plane, data plane and tooling. Highlights:
  - Gossip admission is gated by trust, and org certificates are enforced at admission. Org revocations, vouches and aliases are authenticated.
  - A WireGuard key learned from third-party gossip is installed only when it is that identity's own derived key, so one unsigned gossip entry can no longer impersonate an offline peer. Relays vouch for a key only for trusted organisations.
  - Handshake responses are authenticated before any Diffie-Hellman work. Sender indices are random, counters past `REJECT_AFTER_MESSAGES` are rejected, and pipelined encryption drops batches whose nonces came from a replaced key set (no nonce reuse).
  - Restart claims, hole-punch requests and pings from strangers are rate-limited or restricted to recorded endpoints, which blocks tunnel teardown and reflection attacks.
  - NAT traversal (STUN, UPnP, coordinated punch, SNTP, mDNS) validates its sources and bounds its deadlines.
  - Service policies walk IPv6 extension headers and never port-match IPv4 non-first fragments.
  - Local hardening: `identity.key` is created 0600 and the config dir 0700, key inputs are length-checked, and names cannot escape the config directory. On Windows, `wintun.dll` loads only from the executable's directory or System32, and the CLI refuses squatted control pipes.
  - FFI: entropy comes from the OS only, key material is wiped on destroy, and `meshguard_leave` no longer races the event loop.
- See `SECURITY.md` and `docs/networking-adversarial-review-2026-06-06.md`.

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

[Unreleased]: https://github.com/igorls/meshguard/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/igorls/meshguard/compare/v0.9.0...v0.10.0
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
