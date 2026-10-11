# Changelog

All notable changes to meshguard are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Contacts and delivery status for mobile and browser clients, needed behind
  opaque relays: `meshguard_add_contact` / `remove` / `clear` / `count`,
  `meshguard_set_contacts_only`, `meshguard_send_ex` (returns the nonce),
  `meshguard_set_on_delivery_status` (accepted only from the pinned relay for a
  recently sent frame; `handshake again` re-proves the endpoint at once), and
  `meshguard_set_keepalive_interval` / `meshguard_set_relay_proof_interval`.
  The browser client gains `addContact`, `removeContact`, `status` events and
  `send` returning the nonce.
- Opaque relays (`meshguard up --opaque`): clients stay out of the relay's
  membership and gossip, and a client's ACK describes only the relay, so no
  client learns about another; no ping-req or rendezvous on clients' behalf.
- Delivery status (`0x51`, 47 bytes): a relay answers a sealed frame it does not
  forward with why (offline, rate limited, handshake again, not admitted,
  overloaded), echoing the frame's nonce, limited per source address;
  `--no-delivery-status` turns it off.
- Browser gateway passes: the gateway admits a browser presenting a valid
  pass (organization certificate) from `trustedOrgs`, in addition to
  `allowedIdentities`; `allowedDestinations` becomes optional. Sessions end with
  `4004` when the pass expires and can renew it in place; self-advertisements
  may carry the session's own pass to the relay. New `maxSessions` and
  `maxSessionsPerIp` caps (`1013` when full) and `SIGHUP` reload.
  `gateway/pass.mjs` verifies passes against fixtures shared with the native
  code (`zig build pass-fixtures`). The browser client gains `pass`,
  `renewPass()` and jittered reconnects.
- Trust lifecycle for relays: `meshguard up --relay` fails closed when it has
  no authorized keys or trusted orgs; `SIGHUP` and the owner-only control
  command `RELOAD` re-read `authorized_keys/`, `trusted_orgs/` and `node.cert`
  without a restart and re-check relay clients; certificates tolerate five
  minutes of clock skew with their issuer. Mobile contexts install and replace
  certificates such as relay passes at any time with `meshguard_set_org_cert`
  (`meshguard_clear_org_cert`, `meshguard_get_wg_pubkey`).

- Relay load harness (`bench/relay-load`, `zig build relay-loadgen`):
  simulates thousands of mobile-style relay clients on loopback, with
  flooders, spoofers and reconnect storms, and reports loss, latency and the
  relay's CPU and memory. Baseline numbers are in `PERFORMANCE.md`; CI runs a
  small smoke scenario.
- Authenticated relay forwarding (`src/relay/core.zig`). A relay forwards
  sealed `0x50` and `0x31` frames only from an endpoint where the sender's
  signed WireGuard key is proven by a Noise handshake, only to a destination
  proven the same way, within per-key packet and byte budgets and a global
  forwarding budget that no longer shares the discovery send budget. Every
  daemon answers proof handshakes statelessly, gossip-only relays included,
  without WireGuard peer slots. `meshguard up --relay` requires proof for all
  forwarding; other daemons still forward for senders seen at their known
  endpoint; mobile contexts never forward. New `up` flags set client and
  forwarding limits, and `status` reports relay counters. See
  `docs/reference/relay-forwarding.md`.
- Signed WireGuard bindings: every node, mobile context and browser client
  advertises its WireGuard key with its own Ed25519 signature as an optional
  Ping/Ack extension (`0x02`, 97 bytes). Receivers replace a gossip-claimed key
  with the owner's signed one, certificate-bound keys keep precedence, and
  mobile clients only handshake with a pinned relay whose key is signed or
  derived from its identity. The browser gateway verifies a client's binding
  once at authentication and forwards 262-byte self-advertisements that carry
  it. Older decoders ignore the extension. See
  `docs/concepts/wire-protocol.md`.
- Verified application transfers (`XFER*` control commands, `MGXF1` frames over
  the encrypted `0x50` path): windowed, selectively acknowledged, congestion-
  controlled delivery of files up to 32 MiB with SHA-256 verification, opt-in
  receiving channels, bounded memory, and resend after a receiver restart.
  Transfer commands require the daemon owner on Unix. See
  `docs/reference/app-transfers.md`.
- Isolated application messaging channels over the existing encrypted `0x50`
  payload: `APPSEND` / `APPRECV` / `APPINFO`, `MGAPP1` framing, and per-channel
  queues so Meshrooms (`meshrooms-v1`) cannot be starved by legacy `RECV`.
- `MESHGUARD_CONTROL_PATH` honored on both daemon bind and CLI connect, plus
  `meshguard up --control-path`. Isolated candidate daemons no longer steal
  `/run/meshguard/meshguard.sock` or `\\.\pipe\meshguard`.
- Gossip/listen UDP port override via `--gossip-port` and `MESHGUARD_GOSSIP_PORT`.
  Explicit invalid values fail closed (no silent fallback to 51821).

### Changed
- Answers to pings use their own budget (`--reply-pps`, default 5,000/s) instead
  of the 500/s discovery budget. At 10,000 mobile clients pinging every 3 s only
  15% of pings were answered before; now all are.
- Retained org revocations are re-sent once every five minutes
  (`org_revoke_readvertise_interval_ms`) instead of as fresh broadcasts every
  five seconds, and revoking walks the membership once per batch of affected
  peers instead of once per peer.

### Fixed
- Event loops no longer block forever in `recvfrom` once a peer is live: UDP
  sockets are non-blocking on macOS/BSD (`fcntl`) and Windows (`FIONBIO`) as on
  Linux, with IPv4/IPv6 empty-drain regression tests. Previously the control
  socket stopped answering (`status`, `APPRECV`, …) in `--gossip-only` and TUN
  modes. (Reviewed pilot control fix, patch `c2362fe0`.)
- Control commands no longer wait out the 200 ms gossip poll: gossip-only and
  macOS loops wake on the control socket (and TUN) as well as UDP.
- `0x50` replay state is updated only after a packet authenticates, so forged
  datagrams cannot evict real nonces; transfer frames are kept out of that ring.
- Reject empty control-path overrides before startup side effects, and prevent
  explicit endpoint failures from falling back to the default kernel interface.
- Validate gossip-port overrides before creating an interface; reclaim drained
  application-channel slots and reject empty application payloads consistently.
- Preserve maximum-size JSON-escaped application messages and fragmented Unix
  responses in `apprecv`; accept valid channel names beginning with a hyphen.

## [0.10.0] — 2026-07-05

### Added
- Optional crypto backend selection with `-Dcrypto-backend=auto|std|sodium`
  and the `-Dno-sodium=true` alias. Linux desktop builds still use libsodium
  as an accelerator by default; other targets use Zig `std.crypto`.
- No-libsodium Linux CI coverage and a Linux ARM64 release artifact built with
  `std.crypto`, matching the installer-supported `meshguard-linux-arm64` asset.
- `meshguard up --gossip-only` / `--no-tun` for discovery and rendezvous nodes
  that should not create a TUN/WireGuard interface.
- FFI support for explicit local binds via `meshguard_init_bind` plus opt-in
  `MESHGUARD_STATS=1` diagnostic counters.
- io_uring UDP receive path groundwork and macOS gossip-only relay support.
- Networking adversarial review documentation for the June 2026 hardening pass.

### Changed
- Release validation now checks `src/version.zig`, semantic version constants,
  and `build.zig.zon` before publishing tag artifacts.
- Zig package paths now include the bundled Wintun files needed for Windows
  builds, along with release/security metadata.
- Linux ARM64 install no longer installs libsodium unnecessarily because the
  release artifact is built against the portable `std.crypto` backend.

### Fixed
- SWIM trust admission now rejects untrusted gossip subjects, quarantines
  gossip-discovered certificate peers, and keeps candidate probes direct-only.
- Org certificate admission and org control-plane messages are authenticated
  before they can admit, vouch, alias, or revoke peers.
- WireGuard restart healing now re-advertises peer WG keys, detects peer
  incarnation changes, and avoids spoofed restart teardown while a tunnel is
  still active.
- Lamport clocks saturate safely and remote Lamport absorption is bounded.
- WireGuard anti-replay check/update is atomic, and active tunnel checks honor
  session expiry.
- UDP and DNS paths no longer treat raw syscall `-errno` values as lengths.
- Decoder and FFI receive paths tolerate malformed or truncated packets without
  out-of-bounds reads.
- Windows sockets initialize Winsock before bind/poll and use the correct
  `WSAPoll` flags.
- macOS and FreeBSD interface configuration no longer reports false
  `OutOfMemory` failures from command execution.
- Outdated internal `.jules` prompt/journal files were removed from the
  published tree.

### Security
- Hardened the networking control plane against unauthenticated gossip
  admission, forged org revocations/vouches/aliases, replay-window races,
  packet parsing OOBs, and several DoS-prone edge cases found in the
  adversarial review.

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
