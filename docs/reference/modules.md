# Module Map

Reference map of all source modules and their responsibilities.

## Top-Level

| File                | Purpose                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `main.zig`          | CLI entry point, command dispatch, daemon event loop             |
| `lib.zig`           | Library root — re-exports all modules for embedders              |
| `config.zig`        | Configuration struct with network, discovery, and trust defaults |
| `meshguard_ffi.zig` | C-ABI FFI surface for mobile embedding (Android JNI)             |

## `identity/`

| File        | Purpose                                                      |
| ----------- | ------------------------------------------------------------ |
| `keys.zig`  | Ed25519 keypair generation, save/load, sign/verify           |
| `trust.zig` | `authorized_keys/` management, key validation, authorization |

## `discovery/`

| File             | Purpose                                                                                                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------- |
| `swim.zig`       | SWIM protocol engine: ping/ack loop, gossip propagation, handshake coordination, hole punch triggers          |
| `membership.zig` | Membership table: peer states (alive/suspected/dead), Lamport clocks, suspicion expiry, random peer selection |
| `seed.zig`       | Seed peer resolution: static IP parsing, DNS/mDNS placeholders                                                |
| `lan.zig`        | LAN multicast discovery: UDP beacon broadcast/receive on `239.99.99.1`, app ID filtering                      |

## `wireguard/`

| File            | Purpose                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `noise.zig`     | Noise_IKpsk2 handshake: initiation, response, key derivation, `decryptInitiatorStatic` for O(1) routing                |
| `device.zig`    | `WgDevice` peer manager: `IndexTable` (Fibonacci hash), `StaticKeyTable`, handshake handling, encrypt/decrypt dispatch |
| `tunnel.zig`    | Transport layer: ChaCha20-Poly1305 encrypt/decrypt, `ReplayWindow` (2048-bit sliding window), rekey/keepalive timers   |
| `ip.zig`        | Mesh IP derivation: Blake3(pubkey) → `10.99.X.Y`, IP formatting/parsing                                                |
| `crypto.zig`    | HMAC-Blake2s via `std.crypto.auth.hmac`, HKDF (kdf1/kdf2/kdf3), `mixHash`                                              |
| `wg_config.zig` | Kernel WireGuard setup: configure peers/keys via Genetlink socket                                                      |
| `netlink.zig`   | Genetlink (WG_USERSPACE) socket abstraction                                                                            |
| `nlsocket.zig`  | Raw netlink socket: send/recv, message builder, attribute helpers                                                      |
| `rtnetlink.zig` | RTNETLINK operations: interface create/delete, IP address assignment, route addition, interface up/down                |

## `nat/`

| File                    | Purpose                                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `stun.zig`              | STUN client (RFC 5389): Binding Request/Response encoding, XOR-MAPPED-ADDRESS parsing, NAT type detection              |
| `holepunch.zig`         | UDP hole punching: `Holepuncher` state machine, probe magic (`MGHP`), rendezvous-mediated exchange, 4 concurrent slots |
| `relay.zig`             | Relay selection: best public-IP peer by RTT, capacity checking, `RelayInfo` struct                                     |
| `upnp.zig`              | UPnP-IGD port forwarding: SSDP discovery, SOAP AddPortMapping, lease renewal                                           |
| `coordinated_punch.zig` | Token-based coordinated punch: `meshguard connect` token exchange for direct peer setup                                |

## `protocol/`

| File           | Purpose                                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `messages.zig` | Wire message type definitions: `Ping`, `Ack`, `PingReq`, `HandshakeInit/Resp`, `GossipEntry`, `HolepunchRequest/Response`, `NatType`, `Endpoint` |
| `codec.zig`    | Binary codec: encode/decode for all message types, gossip entry serialization (89 bytes each)                                                    |

## `net/`

| File      | Purpose                                                                            |
| --------- | ---------------------------------------------------------------------------------- |
| `udp.zig` | Non-blocking UDP socket: bind, `sendTo`, `recvFrom`, `pollRead`                    |
| `tun.zig` | Linux TUN device: open, read/write packets, `setMtu`, `setNonBlocking`, `pollRead` |
| `io.zig`  | Event loop placeholder (Phase 2: epoll/io_uring)                                   |

## `docker/`

| File                | Purpose                                                                |
| ------------------- | ---------------------------------------------------------------------- |
| `entrypoint.sh`     | Container entrypoint for Docker-based deployments                      |
| `bench.sh`          | Basic Docker-based benchmark (kernel vs userspace)                     |
| `test-mesh.sh`      | Docker-compose mesh connectivity test                                  |
| `lxc-bench.sh`      | 2-way LXC benchmark (kernel vs meshguard)                              |
| `lxc-4way-bench.sh` | 4-way LXC benchmark (kernel vs meshguard vs wireguard-go vs boringtun) |
