# Configuration

meshguard is configured entirely through CLI flags and environment variables. There is no configuration file.

## Config Directory

meshguard does not read a monolithic configuration file. It uses CLI flags,
environment variables, and small files under the config directory. Override the
directory with the `MESHGUARD_CONFIG_DIR` environment variable:

```bash
export MESHGUARD_CONFIG_DIR=/etc/meshguard
meshguard up --seed 1.2.3.4:51821
```

Without the override, defaults are platform-specific:

| Platform / user | Default |
| ---------------- | ------- |
| Windows | `%APPDATA%\meshguard\` |
| POSIX as root | `/etc/meshguard` |
| POSIX non-root with `XDG_CONFIG_HOME` | `$XDG_CONFIG_HOME/meshguard` |
| POSIX non-root fallback | `~/.config/meshguard` |

### Directory Layout

```
$MESHGUARD_CONFIG_DIR/
├── identity.key           # Ed25519 secret key (permissions: 0600)
├── identity.pub           # Ed25519 public key
├── node.cert              # Optional org-signed node certificate
├── authorized_keys/       # Trusted peer keys
│   ├── peer-a.pub
│   └── peer-b.pub
├── trusted_orgs/          # Org trust (auto-accept org members)
│   └── eosrio.org
├── org/                   # Org admin keypair, if this node signs certs
│   ├── org.key
│   └── org.pub
├── vouched/               # Org vouches learned or created locally
├── seeds/                 # Saved peer seeds from token-based connect
└── services/              # Service access control (optional)
    ├── default            # Default action: "allow" or "deny"
    ├── global.policy      # Global rules applied to all peers
    ├── peer/              # Per-peer policies (by alias)
    │   └── node-1.policy
    └── org/               # Per-org policies
        └── eosrio.policy
```

## CLI Flags

### `meshguard up`

| Flag                | Default  | Description                                      |
| ------------------- | -------- | ------------------------------------------------ |
| `--seed`            | _(none)_ | Seed peer address (`ip:port`). Can be repeated.  |
| `--dns`             | _(none)_ | Discover seeds via DNS TXT records               |
| `--mdns`            | `false`  | Discover seeds via mDNS on LAN                   |
| `--announce`        | _(auto)_ | Manually announce this IP to peers               |
| `--kernel`          | `false`  | Use kernel WireGuard module instead of userspace |
| `--gossip-only`     | `false`  | Run discovery/rendezvous only, without TUN/WG    |
| `--no-tun`          | `false`  | Alias for `--gossip-only`                        |
| `--encrypt-workers` | `0`      | Number of encryption threads (0 = serial)        |
| `--open`            | `false`  | Accept all peers (skip trust enforcement)        |

### `meshguard keygen`

| Flag      | Default | Description                      |
| --------- | ------- | -------------------------------- |
| `--force` | `false` | Overwrite existing identity keys |

### `meshguard trust`

| Flag     | Default  | Description                      |
| -------- | -------- | -------------------------------- |
| `--name` | _(auto)_ | Human-readable name for the peer |

## Network Defaults

| Parameter         | Value          | Source             |
| ----------------- | -------------- | ------------------ |
| Gossip port       | `51821`        | `config.zig`       |
| WireGuard port    | `51830`        | `config.zig`       |
| Mesh prefix       | `10.99.0.0/16` | `wireguard/ip.zig` |
| Interface name    | `mg0`          | `wg_config.zig`    |
| MTU               | `1420`         | `tun.zig`          |
| Max peers         | `64`           | `device.zig`       |
| Suspicion timeout | `30000 ms`     | `config.zig`       |

## SWIM Protocol Defaults

| Parameter          | Value     | Description                            |
| ------------------ | --------- | -------------------------------------- |
| Protocol period    | `5000 ms` | Interval between SWIM probe rounds     |
| Suspicion timeout  | `30000 ms`| Time before suspected → dead           |
| Max gossip entries | `8`       | Gossip entries piggybacked per message |

## WireGuard Transport Defaults

| Parameter            | Value          | Description                        |
| -------------------- | -------------- | ---------------------------------- |
| Rekey after time     | `120 s`        | Handshake renewal interval         |
| Reject after time    | `180 s`        | Maximum key lifetime               |
| Keepalive timeout    | `10 s`         | Passive keepalive interval         |
| Rekey after messages | 2^60           | Message count trigger for rekeying |
| Anti-replay window   | `2048` packets | Sliding-window replay protection   |

## STUN Servers

meshguard uses built-in STUN servers for public endpoint discovery:

| Server                | Port  |
| --------------------- | ----- |
| `stun.l.google.com`   | 19302 |
| `stun.cloudflare.com` | 3478  |

The default `Config` stores these as `host:port` strings. The current runtime
path calls `nat/stun.zig`'s embedded IPv4 defaults for these services, so update
that module if the providers change addresses before a release.
