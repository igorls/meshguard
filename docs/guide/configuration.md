# Configuration

meshguard is configured entirely through CLI flags and environment variables. There is no configuration file.

## Config Directory

The default config directory is `~/.config/meshguard/`. Override it with the `MESHGUARD_CONFIG_DIR` environment variable:

```bash
export MESHGUARD_CONFIG_DIR=/etc/meshguard
meshguard up --seed 1.2.3.4:51821
```

### Directory Layout

```
$MESHGUARD_CONFIG_DIR/
├── identity.key           # Ed25519 secret key (permissions: 0600)
├── identity.pub           # Ed25519 public key
└── authorized_keys/       # Trusted peer keys
    ├── peer-a.pub
    └── peer-b.pub
```

## CLI Flags

### `meshguard up`

| Flag         | Default  | Description                                      |
| ------------ | -------- | ------------------------------------------------ |
| `--seed`     | _(none)_ | Seed peer address (`ip:port`). Can be repeated.  |
| `--port`     | `51821`  | UDP port for gossip + discovery                  |
| `--wg-port`  | `51820`  | WireGuard listen port                            |
| `--announce` | _(auto)_ | Manually announce this IP to peers               |
| `--kernel`   | `false`  | Use kernel WireGuard module instead of userspace |

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
| WireGuard port    | `51820`        | `config.zig`       |
| Mesh prefix       | `10.99.0.0/16` | `wireguard/ip.zig` |
| Interface name    | `mg0`          | `wg_config.zig`    |
| MTU               | `1420`         | `tun.zig`          |
| Max peers         | `64`           | `device.zig`       |
| Suspicion timeout | `5000 ms`      | `config.zig`       |

## SWIM Protocol Defaults

| Parameter          | Value     | Description                            |
| ------------------ | --------- | -------------------------------------- |
| Protocol period    | `1000 ms` | Interval between SWIM probe rounds     |
| Suspicion timeout  | `5000 ms` | Time before suspected → dead           |
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

meshguard uses hardcoded STUN servers for public endpoint discovery:

| Server                | IP               | Port  |
| --------------------- | ---------------- | ----- |
| `stun.l.google.com`   | `74.125.250.129` | 19302 |
| `stun.cloudflare.com` | `104.18.32.7`    | 3478  |
