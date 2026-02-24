# Getting Started

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/install.sh | bash
```

This will:

- Detect your architecture (x86_64 / arm64)
- Install **libsodium** if not present
- Download the latest release from [GitHub Releases](https://github.com/igorls/meshguard/releases/latest)
- Install to `/usr/local/bin/meshguard`

::: tip Manual download
You can also download binaries directly from the [releases page](https://github.com/igorls/meshguard/releases/latest).
:::

## Building from source

Alternatively, build from source with [Zig](https://ziglang.org/download/) 0.15+:

| Requirement     | Details                                          |
| --------------- | ------------------------------------------------ |
| **Zig**         | 0.15 or later                                    |
| **libsodium**   | `libsodium-dev` for building                     |
| **OS**          | Linux (kernel WireGuard module _or_ TUN support) |
| **Permissions** | `sudo` or `CAP_NET_ADMIN` for interface creation |

```bash
# Debug build
zig build

# Optimized static binary
zig build -Doptimize=ReleaseFast

# Cross-compile for aarch64
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast

# Run test suite
zig build test
```

The output binary is placed at `zig-out/bin/meshguard`.

## Quick Start

### 1. Generate an identity

Every meshguard node needs an Ed25519 keypair. Generate one:

```bash
meshguard keygen
```

This creates two files in `~/.config/meshguard/`:

| File           | Contents                                 |
| -------------- | ---------------------------------------- |
| `identity.key` | Base64-encoded Ed25519 secret key (0600) |
| `identity.pub` | Base64-encoded Ed25519 public key        |

::: tip
Running `keygen` again will **not** overwrite existing keys. Use `--force` to regenerate:

```bash
meshguard keygen --force
```

:::

### 2. Export your public key

```bash
meshguard export > my-node.pub
```

Share `my-node.pub` with every node that should trust you.

### 3. Trust a peer

```bash
# From a .pub file
meshguard trust /path/to/peer.pub

# From a raw base64 key
meshguard trust "dGhpcyBpcyBhIHNhbXBsZSBrZXkgZm9yIGRvYw=="

# With a human-readable label
meshguard trust /path/to/peer.pub --name validator-3
```

The key is stored in `~/.config/meshguard/authorized_keys/<name>.pub`.

### 4. Join the mesh

```bash
# With at least one seed peer
meshguard up --seed 1.2.3.4:51821

# Multiple seeds
meshguard up --seed 1.2.3.4:51821 --seed 5.6.7.8:51821

# With a manually announced public IP
meshguard up --seed 1.2.3.4:51821 --announce 203.0.113.42

# Kernel WireGuard mode (default is userspace)
meshguard up --seed 1.2.3.4:51821 --kernel
```

meshguard will:

1. Load your identity from `~/.config/meshguard/`
2. Derive your deterministic mesh IP (`10.99.X.Y`)
3. Create the `mg0` WireGuard interface
4. Run STUN to discover your public endpoint
5. Begin gossiping with seed peers via the SWIM protocol
6. Automatically configure WireGuard tunnels as peers are discovered

### 5. Stop the daemon

```bash
meshguard down
```

This tears down the `mg0` interface.

### 6. Check status

```bash
meshguard status
```

## Docker

A `docker-compose.yml` file is provided specifically for **performance benchmarking** and testing the multi-node mesh locally. It is not intended for production daemon deployments.

```bash
docker compose up
```

See `docker-compose.yml` for the benchmark topology configuration.

## Run as a service

The installer automatically sets up a systemd service. To use it:

```bash
# Configure seed peers
sudo vi /etc/default/meshguard

# Enable and start
sudo systemctl enable meshguard
sudo systemctl start meshguard

# View logs
sudo journalctl -u meshguard -f
```

Edit `/etc/default/meshguard` to set your options:

```bash
# Seed peers and flags
MESHGUARD_OPTS="--seed 1.2.3.4:51821"
```
