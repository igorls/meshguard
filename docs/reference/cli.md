# CLI Commands

## `meshguard keygen`

Generate a new Ed25519 identity keypair.

```bash
meshguard keygen [--force]
```

| Flag      | Description                           |
| --------- | ------------------------------------- |
| `--force` | Overwrite existing keys (destructive) |

**Output files** (in `$MESHGUARD_CONFIG_DIR`, default `~/.config/meshguard/`):

- `identity.key` — secret key (permissions `0600`)
- `identity.pub` — public key

**Safety**: Refuses to overwrite existing keys unless `--force` is passed.

---

## `meshguard export`

Print your public key to stdout.

```bash
meshguard export > my-node.pub
```

---

## `meshguard trust`

Add a peer's public key to your authorized keys.

```bash
meshguard trust <key-or-path> [--name <name>]
```

| Argument        | Description                                            |
| --------------- | ------------------------------------------------------ |
| `<key-or-path>` | Base64 public key string _or_ path to a `.pub` file    |
| `--name`        | Human-readable name (default: auto-generated from key) |

**Validation**:

- Base64 decode check
- Ed25519 point-on-curve check
- Key collision check (same key, different name)
- Name collision check (same name, different key)

---

## `meshguard revoke`

Remove a peer from your authorized keys.

```bash
meshguard revoke <name>
```

Deletes `$MESHGUARD_CONFIG_DIR/authorized_keys/<name>.pub`.

---

## `meshguard up`

Start the meshguard daemon.

```bash
meshguard up [options]
```

| Flag         | Default  | Description                                 |
| ------------ | -------- | ------------------------------------------- |
| `--seed`     | _(none)_ | Seed peer `ip:port`. Can be repeated.       |
| `--dns`      | _(none)_ | Discover seeds via DNS TXT records          |
| `--mdns`     | `false`  | Discover seeds via mDNS on LAN              |
| `--announce` | _(auto)_ | Manually specify public IP for announcement |
| `--kernel`   | `false`  | Use kernel WireGuard instead of userspace   |

**Startup sequence**:

1. Load identity from config directory
2. Derive mesh IP from public key
3. Create `mg0` interface (kernel: RTM_NEWLINK, userspace: TUN)
4. Assign mesh IP and set MTU (1420)
5. Run STUN to discover public endpoint
6. Connect to seed peers
7. Enter SWIM gossip + WireGuard event loop

---

## `meshguard down`

Stop the daemon and remove the `mg0` interface.

```bash
meshguard down
```

Uses `RTM_DELLINK` via RTNETLINK to remove the interface.

---

## `meshguard status`

Display the current mesh state.

```bash
meshguard status
```

---

## `meshguard version`

Print the version.

```bash
meshguard version
```

---

## Environment Variables

| Variable               | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| `MESHGUARD_CONFIG_DIR` | Override config directory (default: `~/.config/meshguard`) |
