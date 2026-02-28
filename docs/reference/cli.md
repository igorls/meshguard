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

| Flag                | Default  | Description                                 |
| ------------------- | -------- | ------------------------------------------- |
| `--seed`            | _(none)_ | Seed peer `ip:port`. Can be repeated.       |
| `--dns`             | _(none)_ | Discover seeds via DNS TXT records          |
| `--mdns`            | `false`  | Discover seeds via mDNS on LAN              |
| `--announce`        | _(auto)_ | Manually specify public IP for announcement |
| `--encrypt-workers` | `0`      | Number of encryption threads (0 = serial)   |
| `--kernel`          | `false`  | Use kernel WireGuard instead of userspace   |
| `--open`            | `false`  | Accept all peers (skip trust enforcement)   |

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

## `meshguard config show`

Display the current node configuration.

```bash
meshguard config show
```

---

## `meshguard service`

Manage service access control policies (port-level allow/deny rules).

```bash
meshguard service <command> [options]
```

### Subcommands

| Subcommand              | Description                                          |
| ----------------------- | ---------------------------------------------------- |
| `list`                  | List all service policies                            |
| `allow <proto> <port>`  | Add an allow rule                                    |
| `deny <proto> <port>`   | Add a deny rule                                      |
| `default <allow\|deny>` | Set default action (when no rule matches)            |
| `show [peer-name]`      | Show effective policy for a peer (or global summary) |
| `reset`                 | Remove all service policies                          |

### Options

| Flag            | Description                                 |
| --------------- | ------------------------------------------- |
| `--peer <name>` | Target a specific peer (by alias or pubkey) |
| `--org <name>`  | Target an organization                      |
| _(no flag)_     | Target the global policy                    |

### Protocol and Port

- **Proto**: `tcp`, `udp`, or `all`
- **Port**: single port (`22`), range (`8000-9000`), or `all`

### Examples

```bash
# Global: allow SSH and HTTPS, deny everything else
meshguard service allow tcp 22
meshguard service allow tcp 443
meshguard service deny all

# Set default-deny mode (when no services/ directory exists, default is allow)
meshguard service default deny

# Peer-specific: allow Postgres for node-1
meshguard service allow --peer node-1 tcp 5432

# Org-specific: allow HTTP for all eosrio members
meshguard service allow --org eosrio tcp 80

# List all policies
meshguard service list

# Show effective policy for a peer
meshguard service show node-1

# Clear all policies
meshguard service reset
```

### Evaluation Order

Rules are evaluated in this order (first match wins):

1. Peer-specific policy (by pubkey or alias)
2. Org-specific policy (by org name)
3. Global policy (`global.policy`)
4. Default action (`services/default` file, defaults to `allow`)

---

## Environment Variables

| Variable               | Description                                                |
| ---------------------- | ---------------------------------------------------------- |
| `MESHGUARD_CONFIG_DIR` | Override config directory (default: `~/.config/meshguard`) |
