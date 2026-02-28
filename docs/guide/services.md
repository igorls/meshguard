# Service Access Control

meshguard supports granular, port-level access control for WireGuard mesh connections. Operators can define which ports are accessible through the mesh, with rules scoped per-peer, per-organization, or globally.

## Overview

By default, peers can access **any port** on a trusted mesh connection — the same as a standard WireGuard tunnel. Service access control lets you restrict this:

- Allow only specific ports (e.g., SSH on port 22, HTTPS on 443)
- Block specific ports (e.g., deny database access on 5432)
- Apply rules per peer, per org, or globally
- Set a default-deny posture for allowlist-only configurations

## How It Works

Service policies are evaluated **in-process** at the WireGuard decrypt → TUN boundary. When a packet arrives through the mesh tunnel:

1. Extract the protocol (TCP/UDP) and destination port from the decrypted IP header
2. Look up the sender's public key
3. Evaluate rules in order: **peer → org → global → default**
4. First match wins — if allowed, the packet reaches the OS; if denied, it's silently dropped

This approach is:

- **Cross-platform** — works on Linux, Android, and any OS (no iptables dependency)
- **Identity-aware** — rules target peers by public key or alias, not IP address
- **Zero-allocation** — the hot path uses fixed-size arrays, no heap allocations during packet processing

## Policy Files

Policies are stored in `$MESHGUARD_CONFIG_DIR/services/`:

```
services/
├── default              # Default action: "allow" or "deny"
├── global.policy        # Global rules (apply to all peers)
├── peer/                # Per-peer policies
│   ├── node-1.policy
│   └── validator-3.policy
└── org/                 # Per-org policies
    └── eosrio.policy
```

### Rule Syntax

Each `.policy` file contains one rule per line:

```
allow tcp 22
allow tcp 443
allow tcp 8000-9000
deny udp 53
deny all
```

| Field    | Values                                       |
| -------- | -------------------------------------------- |
| Action   | `allow` or `deny`                            |
| Protocol | `tcp`, `udp`, or `all`                       |
| Port     | single (`22`), range (`8000-9000`), or `all` |

Lines starting with `#` are comments. Empty lines are ignored.

### Default Action

If no `services/` directory exists, the default action is **allow** (unrestricted access, like standard WireGuard).

To switch to a default-deny posture:

```bash
meshguard service default deny
```

This writes `deny` to `services/default`. All ports are then blocked unless explicitly allowed by a rule.

## CLI Commands

```bash
# Add rules
meshguard service allow tcp 22              # Global: allow SSH
meshguard service allow tcp 443             # Global: allow HTTPS
meshguard service deny all                  # Global: deny everything else

# Per-peer rules
meshguard service allow --peer node-1 tcp 5432  # Allow Postgres for node-1
meshguard service deny --peer untrusted tcp 22  # Block SSH from untrusted

# Per-org rules
meshguard service allow --org eosrio tcp 80     # Allow HTTP for org

# Set default action
meshguard service default deny              # Switch to allowlist mode
meshguard service default allow             # Switch to open mode

# View
meshguard service list                      # List all policies
meshguard service show                      # Summary (counts, default)
meshguard service show node-1               # Effective policy for a peer

# Reset
meshguard service reset                     # Clear all policies (back to allow-all)
```

## Evaluation Order

Rules are evaluated in this priority:

1. **Peer-specific** — `services/peer/<alias>.policy`
2. **Org-specific** — `services/org/<org-name>.policy`
3. **Global** — `services/global.policy`
4. **Default** — `services/default` file (defaults to `allow` if missing)

Within each policy, rules are evaluated top-to-bottom, first match wins.

## Examples

### Example 1: Allow only SSH and HTTPS

```bash
meshguard service default deny
meshguard service allow tcp 22
meshguard service allow tcp 443
```

All peers can reach ports 22 and 443; everything else is blocked.

### Example 2: Allow all, but block databases

```bash
meshguard service deny tcp 3306   # MySQL
meshguard service deny tcp 5432   # PostgreSQL
meshguard service deny tcp 27017  # MongoDB
```

Default is allow, but database ports are explicitly blocked.

### Example 3: Per-peer override

```bash
meshguard service default deny
meshguard service allow tcp 22
meshguard service allow --peer db-admin tcp 5432
```

Only SSH is open globally. The peer `db-admin` additionally gets PostgreSQL access.

## Notes

- Service policies are loaded at daemon startup. To apply changes, restart the daemon.
- Policies apply to **inbound** traffic only (packets received through the mesh and destined for the local OS).
- SWIM gossip and WireGuard handshake traffic are not affected — only transport-layer data packets are filtered.
- ICMP (ping) is currently allowed by default and not filtered by port-based rules.
