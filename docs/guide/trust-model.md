# Trust Model

meshguard uses a **fully decentralized trust model** — no certificate authority, no central key server. Each node decides who it trusts by managing a local directory of authorized public keys, or by trusting an organization's signing key.

## Individual Trust

Every node has an `authorized_keys/` directory under its config path (default: `~/.config/meshguard/authorized_keys/`). Each file in this directory contains a single base64-encoded Ed25519 public key belonging to a trusted peer.

```
~/.config/meshguard/
├── identity.key           # Your Ed25519 secret key (0600)
├── identity.pub           # Your Ed25519 public key
└── authorized_keys/
    ├── gateway.pub         # Peer "gateway"
    ├── validator-1.pub     # Peer "validator-1"
    └── my-laptop.pub       # Peer "my-laptop"
```

When meshguard starts (`meshguard up`), it loads all `.pub` files from this directory and only peers whose keys are in this list will be accepted into the mesh.

### Adding a peer

```bash
# From a file
meshguard trust /path/to/peer.pub --name my-peer

# From a raw base64 key
meshguard trust "dGhpcyBpcyBhbiBlZDI1NTE5IGtleQ==" --name datacenter-01
```

The command validates the key (base64 decode → Ed25519 point verification) before saving. It also checks for:

- **Key conflicts** — the same public key already trusted under a different name
- **Name conflicts** — a different key already uses the same name

### Removing a peer

```bash
meshguard revoke my-peer
```

This deletes `~/.config/meshguard/authorized_keys/my-peer.pub`.

### Exporting your key

```bash
meshguard export > my-node.pub
```

Share this file with peers who should trust you.

## Org Trust (Hierarchical)

For fleet deployments, managing N individual keys becomes impractical. **Org trust** lets you trust a single organization public key and automatically accept all nodes that present a valid certificate signed by that organization.

### How It Works

1. An **org admin** generates an Ed25519 org keypair
2. The admin **signs node certificates** for each fleet member
3. Remote peers **trust the org key** (one-time operation)
4. Nodes presenting a valid org certificate are **auto-accepted**

```
~/.config/meshguard/
├── identity.key / identity.pub    # Node identity
├── node.cert                      # Org-signed certificate (186 bytes)
├── authorized_keys/               # Individual peer trust
│   └── validator-1.pub
├── trusted_orgs/                  # Org trust (auto-accept members)
│   └── eosrio.org
└── org/                           # Org admin only
    ├── org.key                    # Org private key
    └── org.pub                    # Org public key
```

### NodeCertificate Format

Each certificate is a fixed-size 186-byte binary structure:

| Field         | Size     | Description                             |
| ------------- | -------- | --------------------------------------- |
| `version`     | 1 byte   | Certificate version (currently 1)       |
| `org_pubkey`  | 32 bytes | Organization Ed25519 public key         |
| `node_pubkey` | 32 bytes | Node Ed25519 public key                 |
| `node_name`   | 32 bytes | DNS label, null-padded                  |
| `issued_at`   | 8 bytes  | Unix timestamp                          |
| `expires_at`  | 8 bytes  | Unix timestamp (0 = never)              |
| `flags`       | 1 byte   | Reserved                                |
| `signature`   | 64 bytes | Ed25519 signature over all prior fields |
| _padding_     | 8 bytes  | Future expansion                        |

### Mesh DNS

Each organization gets a **deterministic mesh domain** derived from its public key:

```
Blake3(org_pubkey)[0..3].hex() → 6 hex chars → *.a1b2c3.mesh
```

Node names from certificates resolve as `node-name.org-domain.mesh`. For example, a node named `db-1` in org `a1b2c3` resolves to `db-1.a1b2c3.mesh`.

Organizations can also claim **human-readable aliases** (e.g. `*.eosrio.mesh`) via gossip. Alias conflicts are resolved by Lamport timestamp — earliest claim wins.

### CLI Commands

```bash
# Generate org keypair
meshguard org-keygen

# Sign a node's key
meshguard org-sign /path/to/node.pub --name db-1

# Trust an org (auto-accept all signed nodes)
meshguard trust <org-pubkey> --org --name eosrio

# Vouch for an external standalone node
meshguard org-vouch <solo-node-pubkey>
```

### Authorization Flow

When a new peer connects, trust is evaluated in order:

1. **Individual key check** — is the peer's pubkey in `authorized_keys/`?
2. **Org certificate check** — does the peer present a valid `NodeCertificate`?
   - Verify Ed25519 signature
   - Check certificate expiry
   - Confirm issuing org is in `trusted_orgs/`
3. **Revocation check** — has the cert been revoked via gossip?

### Revocation

Org admins can revoke certificates, which are propagated via gossip:

```bash
meshguard org-revoke <node-pubkey>
```

Revoked nodes are disconnected immediately by peers that receive the revocation.

### Org Vouch (External Peers)

Org admins can **vouch for external standalone nodes** without issuing them a full certificate. The vouch is gossip-propagated:

```bash
meshguard org-vouch <solo-node-pubkey>
# → saved to ~/.config/meshguard/vouched/<hex>.vouch
# → gossiped to all org members on next 'meshguard up'
```

All nodes trusting the vouching org will auto-accept the standalone node. This is useful for:

- Cross-org peering without full membership
- Onboarding partners to a fleet
- Temporary trust grants (revocable via `org-revoke`)

### Authorization Flow

When a new peer connects, trust is evaluated in order:

1. **Individual key check** — is the peer's pubkey in `authorized_keys/`?
2. **Org certificate check** — does the peer present a valid `NodeCertificate`?
   - Verify Ed25519 signature
   - Check certificate expiry
   - Confirm issuing org is in `trusted_orgs/`
3. **Org vouch check** — has a trusted org vouched for this peer?
4. **Revocation check** — has the cert/vouch been revoked via gossip?

## Key Validation

Keys are validated at multiple levels:

| Check               | When                     | Purpose                |
| ------------------- | ------------------------ | ---------------------- |
| Base64 decode       | `meshguard trust`        | Format check           |
| Ed25519 point check | `meshguard trust`        | Cryptographic validity |
| Name collision      | `meshguard trust`        | Prevent duplicates     |
| Key collision       | `meshguard trust`        | Prevent aliases        |
| Cert signature      | `meshguard up` (runtime) | Org cert authenticity  |
| Cert expiry         | `meshguard up` (runtime) | Temporal validity      |
| Authorization check | `meshguard up` (runtime) | Mesh gating            |

## Comparison with Other Approaches

| Feature                 | meshguard             | Tailscale/Headscale | Nebula              |
| ----------------------- | --------------------- | ------------------- | ------------------- |
| Key authority           | Each node / org admin | Central server      | CA certificate      |
| Revocation              | Delete file / gossip  | Dashboard/API       | CRL                 |
| Key distribution        | Manual / out-of-band  | Automatic           | Certificate signing |
| Hierarchical trust      | Org certificates      | Teams/ACLs          | Groups              |
| External vouching       | Org vouch (gossip)    | Share nodes         | N/A                 |
| Mesh DNS                | Deterministic + alias | MagicDNS            | Lighthouse          |
| Single point of failure | None                  | Coordination server | CA server           |
