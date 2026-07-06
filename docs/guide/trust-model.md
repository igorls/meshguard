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
├── node.cert                      # Org-signed certificate (v1 186 B, v2 314 B)
├── authorized_keys/               # Individual peer trust
│   └── validator-1.pub
├── trusted_orgs/                  # Org trust (auto-accept members)
│   └── eosrio.org
└── org/                           # Org admin only
    ├── org.key                    # Org private key
    └── org.pub                    # Org public key
```

### NodeCertificate Format

meshguard supports two node-certificate versions during the v2 rollout:

| Version | Wire size | Description |
| ------- | --------- | ----------- |
| v1 | 186 bytes | Org signs node identity, name, issue time, expiry, and flags. WireGuard public keys are still learned from gossip. |
| v2 | 314 bytes | v1 prefix plus signed WireGuard public key binding, issuer key, and optional delegated-issuer grant signature. |

The shared v1 prefix is:

| Field         | Size     | Description                              |
| ------------- | -------- | ---------------------------------------- |
| `version`     | 1 byte   | Certificate version (`1` or `2`)         |
| `org_pubkey`  | 32 bytes | Organization Ed25519 public key          |
| `node_pubkey` | 32 bytes | Node Ed25519 public key                  |
| `node_name`   | 32 bytes | DNS label, null-padded                   |
| `issued_at`   | 8 bytes  | Unix timestamp                           |
| `expires_at`  | 8 bytes  | Unix timestamp (0 = never)               |
| `flags`       | 1 byte   | Delegation flag in v2, reserved in v1    |
| `signature`   | 64 bytes | Ed25519 signature over versioned payload |
| _padding_     | 8 bytes  | v1 padding before v2 extension fields    |

v2 appends:

| Field | Size | Description |
| ----- | ---- | ----------- |
| `wg_pubkey` | 32 bytes | Signed X25519 WireGuard public key for this node |
| `issuer_pubkey` | 32 bytes | Zero for normal direct certs, or the delegated issuer key when the delegation flag is set |
| `delegation_signature` | 64 bytes | Org signature authorizing the delegated issuer; zero for direct org-signed v2 certs |

For direct v2 certs, the org signs the full v2 payload. For delegated v2 certs,
the issuer signs the node payload and the org signs a one-hop grant to that
issuer. The issuer can be a human/role key or a partner org key. Revoking the
issuer with `meshguard org-revoke` invalidates all leaves admitted through that
issuer for the revoking org.

### v1/v2 Migration Policy

Upgraded meshguard nodes accept legacy v1 certificates and v2 certificates.
Legacy meshguard nodes accept only v1 certificates. During a mixed-version
rollout, upgrade binaries first and continue issuing v1 certs until every
trust-enforcing peer has the v2 parser. Then issue v2 certs, usually with
`meshguard org-sign --wg-pubkey`, to bind each node identity to its WireGuard
public key. v1 peers remain supported, but their WireGuard key is still learned
from gossip instead of the certificate.

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

# Sign a node's key with a v1 certificate
meshguard org-sign /path/to/node.pub --name db-1

# Sign a v2 certificate that binds the node's WireGuard public key
meshguard org-sign /path/to/node.pub --name db-1 --wg-pubkey /path/to/node.wg.pub

# Trust an org (auto-accept all signed nodes)
meshguard trust <org-pubkey> --org --name eosrio

# Vouch for an external standalone node
meshguard org-vouch <solo-node-pubkey>

# Revoke an org-signed node certificate
meshguard org-revoke <node-pubkey> --reason admin-removed
```

### Revocation

The wire protocol supports signed `OrgCertRevoke` messages, which are
propagated via gossip and enforced by peers that receive them. The receive-side
verification signs the revoked node key, reason, and Lamport timestamp.

Org admins revoke an org-signed node with `meshguard org-revoke`. The command
loads the local org signing key, writes a signed `OrgCertRevoke` message under
`revoked/`, and `meshguard up` queues the saved revocation for best-effort
broadcast to known peers. Revocations are scoped to the issuing org, so they
invalidate that org's certificate or vouch for the node without cancelling a
different trusted org's authority. Individual trust files can still be removed
locally with `meshguard revoke` when a peer was admitted outside org trust.

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
- Temporary trust grants that can later be revoked with `meshguard org-revoke`

### Authorization Flow

When a new peer connects, trust is evaluated in order:

1. **Individual key check** — is the peer's pubkey in `authorized_keys/`?
2. **Org certificate check** — does the peer present a valid `NodeCertificate`?
   - Verify Ed25519 signature
   - Check certificate expiry
   - Confirm issuing org is in `trusted_orgs/`
   - For v2, bind the peer's WireGuard public key from the signed cert
   - For delegated v2, verify the org-signed issuer grant and issuer signature
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
