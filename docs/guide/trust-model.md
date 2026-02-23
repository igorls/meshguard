# Trust Model

meshguard uses a **fully decentralized trust model** — no certificate authority, no central key server. Each node decides who it trusts by managing a local directory of authorized public keys.

## How It Works

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

## Trust Operations

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

## Mutual Trust Requirement

Trust is **bidirectional** — for two nodes to form a WireGuard tunnel, each must have the other's key in their `authorized_keys/` directory. If only one side trusts the other, the untrusting side will reject the handshake.

## Gossip Filtering

SWIM gossip messages from unauthorized nodes are silently dropped during the handshake phase. The sequence is:

1. Node A discovers Node B via gossip
2. A looks up B's Ed25519 public key in its local `authorized_keys/`
3. If not found → connection refused, gossip entry discarded
4. If found → signed handshake exchange, mutual authentication, WireGuard tunnel establishment

## Key Validation

Keys are validated at multiple levels:

| Check               | When                     | Purpose                |
| ------------------- | ------------------------ | ---------------------- |
| Base64 decode       | `meshguard trust`        | Format check           |
| Ed25519 point check | `meshguard trust`        | Cryptographic validity |
| Name collision      | `meshguard trust`        | Prevent duplicates     |
| Key collision       | `meshguard trust`        | Prevent aliases        |
| Authorization check | `meshguard up` (runtime) | Mesh gating            |

## Comparison with Other Approaches

| Feature                 | meshguard            | Tailscale/Headscale | Nebula              |
| ----------------------- | -------------------- | ------------------- | ------------------- |
| Key authority           | Each node            | Central server      | CA certificate      |
| Revocation              | Delete `.pub` file   | Dashboard/API       | CRL                 |
| Key distribution        | Manual / out-of-band | Automatic           | Certificate signing |
| Single point of failure | None                 | Coordination server | CA server           |
