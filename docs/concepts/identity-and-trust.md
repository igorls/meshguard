# Identity & Mesh IPs

meshguard relies on cryptographic identity for everything: authentication, addressing, and trust. This page covers how identities work and how mesh IPs are derived.

## Ed25519 Identity Keys

Every meshguard node has an Ed25519 keypair:

- **Secret key** (`identity.key`) — 64-byte Ed25519 secret key, base64-encoded, stored with permissions `0600`
- **Public key** (`identity.pub`) — 32-byte Ed25519 public key, base64-encoded

The keypair is generated via Zig's `std.crypto.sign.Ed25519.KeyPair.generate()` using the OS CSPRNG.

### Key Operations

| Operation        | Function          | Usage                          |
| ---------------- | ----------------- | ------------------------------ |
| Generate         | `Keys.generate()` | `meshguard keygen`             |
| Save to disk     | `Keys.save()`     | Writes `.key` + `.pub` files   |
| Load from disk   | `Keys.load()`     | `meshguard up`, `export`, etc. |
| Sign a message   | `Keys.sign()`     | Handshake authentication       |
| Verify signature | `Keys.verify()`   | Handshake validation           |

### Safety

`meshguard keygen` refuses to overwrite existing keys by default. Use `--force` to regenerate:

```bash
# Safe — will error if keys exist
meshguard keygen

# Destructive — overwrites existing keys
meshguard keygen --force
```

## Deterministic Mesh IP Derivation

Every node's mesh IP address is **deterministically derived** from its Ed25519 public key. This means:

- No DHCP server needed
- No central allocator needed
- No coordination between nodes required
- Any node can compute any other node's IP from its public key

### Algorithm

```
Blake3(public_key) → 32 bytes → take bytes [0..1] → 10.99.{byte0}.{byte1}
```

1. Hash the 32-byte Ed25519 public key with **Blake3**
2. Take the first 2 bytes of the hash output
3. Map to the mesh prefix: `10.99.{hash[0]}.{hash[1]}`
4. Adjust reserved octets: third octet `0` becomes `1`; last octet `0` becomes `1`, and `255` becomes `254`

The mesh uses a `/16` prefix (`10.99.0.0/16`). Because the IPv4 host portion is
derived from 16 hash bits, collisions are possible in large meshes and should be
treated operationally the same way as any deterministic-address collision.

### Collision Resistance

Blake3 provides strong uniformity across the 16-bit hash space. With 64K possible addresses, the birthday paradox suggests a 50% collision probability at ~256 nodes. For meshes larger than ~100 nodes, the prefix width should be extended (future work).

::: info
The `10.99.0.0/16` prefix and derivation algorithm are defined in
`wireguard/ip.zig`. Generated IPv4 addresses avoid `10.99.0.x`, `.0`, and
`.255`; the address space is deterministic but not collision-proof.
:::

## Dual Key System

meshguard uses **two separate key systems**, each serving a different purpose:

| Key Type      | Algorithm | Purpose                        | Stored Where               |
| ------------- | --------- | ------------------------------ | -------------------------- |
| **Identity**  | Ed25519   | Authentication, trust, mesh IP | `~/.config/meshguard/`     |
| **WireGuard** | X25519    | Tunnel encryption (Noise IK)   | Ephemeral (in memory)      |
| **Org**       | Ed25519   | Fleet trust, cert signing      | `~/.config/meshguard/org/` |

The X25519 WireGuard keypair is derived or generated at runtime. The Ed25519 identity key is the long-lived anchor of the node's identity. Org keys are only held by organization admins.

When two nodes discover each other:

1. SWIM gossip advertises Ed25519 identity, WireGuard public key, endpoint, and optional org certificate data
2. If individual trust fails, org certificate or vouch trust is verified
3. The peer is added to the userspace or kernel WireGuard configuration
4. The standard WireGuard Noise IK handshake establishes transport keys

## Org Trust & Certificates

Organizations sign `NodeCertificate` structures that bind a node's Ed25519 public key to an org identity. v1 certificates are 186 bytes; v2 certificates are 314 bytes and can also bind the node's WireGuard public key. See the [Trust Model](/guide/trust-model) guide for full details.

## Deterministic Mesh DNS

In addition to mesh IPs (`10.99.X.Y`), each organization gets a **deterministic mesh domain**:

```
Blake3(org_pubkey)[0..3].hex() → *.a1b2c3.mesh
```

Nodes with org certificates resolve as `node-name.org-domain.mesh` (e.g. `db-1.a1b2c3.mesh`). Orgs can also claim aliases (e.g. `*.eosrio.mesh`) via SWIM gossip, with Lamport-based conflict resolution.
