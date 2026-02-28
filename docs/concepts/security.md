# Security Model

meshguard's security model is built on three pillars: **cryptographic identity**, **decentralized trust**, and **attack surface minimization**.

## Threat Model

### What meshguard protects against

| Threat | Mitigation |
|--------|------------|
| **Eavesdropping** | All traffic encrypted with ChaCha20-Poly1305 (WireGuard Noise_IK) |
| **Man-in-the-middle** | Ed25519 signatures in handshake, mutual authentication |
| **Replay attacks** | 2048-bit sliding window + TAI64N timestamps in handshake |
| **Key compromise** | Transport keys rotate every 120s; identity keys never transmitted |
| **Unauthorized peers** | `authorized_keys/` directory gates membership |
| **NAT traversal attacks** | Hole punch uses 16-byte random tokens, not predictable patterns |

### What meshguard does NOT protect against

| Threat | Why | Mitigation |
|--------|-----|------------|
| **Compromised host** | If attacker has root on a trusted node, all mesh traffic is readable | Host hardening, least privilege |
| **Social engineering** | If you add a malicious peer's key, they're in the mesh | Verify fingerprints out-of-band |
| **Traffic analysis** | Packet sizes and timing are visible | Use constant-time padding (future work) |
| **DoS** | UDP flood to public ports | Rate limiting at firewall level |

## Key Hygiene

### Identity Keys

- **Never share `identity.key`** — this is your node's long-term identity
- **Use `--force` carefully** — `meshguard keygen --force` overwrites your identity
- **Backups** — store identity.key offline, not in git

### WireGuard Transport Keys

- **Ephemeral** — X25519 keys are generated at startup, never persisted
- **Auto-rotate** — rekey every 120s (REKEY_AFTER_TIME)
- **Hard timeout** — reject after 180s (REJECT_AFTER_TIME)

### Organization Keys

- **Org admins hold signing keys** — treat like root CA keys
- **Node certificates** — 186 bytes, stored at `~/.config/meshguard/node.cert`
- **Revocation** — use `org-revoke` immediately if a node is compromised

## Attack Surface

### Exposed Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 51821/udp | SWIM + WG | Gossip, handshake, transport (multiplexed) |
| 51830/udp | WG | WireGuard transport (if `--kernel` mode) |

### Network Exposure

- **Public IP nodes** — accept connections from any IP (but only authorized keys)
- **NATed nodes** — only reachable via hole punch or relay
- **Recommendation** — run behind a firewall, whitelist seed peer IPs

### Memory Safety

- **Written in Zig** — no null pointer derefs, bounds-checked slices
- **No dynamic memory** in hot path — fixed-size pools, no allocator in packet processing
- **Secrets zeroized** — `crypto.timing_safe.eql` for comparisons, explicit zeroing on peer removal

## Trust Model

### Individual Trust

- Each node manages its own `authorized_keys/` directory
- No central authority validates membership
- Trust is **bidirectional** — both peers must have each other's keys

### Organization Trust

- **Org certificate** signs node public key + name + expiry
- **Lamport timestamps** resolve alias conflicts (earliest claim wins)
- **Revocation** propagates via SWIM gossip

## Security Recommendations

1. **Firewall the gossip port** — only allow from trusted IP ranges
2. **Use org trust for fleets** — easier key rotation than N individual keys
3. **Monitor for unknown keys** — log new peer joins
4. **Rotate org keys annually** — generate new org keypair, re-sign node certs
5. **Run as non-root if possible** — userspace mode only needs `CAP_NET_ADMIN`

## Comparison with Other VPNs

| Feature | meshguard | Tailscale | WireGuard (manual) |
|---------|-----------|-----------|-------------------|
| Central authority | None | Control plane | None |
| Key distribution | Manual / org-signed | Automatic | Manual |
| Revocation | Delete file / gossip | Dashboard | Manual |
| NAT traversal | STUN + hole punch + relay | DERP servers | Manual port forward |
| Attack surface | Single UDP port | Multiple services | Single UDP port |