# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main | ✅ |
| < 0.6.0 | ❌ |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Instead, please report via one of:

1. **GitHub Security Advisories**: https://github.com/igorls/meshguard/security/advisories/new
2. **Email**: Contact the maintainer directly

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity (critical: 7 days, medium: 30 days)

## Security Features

- **ChaCha20-Poly1305** encryption (WireGuard-compatible)
- **Ed25519** identity keys
- **Noise_IKpsk2** handshake with anti-replay
- **Decentralized trust** (no central authority)
- **Org PKI** for fleet trust
- **Key rotation** every 120 seconds
- **RX cryptokey routing**: decrypted packets must carry an inner source IP belonging to the sending peer
- **Authenticated org control plane**: revoke/alias/vouch messages require a verified org Ed25519 signature
- **Confirmed failure detection**: gossiped death only suspects a peer locally; eviction requires our own probe to fail
- **Inbound-handshake rate limiting**: per-source + global token bucket before the X25519
- **Response authentication**: handshake responses are MAC1-checked before any DH and only an authenticated response changes handshake state
- **Rekey-safe pipelining**: encrypted batches carry the key generation their nonces were reserved under; stale batches are dropped rather than encrypted under new keys
- **First-claim mesh addressing**: a peer cannot take over another peer's routing slot through a mesh host-id collision
- **Signed WireGuard keys**: gossip-learned keys that are not an identity's own derived key authenticate neither tunnels nor application messages until the owner's signed binding or certificate arrives
- **Fail-closed service policy**: malformed policy files stop the daemon; fragments and IPv6 extension headers cannot bypass port rules
- **Owner-only control**: messaging, transfers, reload and stop on the control socket require the daemon's owner; key files are owner-only (0600)
- **Verified installs**: installers and `meshguard upgrade` check release SHA-256 sums before anything is executed or installed

See [docs/concepts/security.md](docs/concepts/security.md) for full security model documentation.