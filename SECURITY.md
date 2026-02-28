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

See [docs/concepts/security.md](docs/concepts/security.md) for full security model documentation.