
## 2026-02-25 - Zero-copy encryption for aligned packets
**Learning:** libsodium's `encrypt` function supports distinct source and destination buffers, enabling zero-copy encryption when no padding is required (e.g., 16-byte aligned packets like Keepalives).
**Action:** Use conditional zero-copy paths for cryptographic operations where input alignment permits, avoiding unnecessary `@memcpy`.
