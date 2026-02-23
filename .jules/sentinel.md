## 2025-05-23 - [CRITICAL] Timing Attack on MAC1 Verification
**Vulnerability:** The function `verifyMac1` in `src/wireguard/noise.zig` uses `std.mem.eql` to compare the computed MAC1 with the received MAC1. This function is not constant-time and terminates early upon finding a mismatch, exposing a timing oracle. An attacker could potentially use this to forge MAC1 values or learn information about the key (although the key is derived from the receiver's public key, the MAC itself is a gatekeeper for processing the handshake).

**Learning:** Developers often reach for `std.mem.eql` for all comparisons without considering the security implications for cryptographic values. The lack of a linter to catch this makes it easy to overlook.

**Prevention:** Always use `std.crypto.utils.timingSafeEql` for comparing MACs, signatures, hashes, and keys. Establish a code review checklist that specifically flags `std.mem.eql` usage on byte arrays that might be secrets or cryptographic proofs.
