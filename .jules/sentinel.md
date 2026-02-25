## 2025-05-23 - [CRITICAL] Timing Attack on MAC1 Verification
**Vulnerability:** The function `verifyMac1` in `src/wireguard/noise.zig` uses `std.mem.eql` to compare the computed MAC1 with the received MAC1. This function is not constant-time and terminates early upon finding a mismatch, exposing a timing oracle. An attacker could potentially use this to forge MAC1 values or learn information about the key (although the key is derived from the receiver's public key, the MAC itself is a gatekeeper for processing the handshake).

**Learning:** Developers often reach for `std.mem.eql` for all comparisons without considering the security implications for cryptographic values. The lack of a linter to catch this makes it easy to overlook.

**Prevention:** Always use `std.crypto.utils.timingSafeEql` for comparing MACs, signatures, hashes, and keys. Establish a code review checklist that specifically flags `std.mem.eql` usage on byte arrays that might be secrets or cryptographic proofs.

## 2026-02-24 - [CRITICAL] Sensitive Key Material Not Zeroed After Use
**Vulnerability:** The `Handshake` struct in `src/wireguard/noise.zig` retains copies of the long-term identity key (`static_private`) and sensitive ephemeral keys (`ephemeral_private`, `precomputed_ss`, `chaining_key`) in memory. These were not explicitly zeroed out when a peer was removed or the handshake object was destroyed, potentially exposing them to memory dumps or swap files.

**Learning:** Zig structs do not have automatic destructors (RAII) like C++ or Rust. Developers must manually implement `deinit` methods and ensure they are called. `WgDevice.removePeer` simply set the peer slot to `null`, which leaves the old memory content intact in the fixed-size array until overwritten by a new peer.

**Prevention:** Implement `deinit` methods for all structs holding sensitive data that use `std.crypto.secureZero`. Audit all lifecycle management points (like `removePeer`) to ensure explicit cleanup is performed before releasing references.

## 2026-05-24 - [CRITICAL] Key Material Leaked in KDF Functions
**Vulnerability:** Intermediate key material (`secret` extracted from chaining key, and expanded `t*_plus` buffers) in `src/wireguard/crypto.zig`'s HKDF implementation (`kdf1`, `kdf2`, `kdf3`) was left on the stack without being zeroed. These buffers contain sensitive pseudorandom keys derived from the handshake chaining key.
**Learning:** Helper functions often create temporary buffers on the stack which persist until overwritten. Unlike the main handshake state struct, these are ephemeral but critical. Zig does not automatically zero stack variables on return.
**Prevention:** Always use `defer std.crypto.secureZero(u8, &var);` immediately after declaring any variable that will hold sensitive key material, especially in crypto primitives.
