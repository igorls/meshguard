## 2025-05-23 - [CRITICAL] Timing Attack on MAC1 Verification
**Vulnerability:** The function `verifyMac1` in `src/wireguard/noise.zig` uses `std.mem.eql` to compare the computed MAC1 with the received MAC1. This function is not constant-time and terminates early upon finding a mismatch, exposing a timing oracle. An attacker could potentially use this to forge MAC1 values or learn information about the key (although the key is derived from the receiver's public key, the MAC itself is a gatekeeper for processing the handshake).

**Learning:** Developers often reach for `std.mem.eql` for all comparisons without considering the security implications for cryptographic values. The lack of a linter to catch this makes it easy to overlook.

**Prevention:** Always use `std.crypto.utils.timingSafeEql` for comparing MACs, signatures, hashes, and keys. Establish a code review checklist that specifically flags `std.mem.eql` usage on byte arrays that might be secrets or cryptographic proofs.

## 2026-02-24 - [CRITICAL] Sensitive Key Material Not Zeroed After Use
**Vulnerability:** The `Handshake` struct in `src/wireguard/noise.zig` retains copies of the long-term identity key (`static_private`) and sensitive ephemeral keys (`ephemeral_private`, `precomputed_ss`, `chaining_key`) in memory. These were not explicitly zeroed out when a peer was removed or the handshake object was destroyed, potentially exposing them to memory dumps or swap files.

**Learning:** Zig structs do not have automatic destructors (RAII) like C++ or Rust. Developers must manually implement `deinit` methods and ensure they are called. `WgDevice.removePeer` simply set the peer slot to `null`, which leaves the old memory content intact in the fixed-size array until overwritten by a new peer.

**Prevention:** Implement `deinit` methods for all structs holding sensitive data that use `std.crypto.secureZero`. Audit all lifecycle management points (like `removePeer`) to ensure explicit cleanup is performed before releasing references.

## 2025-05-24 - [MEDIUM] Insecure Key File Permissions
**Vulnerability:** The functions `save` in `src/identity/keys.zig` and `saveOrgKeyPair` in `src/identity/org.zig` created sensitive key files with default permissions (usually 0o644 or 0o666 depending on umask) before calling `chmod(0o600)`. This introduced a race condition where the file was world-readable for a brief moment. Additionally, the `chmod` result was ignored, potentially leaving files insecure if the operation failed.
**Learning:** `std.fs.createFileAbsolute` accepts a `File.CreateFlags` struct which includes a `mode` field. Setting this field ensures atomic permission setting at creation time. However, on POSIX, `open/creat` with `O_CREAT` ignores the mode if the file already exists. Therefore, a subsequent `chmod` is still necessary to correct permissions on existing files.
**Prevention:** Always use `.mode = 0o600` in `createFileAbsolute` / `createFile` options for sensitive files. Additionally, verify if the file might already exist and if so, explicitly check/fix permissions or use `chmod` ensuring errors are handled.
