//! Signed WireGuard key bindings.
//!
//! A node's WireGuard key is not always derivable from its Ed25519 identity:
//! daemons use the X25519 form of the Ed25519 secret scalar, while mobile and
//! browser identities clamp the seed directly. Without a signature, a peer
//! that learned a WireGuard key from third-party gossip could not tell the
//! owner's key from an attacker's, and a Noise handshake with the wrong key
//! would "prove" the attacker's endpoint for the victim's identity.
//!
//! A binding is the node's own Ed25519 signature over
//! `"meshguard-wg-binding-v1\0" || ed25519_pubkey || wg_pubkey`. It travels as
//! an optional trailer on Ping and Ack (see protocol/codec.zig) and is
//! constant for an identity, so receivers verify it once per key.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const messages = @import("../protocol/messages.zig");

pub const DOMAIN = "meshguard-wg-binding-v1\x00";
pub const PAYLOAD_SIZE = DOMAIN.len + 32 + 32;

/// A WireGuard key and its owner's signature over it.
pub const WgBinding = messages.WgBinding;

pub fn payload(ed25519_pubkey: [32]u8, wg_pubkey: [32]u8) [PAYLOAD_SIZE]u8 {
    var buf: [PAYLOAD_SIZE]u8 = undefined;
    @memcpy(buf[0..DOMAIN.len], DOMAIN);
    @memcpy(buf[DOMAIN.len..][0..32], &ed25519_pubkey);
    @memcpy(buf[DOMAIN.len + 32 ..][0..32], &wg_pubkey);
    return buf;
}

/// Signs a binding with an Ed25519 key pair.
pub fn sign(key_pair: Ed25519.KeyPair, wg_pubkey: [32]u8) !WgBinding {
    const message = payload(key_pair.public_key.toBytes(), wg_pubkey);
    const signature = try key_pair.sign(&message, null);
    return .{ .wg_pubkey = wg_pubkey, .signature = signature.toBytes() };
}

/// Signs a binding with the identity's 32-byte Ed25519 seed.
pub fn signWithSeed(seed: [32]u8, wg_pubkey: [32]u8) !WgBinding {
    var key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key_pair));
    return sign(key_pair, wg_pubkey);
}

/// True when `binding` carries a valid signature by `ed25519_pubkey`.
pub fn verify(ed25519_pubkey: [32]u8, binding: WgBinding) bool {
    if (std.mem.allEqual(u8, &binding.wg_pubkey, 0)) return false;
    const public_key = Ed25519.PublicKey.fromBytes(ed25519_pubkey) catch return false;
    const message = payload(ed25519_pubkey, binding.wg_pubkey);
    Ed25519.Signature.fromBytes(binding.signature).verify(&message, public_key) catch return false;
    return true;
}

/// True when `wg_pubkey` is the X25519 form of `ed25519_pubkey`, as daemon
/// identities derive it. Such keys need no signature.
pub fn isDerived(ed25519_pubkey: [32]u8, wg_pubkey: [32]u8) bool {
    const derived = X25519.publicKeyFromEd25519(Ed25519.PublicKey.fromBytes(ed25519_pubkey) catch return false) catch return false;
    return std.mem.eql(u8, &derived, &wg_pubkey);
}

// ─── Tests ───

test "a binding verifies only for its own identity and key" {
    const seed = [_]u8{7} ** 32;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const wg = [_]u8{9} ** 32;
    const binding = try signWithSeed(seed, wg);
    try std.testing.expect(verify(key_pair.public_key.toBytes(), binding));

    var other_key = binding;
    other_key.wg_pubkey[0] ^= 1;
    try std.testing.expect(!verify(key_pair.public_key.toBytes(), other_key));

    const stranger = try Ed25519.KeyPair.generateDeterministic([_]u8{8} ** 32);
    try std.testing.expect(!verify(stranger.public_key.toBytes(), binding));

    var zero = binding;
    zero.wg_pubkey = std.mem.zeroes([32]u8);
    try std.testing.expect(!verify(key_pair.public_key.toBytes(), zero));
}

test "binding signature matches the browser core's known answer" {
    // tests/web/gateway.test.mjs checks the same vector through the WASM core.
    const binding = try signWithSeed([_]u8{7} ** 32, [_]u8{9} ** 32);
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "16718f492c54ffe80a79fa28e66054faf3f94527239b0305f2b1787d05a718492025daade823f5f0ad24455594702627525cd3c51e82dbc759162537e2a00701");
    try std.testing.expectEqualSlices(u8, &expected, &binding.signature);
}

test "a binding is deterministic for a seed" {
    const a = try signWithSeed([_]u8{3} ** 32, [_]u8{4} ** 32);
    const b = try signWithSeed([_]u8{3} ** 32, [_]u8{4} ** 32);
    try std.testing.expectEqualSlices(u8, &a.signature, &b.signature);
}

test "daemon keys are derived; seed-clamped keys are not" {
    const seed = [_]u8{0x21} ** 32;
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const ed = key_pair.public_key.toBytes();

    // Daemon derivation (main.zig): clamp(SHA-512(seed)[0..32]), the Ed25519
    // secret scalar, whose X25519 public key is the Ed25519 key's X25519 form.
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&seed, &hash, .{});
    var daemon_private: [32]u8 = hash[0..32].*;
    daemon_private[0] &= 248;
    daemon_private[31] &= 127;
    daemon_private[31] |= 64;
    const daemon_wg = try X25519.recoverPublicKey(daemon_private);
    try std.testing.expect(isDerived(ed, daemon_wg));

    // Mobile and browser derivation: the clamped seed.
    var clamped = seed;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    const app_wg = try X25519.recoverPublicKey(clamped);
    try std.testing.expect(!isDerived(ed, app_wg));
}
