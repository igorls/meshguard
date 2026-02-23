///! WireGuard cryptographic primitives.
///!
///! Implements HMAC-Blake2s and HKDF as specified in the WireGuard protocol.
///! Reference: drivers/net/wireguard/noise.c (lines 305-390)
const std = @import("std");
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

pub const HASH_LEN: usize = 32; // Blake2s-256 output
pub const KEY_LEN: usize = 32; // ChaCha20-Poly1305 key
pub const BLOCK_SIZE: usize = 64; // Blake2s block size

/// HMAC-Blake2s using std library implementation.
/// Replaces hand-rolled RFC 2104 construction — less code, less liability.
/// Kernel reference: noise.c:305-338
pub fn hmac(key: []const u8, data: []const u8) [HASH_LEN]u8 {
    var mac: [HASH_LEN]u8 = undefined;
    const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s256);
    HmacBlake2s.create(&mac, data, key);
    return mac;
}

/// HKDF-Blake2s: Extract + Expand (RFC 5869 over HMAC-Blake2s).
/// Returns 1 output key.
/// Kernel reference: noise.c:344-390
pub fn kdf1(chaining_key: [HASH_LEN]u8, data: []const u8) struct { ck: [HASH_LEN]u8 } {
    // Extract
    const secret = hmac(&chaining_key, data);

    // Expand T1: HMAC(secret, 0x01)
    const t1 = hmac(&secret, &[_]u8{0x01});

    return .{ .ck = t1 };
}

/// HKDF-Blake2s: Extract + Expand, 2 output keys.
pub fn kdf2(chaining_key: [HASH_LEN]u8, data: []const u8) struct { ck: [HASH_LEN]u8, key: [KEY_LEN]u8 } {
    // Extract
    const secret = hmac(&chaining_key, data);

    // Expand T1: HMAC(secret, 0x01)
    const t1 = hmac(&secret, &[_]u8{0x01});

    // Expand T2: HMAC(secret, T1 || 0x02)
    var t1_plus: [HASH_LEN + 1]u8 = undefined;
    @memcpy(t1_plus[0..HASH_LEN], &t1);
    t1_plus[HASH_LEN] = 0x02;
    const t2 = hmac(&secret, &t1_plus);

    return .{ .ck = t1, .key = t2 };
}

/// HKDF-Blake2s: Extract + Expand, 3 output keys.
pub fn kdf3(chaining_key: [HASH_LEN]u8, data: []const u8) struct { ck: [HASH_LEN]u8, key1: [KEY_LEN]u8, key2: [KEY_LEN]u8 } {
    // Extract
    const secret = hmac(&chaining_key, data);

    // Expand T1
    const t1 = hmac(&secret, &[_]u8{0x01});

    // Expand T2
    var t1_plus: [HASH_LEN + 1]u8 = undefined;
    @memcpy(t1_plus[0..HASH_LEN], &t1);
    t1_plus[HASH_LEN] = 0x02;
    const t2 = hmac(&secret, &t1_plus);

    // Expand T3
    var t2_plus: [HASH_LEN + 1]u8 = undefined;
    @memcpy(t2_plus[0..HASH_LEN], &t2);
    t2_plus[HASH_LEN] = 0x03;
    const t3 = hmac(&secret, &t2_plus);

    return .{ .ck = t1, .key1 = t2, .key2 = t3 };
}

/// mix_hash: hash = Blake2s(hash || data)
/// Kernel reference: noise.c:432-440
pub fn mixHash(hash: *[HASH_LEN]u8, data: []const u8) void {
    var h = Blake2s256.init(.{});
    h.update(hash);
    h.update(data);
    h.final(hash);
}

/// Constant-time comparison to prevent timing attacks.
/// Works for any type that can be represented as bytes (arrays, structs).
pub fn timingSafeEql(comptime T: type, a: T, b: T) bool {
    const a_bytes = std.mem.asBytes(&a);
    const b_bytes = std.mem.asBytes(&b);
    var acc: u8 = 0;
    for (a_bytes, b_bytes) |x, y| {
        acc |= x ^ y;
    }
    return acc == 0;
}

// ─── Tests ───

test "HMAC-Blake2s basic" {
    // Test that HMAC produces consistent output
    const key = "test-key";
    const data = "test-data";
    const result1 = hmac(key, data);
    const result2 = hmac(key, data);
    try std.testing.expectEqualSlices(u8, &result1, &result2);

    // Different key should produce different output
    const result3 = hmac("other-key", data);
    try std.testing.expect(!std.mem.eql(u8, &result1, &result3));
}

test "KDF2 produces two distinct keys" {
    const ck: [32]u8 = .{0x42} ** 32;
    const result = kdf2(ck, "input");
    // The two outputs should be different
    try std.testing.expect(!std.mem.eql(u8, &result.ck, &result.key));
}

test "KDF3 produces three distinct keys" {
    const ck: [32]u8 = .{0x42} ** 32;
    const result = kdf3(ck, "input");
    try std.testing.expect(!std.mem.eql(u8, &result.ck, &result.key1));
    try std.testing.expect(!std.mem.eql(u8, &result.key1, &result.key2));
    try std.testing.expect(!std.mem.eql(u8, &result.ck, &result.key2));
}

test "mixHash updates hash" {
    var hash: [32]u8 = .{0} ** 32;
    const original = hash;
    mixHash(&hash, "data");
    try std.testing.expect(!std.mem.eql(u8, &hash, &original));
}

test "timingSafeEql compares correctly" {
    const a: [16]u8 = .{1} ** 16;
    const b: [16]u8 = .{1} ** 16;
    const c: [16]u8 = .{2} ** 16;

    try std.testing.expect(timingSafeEql([16]u8, a, b));
    try std.testing.expect(!timingSafeEql([16]u8, a, c));
}
