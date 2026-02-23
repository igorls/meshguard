//! Deterministic mesh IP allocation from Ed25519 public keys.
//!
//! Each node derives its mesh IP from a hash of its public key,
//! ensuring consistent addressing across the mesh without coordination.

const std = @import("std");
const Keys = @import("../identity/keys.zig");

/// Default mesh CIDR: 10.99.0.0/16
/// Gives us 65,534 usable addresses (10.99.0.1 - 10.99.255.254)
pub const default_mesh_prefix = [2]u8{ 10, 99 };
pub const default_mesh_mask: u8 = 16;

/// Derive a mesh IP from a public key.
/// Uses Blake3 hash of the public key to fill the host portion.
/// Avoids .0 and .255 in the last octet to prevent network/broadcast conflicts.
pub fn deriveFromPubkey(public_key: Keys.PublicKey) [4]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&public_key.toBytes(), &hash, .{});

    var host_lo = hash[0];
    var host_hi = hash[1];

    // Avoid .0 in last octet (network address ambiguity)
    if (host_hi == 0) host_hi = 1;
    // Avoid .255 in last octet (broadcast address)
    if (host_hi == 255) host_hi = 254;
    // Avoid .0 in third octet as well
    if (host_lo == 0) host_lo = 1;

    return .{ default_mesh_prefix[0], default_mesh_prefix[1], host_lo, host_hi };
}

/// Format a mesh IP as a CIDR string (e.g., "10.99.42.100/16").
pub fn formatCidr(ip: [4]u8, mask: u8, buf: []u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}/{d}", .{
        ip[0], ip[1], ip[2], ip[3], mask,
    }) catch return "?.?.?.?/?";
    return result;
}

/// Format a mesh IP as a plain dotted-quad string.
pub fn formatIp(ip: [4]u8, buf: []u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        ip[0], ip[1], ip[2], ip[3],
    }) catch return "?.?.?.?";
    return result;
}

/// Convert a 4-byte IP to a 32-bit integer (network byte order).
pub fn toU32(ip: [4]u8) u32 {
    return @as(u32, ip[0]) << 24 | @as(u32, ip[1]) << 16 | @as(u32, ip[2]) << 8 | @as(u32, ip[3]);
}

/// Convert a 32-bit integer to a 4-byte IP.
pub fn fromU32(val: u32) [4]u8 {
    return .{
        @truncate(val >> 24),
        @truncate(val >> 16),
        @truncate(val >> 8),
        @truncate(val),
    };
}

// ─── Tests ───

test "derived IPs are deterministic" {
    const kp = try Keys.generate();
    const ip1 = deriveFromPubkey(kp.public_key);
    const ip2 = deriveFromPubkey(kp.public_key);
    try std.testing.expectEqualSlices(u8, &ip1, &ip2);
}

test "derived IPs use correct prefix" {
    const kp = try Keys.generate();
    const ip = deriveFromPubkey(kp.public_key);
    try std.testing.expectEqual(ip[0], 10);
    try std.testing.expectEqual(ip[1], 99);
}

test "derived IPs avoid reserved addresses" {
    // Generate many keys and check none produce .0 or .255
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const kp = try Keys.generate();
        const ip = deriveFromPubkey(kp.public_key);
        try std.testing.expect(ip[2] != 0);
        try std.testing.expect(ip[3] != 0);
        try std.testing.expect(ip[3] != 255);
    }
}

test "CIDR formatting" {
    var buf: [18]u8 = undefined;
    const ip = [4]u8{ 10, 99, 42, 100 };
    const result = formatCidr(ip, 16, &buf);
    try std.testing.expectEqualStrings("10.99.42.100/16", result);
}

test "u32 roundtrip" {
    const ip = [4]u8{ 10, 99, 42, 100 };
    const val = toU32(ip);
    const back = fromU32(val);
    try std.testing.expectEqualSlices(u8, &ip, &back);
}
