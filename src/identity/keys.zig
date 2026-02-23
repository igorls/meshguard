//! Ed25519 identity key management for meshguard.
//!
//! Each node has a persistent Ed25519 keypair used for:
//! - Signing gossip messages
//! - Mutual authentication handshakes
//! - Deriving deterministic mesh IPs

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const PublicKey = Ed25519.PublicKey;
pub const SecretKey = Ed25519.SecretKey;

pub const KeyPair = struct {
    public_key: PublicKey,
    secret_key: SecretKey,
};

/// Generate a new Ed25519 identity keypair.
pub fn generate() KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return KeyPair{
        .public_key = kp.public_key,
        .secret_key = kp.secret_key,
    };
}

/// Save an identity keypair to the config directory.
///   config_dir/identity.key  — secret key (64 bytes, base64-encoded)
///   config_dir/identity.pub  — public key (32 bytes, base64-encoded)
pub fn save(allocator: std.mem.Allocator, config_dir: []const u8, kp: KeyPair) !void {
    // Save secret key
    const sk_path = try std.fs.path.join(allocator, &.{ config_dir, "identity.key" });
    defer allocator.free(sk_path);

    var sk_buf: [88]u8 = undefined;
    const sk_b64 = std.base64.standard.Encoder.encode(&sk_buf, &kp.secret_key.toBytes());

    const sk_file = try std.fs.createFileAbsolute(sk_path, .{});
    defer sk_file.close();
    // Restrict permissions to owner-only (0o600)
    sk_file.chmod(0o600) catch {};
    try sk_file.writeAll(sk_b64);
    try sk_file.writeAll("\n");

    // Save public key
    const pk_path = try std.fs.path.join(allocator, &.{ config_dir, "identity.pub" });
    defer allocator.free(pk_path);

    var pk_buf: [44]u8 = undefined;
    const pk_b64 = std.base64.standard.Encoder.encode(&pk_buf, &kp.public_key.toBytes());

    const pk_file = try std.fs.createFileAbsolute(pk_path, .{});
    defer pk_file.close();
    try pk_file.writeAll(pk_b64);
    try pk_file.writeAll("\n");
}

/// Load an existing identity keypair from the config directory.
pub fn load(allocator: std.mem.Allocator, config_dir: []const u8) !KeyPair {
    // Load secret key
    const sk_path = try std.fs.path.join(allocator, &.{ config_dir, "identity.key" });
    defer allocator.free(sk_path);

    const sk_file = try std.fs.openFileAbsolute(sk_path, .{});
    defer sk_file.close();

    var sk_raw: [89]u8 = undefined; // 88 b64 chars + possible newline
    const sk_read = try sk_file.readAll(&sk_raw);
    const sk_b64 = std.mem.trimRight(u8, sk_raw[0..sk_read], "\n\r ");

    var sk_bytes: [64]u8 = undefined;
    try std.base64.standard.Decoder.decode(&sk_bytes, sk_b64);

    const secret_key = try SecretKey.fromBytes(sk_bytes);

    // Load public key
    const pk_path = try std.fs.path.join(allocator, &.{ config_dir, "identity.pub" });
    defer allocator.free(pk_path);

    const pk_file = try std.fs.openFileAbsolute(pk_path, .{});
    defer pk_file.close();

    var pk_raw: [45]u8 = undefined; // 44 b64 chars + possible newline
    const pk_read = try pk_file.readAll(&pk_raw);
    const pk_b64 = std.mem.trimRight(u8, pk_raw[0..pk_read], "\n\r ");

    var pk_bytes: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&pk_bytes, pk_b64);

    const public_key = try PublicKey.fromBytes(pk_bytes);

    return KeyPair{
        .public_key = public_key,
        .secret_key = secret_key,
    };
}

/// Sign a message with the node's identity key.
pub fn sign(message: []const u8, secret_key: SecretKey) ![64]u8 {
    const kp = try Ed25519.KeyPair.fromSecretKey(secret_key);
    const sig = try kp.sign(message, null);
    return sig.toBytes();
}

/// Verify a signed message against a public key.
pub fn verify(message: []const u8, signature_bytes: [64]u8, public_key: PublicKey) bool {
    const sig = Ed25519.Signature.fromBytes(signature_bytes);
    sig.verify(message, public_key) catch return false;
    return true;
}

/// Derive a deterministic mesh IP from a public key.
/// The mesh IP is 10.99.X.Y where X and Y come from a hash of the public key.
pub fn deriveMeshIp(public_key: PublicKey) [4]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&public_key.toBytes(), &hash, .{});
    return .{ 10, 99, hash[0], hash[1] };
}

/// Format a mesh IP as a human-readable string.
pub fn formatMeshIp(ip: [4]u8, buf: []u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return "?.?.?.?";
    return result;
}

// ─── Tests ───

test "keygen produces valid keypair" {
    const kp = generate();
    // Public key should be derivable from secret key
    const derived = try Ed25519.KeyPair.fromSecretKey(kp.secret_key);
    try std.testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &derived.public_key.toBytes());
}

test "sign and verify" {
    const kp = generate();
    const msg = "hello meshguard";
    const sig = try sign(msg, kp.secret_key);
    try std.testing.expect(verify(msg, sig, kp.public_key));
    try std.testing.expect(!verify("wrong message", sig, kp.public_key));
}

test "deterministic mesh IP" {
    const kp = generate();
    const ip1 = deriveMeshIp(kp.public_key);
    const ip2 = deriveMeshIp(kp.public_key);
    try std.testing.expectEqualSlices(u8, &ip1, &ip2);
    try std.testing.expectEqual(ip1[0], 10);
    try std.testing.expectEqual(ip1[1], 99);
}

test "mesh IP formatting" {
    var buf: [15]u8 = undefined;
    const ip = [4]u8{ 10, 99, 42, 200 };
    const result = formatMeshIp(ip, &buf);
    try std.testing.expectEqualStrings("10.99.42.200", result);
}
