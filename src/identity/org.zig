//! Organization trust management for meshguard.
//!
//! Provides hierarchical trust: an org Ed25519 keypair signs
//! NodeCertificates for member nodes. Any peer trusting the org
//! automatically trusts all nodes with valid certs.
//!
//! Deterministic mesh DNS:
//!   org_pubkey → Blake3[0..3].hex() → "*.a1b2c3.mesh"

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

// ─── Types ───

pub const OrgKeyPair = struct {
    public_key: Ed25519.PublicKey,
    secret_key: Ed25519.SecretKey,
};

/// Fixed-size node certificate signed by an org key.
/// Total: 186 bytes on the wire.
pub const NodeCertificate = struct {
    version: u8 = 1,
    org_pubkey: [32]u8,
    node_pubkey: [32]u8,
    node_name: [32]u8, // DNS label, null-padded
    issued_at: i64,
    expires_at: i64, // 0 = never
    flags: u8 = 0, // reserved
    signature: [64]u8 = std.mem.zeroes([64]u8),

    pub const WIRE_SIZE: usize = 186;

    /// The portion of the cert that is signed (everything except signature + padding).
    /// version(1) + org_pubkey(32) + node_pubkey(32) + node_name(32) + issued_at(8) + expires_at(8) + flags(1) = 114 bytes
    const SIGNED_LEN: usize = 114;

    /// Serialize to a fixed-size wire buffer.
    pub fn serialize(self: *const NodeCertificate, out: *[WIRE_SIZE]u8) void {
        var pos: usize = 0;
        out[pos] = self.version;
        pos += 1;
        @memcpy(out[pos..][0..32], &self.org_pubkey);
        pos += 32;
        @memcpy(out[pos..][0..32], &self.node_pubkey);
        pos += 32;
        @memcpy(out[pos..][0..32], &self.node_name);
        pos += 32;
        std.mem.writeInt(i64, out[pos..][0..8], self.issued_at, .little);
        pos += 8;
        std.mem.writeInt(i64, out[pos..][0..8], self.expires_at, .little);
        pos += 8;
        out[pos] = self.flags;
        pos += 1;
        @memcpy(out[pos..][0..64], &self.signature);
        pos += 64;
        // Padding
        @memset(out[pos..WIRE_SIZE], 0);
    }

    /// Deserialize from a wire buffer.
    pub fn deserialize(data: *const [WIRE_SIZE]u8) NodeCertificate {
        var pos: usize = 0;
        const version = data[pos];
        pos += 1;
        const org_pubkey = data[pos..][0..32].*;
        pos += 32;
        const node_pubkey = data[pos..][0..32].*;
        pos += 32;
        const node_name = data[pos..][0..32].*;
        pos += 32;
        const issued_at = std.mem.readInt(i64, data[pos..][0..8], .little);
        pos += 8;
        const expires_at = std.mem.readInt(i64, data[pos..][0..8], .little);
        pos += 8;
        const flags = data[pos];
        pos += 1;
        const signature = data[pos..][0..64].*;

        return .{
            .version = version,
            .org_pubkey = org_pubkey,
            .node_pubkey = node_pubkey,
            .node_name = node_name,
            .issued_at = issued_at,
            .expires_at = expires_at,
            .flags = flags,
            .signature = signature,
        };
    }

    /// Extract the signed payload (for signing/verification).
    fn signedPayload(self: *const NodeCertificate) [SIGNED_LEN]u8 {
        var buf: [SIGNED_LEN]u8 = undefined;
        var pos: usize = 0;
        buf[pos] = self.version;
        pos += 1;
        @memcpy(buf[pos..][0..32], &self.org_pubkey);
        pos += 32;
        @memcpy(buf[pos..][0..32], &self.node_pubkey);
        pos += 32;
        @memcpy(buf[pos..][0..32], &self.node_name);
        pos += 32;
        std.mem.writeInt(i64, buf[pos..][0..8], self.issued_at, .little);
        pos += 8;
        std.mem.writeInt(i64, buf[pos..][0..8], self.expires_at, .little);
        pos += 8;
        buf[pos] = self.flags;
        return buf;
    }

    /// Check if certificate is expired. Returns true if valid.
    pub fn isValid(self: *const NodeCertificate) bool {
        if (self.version != 1) return false;
        if (self.expires_at == 0) return true; // never expires
        return std.time.timestamp() < self.expires_at;
    }

    /// Get the node name as a trimmed string (strips null padding).
    pub fn getName(self: *const NodeCertificate) []const u8 {
        return std.mem.trimRight(u8, &self.node_name, "\x00");
    }
};

// ─── Org Keypair Management ───

/// Generate a new org Ed25519 keypair.
pub fn generateOrgKeyPair() OrgKeyPair {
    const kp = Ed25519.KeyPair.generate();
    return .{
        .public_key = kp.public_key,
        .secret_key = kp.secret_key,
    };
}

/// Save an org keypair to the config_dir/org/ directory.
pub fn saveOrgKeyPair(allocator: std.mem.Allocator, config_dir: []const u8, kp: OrgKeyPair) !void {
    const org_dir = try std.fs.path.join(allocator, &.{ config_dir, "org" });
    defer allocator.free(org_dir);
    std.fs.makeDirAbsolute(org_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    // Save secret key (base64, 0o600 permissions)
    const sk_path = try std.fs.path.join(allocator, &.{ org_dir, "org.key" });
    defer allocator.free(sk_path);

    var sk_buf: [88]u8 = undefined;
    const sk_b64 = std.base64.standard.Encoder.encode(&sk_buf, &kp.secret_key.toBytes());

    const sk_file = try std.fs.createFileAbsolute(sk_path, .{});
    defer sk_file.close();
    sk_file.chmod(0o600) catch {};
    try sk_file.writeAll(sk_b64);
    try sk_file.writeAll("\n");

    // Save public key
    const pk_path = try std.fs.path.join(allocator, &.{ org_dir, "org.pub" });
    defer allocator.free(pk_path);

    var pk_buf: [44]u8 = undefined;
    const pk_b64 = std.base64.standard.Encoder.encode(&pk_buf, &kp.public_key.toBytes());

    const pk_file = try std.fs.createFileAbsolute(pk_path, .{});
    defer pk_file.close();
    try pk_file.writeAll(pk_b64);
    try pk_file.writeAll("\n");
}

/// Load an org keypair from config_dir/org/.
pub fn loadOrgKeyPair(allocator: std.mem.Allocator, config_dir: []const u8) !OrgKeyPair {
    const sk_path = try std.fs.path.join(allocator, &.{ config_dir, "org", "org.key" });
    defer allocator.free(sk_path);

    const sk_file = try std.fs.openFileAbsolute(sk_path, .{});
    defer sk_file.close();

    var sk_raw: [89]u8 = undefined;
    const sk_read = try sk_file.readAll(&sk_raw);
    const sk_b64 = std.mem.trimRight(u8, sk_raw[0..sk_read], "\n\r ");

    var sk_bytes: [64]u8 = undefined;
    try std.base64.standard.Decoder.decode(&sk_bytes, sk_b64);

    const pk_path = try std.fs.path.join(allocator, &.{ config_dir, "org", "org.pub" });
    defer allocator.free(pk_path);

    const pk_file = try std.fs.openFileAbsolute(pk_path, .{});
    defer pk_file.close();

    var pk_raw: [45]u8 = undefined;
    const pk_read = try pk_file.readAll(&pk_raw);
    const pk_b64 = std.mem.trimRight(u8, pk_raw[0..pk_read], "\n\r ");

    var pk_bytes: [32]u8 = undefined;
    try std.base64.standard.Decoder.decode(&pk_bytes, pk_b64);

    return .{
        .secret_key = try Ed25519.SecretKey.fromBytes(sk_bytes),
        .public_key = try Ed25519.PublicKey.fromBytes(pk_bytes),
    };
}

// ─── Certificate Signing/Verification ───

/// Sign a node certificate with the org's private key.
pub fn signCertificate(cert: *NodeCertificate, org_secret: Ed25519.SecretKey) !void {
    const payload = cert.signedPayload();
    const kp = try Ed25519.KeyPair.fromSecretKey(org_secret);
    const sig = try kp.sign(&payload, null);
    cert.signature = sig.toBytes();
}

/// Verify a node certificate's signature against the embedded org public key.
pub fn verifyCertificate(cert: *const NodeCertificate) bool {
    const payload = cert.signedPayload();
    const org_pk = Ed25519.PublicKey.fromBytes(cert.org_pubkey) catch return false;
    const sig = Ed25519.Signature.fromBytes(cert.signature);
    sig.verify(&payload, org_pk) catch return false;
    return true;
}

/// Create and sign a NodeCertificate for a node.
pub fn issueCertificate(
    org_kp: OrgKeyPair,
    node_pubkey: [32]u8,
    name: []const u8,
    expires_at: i64,
) !NodeCertificate {
    var node_name: [32]u8 = std.mem.zeroes([32]u8);
    const copy_len = @min(name.len, 32);
    @memcpy(node_name[0..copy_len], name[0..copy_len]);

    var cert = NodeCertificate{
        .org_pubkey = org_kp.public_key.toBytes(),
        .node_pubkey = node_pubkey,
        .node_name = node_name,
        .issued_at = std.time.timestamp(),
        .expires_at = expires_at,
    };

    try signCertificate(&cert, org_kp.secret_key);
    return cert;
}

// ─── Deterministic Mesh DNS ───

/// Derive a deterministic org domain from its public key.
/// Returns 6 hex chars: Blake3(pubkey)[0..3] → "a1b2c3"
pub fn deriveOrgDomain(org_pubkey: [32]u8) [6]u8 {
    var hash: [32]u8 = undefined;
    Blake3.hash(&org_pubkey, &hash, .{});
    const hex_chars = "0123456789abcdef";
    return .{
        hex_chars[hash[0] >> 4], hex_chars[hash[0] & 0xf],
        hex_chars[hash[1] >> 4], hex_chars[hash[1] & 0xf],
        hex_chars[hash[2] >> 4], hex_chars[hash[2] & 0xf],
    };
}

/// Format a full mesh domain: "node-1.a1b2c3.mesh"
pub fn formatMeshDomain(node_name: []const u8, org_domain: [6]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}.{s}.mesh", .{ node_name, org_domain }) catch return "?.mesh";
}

// ─── Certificate File I/O ───

/// Save a certificate to a file (binary, WIRE_SIZE bytes).
pub fn saveCertificate(allocator: std.mem.Allocator, path: []const u8, cert: *const NodeCertificate) !void {
    _ = allocator;
    var wire: [NodeCertificate.WIRE_SIZE]u8 = undefined;
    cert.serialize(&wire);
    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();
    try file.writeAll(&wire);
}

/// Load a certificate from a file.
pub fn loadCertificate(allocator: std.mem.Allocator, path: []const u8) !NodeCertificate {
    _ = allocator;
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var wire: [NodeCertificate.WIRE_SIZE]u8 = undefined;
    const n = try file.readAll(&wire);
    if (n < NodeCertificate.WIRE_SIZE) return error.InvalidCertificate;
    return NodeCertificate.deserialize(&wire);
}

// ─── Tests ───

test "org keygen and cert sign/verify" {
    const org_kp = generateOrgKeyPair();
    const node_kp = Ed25519.KeyPair.generate();

    var cert = try issueCertificate(
        org_kp,
        node_kp.public_key.toBytes(),
        "test-node",
        0, // never expires
    );

    // Verify round-trip
    try std.testing.expect(verifyCertificate(&cert));
    try std.testing.expect(cert.isValid());
    try std.testing.expectEqualStrings("test-node", cert.getName());

    // Tamper with cert → verification fails
    cert.node_name[0] = 'X';
    try std.testing.expect(!verifyCertificate(&cert));
}

test "cert serialize/deserialize round-trip" {
    const org_kp = generateOrgKeyPair();
    const node_kp = Ed25519.KeyPair.generate();

    const cert = try issueCertificate(
        org_kp,
        node_kp.public_key.toBytes(),
        "my-server",
        1700000000,
    );

    var wire: [NodeCertificate.WIRE_SIZE]u8 = undefined;
    cert.serialize(&wire);

    const restored = NodeCertificate.deserialize(&wire);
    try std.testing.expect(verifyCertificate(&restored));
    try std.testing.expectEqual(cert.issued_at, restored.issued_at);
    try std.testing.expectEqual(cert.expires_at, restored.expires_at);
    try std.testing.expectEqualStrings(cert.getName(), restored.getName());
}

test "deterministic org domain" {
    const org_kp = generateOrgKeyPair();
    const domain1 = deriveOrgDomain(org_kp.public_key.toBytes());
    const domain2 = deriveOrgDomain(org_kp.public_key.toBytes());
    try std.testing.expectEqualSlices(u8, &domain1, &domain2);

    // Different org → different domain
    const org_kp2 = generateOrgKeyPair();
    const domain3 = deriveOrgDomain(org_kp2.public_key.toBytes());
    try std.testing.expect(!std.mem.eql(u8, &domain1, &domain3));
}

test "format mesh domain" {
    var buf: [64]u8 = undefined;
    const result = formatMeshDomain("node-1", .{ 'a', '1', 'b', '2', 'c', '3' }, &buf);
    try std.testing.expectEqualStrings("node-1.a1b2c3.mesh", result);
}
