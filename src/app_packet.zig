//! Portable MeshGuard 0x50 application packets. No sockets, clock, or RNG.
//! Entropy and peer admission are supplied by the host transport.
const std = @import("std");
const crypto = @import("wireguard/crypto.zig");
const X25519 = std.crypto.dh.X25519;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const max_payload = 1024;
pub const overhead = 93;
pub const max_packet = max_payload + overhead;

pub const Identity = struct {
    seed: [32]u8,
    public_key: [32]u8,
    wg_private: [32]u8,
    wg_public: [32]u8,

    pub fn fromSeed(seed: [32]u8) !Identity {
        var pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        // Preserve the existing FFI identity derivation exactly.
        var private = seed;
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        return .{ .seed = seed, .public_key = pair.public_key.toBytes(), .wg_private = private, .wg_public = try X25519.recoverPublicKey(private) };
    }

    pub fn clear(self: *Identity) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }

    pub fn sign(self: *const Identity, message: []const u8) ![64]u8 {
        var pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(self.seed);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        return (try pair.sign(message, null)).toBytes();
    }
};

pub fn verify(public_key: [32]u8, message: []const u8, signature: [64]u8) bool {
    const public = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    std.crypto.sign.Ed25519.Signature.fromBytes(signature).verify(message, public) catch return false;
    return true;
}

pub fn seal(sender: [32]u8, private: [32]u8, recipient: [32]u8, recipient_wg: [32]u8, nonce: [12]u8, plaintext: []const u8, out: []u8) !usize {
    if (plaintext.len > max_payload) return error.PayloadTooLarge;
    if (out.len < overhead + plaintext.len) return error.OutputTooSmall;
    var shared = try X25519.scalarmult(private, recipient_wg);
    defer std.crypto.secureZero(u8, &shared);
    var derived = crypto.kdf2(shared, "meshguard-app-v1");
    defer std.crypto.secureZero(u8, std.mem.asBytes(&derived));
    out[0] = 0x50;
    @memcpy(out[1..33], &recipient);
    @memcpy(out[33..65], &sender);
    @memcpy(out[65..77], &nonce);
    var tag: [16]u8 = undefined;
    Aead.encrypt(out[77..][0..plaintext.len], &tag, plaintext, &sender, nonce, derived.key);
    @memcpy(out[77 + plaintext.len ..][0..16], &tag);
    return overhead + plaintext.len;
}

pub const Opened = struct { sender: [32]u8, nonce: [12]u8, len: usize };

pub fn open(recipient: [32]u8, private: [32]u8, sender_wg: [32]u8, packet: []const u8, out: []u8) !Opened {
    if (packet.len < overhead or packet.len > max_packet or packet[0] != 0x50) return error.InvalidPacket;
    if (!std.mem.eql(u8, packet[1..33], &recipient)) return error.WrongRecipient;
    const length = packet.len - overhead;
    if (out.len < length) return error.OutputTooSmall;
    var shared = try X25519.scalarmult(private, sender_wg);
    defer std.crypto.secureZero(u8, &shared);
    var derived = crypto.kdf2(shared, "meshguard-app-v1");
    defer std.crypto.secureZero(u8, std.mem.asBytes(&derived));
    const sender: [32]u8 = packet[33..65].*;
    const nonce: [12]u8 = packet[65..77].*;
    const tag: [16]u8 = packet[77 + length ..][0..16].*;
    Aead.decrypt(out[0..length], packet[77..][0..length], tag, &sender, nonce, derived.key) catch {
        std.crypto.secureZero(u8, out[0..length]);
        return error.AuthenticationFailed;
    };
    return .{ .sender = sender, .nonce = nonce, .len = length };
}

test "portable packets authenticate recipient, sender and ciphertext" {
    var a = try Identity.fromSeed(.{1} ** 32);
    defer a.clear();
    var b = try Identity.fromSeed(.{2} ** 32);
    defer b.clear();
    var packet: [max_packet]u8 = undefined;
    const length = try seal(a.public_key, a.wg_private, b.public_key, b.wg_public, .{7} ** 12, "portable", &packet);
    var plain: [max_payload]u8 = undefined;
    const opened = try open(b.public_key, b.wg_private, a.wg_public, packet[0..length], &plain);
    try std.testing.expectEqualStrings("portable", plain[0..opened.len]);
    try std.testing.expectError(error.WrongRecipient, open(a.public_key, b.wg_private, a.wg_public, packet[0..length], &plain));
    packet[length - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, open(b.public_key, b.wg_private, a.wg_public, packet[0..length], &plain));
    for (plain[0..opened.len]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}
