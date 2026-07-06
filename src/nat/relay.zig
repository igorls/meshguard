//! Mesh relay logic for peers behind symmetric NAT.
//!
//! When hole punching fails (both peers behind symmetric NAT), a public-IP
//! mesh member can relay WireGuard traffic. Since WG provides E2E encryption,
//! the relay only sees ciphertext.
//!
//! Architecture:
//!   Node A (NATed) ←WG→ Relay (public) ←WG→ Node B (NATed)
//!
//! The relay is just another WG peer — no special protocol needed. Both NATed
//! peers add the relay as their WG peer. The relay adds both NATed peers.
//! WG handles routing based on AllowedIPs.

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const Membership = @import("../discovery/membership.zig");
const keys = @import("../identity/keys.zig");

/// Relay node info.
pub const RelayInfo = struct {
    /// Whether this node can serve as a relay
    is_relay_capable: bool,
    /// Number of active relay connections
    active_relay_count: u16,
    /// Max relay connections allowed
    max_relay_peers: u16,
};

/// Maximum relay connections per node (default).
pub const DEFAULT_MAX_RELAY_PEERS: u16 = 10;
pub const MAX_RENDEZVOUS_RECORDS: usize = 64;
pub const MAX_RELAY_PAYLOAD: usize = 2048;
pub const RELAY_FRAME_HEADER_SIZE: usize = 1 + 32 + 32 + 2;
pub const REGISTRATION_NONCE_SIZE: usize = 32;
pub const REGISTRATION_SIGNED_SIZE: usize = 32 + 1 + 16 + 2 + REGISTRATION_NONCE_SIZE;
const CHALLENGE_TTL_NS: i128 = 60 * std.time.ns_per_s;
const REGISTER_MIN_INTERVAL_NS: i128 = std.time.ns_per_s;

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub const RelayError = error{
    BufferTooShort,
    InvalidFrame,
    PayloadTooLarge,
    NotWireGuardCiphertext,
    NoChallenge,
    ChallengeExpired,
    InvalidSignature,
    RateLimited,
    RegistryFull,
};

pub const RelayPath = enum {
    direct,
    holepunch,
    relay,
    unavailable,
};

pub const DecodedRelayData = struct {
    sender_pubkey: [32]u8,
    target_pubkey: [32]u8,
    payload: []const u8,
};

pub const RendezvousRecord = struct {
    pubkey: [32]u8,
    endpoint: ?messages.Endpoint = null,
    challenge: [REGISTRATION_NONCE_SIZE]u8 = .{0} ** REGISTRATION_NONCE_SIZE,
    challenge_issued_ns: i128 = 0,
    registered_at_ns: i128 = 0,
};

const RateEntry = struct {
    pubkey: [32]u8,
    tokens: f64,
    last_refill_ns: i128,
};

pub const IdentityRateLimiter = struct {
    pub const BURST_TOKENS: usize = 100;
    const RATE_PER_SEC: f64 = 50.0;
    const BURST: f64 = @floatFromInt(BURST_TOKENS);

    entries: [MAX_RENDEZVOUS_RECORDS]?RateEntry = .{null} ** MAX_RENDEZVOUS_RECORDS,

    pub fn allow(self: *IdentityRateLimiter, pubkey: [32]u8, now_ns: i128) bool {
        const slot = self.findOrInsert(pubkey, now_ns) orelse return false;
        var entry = &self.entries[slot].?;
        const elapsed_ns = @max(now_ns - entry.last_refill_ns, 0);
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        entry.tokens = @min(BURST, entry.tokens + elapsed_s * RATE_PER_SEC);
        entry.last_refill_ns = now_ns;
        if (entry.tokens < 1.0) return false;
        entry.tokens -= 1.0;
        return true;
    }

    fn findOrInsert(self: *IdentityRateLimiter, pubkey: [32]u8, now_ns: i128) ?usize {
        var empty: ?usize = null;
        for (&self.entries, 0..) |*entry, i| {
            if (entry.*) |e| {
                if (std.mem.eql(u8, &e.pubkey, &pubkey)) return i;
            } else if (empty == null) {
                empty = i;
            }
        }
        const slot = empty orelse return null;
        self.entries[slot] = .{
            .pubkey = pubkey,
            .tokens = BURST,
            .last_refill_ns = now_ns,
        };
        return slot;
    }
};

pub const RendezvousRegistry = struct {
    records: [MAX_RENDEZVOUS_RECORDS]?RendezvousRecord = .{null} ** MAX_RENDEZVOUS_RECORDS,

    pub fn issueChallenge(self: *RendezvousRegistry, pubkey: [32]u8, now_ns: i128) RelayError![REGISTRATION_NONCE_SIZE]u8 {
        const slot = self.findOrInsert(pubkey) orelse return error.RegistryFull;
        var challenge: [REGISTRATION_NONCE_SIZE]u8 = undefined;
        zio().random(&challenge);
        if (self.records[slot]) |*record| {
            record.challenge = challenge;
            record.challenge_issued_ns = now_ns;
        } else {
            self.records[slot] = .{
                .pubkey = pubkey,
                .challenge = challenge,
                .challenge_issued_ns = now_ns,
            };
        }
        return challenge;
    }

    pub fn register(
        self: *RendezvousRegistry,
        pubkey: [32]u8,
        endpoint: messages.Endpoint,
        challenge: [REGISTRATION_NONCE_SIZE]u8,
        signature: [64]u8,
        now_ns: i128,
    ) RelayError!void {
        const slot = self.findSlot(pubkey) orelse return error.NoChallenge;
        var record = &self.records[slot].?;
        if (!std.mem.eql(u8, &record.challenge, &challenge)) return error.NoChallenge;
        if (now_ns - record.challenge_issued_ns > CHALLENGE_TTL_NS) return error.ChallengeExpired;
        if (record.endpoint != null and now_ns - record.registered_at_ns < REGISTER_MIN_INTERVAL_NS) return error.RateLimited;

        const signed = registrationSignedBytes(pubkey, endpoint, challenge);
        const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(pubkey) catch return error.InvalidSignature;
        if (!keys.verify(&signed, signature, pk)) return error.InvalidSignature;

        record.endpoint = endpoint;
        record.registered_at_ns = now_ns;
    }

    pub fn lookup(self: *const RendezvousRegistry, pubkey: [32]u8) ?messages.Endpoint {
        const slot = self.findSlot(pubkey) orelse return null;
        return self.records[slot].?.endpoint;
    }

    fn findSlot(self: *const RendezvousRegistry, pubkey: [32]u8) ?usize {
        for (self.records, 0..) |record, i| {
            if (record) |r| {
                if (std.mem.eql(u8, &r.pubkey, &pubkey)) return i;
            }
        }
        return null;
    }

    fn findOrInsert(self: *RendezvousRegistry, pubkey: [32]u8) ?usize {
        var empty: ?usize = null;
        for (&self.records, 0..) |*record, i| {
            if (record.*) |r| {
                if (std.mem.eql(u8, &r.pubkey, &pubkey)) return i;
            } else if (empty == null) {
                empty = i;
            }
        }
        return empty;
    }
};

pub fn registrationSignedBytes(
    pubkey: [32]u8,
    endpoint: messages.Endpoint,
    challenge: [REGISTRATION_NONCE_SIZE]u8,
) [REGISTRATION_SIGNED_SIZE]u8 {
    var out: [REGISTRATION_SIGNED_SIZE]u8 = undefined;
    var pos: usize = 0;
    @memcpy(out[pos..][0..32], &pubkey);
    pos += 32;
    if (endpoint.addr6) |addr6| {
        out[pos] = 6;
        pos += 1;
        @memcpy(out[pos..][0..16], &addr6);
    } else {
        out[pos] = 4;
        pos += 1;
        @memset(out[pos..][0..16], 0);
        @memcpy(out[pos..][0..4], &endpoint.addr);
    }
    pos += 16;
    std.mem.writeInt(u16, out[pos..][0..2], endpoint.port, .big);
    pos += 2;
    @memcpy(out[pos..][0..REGISTRATION_NONCE_SIZE], &challenge);
    return out;
}

pub fn isWireGuardCiphertext(payload: []const u8) bool {
    if (payload.len < 4) return false;
    const msg_type = std.mem.readInt(u32, payload[0..4], .little);
    return msg_type >= 1 and msg_type <= 4;
}

pub fn encodeRelayData(
    buf: []u8,
    sender_pubkey: [32]u8,
    target_pubkey: [32]u8,
    payload: []const u8,
) RelayError!usize {
    if (!isWireGuardCiphertext(payload)) return error.NotWireGuardCiphertext;
    if (payload.len > MAX_RELAY_PAYLOAD or payload.len > std.math.maxInt(u16)) return error.PayloadTooLarge;
    const required = RELAY_FRAME_HEADER_SIZE + payload.len;
    if (buf.len < required) return error.BufferTooShort;

    var pos: usize = 0;
    buf[pos] = @intFromEnum(messages.MessageType.relay_data);
    pos += 1;
    @memcpy(buf[pos..][0..32], &sender_pubkey);
    pos += 32;
    @memcpy(buf[pos..][0..32], &target_pubkey);
    pos += 32;
    std.mem.writeInt(u16, buf[pos..][0..2], @intCast(payload.len), .big);
    pos += 2;
    @memcpy(buf[pos..][0..payload.len], payload);
    return required;
}

pub fn decodeRelayData(data: []const u8) RelayError!DecodedRelayData {
    if (data.len < RELAY_FRAME_HEADER_SIZE) return error.BufferTooShort;
    if (data[0] != @intFromEnum(messages.MessageType.relay_data)) return error.InvalidFrame;
    var pos: usize = 1;
    var sender_pubkey: [32]u8 = undefined;
    @memcpy(&sender_pubkey, data[pos..][0..32]);
    pos += 32;
    var target_pubkey: [32]u8 = undefined;
    @memcpy(&target_pubkey, data[pos..][0..32]);
    pos += 32;
    const payload_len = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;
    if (payload_len > MAX_RELAY_PAYLOAD) return error.PayloadTooLarge;
    if (data.len != pos + payload_len) return error.InvalidFrame;
    const payload = data[pos..][0..payload_len];
    if (!isWireGuardCiphertext(payload)) return error.NotWireGuardCiphertext;
    return .{
        .sender_pubkey = sender_pubkey,
        .target_pubkey = target_pubkey,
        .payload = payload,
    };
}

pub fn choosePath(
    our_nat: messages.NatType,
    peer_nat: messages.NatType,
    has_peer_endpoint: bool,
    relay_available: bool,
) RelayPath {
    if (has_peer_endpoint and (our_nat == .public or peer_nat == .public)) return .direct;
    if (has_peer_endpoint and our_nat == .cone and peer_nat == .cone) return .holepunch;
    if (relay_available) return .relay;
    return .unavailable;
}

/// Check if this node can serve as a relay.
pub fn selfRelayInfo(nat_type: messages.NatType, active_count: u16, max_peers: u16) RelayInfo {
    return .{
        .is_relay_capable = nat_type == .public and active_count < max_peers,
        .active_relay_count = active_count,
        .max_relay_peers = max_peers,
    };
}

/// Select the best relay candidate from known peers.
/// Prefers peers that are:
///   1. Public (no NAT)
///   2. Relay-capable (not at capacity)
///   3. Lowest RTT (closest)
pub fn selectRelay(
    peers: *std.AutoHashMap([32]u8, Membership.Peer),
    exclude: ?[32]u8,
) ?*const Membership.Peer {
    return selectRelayForPair(peers, exclude, null);
}

pub fn selectRelayForPair(
    peers: *std.AutoHashMap([32]u8, Membership.Peer),
    exclude_a: ?[32]u8,
    exclude_b: ?[32]u8,
) ?*const Membership.Peer {
    var best: ?*const Membership.Peer = null;
    var best_rtt: u64 = std.math.maxInt(u64);

    var iter = peers.iterator();
    while (iter.next()) |entry| {
        const peer = entry.value_ptr;

        // Skip endpoints involved in the relayed pair.
        if (exclude_a) |ex| {
            if (std.mem.eql(u8, &peer.pubkey, &ex)) continue;
        }
        if (exclude_b) |ex| {
            if (std.mem.eql(u8, &peer.pubkey, &ex)) continue;
        }

        // Must be alive and relay-capable
        if (peer.state != .alive) continue;
        if (!peer.is_relay_capable) continue;
        if (peer.nat_type != .public) continue;

        // Prefer lowest RTT
        if (peer.last_rtt_ns) |rtt| {
            if (rtt < best_rtt) {
                best_rtt = rtt;
                best = peer;
            }
        } else if (best == null) {
            // No RTT data, but it's the only candidate
            best = peer;
        }
    }

    return best;
}

// ─── Tests ───

test "selfRelayInfo public node" {
    const info = selfRelayInfo(.public, 3, 10);
    try std.testing.expect(info.is_relay_capable);
    try std.testing.expectEqual(info.active_relay_count, 3);
}

test "selfRelayInfo NATed node" {
    const info = selfRelayInfo(.cone, 0, 10);
    try std.testing.expect(!info.is_relay_capable);
}

test "selfRelayInfo at capacity" {
    const info = selfRelayInfo(.public, 10, 10);
    try std.testing.expect(!info.is_relay_capable);
}

test "choosePath prefers direct then punch then relay" {
    try std.testing.expectEqual(RelayPath.direct, choosePath(.public, .cone, true, true));
    try std.testing.expectEqual(RelayPath.direct, choosePath(.cone, .public, true, true));
    try std.testing.expectEqual(RelayPath.holepunch, choosePath(.cone, .cone, true, true));
    try std.testing.expectEqual(RelayPath.relay, choosePath(.symmetric, .symmetric, true, true));
    try std.testing.expectEqual(RelayPath.relay, choosePath(.unknown, .cone, false, true));
    try std.testing.expectEqual(RelayPath.unavailable, choosePath(.symmetric, .symmetric, true, false));
}

test "relay frame carries only opaque WireGuard packet types" {
    const sender = [_]u8{0xAA} ** 32;
    const target = [_]u8{0xBB} ** 32;
    var wg_payload = [_]u8{0} ** 32;
    std.mem.writeInt(u32, wg_payload[0..4], 4, .little);

    var buf: [RELAY_FRAME_HEADER_SIZE + wg_payload.len]u8 = undefined;
    const len = try encodeRelayData(&buf, sender, target, &wg_payload);
    const decoded = try decodeRelayData(buf[0..len]);
    try std.testing.expectEqualSlices(u8, &sender, &decoded.sender_pubkey);
    try std.testing.expectEqualSlices(u8, &target, &decoded.target_pubkey);
    try std.testing.expectEqualSlices(u8, &wg_payload, decoded.payload);

    var plaintext = [_]u8{ 0x50, 0x4c, 0x41, 0x49 }; // "PLAI", not WG type 1-4
    try std.testing.expectError(error.NotWireGuardCiphertext, encodeRelayData(&buf, sender, target, &plaintext));
}

test "rendezvous registration requires signed challenge" {
    const kp = keys.generate();
    const pubkey = kp.public_key.toBytes();
    const endpoint = messages.Endpoint.initV4(.{ 203, 0, 113, 7 }, 51821);

    var registry = RendezvousRegistry{};
    const challenge = try registry.issueChallenge(pubkey, 1);
    const signed = registrationSignedBytes(pubkey, endpoint, challenge);
    const signature = try keys.sign(&signed, kp.secret_key);

    try registry.register(pubkey, endpoint, challenge, signature, 2);
    try std.testing.expect(messages.Endpoint.eql(endpoint, registry.lookup(pubkey).?));

    var bad_sig = signature;
    bad_sig[0] ^= 0xff;
    try std.testing.expectError(error.RateLimited, registry.register(pubkey, endpoint, challenge, signature, 3));

    const challenge2 = try registry.issueChallenge(pubkey, REGISTER_MIN_INTERVAL_NS + 10);
    const signed2 = registrationSignedBytes(pubkey, endpoint, challenge2);
    try std.testing.expectError(error.InvalidSignature, registry.register(pubkey, endpoint, challenge2, bad_sig, REGISTER_MIN_INTERVAL_NS + 11));
    try registry.register(pubkey, endpoint, challenge2, try keys.sign(&signed2, kp.secret_key), REGISTER_MIN_INTERVAL_NS + 11);
}

test "identity rate limiter is per identity" {
    var limiter = IdentityRateLimiter{};
    const a = [_]u8{0xAA} ** 32;
    const b = [_]u8{0xBB} ** 32;

    for (0..IdentityRateLimiter.BURST_TOKENS) |_| {
        try std.testing.expect(limiter.allow(a, 0));
    }
    try std.testing.expect(!limiter.allow(a, 0));
    try std.testing.expect(limiter.allow(b, 0));
    try std.testing.expect(limiter.allow(a, std.time.ns_per_s));
}
