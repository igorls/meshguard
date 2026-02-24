//! Binary codec for wire protocol messages.
//!
//! Format: [1B type][payload...]
//!
//! Ping:     [0x01][32B pubkey][8B seq][1B gossip_count][N × gossip_entry]
//! Ack:      [0x03][32B pubkey][8B seq][1B gossip_count][N × gossip_entry]
//! PingReq:  [0x02][32B sender][32B target][8B seq]
//!
//! GossipEntry: [32B subject][1B event][8B lamport][1B has_ep][4B addr][2B port]

const std = @import("std");
const messages = @import("messages.zig");

const GOSSIP_ENTRY_SIZE = 32 + 1 + 8 + 1 + 4 + 2 + 1 + 32 + 1 + 4 + 2 + 1; // 89 bytes

// ─── Encoding ───

/// Encode a Ping message into a buffer. Returns bytes written.
pub fn encodePing(buf: []u8, ping: messages.Ping) !usize {
    var pos: usize = 0;

    // Type tag
    buf[pos] = @intFromEnum(messages.MessageType.ping);
    pos += 1;

    // Pubkey
    @memcpy(buf[pos..][0..32], &ping.sender_pubkey);
    pos += 32;

    // Sequence
    std.mem.writeInt(u64, buf[pos..][0..8], ping.seq, .little);
    pos += 8;

    // Gossip entries
    const gossip_count: u8 = @intCast(@min(ping.gossip.len, 255));
    buf[pos] = gossip_count;
    pos += 1;

    for (ping.gossip[0..gossip_count]) |entry| {
        pos += encodeGossipEntry(buf[pos..], entry);
    }

    return pos;
}

/// Encode an Ack message into a buffer. Returns bytes written.
pub fn encodeAck(buf: []u8, ack: messages.Ack) !usize {
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.ack);
    pos += 1;

    @memcpy(buf[pos..][0..32], &ack.sender_pubkey);
    pos += 32;

    std.mem.writeInt(u64, buf[pos..][0..8], ack.seq, .little);
    pos += 8;

    const gossip_count: u8 = @intCast(@min(ack.gossip.len, 255));
    buf[pos] = gossip_count;
    pos += 1;

    for (ack.gossip[0..gossip_count]) |entry| {
        pos += encodeGossipEntry(buf[pos..], entry);
    }

    return pos;
}

/// Encode a PingReq message.
pub fn encodePingReq(buf: []u8, req: messages.PingReq) !usize {
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.ping_req);
    pos += 1;

    @memcpy(buf[pos..][0..32], &req.sender_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &req.target_pubkey);
    pos += 32;

    std.mem.writeInt(u64, buf[pos..][0..8], req.seq, .little);
    pos += 8;

    return pos;
}

/// Encode a HolepunchRequest. Returns bytes written.
/// Wire: [0x33][32B sender][32B target][4B addr][2B port][16B token]
pub fn encodeHolepunchRequest(buf: []u8, req: messages.HolepunchRequest) !usize {
    if (buf.len < 1 + 32 + 32 + 4 + 2 + 16) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.holepunch_request);
    pos += 1;

    @memcpy(buf[pos..][0..32], &req.sender_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &req.target_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..4], &req.public_endpoint.addr);
    pos += 4;

    std.mem.writeInt(u16, buf[pos..][0..2], req.public_endpoint.port, .little);
    pos += 2;

    @memcpy(buf[pos..][0..16], &req.token);
    pos += 16;

    return pos;
}

/// Encode a HolepunchResponse. Returns bytes written.
/// Wire: [0x34][32B sender][4B addr][2B port][16B token_echo]
pub fn encodeHolepunchResponse(buf: []u8, resp: messages.HolepunchResponse) !usize {
    if (buf.len < 1 + 32 + 4 + 2 + 16) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.holepunch_response);
    pos += 1;

    @memcpy(buf[pos..][0..32], &resp.sender_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..4], &resp.public_endpoint.addr);
    pos += 4;

    std.mem.writeInt(u16, buf[pos..][0..2], resp.public_endpoint.port, .little);
    pos += 2;

    @memcpy(buf[pos..][0..16], &resp.token_echo);
    pos += 16;

    return pos;
}

// ─── Org Trust Encoding ───

/// Encode an OrgAliasAnnounce message.
/// Wire: [0x41][32B org_pubkey][32B alias][8B lamport][64B signature]
pub fn encodeOrgAliasAnnounce(buf: []u8, msg: messages.OrgAliasAnnounce) !usize {
    const required = 1 + 32 + 32 + 8 + 64;
    if (buf.len < required) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.org_alias_announce);
    pos += 1;

    @memcpy(buf[pos..][0..32], &msg.org_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &msg.alias);
    pos += 32;

    std.mem.writeInt(u64, buf[pos..][0..8], msg.lamport, .little);
    pos += 8;

    @memcpy(buf[pos..][0..64], &msg.signature);
    pos += 64;

    return pos;
}

/// Encode an OrgCertRevoke message.
/// Wire: [0x42][32B org_pubkey][32B node_pubkey][1B reason][8B lamport][64B signature]
pub fn encodeOrgCertRevoke(buf: []u8, msg: messages.OrgCertRevoke) !usize {
    const required = 1 + 32 + 32 + 1 + 8 + 64;
    if (buf.len < required) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.org_cert_revoke);
    pos += 1;

    @memcpy(buf[pos..][0..32], &msg.org_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &msg.node_pubkey);
    pos += 32;

    buf[pos] = msg.reason;
    pos += 1;

    std.mem.writeInt(u64, buf[pos..][0..8], msg.lamport, .little);
    pos += 8;

    @memcpy(buf[pos..][0..64], &msg.signature);
    pos += 64;

    return pos;
}

/// Encode an OrgTrustVouch message.
/// Wire: [0x43][32B org_pubkey][32B vouched_pubkey][8B lamport][64B signature]
pub fn encodeOrgTrustVouch(buf: []u8, msg: messages.OrgTrustVouch) !usize {
    const required = 1 + 32 + 32 + 8 + 64;
    if (buf.len < required) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @intFromEnum(messages.MessageType.org_trust_vouch);
    pos += 1;

    @memcpy(buf[pos..][0..32], &msg.org_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &msg.vouched_pubkey);
    pos += 32;

    std.mem.writeInt(u64, buf[pos..][0..8], msg.lamport, .little);
    pos += 8;

    @memcpy(buf[pos..][0..64], &msg.signature);
    pos += 64;

    return pos;
}

fn encodeGossipEntry(buf: []u8, entry: messages.GossipEntry) usize {
    var pos: usize = 0;

    @memcpy(buf[pos..][0..32], &entry.subject_pubkey);
    pos += 32;

    buf[pos] = @intFromEnum(entry.event);
    pos += 1;

    std.mem.writeInt(u64, buf[pos..][0..8], entry.lamport, .little);
    pos += 8;

    if (entry.endpoint) |ep| {
        buf[pos] = 1;
        pos += 1;
        @memcpy(buf[pos..][0..4], &ep.addr);
        pos += 4;
        std.mem.writeInt(u16, buf[pos..][0..2], ep.port, .little);
        pos += 2;
    } else {
        buf[pos] = 0;
        pos += 1;
        @memset(buf[pos..][0..6], 0);
        pos += 6;
    }

    // WG public key
    if (entry.wg_pubkey) |wg_key| {
        buf[pos] = 1;
        pos += 1;
        @memcpy(buf[pos..][0..32], &wg_key);
        pos += 32;
    } else {
        buf[pos] = 0;
        pos += 1;
        @memset(buf[pos..][0..32], 0);
        pos += 32;
    }

    // Public endpoint (STUN-discovered)
    if (entry.public_endpoint) |pub_ep| {
        buf[pos] = 1;
        pos += 1;
        @memcpy(buf[pos..][0..4], &pub_ep.addr);
        pos += 4;
        std.mem.writeInt(u16, buf[pos..][0..2], pub_ep.port, .little);
        pos += 2;
    } else {
        buf[pos] = 0;
        pos += 1;
        @memset(buf[pos..][0..6], 0);
        pos += 6;
    }

    // NAT type
    buf[pos] = @intFromEnum(entry.nat_type);
    pos += 1;

    return pos;
}

// ─── Decoding ───

pub const DecodeError = error{
    BufferTooShort,
    InvalidMessageType,
    InvalidGossipEvent,
};

/// Decoded message variant.
pub const DecodedMessage = union(enum) {
    ping: DecodedPing,
    ack: DecodedAck,
    ping_req: messages.PingReq,
    holepunch_request: messages.HolepunchRequest,
    holepunch_response: messages.HolepunchResponse,
    org_alias_announce: messages.OrgAliasAnnounce,
    org_cert_revoke: messages.OrgCertRevoke,
    org_trust_vouch: messages.OrgTrustVouch,
};

/// Decoded Ping with owned gossip slice.
pub const DecodedPing = struct {
    sender_pubkey: [32]u8,
    seq: u64,
    gossip_buf: [8]messages.GossipEntry = undefined,
    gossip_count: u8 = 0,

    pub fn gossip(self: *const DecodedPing) []const messages.GossipEntry {
        return self.gossip_buf[0..self.gossip_count];
    }
};

/// Decoded Ack with owned gossip slice.
pub const DecodedAck = struct {
    sender_pubkey: [32]u8,
    seq: u64,
    gossip_buf: [8]messages.GossipEntry = undefined,
    gossip_count: u8 = 0,

    pub fn gossip(self: *const DecodedAck) []const messages.GossipEntry {
        return self.gossip_buf[0..self.gossip_count];
    }
};

/// Decode a message from a wire buffer.
pub fn decode(data: []const u8) DecodeError!DecodedMessage {
    if (data.len < 1) return error.BufferTooShort;

    const msg_type = std.meta.intToEnum(messages.MessageType, data[0]) catch {
        return error.InvalidMessageType;
    };

    return switch (msg_type) {
        .ping => .{ .ping = try decodePing(data[1..]) },
        .ack => .{ .ack = try decodeAck(data[1..]) },
        .ping_req => .{ .ping_req = try decodePingReq(data[1..]) },
        .holepunch_request => .{ .holepunch_request = try decodeHolepunchRequest(data[1..]) },
        .holepunch_response => .{ .holepunch_response = try decodeHolepunchResponse(data[1..]) },
        .org_alias_announce => .{ .org_alias_announce = try decodeOrgAliasAnnounce(data[1..]) },
        .org_cert_revoke => .{ .org_cert_revoke = try decodeOrgCertRevoke(data[1..]) },
        .org_trust_vouch => .{ .org_trust_vouch = try decodeOrgTrustVouch(data[1..]) },
        else => error.InvalidMessageType,
    };
}

fn decodePing(data: []const u8) DecodeError!DecodedPing {
    if (data.len < 32 + 8 + 1) return error.BufferTooShort;

    var result = DecodedPing{
        .sender_pubkey = undefined,
        .seq = undefined,
    };

    @memcpy(&result.sender_pubkey, data[0..32]);
    result.seq = std.mem.readInt(u64, data[32..40], .little);

    const gossip_count = @min(data[40], 8);
    result.gossip_count = gossip_count;

    var pos: usize = 41;
    for (0..gossip_count) |i| {
        if (pos + GOSSIP_ENTRY_SIZE > data.len) break;
        result.gossip_buf[i] = decodeGossipEntry(data[pos..]) catch break;
        pos += GOSSIP_ENTRY_SIZE;
    }

    return result;
}

fn decodeAck(data: []const u8) DecodeError!DecodedAck {
    if (data.len < 32 + 8 + 1) return error.BufferTooShort;

    var result = DecodedAck{
        .sender_pubkey = undefined,
        .seq = undefined,
    };

    @memcpy(&result.sender_pubkey, data[0..32]);
    result.seq = std.mem.readInt(u64, data[32..40], .little);

    const gossip_count = @min(data[40], 8);
    result.gossip_count = gossip_count;

    var pos: usize = 41;
    for (0..gossip_count) |i| {
        if (pos + GOSSIP_ENTRY_SIZE > data.len) break;
        result.gossip_buf[i] = decodeGossipEntry(data[pos..]) catch break;
        pos += GOSSIP_ENTRY_SIZE;
    }

    return result;
}

fn decodePingReq(data: []const u8) DecodeError!messages.PingReq {
    if (data.len < 32 + 32 + 8) return error.BufferTooShort;

    var result: messages.PingReq = undefined;
    @memcpy(&result.sender_pubkey, data[0..32]);
    @memcpy(&result.target_pubkey, data[32..64]);
    result.seq = std.mem.readInt(u64, data[64..72], .little);

    return result;
}

fn decodeHolepunchRequest(data: []const u8) DecodeError!messages.HolepunchRequest {
    if (data.len < 32 + 32 + 4 + 2 + 16) return error.BufferTooShort;

    var result: messages.HolepunchRequest = undefined;
    @memcpy(&result.sender_pubkey, data[0..32]);
    @memcpy(&result.target_pubkey, data[32..64]);
    @memcpy(&result.public_endpoint.addr, data[64..68]);
    result.public_endpoint.port = std.mem.readInt(u16, data[68..70], .little);
    @memcpy(&result.token, data[70..86]);

    return result;
}

fn decodeHolepunchResponse(data: []const u8) DecodeError!messages.HolepunchResponse {
    if (data.len < 32 + 4 + 2 + 16) return error.BufferTooShort;

    var result: messages.HolepunchResponse = undefined;
    @memcpy(&result.sender_pubkey, data[0..32]);
    @memcpy(&result.public_endpoint.addr, data[32..36]);
    result.public_endpoint.port = std.mem.readInt(u16, data[36..38], .little);
    @memcpy(&result.token_echo, data[38..54]);

    return result;
}

fn decodeGossipEntry(data: []const u8) DecodeError!messages.GossipEntry {
    if (data.len < GOSSIP_ENTRY_SIZE) return error.BufferTooShort;

    var entry: messages.GossipEntry = .{
        .subject_pubkey = undefined,
        .event = undefined,
        .lamport = undefined,
        .endpoint = null,
        .wg_pubkey = null,
        .public_endpoint = null,
        .nat_type = .unknown,
    };
    @memcpy(&entry.subject_pubkey, data[0..32]);
    entry.event = std.meta.intToEnum(messages.MemberEvent, data[32]) catch return error.InvalidGossipEvent;
    entry.lamport = std.mem.readInt(u64, data[33..41], .little);

    if (data[41] == 1) {
        var addr: [4]u8 = undefined;
        @memcpy(&addr, data[42..46]);
        entry.endpoint = .{
            .addr = addr,
            .port = std.mem.readInt(u16, data[46..48], .little),
        };
    }

    // WG public key (byte 48 = has_wg, bytes 49..81 = key)
    if (data[48] == 1) {
        var wg_key: [32]u8 = undefined;
        @memcpy(&wg_key, data[49..81]);
        entry.wg_pubkey = wg_key;
    }

    // Public endpoint (byte 81 = has_pub_ep, bytes 82..88 = addr:port)
    if (data[81] == 1) {
        var pub_addr: [4]u8 = undefined;
        @memcpy(&pub_addr, data[82..86]);
        entry.public_endpoint = .{
            .addr = pub_addr,
            .port = std.mem.readInt(u16, data[86..88], .little),
        };
    }

    // NAT type (byte 88)
    entry.nat_type = std.meta.intToEnum(messages.NatType, data[88]) catch .unknown;

    return entry;
}

fn decodeOrgAliasAnnounce(data: []const u8) DecodeError!messages.OrgAliasAnnounce {
    if (data.len < 32 + 32 + 8 + 64) return error.BufferTooShort;

    var result: messages.OrgAliasAnnounce = undefined;
    @memcpy(&result.org_pubkey, data[0..32]);
    @memcpy(&result.alias, data[32..64]);
    result.lamport = std.mem.readInt(u64, data[64..72], .little);
    @memcpy(&result.signature, data[72..136]);

    return result;
}

fn decodeOrgCertRevoke(data: []const u8) DecodeError!messages.OrgCertRevoke {
    if (data.len < 32 + 32 + 1 + 8 + 64) return error.BufferTooShort;

    var result: messages.OrgCertRevoke = undefined;
    @memcpy(&result.org_pubkey, data[0..32]);
    @memcpy(&result.node_pubkey, data[32..64]);
    result.reason = data[64];
    result.lamport = std.mem.readInt(u64, data[65..73], .little);
    @memcpy(&result.signature, data[73..137]);

    return result;
}

fn decodeOrgTrustVouch(data: []const u8) DecodeError!messages.OrgTrustVouch {
    if (data.len < 32 + 32 + 8 + 64) return error.BufferTooShort;

    var result: messages.OrgTrustVouch = undefined;
    @memcpy(&result.org_pubkey, data[0..32]);
    @memcpy(&result.vouched_pubkey, data[32..64]);
    result.lamport = std.mem.readInt(u64, data[64..72], .little);
    @memcpy(&result.signature, data[72..136]);

    return result;
}

// ─── Tests ───

test "ping roundtrip" {
    const pubkey = [_]u8{0x42} ** 32;
    const ping = messages.Ping{
        .sender_pubkey = pubkey,
        .seq = 12345,
        .gossip = &.{},
    };

    var buf: [512]u8 = undefined;
    const written = try encodePing(&buf, ping);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ping => |p| {
            try std.testing.expectEqualSlices(u8, &pubkey, &p.sender_pubkey);
            try std.testing.expectEqual(p.seq, 12345);
            try std.testing.expectEqual(p.gossip_count, 0);
        },
        else => return error.InvalidMessageType,
    }
}

test "ack roundtrip" {
    const pubkey = [_]u8{0xAA} ** 32;
    const ack = messages.Ack{
        .sender_pubkey = pubkey,
        .seq = 99,
        .gossip = &.{},
    };

    var buf: [512]u8 = undefined;
    const written = try encodeAck(&buf, ack);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ack => |a| {
            try std.testing.expectEqual(a.seq, 99);
        },
        else => return error.InvalidMessageType,
    }
}

test "ping with gossip roundtrip" {
    const pubkey = [_]u8{0x01} ** 32;
    const subject = [_]u8{0x02} ** 32;

    const gossip = [_]messages.GossipEntry{.{
        .subject_pubkey = subject,
        .event = .alive,
        .lamport = 42,
        .endpoint = .{ .addr = .{ 10, 99, 1, 2 }, .port = 51821 },
    }};

    const ping = messages.Ping{
        .sender_pubkey = pubkey,
        .seq = 7,
        .gossip = &gossip,
    };

    var buf: [512]u8 = undefined;
    const written = try encodePing(&buf, ping);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ping => |p| {
            try std.testing.expectEqual(p.gossip_count, 1);
            const g = p.gossip();
            try std.testing.expectEqual(g[0].event, .alive);
            try std.testing.expectEqual(g[0].lamport, 42);
            try std.testing.expect(g[0].endpoint != null);
            try std.testing.expectEqual(g[0].endpoint.?.port, 51821);
        },
        else => return error.InvalidMessageType,
    }
}

test "ping_req roundtrip" {
    const sender = [_]u8{0x01} ** 32;
    const target = [_]u8{0x02} ** 32;

    const req = messages.PingReq{
        .sender_pubkey = sender,
        .target_pubkey = target,
        .seq = 55,
    };

    var buf: [128]u8 = undefined;
    const written = try encodePingReq(&buf, req);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ping_req => |r| {
            try std.testing.expectEqualSlices(u8, &sender, &r.sender_pubkey);
            try std.testing.expectEqualSlices(u8, &target, &r.target_pubkey);
            try std.testing.expectEqual(r.seq, 55);
        },
        else => return error.InvalidMessageType,
    }
}

test "org alias announce roundtrip" {
    const org_pk = [_]u8{0xAA} ** 32;
    const alias_name = "eosrio\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const sig = [_]u8{0x55} ** 64;

    const msg = messages.OrgAliasAnnounce{
        .org_pubkey = org_pk,
        .alias = alias_name.*,
        .lamport = 100,
        .signature = sig,
    };

    var buf: [256]u8 = undefined;
    const written = try encodeOrgAliasAnnounce(&buf, msg);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .org_alias_announce => |a| {
            try std.testing.expectEqualSlices(u8, &org_pk, &a.org_pubkey);
            try std.testing.expectEqual(a.lamport, 100);
            try std.testing.expectEqualSlices(u8, a.alias[0..6], "eosrio");
        },
        else => return error.InvalidMessageType,
    }
}

test "org cert revoke roundtrip" {
    const org_pk = [_]u8{0xBB} ** 32;
    const node_pk = [_]u8{0xCC} ** 32;
    const sig = [_]u8{0xDD} ** 64;

    const msg = messages.OrgCertRevoke{
        .org_pubkey = org_pk,
        .node_pubkey = node_pk,
        .reason = 1, // key_compromised
        .lamport = 42,
        .signature = sig,
    };

    var buf: [256]u8 = undefined;
    const written = try encodeOrgCertRevoke(&buf, msg);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .org_cert_revoke => |r| {
            try std.testing.expectEqualSlices(u8, &org_pk, &r.org_pubkey);
            try std.testing.expectEqualSlices(u8, &node_pk, &r.node_pubkey);
            try std.testing.expectEqual(r.reason, 1);
            try std.testing.expectEqual(r.lamport, 42);
        },
        else => return error.InvalidMessageType,
    }
}

test "org trust vouch roundtrip" {
    const org_pk = [_]u8{0xEE} ** 32;
    const vouched_pk = [_]u8{0xFF} ** 32;
    const sig = [_]u8{0x11} ** 64;

    const msg = messages.OrgTrustVouch{
        .org_pubkey = org_pk,
        .vouched_pubkey = vouched_pk,
        .lamport = 777,
        .signature = sig,
    };

    var buf: [256]u8 = undefined;
    const written = try encodeOrgTrustVouch(&buf, msg);

    // Verify wire size: 1 + 32 + 32 + 8 + 64 = 137
    try std.testing.expectEqual(written, 137);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .org_trust_vouch => |v| {
            try std.testing.expectEqualSlices(u8, &org_pk, &v.org_pubkey);
            try std.testing.expectEqualSlices(u8, &vouched_pk, &v.vouched_pubkey);
            try std.testing.expectEqual(v.lamport, 777);
            try std.testing.expectEqualSlices(u8, &sig, &v.signature);
        },
        else => return error.InvalidMessageType,
    }
}
