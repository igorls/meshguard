//! Binary codec for wire protocol messages.
//!
//! Format: [1B type][payload...]
//!
//! Ping:     [0x01][32B pubkey][8B seq][8B incarnation][1B gossip_count][N × gossip_entry][extensions]
//! Ack:      [0x03][32B pubkey][8B seq][8B incarnation][1B gossip_count][N × gossip_entry][extensions]
//! PingReq:  [0x02][32B sender][32B target][8B seq]
//!
//! GossipEntry endpoints: [1B has_ep][1B family: 4/6][16B addr][2B port]
//!
//! Ping/Ack extensions, in this order, each optional:
//!   [0x01][314B org certificate]     (legacy senders may send a 186-byte v1 cert)
//!   [0x02][32B wg_pubkey][64B sig]   signed WireGuard binding (identity/binding.zig)
//! Older decoders read only a leading 0x01 and copy at most 314 bytes, so they
//! ignore the binding.

const std = @import("std");
const messages = @import("messages.zig");

const ENDPOINT_SIZE = 1 + 1 + 16 + 2;
const GOSSIP_ENTRY_SIZE = 32 + 1 + 8 + ENDPOINT_SIZE + 1 + 32 + ENDPOINT_SIZE + 1; // 115 bytes
const ORG_CERT_EXTENSION_SIZE = 1 + messages.ORG_CERT_WIRE_SIZE;
const ORG_CERT_V1_EXTENSION_SIZE = 1 + 186;
const WG_BINDING_EXTENSION_SIZE = 1 + messages.WgBinding.WIRE_SIZE;
const EXT_ORG_CERT: u8 = 0x01;
const EXT_WG_BINDING: u8 = 0x02;
const PING_HEADER_SIZE = 1 + 32 + 8 + 8 + 1;

/// Ping/Ack datagrams stay within this size, below the 1280-byte IPv6
/// minimum MTU once IP and UDP headers are added.
pub const MAX_SWIM_DATAGRAM: usize = 1200;
/// Decoders keep at most this many gossip entries per message.
pub const MAX_DECODED_GOSSIP: usize = 8;

/// How many gossip entries fit next to the given extensions.
pub fn maxGossipEntries(has_org_cert: bool, has_wg_binding: bool) usize {
    const extensions = (if (has_org_cert) ORG_CERT_EXTENSION_SIZE else 0) +
        (if (has_wg_binding) WG_BINDING_EXTENSION_SIZE else 0);
    return @min(MAX_DECODED_GOSSIP, (MAX_SWIM_DATAGRAM - PING_HEADER_SIZE - extensions) / GOSSIP_ENTRY_SIZE);
}

fn extensionsSize(has_org_cert: bool, wg_binding: ?messages.WgBinding) usize {
    return (if (has_org_cert) ORG_CERT_EXTENSION_SIZE else 0) +
        (if (wg_binding != null) WG_BINDING_EXTENSION_SIZE else 0);
}

fn encodeExtensions(buf: []u8, has_org_cert: bool, org_cert: *const [messages.ORG_CERT_WIRE_SIZE]u8, wg_binding: ?messages.WgBinding) usize {
    var pos: usize = 0;
    if (has_org_cert) {
        buf[pos] = EXT_ORG_CERT;
        pos += 1;
        @memcpy(buf[pos..][0..messages.ORG_CERT_WIRE_SIZE], org_cert);
        pos += messages.ORG_CERT_WIRE_SIZE;
    }
    if (wg_binding) |binding| {
        buf[pos] = EXT_WG_BINDING;
        pos += 1;
        @memcpy(buf[pos..][0..32], &binding.wg_pubkey);
        pos += 32;
        @memcpy(buf[pos..][0..64], &binding.signature);
        pos += 64;
    }
    return pos;
}

// ─── Encoding ───

/// Encode a Ping message into a buffer. Returns bytes written.
pub fn encodePing(buf: []u8, ping: messages.Ping) !usize {
    const required = PING_HEADER_SIZE + @as(usize, @min(ping.gossip.len, 255)) * GOSSIP_ENTRY_SIZE +
        extensionsSize(ping.has_org_cert, ping.wg_binding);
    if (buf.len < required) return error.BufferTooShort;

    var pos: usize = 0;

    // Type tag
    buf[pos] = @backingInt(messages.MessageType.ping);
    pos += 1;

    // Pubkey
    @memcpy(buf[pos..][0..32], &ping.sender_pubkey);
    pos += 32;

    // Sequence
    std.mem.writeInt(u64, buf[pos..][0..8], ping.seq, .little);
    pos += 8;

    // Incarnation
    std.mem.writeInt(u64, buf[pos..][0..8], ping.incarnation, .little);
    pos += 8;

    // Gossip entries
    const gossip_count: u8 = @intCast(@min(ping.gossip.len, 255));
    buf[pos] = gossip_count;
    pos += 1;

    for (ping.gossip[0..gossip_count]) |entry| {
        pos += try encodeGossipEntry(buf[pos..], entry);
    }

    pos += encodeExtensions(buf[pos..], ping.has_org_cert, &ping.org_cert, ping.wg_binding);
    return pos;
}

/// Encode an Ack message into a buffer. Returns bytes written.
pub fn encodeAck(buf: []u8, ack: messages.Ack) !usize {
    const required = PING_HEADER_SIZE + @as(usize, @min(ack.gossip.len, 255)) * GOSSIP_ENTRY_SIZE +
        extensionsSize(ack.has_org_cert, ack.wg_binding);
    if (buf.len < required) return error.BufferTooShort;

    var pos: usize = 0;

    buf[pos] = @backingInt(messages.MessageType.ack);
    pos += 1;

    @memcpy(buf[pos..][0..32], &ack.sender_pubkey);
    pos += 32;

    std.mem.writeInt(u64, buf[pos..][0..8], ack.seq, .little);
    pos += 8;

    // Incarnation
    std.mem.writeInt(u64, buf[pos..][0..8], ack.incarnation, .little);
    pos += 8;

    const gossip_count: u8 = @intCast(@min(ack.gossip.len, 255));
    buf[pos] = gossip_count;
    pos += 1;

    for (ack.gossip[0..gossip_count]) |entry| {
        pos += try encodeGossipEntry(buf[pos..], entry);
    }

    pos += encodeExtensions(buf[pos..], ack.has_org_cert, &ack.org_cert, ack.wg_binding);
    return pos;
}

/// Encode a PingReq message.
pub fn encodePingReq(buf: []u8, req: messages.PingReq) !usize {
    const required = 1 + 32 + 32 + 8;
    if (buf.len < required) return error.BufferTooShort;

    var pos: usize = 0;

    buf[pos] = @backingInt(messages.MessageType.ping_req);
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
pub fn encodeHolepunchRequest(buf: []u8, req: messages.HolepunchRequest) !usize {
    if (buf.len < 1 + 32 + 32 + ENDPOINT_SIZE + 16) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @backingInt(messages.MessageType.holepunch_request);
    pos += 1;

    @memcpy(buf[pos..][0..32], &req.sender_pubkey);
    pos += 32;

    @memcpy(buf[pos..][0..32], &req.target_pubkey);
    pos += 32;

    pos += try encodeEndpoint(buf[pos..], req.public_endpoint);

    @memcpy(buf[pos..][0..16], &req.token);
    pos += 16;

    return pos;
}

/// Encode a HolepunchResponse. Returns bytes written.
pub fn encodeHolepunchResponse(buf: []u8, resp: messages.HolepunchResponse) !usize {
    if (buf.len < 1 + 32 + ENDPOINT_SIZE + 16) return error.BufferTooShort;
    var pos: usize = 0;

    buf[pos] = @backingInt(messages.MessageType.holepunch_response);
    pos += 1;

    @memcpy(buf[pos..][0..32], &resp.sender_pubkey);
    pos += 32;

    pos += try encodeEndpoint(buf[pos..], resp.public_endpoint);

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

    buf[pos] = @backingInt(messages.MessageType.org_alias_announce);
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

    buf[pos] = @backingInt(messages.MessageType.org_cert_revoke);
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

    buf[pos] = @backingInt(messages.MessageType.org_trust_vouch);
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

// ─── Canonical signed-payload builders for org control messages ───
//
// These define exactly which bytes the org's Ed25519 signature covers, so that
// both a future signer and the receive-side verifier agree. Layouts match the
// `signature:` comments in messages.zig; the lamport is little-endian to match
// the wire encoding above.

/// OrgAliasAnnounce signed payload: alias(32) ‖ lamport(8 LE).
pub fn orgAliasSignedBytes(msg: messages.OrgAliasAnnounce) [40]u8 {
    var out: [40]u8 = undefined;
    @memcpy(out[0..32], &msg.alias);
    std.mem.writeInt(u64, out[32..40], msg.lamport, .little);
    return out;
}

/// OrgCertRevoke signed payload: node_pubkey(32) ‖ reason(1) ‖ lamport(8 LE).
pub fn orgRevokeSignedBytes(msg: messages.OrgCertRevoke) [41]u8 {
    var out: [41]u8 = undefined;
    @memcpy(out[0..32], &msg.node_pubkey);
    out[32] = msg.reason;
    std.mem.writeInt(u64, out[33..41], msg.lamport, .little);
    return out;
}

/// OrgTrustVouch signed payload: vouched_pubkey(32) ‖ lamport(8 LE).
pub fn orgVouchSignedBytes(msg: messages.OrgTrustVouch) [40]u8 {
    var out: [40]u8 = undefined;
    @memcpy(out[0..32], &msg.vouched_pubkey);
    std.mem.writeInt(u64, out[32..40], msg.lamport, .little);
    return out;
}

fn encodeGossipEntry(buf: []u8, entry: messages.GossipEntry) !usize {
    var pos: usize = 0;

    @memcpy(buf[pos..][0..32], &entry.subject_pubkey);
    pos += 32;

    buf[pos] = @backingInt(entry.event);
    pos += 1;

    std.mem.writeInt(u64, buf[pos..][0..8], entry.lamport, .little);
    pos += 8;

    pos += try encodeEndpoint(buf[pos..], entry.endpoint);

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
    pos += try encodeEndpoint(buf[pos..], entry.public_endpoint);

    // NAT type
    buf[pos] = @backingInt(entry.nat_type);
    pos += 1;

    return pos;
}

fn encodeEndpoint(buf: []u8, endpoint: ?messages.Endpoint) !usize {
    if (buf.len < ENDPOINT_SIZE) return error.BufferTooShort;
    if (endpoint) |ep| {
        buf[0] = 1;
        if (ep.addr6) |addr6| {
            buf[1] = 6;
            @memcpy(buf[2..][0..16], &addr6);
        } else {
            buf[1] = 4;
            @memset(buf[2..][0..16], 0);
            @memcpy(buf[2..][0..4], &ep.addr);
        }
        std.mem.writeInt(u16, buf[18..][0..2], ep.port, .little);
    } else {
        @memset(buf[0..ENDPOINT_SIZE], 0);
    }
    return ENDPOINT_SIZE;
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
    incarnation: u64 = 0,
    gossip_buf: [8]messages.GossipEntry = undefined,
    gossip_count: u8 = 0,
    org_cert: [messages.ORG_CERT_WIRE_SIZE]u8 = std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
    has_org_cert: bool = false,
    wg_binding: ?messages.WgBinding = null,

    pub fn gossip(self: *const DecodedPing) []const messages.GossipEntry {
        return self.gossip_buf[0..self.gossip_count];
    }
};

/// Decoded Ack with owned gossip slice.
pub const DecodedAck = struct {
    sender_pubkey: [32]u8,
    seq: u64,
    incarnation: u64 = 0,
    gossip_buf: [8]messages.GossipEntry = undefined,
    gossip_count: u8 = 0,
    org_cert: [messages.ORG_CERT_WIRE_SIZE]u8 = std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
    has_org_cert: bool = false,
    wg_binding: ?messages.WgBinding = null,

    pub fn gossip(self: *const DecodedAck) []const messages.GossipEntry {
        return self.gossip_buf[0..self.gossip_count];
    }
};

/// Decode a message from a wire buffer.
pub fn decode(data: []const u8) DecodeError!DecodedMessage {
    if (data.len < 1) return error.BufferTooShort;

    const msg_type = std.enums.fromInt(messages.MessageType, data[0]) orelse {
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
    if (data.len < 32 + 8 + 8 + 1) return error.BufferTooShort;

    var result = DecodedPing{
        .sender_pubkey = undefined,
        .seq = undefined,
    };

    @memcpy(&result.sender_pubkey, data[0..32]);
    result.seq = std.mem.readInt(u64, data[32..40], .little);
    result.incarnation = std.mem.readInt(u64, data[40..48], .little);

    result.gossip_count = decodeGossipEntries(data, &result.gossip_buf);
    decodeExtensions(data, &result.org_cert, &result.has_org_cert, &result.wg_binding);

    return result;
}

fn decodeAck(data: []const u8) DecodeError!DecodedAck {
    if (data.len < 32 + 8 + 8 + 1) return error.BufferTooShort;

    var result = DecodedAck{
        .sender_pubkey = undefined,
        .seq = undefined,
    };

    @memcpy(&result.sender_pubkey, data[0..32]);
    result.seq = std.mem.readInt(u64, data[32..40], .little);
    result.incarnation = std.mem.readInt(u64, data[40..48], .little);

    result.gossip_count = decodeGossipEntries(data, &result.gossip_buf);
    decodeExtensions(data, &result.org_cert, &result.has_org_cert, &result.wg_binding);

    return result;
}

/// Decodes up to MAX_DECODED_GOSSIP entries that follow the Ping/Ack header.
fn decodeGossipEntries(data: []const u8, out: *[MAX_DECODED_GOSSIP]messages.GossipEntry) u8 {
    const advertised: usize = @min(data[48], MAX_DECODED_GOSSIP);
    var pos: usize = PING_HEADER_SIZE - 1;
    var parsed: u8 = 0;
    for (0..advertised) |i| {
        if (pos + GOSSIP_ENTRY_SIZE > data.len) break;
        out[i] = decodeGossipEntry(data[pos..]) catch break;
        pos += GOSSIP_ENTRY_SIZE;
        parsed += 1;
    }
    return parsed;
}

/// Reads the optional extensions after every advertised gossip entry. `data`
/// excludes the type byte. A truncated or malformed extension never
/// invalidates the packet: its liveness and gossip are already parsed.
fn decodeExtensions(
    data: []const u8,
    cert: *[messages.ORG_CERT_WIRE_SIZE]u8,
    has_cert: *bool,
    wg_binding: *?messages.WgBinding,
) void {
    var pos: usize = PING_HEADER_SIZE - 1 + @as(usize, data[48]) * GOSSIP_ENTRY_SIZE;
    if (pos >= data.len) return;
    if (data[pos] == EXT_ORG_CERT) {
        // Accept legacy v1 186-byte certs and zero-fill the v2 fields.
        if (pos + ORG_CERT_V1_EXTENSION_SIZE > data.len) return;
        @memset(cert, 0);
        const available = data.len - pos - 1;
        const copy_len = @min(available, messages.ORG_CERT_WIRE_SIZE);
        @memcpy(cert[0..copy_len], data[pos + 1 ..][0..copy_len]);
        has_cert.* = true;
        // Only a full-size certificate can be followed by another extension.
        if (available < messages.ORG_CERT_WIRE_SIZE) return;
        pos += ORG_CERT_EXTENSION_SIZE;
    }
    if (pos + WG_BINDING_EXTENSION_SIZE <= data.len and data[pos] == EXT_WG_BINDING) {
        wg_binding.* = .{
            .wg_pubkey = data[pos + 1 ..][0..32].*,
            .signature = data[pos + 33 ..][0..64].*,
        };
    }
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
    if (data.len < 32 + 32 + ENDPOINT_SIZE + 16) return error.BufferTooShort;

    var result: messages.HolepunchRequest = undefined;
    @memcpy(&result.sender_pubkey, data[0..32]);
    @memcpy(&result.target_pubkey, data[32..64]);
    result.public_endpoint = decodeEndpoint(data[64..][0..ENDPOINT_SIZE]) orelse return error.BufferTooShort;
    @memcpy(&result.token, data[64 + ENDPOINT_SIZE ..][0..16]);

    return result;
}

fn decodeHolepunchResponse(data: []const u8) DecodeError!messages.HolepunchResponse {
    if (data.len < 32 + ENDPOINT_SIZE + 16) return error.BufferTooShort;

    var result: messages.HolepunchResponse = undefined;
    @memcpy(&result.sender_pubkey, data[0..32]);
    result.public_endpoint = decodeEndpoint(data[32..][0..ENDPOINT_SIZE]) orelse return error.BufferTooShort;
    @memcpy(&result.token_echo, data[32 + ENDPOINT_SIZE ..][0..16]);

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
    entry.event = std.enums.fromInt(messages.MemberEvent, data[32]) orelse return error.InvalidGossipEvent;
    entry.lamport = std.mem.readInt(u64, data[33..41], .little);

    var pos: usize = 41;
    entry.endpoint = decodeEndpoint(data[pos..][0..ENDPOINT_SIZE]);
    pos += ENDPOINT_SIZE;

    // WG public key
    if (data[pos] == 1) {
        var wg_key: [32]u8 = undefined;
        @memcpy(&wg_key, data[pos + 1 ..][0..32]);
        entry.wg_pubkey = wg_key;
    }
    pos += 1 + 32;

    // Public endpoint
    entry.public_endpoint = decodeEndpoint(data[pos..][0..ENDPOINT_SIZE]);
    pos += ENDPOINT_SIZE;

    // NAT type
    entry.nat_type = std.enums.fromInt(messages.NatType, data[pos]) orelse .unknown;

    return entry;
}

fn decodeEndpoint(data: []const u8) ?messages.Endpoint {
    if (data.len < ENDPOINT_SIZE) return null;
    if (data[0] == 0) return null;
    const port = std.mem.readInt(u16, data[18..][0..2], .little);
    if (data[1] == 6) {
        var addr6: [16]u8 = undefined;
        @memcpy(&addr6, data[2..][0..16]);
        return messages.Endpoint.initV6(addr6, port);
    }
    var addr: [4]u8 = undefined;
    @memcpy(&addr, data[2..][0..4]);
    return messages.Endpoint.initV4(addr, port);
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
    const pubkey = @as([32]u8, @splat(0x42));
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
    const pubkey = @as([32]u8, @splat(0xAA));
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

test "ping optional org cert extension roundtrip" {
    const pubkey = @as([32]u8, @splat(0x42));
    const cert = @as([messages.ORG_CERT_WIRE_SIZE]u8, @splat(0xC7));
    const ping = messages.Ping{
        .sender_pubkey = pubkey,
        .seq = 12345,
        .gossip = &.{},
        .org_cert = cert,
        .has_org_cert = true,
    };

    var buf: [512]u8 = undefined;
    const written = try encodePing(&buf, ping);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ping => |p| {
            try std.testing.expect(p.has_org_cert);
            try std.testing.expectEqualSlices(u8, &cert, &p.org_cert);
        },
        else => return error.InvalidMessageType,
    }
}

test "ack optional org cert extension roundtrip" {
    const pubkey = @as([32]u8, @splat(0xAA));
    const cert = @as([messages.ORG_CERT_WIRE_SIZE]u8, @splat(0xAC));
    const ack = messages.Ack{
        .sender_pubkey = pubkey,
        .seq = 99,
        .gossip = &.{},
        .org_cert = cert,
        .has_org_cert = true,
    };

    var buf: [512]u8 = undefined;
    const written = try encodeAck(&buf, ack);

    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ack => |a| {
            try std.testing.expect(a.has_org_cert);
            try std.testing.expectEqualSlices(u8, &cert, &a.org_cert);
        },
        else => return error.InvalidMessageType,
    }
}

test "ack accepts legacy v1 org cert extension" {
    const pubkey = @as([32]u8, @splat(0xAA));
    const legacy_cert = @as([186]u8, @splat(0xA1));
    var buf: [1 + 32 + 8 + 8 + 1 + 1 + 186]u8 = undefined;
    var pos: usize = 0;

    buf[pos] = @backingInt(messages.MessageType.ack);
    pos += 1;
    @memcpy(buf[pos..][0..32], &pubkey);
    pos += 32;
    std.mem.writeInt(u64, buf[pos..][0..8], 99, .little);
    pos += 8;
    std.mem.writeInt(u64, buf[pos..][0..8], 0, .little);
    pos += 8;
    buf[pos] = 0;
    pos += 1;
    buf[pos] = 1;
    pos += 1;
    @memcpy(buf[pos..][0..legacy_cert.len], &legacy_cert);
    pos += legacy_cert.len;

    const decoded = try decode(buf[0..pos]);
    switch (decoded) {
        .ack => |a| {
            try std.testing.expect(a.has_org_cert);
            try std.testing.expectEqualSlices(u8, &legacy_cert, a.org_cert[0..legacy_cert.len]);
            try std.testing.expect(std.mem.allEqual(u8, a.org_cert[legacy_cert.len..], 0));
        },
        else => return error.InvalidMessageType,
    }
}

test "ping with gossip roundtrip" {
    const pubkey = @as([32]u8, @splat(0x01));
    const subject = @as([32]u8, @splat(0x02));

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

test "ping with IPv6 gossip endpoint roundtrip" {
    const pubkey = @as([32]u8, @splat(0x01));
    const subject = @as([32]u8, @splat(0x02));
    const addr6 = [16]u8{ 0xfd, 0x99, 0x6d, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    const gossip = [_]messages.GossipEntry{.{
        .subject_pubkey = subject,
        .event = .alive,
        .lamport = 43,
        .endpoint = messages.Endpoint.initV6(addr6, 51821),
        .public_endpoint = messages.Endpoint.initV6(addr6, 51822),
    }};

    const ping = messages.Ping{
        .sender_pubkey = pubkey,
        .seq = 8,
        .gossip = &gossip,
    };

    var buf: [512]u8 = undefined;
    const written = try encodePing(&buf, ping);
    const decoded = try decode(buf[0..written]);
    switch (decoded) {
        .ping => |p| {
            const g = p.gossip();
            try std.testing.expect(g[0].endpoint.?.addr6 != null);
            const decoded_addr6 = g[0].endpoint.?.addr6.?;
            try std.testing.expectEqualSlices(u8, &addr6, &decoded_addr6);
            try std.testing.expectEqual(g[0].public_endpoint.?.port, 51822);
        },
        else => return error.InvalidMessageType,
    }
}

test "ping_req roundtrip" {
    const sender = @as([32]u8, @splat(0x01));
    const target = @as([32]u8, @splat(0x02));

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
    const org_pk = @as([32]u8, @splat(0xAA));
    const alias_name = "acme\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    const sig = @as([64]u8, @splat(0x55));

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
            try std.testing.expectEqualSlices(u8, a.alias[0..4], "acme");
        },
        else => return error.InvalidMessageType,
    }
}

test "org cert revoke roundtrip" {
    const org_pk = @as([32]u8, @splat(0xBB));
    const node_pk = @as([32]u8, @splat(0xCC));
    const sig = @as([64]u8, @splat(0xDD));

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
    const org_pk = @as([32]u8, @splat(0xEE));
    const vouched_pk = @as([32]u8, @splat(0xFF));
    const sig = @as([64]u8, @splat(0x11));

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

test "truncated trailing org-cert flag does not drop the whole packet (C4)" {
    const pubkey = @as([32]u8, @splat(0x01));
    const ping = messages.Ping{ .sender_pubkey = pubkey, .seq = 7, .gossip = &.{} };

    var buf: [600]u8 = undefined;
    const written = try encodePing(&buf, ping);

    // Append a stray cert-present flag (0x01) with no room for a legacy 186-byte cert.
    // Pre-fix this returned error.BufferTooShort and failed the ENTIRE decode,
    // discarding otherwise-valid SWIM liveness + gossip.
    buf[written] = 1;
    const decoded = try decode(buf[0 .. written + 1]);
    switch (decoded) {
        .ping => |p| try std.testing.expect(!p.has_org_cert),
        else => return error.InvalidMessageType,
    }
}

fn testGossipEntry(i: u8) messages.GossipEntry {
    return .{
        .subject_pubkey = @as([32]u8, @splat(i)),
        .event = .alive,
        .lamport = i,
        .endpoint = messages.Endpoint.initV4(.{ 10, 0, 0, i }, 51821),
        .wg_pubkey = @as([32]u8, @splat(i +% 1)),
    };
}

test "ping and ack carry a WireGuard binding with or without a certificate" {
    const binding = messages.WgBinding{ .wg_pubkey = @as([32]u8, @splat(0x5A)), .signature = @as([64]u8, @splat(0xB5)) };
    const cert = @as([messages.ORG_CERT_WIRE_SIZE]u8, @splat(0xC7));
    const gossip = [_]messages.GossipEntry{testGossipEntry(3)};

    for ([_]bool{ false, true }) |with_cert| {
        var buf: [1500]u8 = undefined;
        const ping_len = try encodePing(&buf, .{
            .sender_pubkey = @as([32]u8, @splat(0x42)),
            .seq = 5,
            .gossip = &gossip,
            .org_cert = if (with_cert) cert else std.mem.zeroes([messages.ORG_CERT_WIRE_SIZE]u8),
            .has_org_cert = with_cert,
            .wg_binding = binding,
        });
        const ping = (try decode(buf[0..ping_len])).ping;
        try std.testing.expectEqual(with_cert, ping.has_org_cert);
        if (with_cert) try std.testing.expectEqualSlices(u8, &cert, &ping.org_cert);
        try std.testing.expectEqual(@as(u8, 1), ping.gossip_count);
        try std.testing.expectEqualSlices(u8, &binding.wg_pubkey, &ping.wg_binding.?.wg_pubkey);
        try std.testing.expectEqualSlices(u8, &binding.signature, &ping.wg_binding.?.signature);

        const ack_len = try encodeAck(&buf, .{
            .sender_pubkey = @as([32]u8, @splat(0x43)),
            .seq = 6,
            .gossip = &gossip,
            .org_cert = cert,
            .has_org_cert = with_cert,
            .wg_binding = binding,
        });
        const ack = (try decode(buf[0..ack_len])).ack;
        try std.testing.expectEqual(with_cert, ack.has_org_cert);
        try std.testing.expectEqualSlices(u8, &binding.signature, &ack.wg_binding.?.signature);
    }
}

test "packets without a binding decode as before" {
    var buf: [1500]u8 = undefined;
    const len = try encodePing(&buf, .{ .sender_pubkey = @as([32]u8, @splat(1)), .seq = 1, .gossip = &.{} });
    const ping = (try decode(buf[0..len])).ping;
    try std.testing.expect(ping.wg_binding == null);
    try std.testing.expect(!ping.has_org_cert);
}

test "a legacy decoder reading the certificate ignores the binding behind it" {
    // Pre-binding decoders copy at most 314 bytes after a 0x01 flag; the
    // binding must start exactly there so they never mistake it for a cert.
    const cert = @as([messages.ORG_CERT_WIRE_SIZE]u8, @splat(0xC7));
    var buf: [1500]u8 = undefined;
    const len = try encodePing(&buf, .{
        .sender_pubkey = @as([32]u8, @splat(1)),
        .seq = 1,
        .gossip = &.{},
        .org_cert = cert,
        .has_org_cert = true,
        .wg_binding = .{ .wg_pubkey = @as([32]u8, @splat(2)), .signature = @as([64]u8, @splat(3)) },
    });
    try std.testing.expectEqual(@as(usize, PING_HEADER_SIZE + ORG_CERT_EXTENSION_SIZE + WG_BINDING_EXTENSION_SIZE), len);
    try std.testing.expectEqual(EXT_ORG_CERT, buf[PING_HEADER_SIZE]);
    try std.testing.expectEqual(EXT_WG_BINDING, buf[PING_HEADER_SIZE + ORG_CERT_EXTENSION_SIZE]);
}

test "a truncated binding is ignored without dropping the packet" {
    var buf: [1500]u8 = undefined;
    const len = try encodePing(&buf, .{
        .sender_pubkey = @as([32]u8, @splat(1)),
        .seq = 1,
        .gossip = &.{},
        .wg_binding = .{ .wg_pubkey = @as([32]u8, @splat(2)), .signature = @as([64]u8, @splat(3)) },
    });
    const ping = (try decode(buf[0 .. len - 1])).ping;
    try std.testing.expect(ping.wg_binding == null);
}

test "maximum gossip with every extension stays within the datagram budget" {
    var entries: [MAX_DECODED_GOSSIP]messages.GossipEntry = undefined;
    for (&entries, 0..) |*entry, i| entry.* = testGossipEntry(@intCast(i + 1));

    for ([_]bool{ false, true }) |with_cert| {
        for ([_]bool{ false, true }) |with_binding| {
            const count = maxGossipEntries(with_cert, with_binding);
            var buf: [1500]u8 = undefined;
            const len = try encodePing(&buf, .{
                .sender_pubkey = @as([32]u8, @splat(1)),
                .seq = 1,
                .gossip = entries[0..count],
                .has_org_cert = with_cert,
                .wg_binding = if (with_binding) messages.WgBinding{ .wg_pubkey = @as([32]u8, @splat(2)), .signature = @as([64]u8, @splat(3)) } else null,
            });
            try std.testing.expect(len <= MAX_SWIM_DATAGRAM);
            const ping = (try decode(buf[0..len])).ping;
            try std.testing.expectEqual(@as(u8, @intCast(count)), ping.gossip_count);
            try std.testing.expectEqual(with_binding, ping.wg_binding != null);
        }
    }
    try std.testing.expectEqual(@as(usize, 6), maxGossipEntries(true, true));
}
