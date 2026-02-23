//! STUN client for NAT traversal (RFC 5389 Binding Request/Response).
//!
//! Implements the minimal subset needed for NAT type detection:
//!   1. Send Binding Request (20-byte header)
//!   2. Receive Binding Response
//!   3. Parse XOR-MAPPED-ADDRESS to learn our public IP:port
//!
//! Wire format:
//!   Request:  [2B type=0x0001][2B len=0][4B magic=0x2112A442][12B txn_id]
//!   Response: [20B header][attributes...]
//!     XOR-MAPPED-ADDRESS (0x0020): [2B reserved][1B family][2B xport][4B xaddr]

const std = @import("std");
const Udp = @import("../net/udp.zig");
const messages = @import("../protocol/messages.zig");

/// STUN magic cookie (RFC 5389 §6)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// IPv4 address family
const FAMILY_IPV4: u8 = 0x01;

/// The external (public) address as seen by a STUN server.
pub const ExternalAddress = struct {
    addr: [4]u8,
    port: u16,
};

/// Re-export NatType from messages for convenience.
pub const NatType = messages.NatType;

/// Result of STUN discovery.
pub const StunResult = struct {
    external: ExternalAddress,
    nat_type: NatType,
};

/// Default STUN servers to try.
pub const DEFAULT_STUN_SERVERS = [_]StunServer{
    .{ .host = .{ 74, 125, 250, 129 }, .port = 19302 }, // stun.l.google.com
    .{ .host = .{ 104, 18, 32, 7 }, .port = 3478 }, // stun.cloudflare.com
};

pub const StunServer = struct {
    host: [4]u8,
    port: u16,
};

// ─── Encoding ───

/// Build a 20-byte STUN Binding Request.
pub fn encodBindingRequest(buf: *[20]u8) [12]u8 {
    // Type: Binding Request (0x0001)
    std.mem.writeInt(u16, buf[0..2], BINDING_REQUEST, .big);
    // Length: 0 (no attributes)
    std.mem.writeInt(u16, buf[2..4], 0, .big);
    // Magic Cookie
    std.mem.writeInt(u32, buf[4..8], MAGIC_COOKIE, .big);
    // Transaction ID: 12 random bytes
    var txn_id: [12]u8 = undefined;
    std.crypto.random.bytes(&txn_id);
    @memcpy(buf[8..20], &txn_id);
    return txn_id;
}

// ─── Decoding ───

pub const StunDecodeError = error{
    BufferTooShort,
    InvalidMagicCookie,
    NotBindingResponse,
    TransactionIdMismatch,
    NoMappedAddress,
    UnsupportedFamily,
};

/// Parse a STUN Binding Response and extract the XOR-MAPPED-ADDRESS.
pub fn decodeBindingResponse(
    data: []const u8,
    expected_txn_id: [12]u8,
) StunDecodeError!ExternalAddress {
    if (data.len < 20) return error.BufferTooShort;

    // Verify message type
    const msg_type = std.mem.readInt(u16, data[0..2], .big);
    if (msg_type != BINDING_RESPONSE) return error.NotBindingResponse;

    // Verify magic cookie
    const cookie = std.mem.readInt(u32, data[4..8], .big);
    if (cookie != MAGIC_COOKIE) return error.InvalidMagicCookie;

    // Verify transaction ID
    if (!std.mem.eql(u8, data[8..20], &expected_txn_id)) return error.TransactionIdMismatch;

    // Parse attributes
    const msg_len = std.mem.readInt(u16, data[2..4], .big);
    const attr_end = @min(20 + msg_len, data.len);
    var pos: usize = 20;

    while (pos + 4 <= attr_end) {
        const attr_type = std.mem.readInt(u16, data[pos..][0..2], .big);
        const attr_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        pos += 4;

        if (pos + attr_len > attr_end) break;

        if (attr_type == ATTR_XOR_MAPPED_ADDRESS) {
            return parseXorMappedAddress(data[pos..][0..attr_len], data[4..8], data[8..20]);
        } else if (attr_type == ATTR_MAPPED_ADDRESS) {
            // Fallback: some servers only send MAPPED-ADDRESS
            return parseMappedAddress(data[pos..][0..attr_len]);
        }

        // Advance to next attribute (padded to 4-byte boundary)
        pos += (attr_len + 3) & ~@as(usize, 3);
    }

    return error.NoMappedAddress;
}

fn parseXorMappedAddress(attr: []const u8, cookie_bytes: *const [4]u8, txn_id: *const [12]u8) StunDecodeError!ExternalAddress {
    _ = txn_id;
    if (attr.len < 8) return error.BufferTooShort;

    const family = attr[1];
    if (family != FAMILY_IPV4) return error.UnsupportedFamily;

    // XOR port with top 16 bits of magic cookie
    const xport = std.mem.readInt(u16, attr[2..4], .big);
    const port = xport ^ @as(u16, @truncate(MAGIC_COOKIE >> 16));

    // XOR address with magic cookie
    var addr: [4]u8 = undefined;
    addr[0] = attr[4] ^ cookie_bytes[0];
    addr[1] = attr[5] ^ cookie_bytes[1];
    addr[2] = attr[6] ^ cookie_bytes[2];
    addr[3] = attr[7] ^ cookie_bytes[3];

    return .{ .addr = addr, .port = port };
}

fn parseMappedAddress(attr: []const u8) StunDecodeError!ExternalAddress {
    if (attr.len < 8) return error.BufferTooShort;

    const family = attr[1];
    if (family != FAMILY_IPV4) return error.UnsupportedFamily;

    const port = std.mem.readInt(u16, attr[2..4], .big);
    var addr: [4]u8 = undefined;
    @memcpy(&addr, attr[4..8]);

    return .{ .addr = addr, .port = port };
}

// ─── High-level API ───

/// Query a STUN server to discover our external endpoint.
/// Uses the provided UDP socket (already bound to the gossip port).
pub fn discoverPublicEndpoint(socket: *Udp.UdpSocket, server: StunServer) !ExternalAddress {
    var req_buf: [20]u8 = undefined;
    const txn_id = encodBindingRequest(&req_buf);

    // Send Binding Request
    _ = try socket.sendTo(&req_buf, server.host, server.port);

    // Wait for response (2 second timeout)
    if (!try socket.pollRead(2000)) return error.Timeout;

    var recv_buf: [512]u8 = undefined;
    const result = try socket.recvFrom(&recv_buf);
    if (result == null) return error.NoResponse;

    const recv = result.?;
    return decodeBindingResponse(recv.data, txn_id) catch |err| switch (err) {
        error.TransactionIdMismatch => error.NoResponse,
        error.NotBindingResponse => error.NoResponse,
        else => error.NoResponse,
    };
}

/// Try multiple STUN servers and determine our NAT type.
/// `local_port` is the port we're bound to locally.
pub fn discover(socket: *Udp.UdpSocket, local_port: u16, servers: []const StunServer) StunResult {
    for (servers) |server| {
        const ext = discoverPublicEndpoint(socket, server) catch continue;

        // Determine NAT type by comparing ports
        const nat_type: NatType = if (ext.port == local_port)
            .public // same port → likely no NAT or full cone
        else
            .cone; // different port → some NAT present

        return .{ .external = ext, .nat_type = nat_type };
    }

    // All servers failed
    return .{
        .external = .{ .addr = .{ 0, 0, 0, 0 }, .port = 0 },
        .nat_type = .unknown,
    };
}

// ─── Tests ───

test "encode binding request" {
    var buf: [20]u8 = undefined;
    const txn_id = encodBindingRequest(&buf);

    // Check type
    try std.testing.expectEqual(std.mem.readInt(u16, buf[0..2], .big), BINDING_REQUEST);
    // Check length
    try std.testing.expectEqual(std.mem.readInt(u16, buf[2..4], .big), 0);
    // Check magic cookie
    try std.testing.expectEqual(std.mem.readInt(u32, buf[4..8], .big), MAGIC_COOKIE);
    // Check txn_id is embedded
    try std.testing.expectEqualSlices(u8, &txn_id, buf[8..20]);
}

test "decode xor-mapped-address response" {
    // Construct a synthetic STUN Binding Response
    // Public IP: 203.0.113.42:12345
    var txn_id: [12]u8 = undefined;
    @memset(&txn_id, 0xAB);

    const cookie_bytes: [4]u8 = .{ 0x21, 0x12, 0xA4, 0x42 };

    // XOR port: 12345 ^ (0x2112 >> 0) = 12345 ^ 0x2112
    const xport: u16 = 12345 ^ 0x2112;
    // XOR addr: 203.0.113.42 ^ 0x2112A442
    const xaddr: [4]u8 = .{
        203 ^ cookie_bytes[0],
        0 ^ cookie_bytes[1],
        113 ^ cookie_bytes[2],
        42 ^ cookie_bytes[3],
    };

    // Build response packet
    var resp: [32]u8 = undefined;
    // Header
    std.mem.writeInt(u16, resp[0..2], BINDING_RESPONSE, .big);
    std.mem.writeInt(u16, resp[2..4], 12, .big); // attr length = 12 bytes (4 header + 8 value)
    std.mem.writeInt(u32, resp[4..8], MAGIC_COOKIE, .big);
    @memcpy(resp[8..20], &txn_id);
    // XOR-MAPPED-ADDRESS attribute
    std.mem.writeInt(u16, resp[20..22], ATTR_XOR_MAPPED_ADDRESS, .big);
    std.mem.writeInt(u16, resp[22..24], 8, .big); // value length
    resp[24] = 0; // reserved
    resp[25] = FAMILY_IPV4;
    std.mem.writeInt(u16, resp[26..28], xport, .big);
    @memcpy(resp[28..32], &xaddr);

    const result = try decodeBindingResponse(&resp, txn_id);
    try std.testing.expectEqual(result.port, 12345);
    try std.testing.expectEqual(result.addr[0], 203);
    try std.testing.expectEqual(result.addr[1], 0);
    try std.testing.expectEqual(result.addr[2], 113);
    try std.testing.expectEqual(result.addr[3], 42);
}

test "decode mapped-address fallback" {
    var txn_id: [12]u8 = undefined;
    @memset(&txn_id, 0xCC);

    var resp: [32]u8 = undefined;
    std.mem.writeInt(u16, resp[0..2], BINDING_RESPONSE, .big);
    std.mem.writeInt(u16, resp[2..4], 12, .big);
    std.mem.writeInt(u32, resp[4..8], MAGIC_COOKIE, .big);
    @memcpy(resp[8..20], &txn_id);
    // MAPPED-ADDRESS attribute (non-XOR)
    std.mem.writeInt(u16, resp[20..22], ATTR_MAPPED_ADDRESS, .big);
    std.mem.writeInt(u16, resp[22..24], 8, .big);
    resp[24] = 0;
    resp[25] = FAMILY_IPV4;
    std.mem.writeInt(u16, resp[26..28], 54321, .big);
    resp[28] = 192;
    resp[29] = 168;
    resp[30] = 1;
    resp[31] = 100;

    const result = try decodeBindingResponse(&resp, txn_id);
    try std.testing.expectEqual(result.port, 54321);
    try std.testing.expectEqual(result.addr[0], 192);
    try std.testing.expectEqual(result.addr[1], 168);
    try std.testing.expectEqual(result.addr[2], 1);
    try std.testing.expectEqual(result.addr[3], 100);
}

test "decode rejects wrong txn_id" {
    var txn_id: [12]u8 = undefined;
    @memset(&txn_id, 0xAA);

    var wrong_txn: [12]u8 = undefined;
    @memset(&wrong_txn, 0xBB);

    var resp: [20]u8 = undefined;
    std.mem.writeInt(u16, resp[0..2], BINDING_RESPONSE, .big);
    std.mem.writeInt(u16, resp[2..4], 0, .big);
    std.mem.writeInt(u32, resp[4..8], MAGIC_COOKIE, .big);
    @memcpy(resp[8..20], &wrong_txn);

    try std.testing.expectError(error.TransactionIdMismatch, decodeBindingResponse(&resp, txn_id));
}
