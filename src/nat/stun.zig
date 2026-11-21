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
const Dns = @import("../net/dns.zig");
const Udp = @import("../net/udp.zig");
const Ip = @import("../wireguard/ip.zig");
const messages = @import("../protocol/messages.zig");

fn zio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

fn nowMs() i64 {
    return @intCast(std.Io.Timestamp.now(zio(), .awake).toMilliseconds());
}

/// STUN magic cookie (RFC 5389 §6)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// How long one Binding Request waits for its response. Stray datagrams on the
/// shared gossip socket are discarded without ending the wait early.
const STUN_TIMEOUT_MS: i64 = 2000;

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
    server: ?StunServer = null,
};

/// Numeric fallback STUN servers used when configured hostnames cannot be resolved.
pub const DEFAULT_STUN_SERVERS = [_]StunServer{
    .{ .host = .{ 74, 125, 250, 129 }, .port = 19302 }, // stun.l.google.com
    .{ .host = .{ 104, 18, 32, 7 }, .port = 3478 }, // stun.cloudflare.com
};

pub const MAX_CONFIGURED_STUN_SERVERS: usize = 8;

pub const StunServer = struct {
    host: [4]u8,
    port: u16,
};

pub const StunServerSpec = struct {
    host: []const u8,
    port: u16,
};

pub fn parseServerSpec(spec: []const u8) ?StunServerSpec {
    const trimmed = std.mem.trim(u8, spec, " \t\r\n");
    const colon_idx = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return null;
    const host = std.mem.trim(u8, trimmed[0..colon_idx], " \t");
    const port_str = std.mem.trim(u8, trimmed[colon_idx + 1 ..], " \t");
    if (host.len == 0 or port_str.len == 0) return null;

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    if (port == 0) return null;
    return .{ .host = host, .port = port };
}

pub fn resolveServerSpec(spec: []const u8) ?StunServer {
    const parsed = parseServerSpec(spec) orelse return null;
    const host = parseIpv4(parsed.host) orelse blk: {
        if (!shouldResolveHostname(parsed.host)) return null;
        break :blk Dns.resolveA(parsed.host) orelse return null;
    };
    return .{ .host = host, .port = parsed.port };
}

pub fn resolveConfiguredServers(configured: []const []const u8, out: []StunServer) []const StunServer {
    var count: usize = 0;
    for (configured) |spec| {
        if (count >= out.len) break;
        if (resolveServerSpec(spec)) |server| {
            out[count] = server;
            count += 1;
        }
    }
    return out[0..count];
}

pub fn configuredOrDefault(configured: []const []const u8, out: []StunServer) []const StunServer {
    const resolved = resolveConfiguredServers(configured, out);
    if (resolved.len > 0) return resolved;
    return &DEFAULT_STUN_SERVERS;
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4 or octet.len == 0) return null;
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return addr;
}

fn shouldResolveHostname(host: []const u8) bool {
    if (std.mem.indexOfScalar(u8, host, ':') != null) return false;
    if (looksLikeIpv4Literal(host)) return false;
    return true;
}

fn looksLikeIpv4Literal(host: []const u8) bool {
    if (host.len == 0) return false;
    var saw_dot = false;
    for (host) |ch| {
        switch (ch) {
            '0'...'9' => {},
            '.' => saw_dot = true,
            else => return false,
        }
    }
    return saw_dot;
}

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
    zio().random(&txn_id);
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

/// Whether `addr` could plausibly be our public endpoint as seen from outside.
/// Rejects unspecified (0/8), loopback (127/8), link-local (169.254/16),
/// multicast (224/4), reserved + broadcast (240/4 incl. 255.255.255.255) and
/// the mesh prefix itself (a STUN-mapped address inside the mesh can only be a
/// spoof or a loop). RFC1918 and CGNAT (100.64/10) are deliberately accepted:
/// nodes behind the same corporate NAT or CGNAT legitimately see those.
pub fn isPlausiblePublicAddress(addr: [4]u8) bool {
    if (addr[0] == 0) return false;
    if (addr[0] == 127) return false;
    if (addr[0] == 169 and addr[1] == 254) return false;
    if (addr[0] >= 224) return false;
    if (addr[0] == Ip.default_mesh_prefix[0] and addr[1] == Ip.default_mesh_prefix[1]) return false;
    return true;
}

/// Whether a datagram came from the STUN server we queried (address AND port).
pub fn isFromServer(sender_addr: [4]u8, sender_port: u16, server: StunServer) bool {
    return sender_port == server.port and std.mem.eql(u8, &sender_addr, &server.host);
}

/// Query a STUN server to discover our external endpoint.
/// Uses the provided UDP socket (already bound to the gossip port).
pub fn discoverPublicEndpoint(socket: *Udp.UdpSocket, server: StunServer) !ExternalAddress {
    var req_buf: [20]u8 = undefined;
    const txn_id = encodBindingRequest(&req_buf);

    // Send Binding Request
    _ = try socket.sendTo(&req_buf, server.host, server.port);

    // SECURITY: the gossip socket is shared with peer traffic, so keep reading
    // until the deadline and discard every datagram that is not from the queried
    // server (address AND port) or does not echo our 96-bit transaction id. Before
    // this, any host could answer the query, and one unrelated datagram failed it.
    const deadline = nowMs() + STUN_TIMEOUT_MS;
    var recv_buf: [512]u8 = undefined;
    while (true) {
        const remaining = deadline - nowMs();
        if (remaining <= 0) return error.Timeout;
        if (!try socket.pollRead(@intCast(remaining))) return error.Timeout;

        const recv = (try socket.recvFrom(&recv_buf)) orelse continue;
        if (!isFromServer(recv.sender_addr, recv.sender_port, server)) continue;
        return decodeBindingResponse(recv.data, txn_id) catch continue;
    }
}

pub fn externalAddressEql(a: ExternalAddress, b: ExternalAddress) bool {
    return a.port == b.port and std.mem.eql(u8, &a.addr, &b.addr);
}

/// Classify NAT mapping behavior from one or more STUN observations.
///
/// A single server can only distinguish "same mapped port" from "mapped port";
/// two different server observations are needed to identify endpoint-dependent
/// mappings. If the external port changes across servers, peers should stop
/// spending time on hole punching and move to relay fallback.
///
/// SECURITY: if the servers disagree on the public IP, at least one of them is
/// wrong and we cannot tell which; the result is `.unknown` (no public endpoint)
/// rather than trusting the first server, so a single hostile STUN server cannot
/// choose the address we advertise to the mesh.
pub fn classifyMapping(local_port: u16, observations: []const ExternalAddress) NatType {
    if (observations.len == 0) return .unknown;
    const first = observations[0];
    var port_changed = false;
    for (observations[1..]) |obs| {
        if (!std.mem.eql(u8, &first.addr, &obs.addr)) return .unknown;
        if (obs.port != first.port) port_changed = true;
    }
    if (port_changed) return .symmetric;
    return if (first.port == local_port) .public else .cone;
}

const UNKNOWN_RESULT = StunResult{
    .external = .{ .addr = .{ 0, 0, 0, 0 }, .port = 0 },
    .nat_type = .unknown,
    .server = null,
};

/// Try multiple STUN servers and determine our NAT type.
/// `local_port` is the port we're bound to locally.
pub fn discover(socket: *Udp.UdpSocket, local_port: u16, servers: []const StunServer) StunResult {
    var observations: [MAX_CONFIGURED_STUN_SERVERS]ExternalAddress = undefined;
    var observation_count: usize = 0;
    var first_server: ?StunServer = null;

    for (servers) |server| {
        const ext = discoverPublicEndpoint(socket, server) catch continue;
        // SECURITY: a mapped address that cannot be a public endpoint comes from
        // a lying or broken server; it is not an observation.
        if (!isPlausiblePublicAddress(ext.addr)) continue;
        if (observation_count == 0) first_server = server;
        if (observation_count < observations.len) {
            observations[observation_count] = ext;
            observation_count += 1;
        }
        if (observation_count >= 2) break;
    }

    if (observation_count == 0) return UNKNOWN_RESULT;

    const nat_type = classifyMapping(local_port, observations[0..observation_count]);
    if (nat_type == .unknown) return UNKNOWN_RESULT;

    return .{
        .external = observations[0],
        .nat_type = nat_type,
        .server = first_server,
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

test "parse STUN server specs" {
    const parsed = parseServerSpec(" stun.example.com:3478 ").?;
    try std.testing.expectEqualStrings("stun.example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 3478), parsed.port);

    try std.testing.expect(parseServerSpec("stun.example.com") == null);
    try std.testing.expect(parseServerSpec(":3478") == null);
    try std.testing.expect(parseServerSpec("stun.example.com:0") == null);
    try std.testing.expect(parseServerSpec("stun.example.com:not-a-port") == null);
}

test "reject malformed STUN host specs before DNS" {
    try std.testing.expect(resolveServerSpec("1.2.3.999:3478") == null);
    try std.testing.expect(resolveServerSpec("1.2.3.4.5:3478") == null);
    try std.testing.expect(resolveServerSpec("[2001:db8::1]:3478") == null);
}

test "resolve configured STUN server IP literals" {
    var out: [MAX_CONFIGURED_STUN_SERVERS]StunServer = undefined;
    const resolved = resolveConfiguredServers(&.{
        "203.0.113.10:3478",
        "bad-entry",
        "198.51.100.20:19302",
    }, &out);

    try std.testing.expectEqual(@as(usize, 2), resolved.len);
    try std.testing.expectEqual([4]u8{ 203, 0, 113, 10 }, resolved[0].host);
    try std.testing.expectEqual(@as(u16, 3478), resolved[0].port);
    try std.testing.expectEqual([4]u8{ 198, 51, 100, 20 }, resolved[1].host);
    try std.testing.expectEqual(@as(u16, 19302), resolved[1].port);
}

test "configured STUN servers fall back when none resolve" {
    var out: [MAX_CONFIGURED_STUN_SERVERS]StunServer = undefined;
    const resolved = configuredOrDefault(&.{ "bad-entry", "also-bad" }, &out);

    try std.testing.expectEqual(@as(usize, DEFAULT_STUN_SERVERS.len), resolved.len);
    try std.testing.expectEqual(DEFAULT_STUN_SERVERS[0].host, resolved[0].host);
    try std.testing.expectEqual(DEFAULT_STUN_SERVERS[0].port, resolved[0].port);
}

test "classify mapping detects endpoint dependent symmetric NAT" {
    const a = ExternalAddress{ .addr = .{ 203, 0, 113, 10 }, .port = 40000 };
    const b = ExternalAddress{ .addr = .{ 203, 0, 113, 10 }, .port = 40001 };
    try std.testing.expectEqual(NatType.symmetric, classifyMapping(51821, &.{ a, b }));
}

test "classify mapping keeps stable mappings direct or cone" {
    const public = ExternalAddress{ .addr = .{ 203, 0, 113, 10 }, .port = 51821 };
    try std.testing.expectEqual(NatType.public, classifyMapping(51821, &.{public}));
    try std.testing.expectEqual(NatType.public, classifyMapping(51821, &.{ public, public }));

    const cone = ExternalAddress{ .addr = .{ 203, 0, 113, 10 }, .port = 40000 };
    try std.testing.expectEqual(NatType.cone, classifyMapping(51821, &.{cone}));
    try std.testing.expectEqual(NatType.cone, classifyMapping(51821, &.{ cone, cone }));
}

test "classify mapping returns unknown when servers disagree on the public IP" {
    // Two servers reporting different IPs: one is lying (or we are multi-homed).
    // Neither observation may be trusted, even with identical ports.
    const a = ExternalAddress{ .addr = .{ 203, 0, 113, 10 }, .port = 51821 };
    const b = ExternalAddress{ .addr = .{ 198, 51, 100, 7 }, .port = 51821 };
    try std.testing.expectEqual(NatType.unknown, classifyMapping(51821, &.{ a, b }));
    try std.testing.expectEqual(NatType.unknown, classifyMapping(51821, &.{ b, a }));

    // A different IP *and* port is still "unknown", not "symmetric".
    const c = ExternalAddress{ .addr = .{ 198, 51, 100, 7 }, .port = 40001 };
    try std.testing.expectEqual(NatType.unknown, classifyMapping(51821, &.{ a, c }));
}

test "isPlausiblePublicAddress rejects addresses that cannot be a public endpoint" {
    const rejected = [_][4]u8{
        .{ 0, 0, 0, 0 }, // unspecified
        .{ 0, 1, 2, 3 }, // 0.0.0.0/8
        .{ 127, 0, 0, 1 }, // loopback
        .{ 127, 255, 255, 254 },
        .{ 169, 254, 1, 1 }, // link-local
        .{ 224, 0, 0, 251 }, // multicast
        .{ 239, 255, 255, 250 },
        .{ 240, 0, 0, 1 }, // reserved
        .{ 255, 255, 255, 255 }, // broadcast
        .{ 10, 99, 1, 2 }, // mesh prefix
        .{ 10, 99, 0, 0 },
    };
    for (rejected) |addr| {
        try std.testing.expect(!isPlausiblePublicAddress(addr));
    }

    // RFC1918 (other than the mesh /16) and CGNAT stay accepted: peers behind the
    // same corporate NAT or carrier-grade NAT legitimately observe them.
    const accepted = [_][4]u8{
        .{ 203, 0, 113, 42 },
        .{ 8, 8, 8, 8 },
        .{ 1, 0, 0, 1 },
        .{ 223, 255, 255, 255 },
        .{ 192, 168, 1, 100 },
        .{ 172, 16, 0, 1 },
        .{ 10, 0, 0, 1 },
        .{ 10, 98, 255, 255 },
        .{ 10, 100, 0, 1 },
        .{ 100, 64, 0, 1 },
        .{ 100, 127, 255, 254 },
        .{ 169, 253, 0, 1 },
    };
    for (accepted) |addr| {
        try std.testing.expect(isPlausiblePublicAddress(addr));
    }
}

test "isFromServer requires the queried server's address and port" {
    const server = StunServer{ .host = .{ 74, 125, 250, 129 }, .port = 19302 };
    try std.testing.expect(isFromServer(.{ 74, 125, 250, 129 }, 19302, server));
    try std.testing.expect(!isFromServer(.{ 74, 125, 250, 129 }, 3478, server)); // wrong port
    try std.testing.expect(!isFromServer(.{ 74, 125, 250, 130 }, 19302, server)); // wrong host
    try std.testing.expect(!isFromServer(.{ 0, 0, 0, 0 }, 19302, server));
}
