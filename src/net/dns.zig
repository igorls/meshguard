//! Minimal DNS resolver for meshguard seed discovery.
//!
//! Implements RFC 1035 DNS queries over UDP to resolve:
//!   - A records (hostname → IPv4)
//!   - TXT records (service discovery via `_meshguard._udp.domain`)
//!   - mDNS queries (multicast to 224.0.0.251:5353)
//!
//! Zero dependencies beyond std and the project's UdpSocket.

const std = @import("std");
const posix = std.posix;

// ─── DNS Wire Format Constants ───

const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;
const MDNS_ADDR: [4]u8 = .{ 224, 0, 0, 251 };

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const CLASS_IN: u16 = 1;

const HEADER_LEN: usize = 12;
const MAX_RESPONSE: usize = 512; // Standard DNS UDP max

// ─── DNS Header ───

const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

// ─── Public API ───

/// Parse /etc/resolv.conf and return up to 3 nameserver IPv4 addresses.
pub fn getNameservers(buf: *[3][4]u8) usize {
    const file = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch return 0;
    defer file.close();

    var read_buf: [2048]u8 = undefined;
    const n = file.readAll(&read_buf) catch return 0;
    const content = read_buf[0..n];

    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (count >= 3) break;
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "nameserver")) {
            const rest = std.mem.trimLeft(u8, trimmed["nameserver".len..], " \t");
            // Trim any trailing whitespace/CR
            const ip_str = std.mem.trimRight(u8, rest, " \t\r");
            if (parseIpv4(ip_str)) |addr| {
                buf[count] = addr;
                count += 1;
            }
        }
    }
    return count;
}

/// Resolve a hostname to an IPv4 address via DNS A record query.
/// Returns null if resolution fails or times out.
pub fn resolveA(hostname: []const u8) ?[4]u8 {
    var ns_buf: [3][4]u8 = undefined;
    const ns_count = getNameservers(&ns_buf);
    if (ns_count == 0) return null;

    // Try each nameserver
    for (ns_buf[0..ns_count]) |ns| {
        if (queryA(ns, hostname)) |addr| {
            return addr;
        }
    }
    return null;
}

/// Query a specific nameserver for an A record.
fn queryA(nameserver: [4]u8, hostname: []const u8) ?[4]u8 {
    var query_buf: [512]u8 = undefined;
    const query_len = buildQuery(&query_buf, hostname, TYPE_A, 0xABCD) catch return null;

    const response = sendQuery(nameserver, DNS_PORT, query_buf[0..query_len]) orelse return null;

    // Parse A record from response
    return parseAResponse(&response.data, response.len);
}

/// Query DNS TXT records for a domain.
/// Returns parsed TXT record strings as "key=value" pairs.
/// Caller owns the returned slice and each string.
pub fn queryTXT(allocator: std.mem.Allocator, domain: []const u8) ![][]const u8 {
    var ns_buf: [3][4]u8 = undefined;
    const ns_count = getNameservers(&ns_buf);
    if (ns_count == 0) return &.{};

    for (ns_buf[0..ns_count]) |ns| {
        var query_buf: [512]u8 = undefined;
        const query_len = buildQuery(&query_buf, domain, TYPE_TXT, 0xCDEF) catch continue;

        const response = sendQuery(ns, DNS_PORT, query_buf[0..query_len]) orelse continue;
        return parseTXTResponse(allocator, &response.data, response.len);
    }
    return &.{};
}

/// Query mDNS for TXT records on the local network.
/// Sends multicast to 224.0.0.251:5353 and collects responses.
/// Caller owns the returned slice and each string.
pub fn queryMDNS(allocator: std.mem.Allocator, service_name: []const u8) ![][]const u8 {
    var query_buf: [512]u8 = undefined;
    const query_len = buildQuery(&query_buf, service_name, TYPE_TXT, 0) catch return &.{};

    // Create UDP socket for mDNS
    const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return &.{};
    defer posix.close(sock_fd);

    // Set SO_REUSEADDR
    const one: i32 = 1;
    posix.setsockopt(sock_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

    // Send multicast query
    const mdns_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, MDNS_PORT),
        .addr = std.mem.nativeToBig(u32, @as(u32, @bitCast(MDNS_ADDR))),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    _ = posix.sendto(sock_fd, query_buf[0..query_len], 0, @ptrCast(&mdns_addr), @sizeOf(posix.sockaddr.in)) catch return &.{};

    // Collect responses with a short timeout (500ms)
    var results: std.ArrayList([]const u8) = .empty;

    var fds = [_]posix.pollfd{
        .{ .fd = sock_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    // Poll for up to 1 second, collecting multiple responses
    var deadline: i32 = 1000;
    while (deadline > 0) {
        const poll_start = std.time.milliTimestamp();
        const n = posix.poll(&fds, deadline) catch break;
        const elapsed: i32 = @intCast(@min(std.time.milliTimestamp() - poll_start, deadline));
        deadline -= elapsed;

        if (n == 0) break; // timeout

        if (fds[0].revents & posix.POLL.IN != 0) {
            var resp_buf: [MAX_RESPONSE]u8 = undefined;
            const resp_n = posix.recvfrom(sock_fd, &resp_buf, 0, null, null) catch break;
            if (resp_n > HEADER_LEN) {
                const parsed = parseTXTResponse(allocator, &resp_buf, resp_n) catch continue;
                for (parsed) |txt| {
                    results.append(allocator, txt) catch {};
                }
                if (parsed.len > 0) allocator.free(parsed);
            }
        }
    }

    return results.toOwnedSlice(allocator);
}

// ─── DNS Wire Encoding ───

/// Build a DNS query packet for the given domain and record type.
fn buildQuery(buf: *[512]u8, domain: []const u8, qtype: u16, id: u16) !usize {
    var pos: usize = 0;

    // Header
    writeU16(buf, &pos, id); // ID
    writeU16(buf, &pos, 0x0100); // Flags: standard query, recursion desired
    writeU16(buf, &pos, 1); // QDCOUNT: 1 question
    writeU16(buf, &pos, 0); // ANCOUNT
    writeU16(buf, &pos, 0); // NSCOUNT
    writeU16(buf, &pos, 0); // ARCOUNT

    // Question: encode domain name as labels
    pos = try encodeDomainName(buf, pos, domain);

    // QTYPE and QCLASS
    writeU16(buf, &pos, qtype);
    writeU16(buf, &pos, CLASS_IN);

    return pos;
}

/// Encode a domain name as DNS labels (e.g., "example.com" → \x07example\x03com\x00).
fn encodeDomainName(buf: *[512]u8, start: usize, domain: []const u8) !usize {
    var pos = start;
    var labels = std.mem.splitScalar(u8, domain, '.');

    while (labels.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        if (pos + 1 + label.len >= buf.len) return error.BufferTooSmall;

        buf[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(buf[pos .. pos + label.len], label);
        pos += label.len;
    }

    // Null terminator
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = 0;
    pos += 1;

    return pos;
}

// ─── DNS Wire Decoding ───

/// Parse an A record response, returning the first IPv4 address found.
fn parseAResponse(data: []const u8, len: usize) ?[4]u8 {
    if (len < HEADER_LEN) return null;

    const ancount = readU16(data, 6);
    if (ancount == 0) return null;

    // Skip header + question section
    var pos: usize = HEADER_LEN;
    pos = skipDomainName(data, pos, len) orelse return null;
    pos += 4; // QTYPE + QCLASS
    if (pos >= len) return null;

    // Parse answer records
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        pos = skipDomainName(data, pos, len) orelse return null;
        if (pos + 10 > len) return null;

        const rtype = readU16(data, pos);
        pos += 2;
        _ = readU16(data, pos); // class
        pos += 2;
        pos += 4; // TTL
        const rdlength = readU16(data, pos);
        pos += 2;

        if (rtype == TYPE_A and rdlength == 4 and pos + 4 <= len) {
            return .{ data[pos], data[pos + 1], data[pos + 2], data[pos + 3] };
        }

        pos += rdlength;
        if (pos > len) return null;
    }
    return null;
}

/// Parse TXT record responses, returning all TXT strings.
fn parseTXTResponse(allocator: std.mem.Allocator, data: []const u8, len: usize) ![][]const u8 {
    if (len < HEADER_LEN) return &.{};

    const flags = readU16(data, 2);
    // Check RCODE (bits 0-3): 0 = no error
    if (flags & 0x000F != 0) return &.{};

    const ancount = readU16(data, 6);
    if (ancount == 0) return &.{};

    var results: std.ArrayList([]const u8) = .empty;

    // Skip header + question section
    var pos: usize = HEADER_LEN;
    pos = skipDomainName(data, pos, len) orelse return results.toOwnedSlice(allocator);
    pos += 4; // QTYPE + QCLASS
    if (pos >= len) return results.toOwnedSlice(allocator);

    // Parse answer records
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        pos = skipDomainName(data, pos, len) orelse break;
        if (pos + 10 > len) break;

        const rtype = readU16(data, pos);
        pos += 2;
        _ = readU16(data, pos); // class
        pos += 2;
        pos += 4; // TTL
        const rdlength = readU16(data, pos);
        pos += 2;

        if (rtype == TYPE_TXT) {
            // TXT RDATA: one or more length-prefixed strings
            const rdata_end = pos + rdlength;
            while (pos < rdata_end and pos < len) {
                const txt_len = data[pos];
                pos += 1;
                if (pos + txt_len > len or pos + txt_len > rdata_end) break;

                const txt = try allocator.dupe(u8, data[pos .. pos + txt_len]);
                try results.append(allocator, txt);
                pos += txt_len;
            }
        } else {
            pos += rdlength;
        }

        if (pos > len) break;
    }

    return results.toOwnedSlice(allocator);
}

/// Skip a DNS domain name (handles compression pointers).
fn skipDomainName(data: []const u8, start: usize, len: usize) ?usize {
    var pos = start;
    while (pos < len) {
        const label_len = data[pos];
        if (label_len == 0) {
            return pos + 1; // null terminator
        }
        // Compression pointer (top 2 bits set)
        if (label_len & 0xC0 == 0xC0) {
            return pos + 2; // pointer is 2 bytes
        }
        pos += 1 + label_len;
    }
    return null;
}

// ─── Network I/O ───

const QueryResponse = struct {
    data: [MAX_RESPONSE]u8,
    len: usize,
};

/// Send a DNS query to a nameserver and wait for a response (2s timeout).
fn sendQuery(nameserver: [4]u8, port: u16, query: []const u8) ?QueryResponse {
    const sock_fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return null;
    defer posix.close(sock_fd);

    const addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, @as(u32, @bitCast(nameserver))),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    _ = posix.sendto(sock_fd, query, 0, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return null;

    // Wait for response with 2s timeout
    var fds = [_]posix.pollfd{
        .{ .fd = sock_fd, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = posix.poll(&fds, 2000) catch return null;
    if (ready == 0) return null;

    var result: QueryResponse = undefined;
    const n = posix.recvfrom(sock_fd, &result.data, 0, null, null) catch return null;
    result.len = n;
    return result;
}

// ─── Helpers ───

fn writeU16(buf: *[512]u8, pos: *usize, value: u16) void {
    buf[pos.*] = @intCast(value >> 8);
    buf[pos.* + 1] = @intCast(value & 0xFF);
    pos.* += 2;
}

fn readU16(data: []const u8, offset: usize) u16 {
    return (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4) return null;
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
    return addr;
}

/// Parse meshguard TXT record values.
/// Expected format: "meshguard=ip:port"
/// Returns the endpoint portion ("ip:port") or null if not a meshguard record.
pub fn parseMeshguardTXT(txt: []const u8) ?struct { addr: [4]u8, port: u16 } {
    const prefix = "meshguard=";
    if (!std.mem.startsWith(u8, txt, prefix)) return null;
    const endpoint_str = txt[prefix.len..];

    const colon_idx = std.mem.lastIndexOfScalar(u8, endpoint_str, ':') orelse return null;
    const ip_str = endpoint_str[0..colon_idx];
    const port_str = endpoint_str[colon_idx + 1 ..];

    const addr = parseIpv4(ip_str) orelse return null;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    return .{ .addr = addr, .port = port };
}

// ─── Tests ───

test "encode domain name" {
    var buf: [512]u8 = undefined;
    const pos = try encodeDomainName(&buf, 0, "example.com");
    try std.testing.expectEqual(pos, 13); // \x07example\x03com\x00
    try std.testing.expectEqual(buf[0], 7);
    try std.testing.expectEqualSlices(u8, buf[1..8], "example");
    try std.testing.expectEqual(buf[8], 3);
    try std.testing.expectEqualSlices(u8, buf[9..12], "com");
    try std.testing.expectEqual(buf[12], 0);
}

test "build query" {
    var buf: [512]u8 = undefined;
    const len = try buildQuery(&buf, "example.com", TYPE_A, 0x1234);
    try std.testing.expect(len > HEADER_LEN);
    // Check ID
    try std.testing.expectEqual(buf[0], 0x12);
    try std.testing.expectEqual(buf[1], 0x34);
    // Check QDCOUNT = 1
    try std.testing.expectEqual(readU16(&buf, 4), 1);
}

test "parse meshguard TXT" {
    const result = parseMeshguardTXT("meshguard=1.2.3.4:51821").?;
    try std.testing.expectEqual(result.addr, [4]u8{ 1, 2, 3, 4 });
    try std.testing.expectEqual(result.port, 51821);

    // Non-meshguard TXT should return null
    try std.testing.expect(parseMeshguardTXT("v=spf1 include:...") == null);
    try std.testing.expect(parseMeshguardTXT("") == null);
}

test "parse resolv.conf nameservers" {
    // This test just verifies the function doesn't crash — actual content
    // depends on the host system
    var buf: [3][4]u8 = undefined;
    _ = getNameservers(&buf);
}

test "skip domain name" {
    // Regular name: \x03www\x07example\x03com\x00
    const name = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const pos = skipDomainName(&name, 0, name.len).?;
    try std.testing.expectEqual(pos, 17);

    // Compression pointer
    const compressed = [_]u8{ 0xC0, 0x0C };
    const pos2 = skipDomainName(&compressed, 0, compressed.len).?;
    try std.testing.expectEqual(pos2, 2);
}
