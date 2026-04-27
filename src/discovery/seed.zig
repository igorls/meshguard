//! Seed peer resolution for mesh bootstrap.
//!
//! Supports three discovery methods:
//!   1. Static seeds: `--seed ip:port` or `--seed hostname:port`
//!   2. DNS TXT records: `--dns domain` → queries `_meshguard._udp.domain`
//!   3. mDNS LAN discovery: `--mdns` → multicast query for `_meshguard._udp.local`

const std = @import("std");
const messages = @import("../protocol/messages.zig");
const dns = @import("../net/dns.zig");

/// Resolve seed peers from all configured sources.
pub fn resolveSeeds(
    allocator: std.mem.Allocator,
    static_seeds: []const []const u8,
    dns_domain: []const u8,
    use_mdns: bool,
) ![]messages.Endpoint {
    var endpoints: std.ArrayList(messages.Endpoint) = .empty;

    // 1. Parse static seed addresses (ip:port or hostname:port)
    for (static_seeds) |seed| {
        if (parseEndpoint(seed)) |ep| {
            try endpoints.append(allocator, ep);
        } else if (resolveHostSeed(seed)) |ep| {
            try endpoints.append(allocator, ep);
        }
    }

    // 2. DNS TXT record lookup
    if (dns_domain.len > 0) {
        // Query _meshguard._udp.{domain} for TXT records
        var srv_name_buf: [256]u8 = undefined;
        const srv_name = std.fmt.bufPrint(&srv_name_buf, "_meshguard._udp.{s}", .{dns_domain}) catch dns_domain;

        const txt_records = dns.queryTXT(allocator, srv_name) catch &.{};
        defer {
            for (txt_records) |txt| allocator.free(txt);
            if (txt_records.len > 0) allocator.free(txt_records);
        }

        for (txt_records) |txt| {
            if (dns.parseMeshguardTXT(txt)) |parsed| {
                try endpoints.append(allocator, messages.Endpoint.initV4(parsed.addr, parsed.port));
            }
        }
    }

    // 3. mDNS LAN discovery
    if (use_mdns) {
        const mdns_records = dns.queryMDNS(allocator, "_meshguard._udp.local") catch &.{};
        defer {
            for (mdns_records) |txt| allocator.free(txt);
            if (mdns_records.len > 0) allocator.free(mdns_records);
        }

        for (mdns_records) |txt| {
            if (dns.parseMeshguardTXT(txt)) |parsed| {
                try endpoints.append(allocator, messages.Endpoint.initV4(parsed.addr, parsed.port));
            }
        }
    }

    return endpoints.toOwnedSlice(allocator);
}

/// Parse an "ip:port" string into an Endpoint.
pub fn parseEndpoint(s: []const u8) ?messages.Endpoint {
    const parsed = splitHostPort(s) orelse return null;
    const ip_str = parsed.host;
    const port_str = parsed.port;

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    if (parseIpv6(ip_str)) |addr6| {
        return messages.Endpoint.initV6(addr6, port);
    }

    // Parse IPv4 dotted-quad
    var addr: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;
    while (octets.next()) |octet| {
        if (i >= 4) return null;
        addr[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;

    return messages.Endpoint.initV4(addr, port);
}

fn splitHostPort(s: []const u8) ?struct { host: []const u8, port: []const u8 } {
    if (s.len > 0 and s[0] == '[') {
        const close = std.mem.indexOfScalar(u8, s, ']') orelse return null;
        if (close + 1 >= s.len or s[close + 1] != ':') return null;
        return .{ .host = s[1..close], .port = s[close + 2 ..] };
    }
    const colon_idx = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    return .{ .host = s[0..colon_idx], .port = s[colon_idx + 1 ..] };
}

fn parseIpv6(s: []const u8) ?[16]u8 {
    if (std.mem.indexOfScalar(u8, s, ':') == null) return null;
    var groups: [8]u16 = .{0} ** 8;
    var group_count: usize = 0;

    const compress_idx = std.mem.indexOf(u8, s, "::");
    if (compress_idx != null and std.mem.indexOf(u8, s[compress_idx.? + 2 ..], "::") != null) return null;

    const left = if (compress_idx) |idx| s[0..idx] else s;
    const right = if (compress_idx) |idx| s[idx + 2 ..] else "";

    group_count += parseIpv6Part(left, groups[group_count..]) orelse return null;
    const right_count = parseIpv6Part(right, groups[group_count..]) orelse return null;
    if (group_count + right_count > 8) return null;
    if (compress_idx == null and group_count + right_count != 8) return null;
    if (compress_idx != null and group_count + right_count >= 8) return null;
    const zeros = if (compress_idx != null) 8 - group_count - right_count else 0;

    var src: usize = 0;
    var dst: usize = 0;
    var out: [16]u8 = .{0} ** 16;
    while (dst < 8) : (dst += 1) {
        const value: u16 = if (compress_idx != null and dst >= group_count and dst < group_count + zeros)
            0
        else blk: {
            const v = groups[src];
            src += 1;
            break :blk v;
        };
        out[dst * 2] = @truncate(value >> 8);
        out[dst * 2 + 1] = @truncate(value);
    }
    return out;
}

fn parseIpv6Part(part: []const u8, out: []u16) ?usize {
    if (part.len == 0) return 0;
    var count: usize = 0;
    var iter = std.mem.splitScalar(u8, part, ':');
    while (iter.next()) |group| {
        if (group.len == 0 or group.len > 4 or count >= out.len) return null;
        out[count] = std.fmt.parseInt(u16, group, 16) catch return null;
        count += 1;
    }
    return count;
}

/// Resolve a "hostname:port" seed by looking up the hostname via DNS A record.
fn resolveHostSeed(s: []const u8) ?messages.Endpoint {
    const parsed = splitHostPort(s) orelse return null;
    const hostname = parsed.host;
    const port_str = parsed.port;

    // Must have a non-numeric hostname (IP-based seeds go through parseEndpoint)
    if (hostname.len == 0) return null;
    // Quick check: if all chars are digits or dots, it's an IP (already tried in parseEndpoint)
    var is_ip = true;
    for (hostname) |c| {
        if (c != '.' and (c < '0' or c > '9')) {
            is_ip = false;
            break;
        }
    }
    if (is_ip) return null;

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    const addr = dns.resolveA(hostname) orelse return null;

    return messages.Endpoint.initV4(addr, port);
}

test "parse endpoint" {
    const ep = parseEndpoint("1.2.3.4:51821").?;
    try std.testing.expectEqual(ep.addr, [4]u8{ 1, 2, 3, 4 });
    try std.testing.expectEqual(ep.port, 51821);
}

test "parse IPv6 endpoint" {
    const ep = parseEndpoint("[fd99:6d67::1]:51821").?;
    try std.testing.expect(ep.addr6 != null);
    try std.testing.expectEqual(ep.addr6.?[0], 0xfd);
    try std.testing.expectEqual(ep.addr6.?[1], 0x99);
    try std.testing.expectEqual(ep.port, 51821);

    const compressed_zero = parseEndpoint("[::0]:51821").?;
    try std.testing.expect(compressed_zero.addr6 != null);
    try std.testing.expectEqual(compressed_zero.addr6.?[15], 0);

    const zero_group = parseEndpoint("[fd99:0::1]:51821").?;
    try std.testing.expect(zero_group.addr6 != null);
    try std.testing.expectEqual(zero_group.addr6.?[2], 0);
    try std.testing.expectEqual(zero_group.addr6.?[3], 0);
}

test "parse invalid endpoint" {
    try std.testing.expect(parseEndpoint("not-an-ip") == null);
    try std.testing.expect(parseEndpoint("1.2.3.4") == null);
    try std.testing.expect(parseEndpoint("") == null);
}

test "resolve host seed with numeric IP falls through" {
    // Numeric IPs should return null (handled by parseEndpoint instead)
    try std.testing.expect(resolveHostSeed("1.2.3.4:51821") == null);
}
